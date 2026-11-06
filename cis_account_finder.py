#!/usr/bin/env python3
"""Consent-based audit of a user's own publicly indexed phone-number footprint.

Only public web-search results are queried. This script does not test hidden
account registrations, use private application APIs, bypass authentication, or
access contact books. Use only your own number or with the owner's explicit consent.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

APP_DIR = Path.home() / ".config" / "cis-account-finder"
CONFIG_PATH = APP_DIR / "config.json"
REPORT_DIR = Path.home() / "cis-account-finder-reports"
API_URL = "https://searchapi.api.cloud.yandex.net/v2/web/search"
USER_AGENT = "cis-account-finder/1.0 (public-footprint-audit)"

SITES = {
    "VK": "vk.com",
    "Odnoklassniki": "ok.ru",
    "TikTok": "tiktok.com",
    "Mail.ru": "mail.ru",
    "Telegram public pages": "t.me",
    "WhatsApp public pages": "wa.me",
    "Viber public pages": "viber.com",
    "Avito": "avito.ru",
    "MAX public pages": "max.ru",
}


@dataclass
class SearchResult:
    platform: str
    url: str
    title: str


def normalize_ru_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10:
        return "+7" + digits
    if len(digits) == 11 and digits[0] in {"7", "8"}:
        return "+7" + digits[1:]
    raise ValueError("Введите российский номер: 10 цифр или 11 цифр, начиная с 7/8.")


def load_config() -> dict[str, str] | None:
    if not CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Не удалось прочитать конфигурацию {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("config.json должен содержать JSON-объект.")
    api_key = str(data.get("api_key", "")).strip()
    folder_id = str(data.get("folder_id", "")).strip()
    if not api_key or not folder_id:
        raise RuntimeError("В config.json отсутствует api_key или folder_id. Запустите --setup.")
    return {"api_key": api_key, "folder_id": folder_id}


def save_config(api_key: str, folder_id: str) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(APP_DIR, 0o700)
    except OSError:
        pass
    CONFIG_PATH.write_text(
        json.dumps({"api_key": api_key.strip(), "folder_id": folder_id.strip()},
                   ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def setup() -> None:
    print("Настройка Yandex Search API")
    print("Ключ API вводится скрыто и хранится локально.")
    api_key = getpass.getpass("Yandex API key: ").strip()
    folder_id = input("Yandex Cloud Folder ID: ").strip()
    if not api_key or not folder_id:
        raise ValueError("API key и Folder ID не должны быть пустыми.")
    save_config(api_key, folder_id)
    print(f"Конфигурация сохранена: {CONFIG_PATH}")
    print("Не отправляйте config.json другим людям и не добавляйте его в Git.")


class ResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.current_href: str | None = None
        self.current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href and href.startswith(("http://", "https://")):
                self.current_href = href
                self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.current_href is not None and data.strip():
            self.current_text.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self.current_href is not None:
            title = " ".join(self.current_text).strip()
            self.links.append((self.current_href, title))
            self.current_href = None
            self.current_text = []


def decode_raw_data(response: dict[str, Any]) -> str:
    raw = response.get("rawData")
    if not isinstance(raw, str) or not raw:
        raise RuntimeError("Yandex API вернул ответ без rawData.")
    try:
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("Не удалось декодировать rawData от Yandex API.") from exc


def yandex_search(api_key: str, folder_id: str, query_text: str) -> str:
    body = {
        "query": {
            "searchType": "SEARCH_TYPE_RU",
            "queryText": query_text[:400],
            "familyMode": "FAMILY_MODE_MODERATE",
            "page": "0",
            "fixTypoMode": "FIX_TYPO_MODE_OFF",
        },
        "groupSpec": {
            "groupMode": "GROUP_MODE_FLAT",
            "groupsOnPage": "10",
            "docsInGroup": "1",
        },
        "maxPassages": "3",
        "folderId": folder_id,
        "responseFormat": "FORMAT_HTML",
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": "Api-Key " + api_key,
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")[:800]
        if exc.code in (401, 403):
            raise RuntimeError(
                "Yandex отклонил ключ или доступ к Search API. Проверьте API key, "
                "Folder ID и права ключа."
            ) from exc
        raise RuntimeError(f"Yandex API вернул HTTP {exc.code}: {details}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Не удалось подключиться к Yandex API: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("Yandex API вернул некорректный JSON.") from exc
    return decode_raw_data(payload)


def parse_results(raw_html: str, platform: str, domain: str) -> list[SearchResult]:
    parser = ResultParser()
    parser.feed(raw_html)
    found: list[SearchResult] = []
    seen: set[str] = set()
    for raw_url, title in parser.links:
        try:
            parsed = urllib.parse.urlparse(raw_url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            continue
        if host != domain and not host.endswith("." + domain):
            continue
        url = urllib.parse.urlunparse(parsed._replace(fragment=""))
        if url in seen:
            continue
        seen.add(url)
        found.append(SearchResult(platform, url, title or "(заголовок не извлечён)"))
    return found


def audit(phone: str, config: dict[str, str]) -> list[SearchResult]:
    results: list[SearchResult] = []
    for index, (platform, domain) in enumerate(SITES.items(), start=1):
        query = f'"{phone}" site:{domain}'
        print(f"[{index}/{len(SITES)}] {platform} ({domain})")
        raw_html = yandex_search(config["api_key"], config["folder_id"], query)
        matches = parse_results(raw_html, platform, domain)
        results.extend(matches)
        print(f"    публичных ссылок: {len(matches)}")
        time.sleep(0.35)
    unique: dict[str, SearchResult] = {}
    for item in results:
        unique.setdefault(item.url, item)
    return list(unique.values())


def save_reports(phone: str, results: list[SearchResult]) -> tuple[Path, Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(REPORT_DIR, 0o700)
    except OSError:
        pass
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = re.sub(r"\D", "", phone)[-4:]
    base = REPORT_DIR / f"audit-{suffix}-{stamp}"
    txt_path, json_path = base.with_suffix(".txt"), base.with_suffix(".json")
    payload = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "phone": phone,
        "scope": "publicly indexed pages only",
        "results": [asdict(item) for item in results],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "CIS Account Finder — отчёт публичного аудита",
        f"Номер: {phone}",
        f"Время UTC: {payload['created_at_utc']}",
        f"Найдено ссылок: {len(results)}",
        "",
        "Поисковая выдача не доказывает владение профилем или регистрацию номера.",
        "Каждую ссылку необходимо проверить вручную.",
        "",
    ]
    for i, item in enumerate(results, start=1):
        lines.extend([f"{i}. {item.platform}", f"   {item.title}", f"   {item.url}", ""])
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    for path in (txt_path, json_path):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return txt_path, json_path


def self_tests() -> None:
    valid = {
        "+7 (999) 123-45-67": "+79991234567",
        "8 999 123 45 67": "+79991234567",
        "9991234567": "+79991234567",
        "7-999-123-45-67": "+79991234567",
    }
    for source, expected in valid.items():
        assert normalize_ru_phone(source) == expected
    for source in ("12345", "+1 202 555 0100", "123456789012"):
        try:
            normalize_ru_phone(source)
        except ValueError:
            continue
        raise AssertionError(f"Invalid number was accepted: {source}")
    sample = (
        '<a href="https://vk.com/example">Public profile</a>'
        '<a href="https://evil.example/test">Other site</a>'
    )
    parsed = parse_results(sample, "VK", "vk.com")
    assert len(parsed) == 1 and parsed[0].url == "https://vk.com/example"
    print("Self-test: 8 checks passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Аудит собственного публичного цифрового следа по российскому номеру."
    )
    parser.add_argument("--setup", action="store_true", help="настроить ключ Yandex Search API")
    parser.add_argument("--self-test", action="store_true", help="локальные тесты без сети")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_tests()
            return 0
        if args.setup:
            setup()
            return 0
        config = load_config()
        if config is None:
            print("Сначала настрой API: python3 cis_account_finder.py --setup")
            return 2

        print("=" * 62)
        print("CIS ACCOUNT FINDER — АУДИТ ПУБЛИЧНОГО ЦИФРОВОГО СЛЕДА")
        print("=" * 62)
        print("Поиск выполняется только по публично индексируемым страницам.")
        print("Скрытая регистрация, приватные API и закрытые профили не проверяются.")
        print("Введённый номер будет передан Yandex Search API.")
        consent = input(
            "Подтверждаете, что это ваш номер или есть явное согласие владельца? [да/нет]: "
        ).strip().lower()
        if consent not in {"да", "д", "yes", "y"}:
            print("Отменено.")
            return 0

        phone = normalize_ru_phone(input("Российский номер: ").strip())
        print(f"Нормализованный номер: {phone}")
        confirm = input("Начать поиск по публичным страницам? [да/нет]: ").strip().lower()
        if confirm not in {"да", "д", "yes", "y"}:
            print("Отменено.")
            return 0

        results = audit(phone, config)
        print("\n" + "=" * 62)
        print(f"Готово. Уникальных ссылок найдено: {len(results)}")
        for item in results:
            print(f"- [{item.platform}] {item.title}\n  {item.url}")
        if not results:
            print("Совпадений в проверенной поисковой выдаче не обнаружено.")
        print("\nОтсутствие результатов не означает отсутствие аккаунтов.")
        save = input("Сохранить локальные TXT и JSON отчёты? [да/нет]: ").strip().lower()
        if save in {"да", "д", "yes", "y"}:
            txt_path, json_path = save_reports(phone, results)
            print(f"TXT:  {txt_path}")
            print(f"JSON: {json_path}")
        return 0
    except (ValueError, RuntimeError, OSError, AssertionError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
