"""Tests for the i18n module and language switching."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import app
from juniper_policy_generator.i18n import (
    DEFAULT_LANG,
    SUPPORTED_LANGS,
    TRANSLATIONS,
    make_t,
    normalize_lang,
)


@pytest.fixture
def client() -> TestClient:
    """Fresh TestClient per test so cookies don't leak between tests."""
    return TestClient(app)


class TestNormalizeLang:
    def test_valid_lang_returned_as_is(self) -> None:
        assert normalize_lang("en") == "en"
        assert normalize_lang("zh") == "zh"

    def test_invalid_lang_falls_back_to_default(self) -> None:
        assert normalize_lang("fr") == DEFAULT_LANG
        assert normalize_lang("") == DEFAULT_LANG
        assert normalize_lang(None) == DEFAULT_LANG


class TestMakeT:
    def test_known_key_english(self) -> None:
        t = make_t("en")
        assert t("title") == "Juniper Policy Generator"

    def test_known_key_chinese(self) -> None:
        t = make_t("zh")
        assert t("title") == "Juniper 策略生成器"

    def test_unknown_key_returns_key(self) -> None:
        t = make_t("en")
        assert t("nonexistent_key") == "nonexistent_key"

    def test_unknown_lang_falls_back_to_default(self) -> None:
        t = make_t("klingon")
        assert t("title") == TRANSLATIONS[DEFAULT_LANG]["title"]


class TestTranslationsCompleteness:
    def test_both_langs_have_same_keys(self) -> None:
        en_keys = set(TRANSLATIONS["en"].keys())
        zh_keys = set(TRANSLATIONS["zh"].keys())
        missing_in_zh = en_keys - zh_keys
        missing_in_en = zh_keys - en_keys
        assert not missing_in_zh, f"keys missing in zh: {missing_in_zh}"
        assert not missing_in_en, f"keys missing in en: {missing_in_en}"

    def test_no_empty_values(self) -> None:
        for lang in SUPPORTED_LANGS:
            for key, value in TRANSLATIONS[lang].items():
                assert value.strip(), f"empty value for {lang}.{key}"


class TestIndexEndpointLanguages:
    def test_default_lang_english(self, client: TestClient) -> None:
        resp = client.get("/", headers={"Accept-Language": "en-US"})
        assert resp.status_code == 200
        assert "Juniper Policy Generator" in resp.text
        assert "Juniper 策略生成器" not in resp.text

    def test_explicit_lang_zh(self, client: TestClient) -> None:
        resp = client.get("/?lang=zh")
        assert resp.status_code == 200
        assert "Juniper 策略生成器" in resp.text
        # The English title should not appear as a heading in Chinese mode.
        assert "<h1>Juniper Policy Generator</h1>" not in resp.text

    def test_explicit_lang_en(self, client: TestClient) -> None:
        resp = client.get("/?lang=en")
        assert resp.status_code == 200
        assert "<h1>Juniper Policy Generator</h1>" in resp.text

    def test_invalid_lang_falls_back_to_default(self, client: TestClient) -> None:
        resp = client.get("/?lang=fr")
        assert resp.status_code == 200
        assert "<h1>Juniper Policy Generator</h1>" in resp.text

    def test_accept_language_zh_picks_chinese(self, client: TestClient) -> None:
        resp = client.get("/", headers={"Accept-Language": "zh-CN,zh;q=0.9"})
        assert resp.status_code == 200
        assert "Juniper 策略生成器" in resp.text

    def test_cookie_overrides_default(self, client: TestClient) -> None:
        resp = client.get(
            "/",
            cookies={"lang": "zh"},
            headers={"Accept-Language": "en"},
        )
        assert resp.status_code == 200
        assert "Juniper 策略生成器" in resp.text

    def test_query_param_overrides_cookie(self, client: TestClient) -> None:
        resp = client.get(
            "/?lang=en",
            cookies={"lang": "zh"},
        )
        assert resp.status_code == 200
        assert "<h1>Juniper Policy Generator</h1>" in resp.text

    def test_sets_cookie_on_response(self, client: TestClient) -> None:
        resp = client.get("/?lang=zh")
        assert resp.cookies.get("lang") == "zh"

    def test_chinese_form_labels_present(self, client: TestClient) -> None:
        resp = client.get("/?lang=zh")
        assert "策略名称" in resp.text
        assert "源 zone" in resp.text
        assert "目的 zone" in resp.text
        assert "动作" in resp.text
        assert "生成 set 命令" in resp.text

    def test_english_form_labels_present(self, client: TestClient) -> None:
        resp = client.get("/?lang=en")
        assert "Policy name" in resp.text
        assert "From zone" in resp.text
        assert "To zone" in resp.text
        assert "Action" in resp.text
        assert "Generate set commands" in resp.text

    def test_lang_switch_links_present(self, client: TestClient) -> None:
        resp = client.get("/?lang=zh")
        assert 'href="?lang=en"' in resp.text
        assert 'href="?lang=zh"' in resp.text
        # The active one gets the .active class.
        assert 'class="active">中文' in resp.text

    def test_i18n_json_embedded_for_js(self, client: TestClient) -> None:
        resp = client.get("/?lang=zh")
        # The Jinja-rendered JSON should contain the Chinese copy text.
        assert "已复制" in resp.text
        assert "预览不可用" in resp.text
