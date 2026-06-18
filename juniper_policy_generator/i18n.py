"""Translation strings for the UI.

Two languages are supported: 'en' and 'zh'. The lookup helper falls back
to the key itself if a string is missing, so the template can render even
when translations are incomplete.

To add a new string:
  1. Add the key to BOTH 'en' and 'zh' dicts.
  2. Reference it in the template with `{{ t('key') }}` or in JS with
     `window.I18N['key']`.
"""
from __future__ import annotations

from typing import Callable

SUPPORTED_LANGS: tuple[str, ...] = ("en", "zh")
DEFAULT_LANG: str = "en"


TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        # Header
        "title": "Juniper Policy Generator",
        "description": (
            "Fill the form, get a clean set command block — including "
            "auto-generated address and application objects, with CIDR "
            "normalized. Paste it into your SRX."
        ),
        "step1": "step1: input policy info",
        "step2": "step2: click generate",
        "step3": "step3: copy to clipboard",
        # Form
        "input_heading": "Input",
        "policy_name": "Policy name",
        "from_zone": "From zone",
        "to_zone": "To zone",
        "src_ips_label": "Source IPs (one per line: IP or CIDR)",
        "dst_ips_label": "Destination IPs (one per line: IP or CIDR)",
        "tcp_ports_label": "TCP ports (one per line: port or start-end)",
        "udp_ports_label": "UDP ports (one per line)",
        "action": "Action",
        "permit": "permit",
        "deny": "deny",
        "description_label": "Description (optional)",
        "generate": "Generate set commands",
        "reload_example": "Reload example",
        # Result
        "output_heading": "Output",
        "summary_addresses": "addresses:",
        "summary_applications": "applications:",
        "summary_policy": "policy:",
        "summary_action": "action:",
        "summary_object": "Object summary",
        "empty_output": "Fill the form and click Generate.",
        "copy": "Copy to clipboard",
        "download": "Download .set",
        "copied": "Copied ✓",
        "press_ctrl_c": "Press Ctrl+C",
        "nothing_to_copy": "Nothing to copy",
        # Preview (used by JS)
        "preview_unavailable": "preview unavailable",
        "empty_preview": "(empty)",
        "normalized_suffix": "  (normalized)",
    },
    "zh": {
        # Header
        "title": "Juniper 策略生成器",
        "description": (
            "填写表单，自动生成包含 address 和 application 对象的 set 命令块，"
            "CIDR 自动归一化。直接粘贴到 SRX 即可。"
        ),
        "step1": "step1: 输入策略信息",
        "step2": "step2: 点击生成",
        "step3": "step3: 复制到剪贴板",
        # Form
        "input_heading": "输入",
        "policy_name": "策略名称",
        "from_zone": "源 zone",
        "to_zone": "目的 zone",
        "src_ips_label": "源 IP（每行一个 IP 或 CIDR）",
        "dst_ips_label": "目的 IP（每行一个 IP 或 CIDR）",
        "tcp_ports_label": "TCP 端口（每行一个端口或范围，如 8000-8100）",
        "udp_ports_label": "UDP 端口（每行一个）",
        "action": "动作",
        "permit": "允许",
        "deny": "拒绝",
        "description_label": "描述（可选）",
        "generate": "生成 set 命令",
        "reload_example": "加载示例",
        # Result
        "output_heading": "输出",
        "summary_addresses": "地址对象:",
        "summary_applications": "应用对象:",
        "summary_policy": "策略:",
        "summary_action": "动作:",
        "summary_object": "对象详情",
        "empty_output": "填写表单后点击生成按钮。",
        "copy": "复制到剪贴板",
        "download": "下载 .set 文件",
        "copied": "已复制 ✓",
        "press_ctrl_c": "请按 Ctrl+C 复制",
        "nothing_to_copy": "没有内容可复制",
        # Preview (used by JS)
        "preview_unavailable": "预览不可用",
        "empty_preview": "（空）",
        "normalized_suffix": "  (已归一化)",
    },
}


def normalize_lang(lang: str | None) -> str:
    """Return a supported language code, falling back to the default."""
    if lang and lang in SUPPORTED_LANGS:
        return lang
    return DEFAULT_LANG


def make_t(lang: str) -> Callable[[str], str]:
    """Return a translator function bound to the given language.

    >>> t = make_t("en")
    >>> t("title")
    'Juniper Policy Generator'
    >>> t = make_t("zh")
    >>> t("title")
    'Juniper 策略生成器'
    """
    table = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])

    def t(key: str) -> str:
        return table.get(key, key)

    return t
