"""Local prompt-injection detector.

This scores untrusted text for signs that it is trying to override the
model's instructions, hide directives, or smuggle a second task. It is a
heuristic gate, not a guarantee: novel phrasing can still score low, and
the gateway treats a high score as a reason to stop rather than to "fix"
the attack and forward it.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

_OVERRIDE = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|messages)"
    r"|disregard\s+(your|the|all)\s+(system\s+)?(instructions|rules|prompt)"
    r"|forget\s+(everything|all)\s+(you\s+were\s+told|above|previous)"
    r"|override\s+(your\s+)?(system\s+)?(prompt|instructions|safety)"
    r"|you\s+are\s+now\s+(a|an|in)\b"
    r"|enter\s+(developer|admin|god)\s+mode"
    r"|jailbreak"
    r"|do\s+anything\s+now"
    r"|<\s*/?\s*(system|instructions?|hidden)\s*>"
    r"|\[\[\s*system\s*\]\]"
    r")"
)

_EXFIL = re.compile(
    r"(?i)("
    r"reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions|secrets?|api\s+keys?)"
    r"|print\s+(the\s+)?(system\s+prompt|hidden\s+prompt|environment\s+variables)"
    r"|send\s+(the\s+)?(secrets?|credentials|api\s+keys?|conversation)\s+to"
    r"|exfiltrat"
    r"|ignore\s+safety\s+and\s+(send|upload|post|email)"
    r"|new\s+instructions\s*:"
    r")"
)

_ROLE = re.compile(
    r"(?im)^[ \t]{0,3}(system|developer|assistant)\s*:\s+\S"
)

_DELIMITER = re.compile(
    r"(?i)(---\s*end\s+(of\s+)?(system|prompt)|```\s*system\b|<\|im_start\|>\s*system)"
)

_ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff\u180e"),
    None,
)
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")

_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


@dataclass(frozen=True)
class InjectionSignal:
    kind: str
    weight: int
    detail: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "weight": self.weight, "detail": self.detail}


@dataclass(frozen=True)
class InjectionReport:
    score: int
    severity: str
    signals: list[InjectionSignal]

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "signals": [signal.as_dict() for signal in self.signals],
        }


def _severity(score: int) -> str:
    if score >= 70:
        return "block"
    if score >= 40:
        return "warn"
    return "allow"


def _hidden_plain(text: str) -> str:
    stripped = text.translate(_ZERO_WIDTH)
    stripped = _BIDI.sub("", stripped)
    stripped = _TAG_CHARS.sub("", stripped)
    return stripped


def _decode_base64_payloads(text: str) -> list[str]:
    payloads: list[str] = []
    for match in _B64.finditer(text):
        raw = match.group(0)
        padded = raw + "=" * ((4 - len(raw) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        if not decoded or len(decoded) > 4000:
            continue
        try:
            plain = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"[A-Za-z]{4}", plain):
            payloads.append(plain)
        if len(payloads) >= 3:
            break
    return payloads


def scan_injection(text: str) -> InjectionReport:
    if not text or not text.strip():
        return InjectionReport(0, "allow", [])

    signals: list[InjectionSignal] = []
    visible = _hidden_plain(text)
    hidden_changed = visible != text

    def add(kind: str, weight: int, detail: str) -> None:
        signals.append(InjectionSignal(kind, weight, detail))

    if _OVERRIDE.search(visible):
        add("instruction_override", 75, "Text tries to replace the model's instructions.")
    if _EXFIL.search(visible):
        add("data_theft", 70, "Text asks the model to reveal or send protected data.")
    if _DELIMITER.search(visible):
        add("delimiter_smuggle", 55, "Text uses a fake system delimiter.")
    role_hits = _ROLE.findall(visible)
    if role_hits:
        add("role_hijack", 45, "Text injects a system, developer, or assistant turn.")

    if hidden_changed:
        weight = 35
        detail = "Text contains hidden or bidirectional Unicode."
        if _OVERRIDE.search(visible) or _EXFIL.search(visible):
            weight = 80
            detail = "Hidden Unicode conceals an instruction override."
        add("hidden_unicode", weight, detail)

    for payload in _decode_base64_payloads(text):
        nested = scan_injection(payload[:2000])
        if nested.score >= 40:
            add(
                "encoded_payload",
                min(85, nested.score),
                "A Base64 blob decodes to instruction-like text.",
            )
            break

    score = min(100, sum(signal.weight for signal in signals))
    return InjectionReport(score, _severity(score), signals)
