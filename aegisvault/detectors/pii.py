"""Local sensitive-text detector.

Patterns run entirely in-process. Labeled secrets are masked even when the
value would not match a strict checksum, because a field name such as
"Aadhaar:" is itself a strong signal. Unlabeled numbers must pass a checksum
so ordinary quantities are left alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][digit]]
    return checksum == 0


def luhn_valid(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    label: str
    preview: str

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "preview": self.preview,
        }


def _preview(value: str) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    if len(compact) <= 4:
        return "•" * len(compact)
    return compact[:2] + "…" + compact[-2:]


# Higher priority wins when two patterns cover the same characters.
_RULES: list[tuple[str, int, re.Pattern[str], str | None]] = [
    (
        "API_KEY",
        100,
        re.compile(
            r"\b(?:sk-(?:ant-|proj-)?|ghp_|github_pat_|xox[baprs]-|AKIA|AIza)"
            r"[A-Za-z0-9_\-]{12,}\b"
        ),
        None,
    ),
    (
        "JWT",
        95,
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        None,
    ),
    (
        "EMAIL",
        90,
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        "PAN",
        85,
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        None,
    ),
    (
        "SSN",
        84,
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        None,
    ),
    (
        "IBAN",
        83,
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        None,
    ),
    (
        "CARD",
        80,
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "luhn",
    ),
    (
        "AADHAAR",
        78,
        re.compile(r"\b\d{4}[ \-]?\d{4}[ \-]?\d{4}\b"),
        "verhoeff",
    ),
    (
        "PHONE",
        70,
        re.compile(
            r"(?<!\d)(?:\+\d{1,3}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}|\d{5}[\s.\-]\d{5})(?!\d)"
        ),
        None,
    ),
    (
        "SECRET",
        120,
        re.compile(
            r"(?i)\b(?:password|passcode|api[ _-]?key|secret|access[ _-]?token|auth[ _-]?token)"
            r"\b\s*[:=]\s*\S+"
        ),
        None,
    ),
    (
        "MRN",
        76,
        re.compile(
            r"(?i)\b(?:mrn|medical\s+record(?:\s+number)?|patient\s+id|account\s+number)\b"
            r"\s*[:#]?\s*[A-Za-z0-9\-]{4,}"
        ),
        None,
    ),
    (
        "DOB",
        60,
        re.compile(
            r"(?i)\b(?:dob|date\s+of\s+birth|born)\b\s*[:#]?\s*"
            r"(?:\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}|\d{4}[\/\-.]\d{1,2}[\/\-.]\d{1,2})"
        ),
        None,
    ),
]

_LABELED = re.compile(
    r"(?i)\b(aadhaar|ssn|social\s+security|pan|passport|card(?:\s+number)?|"
    r"credit\s+card|cvv|email|e-mail|phone|mobile|mrn|patient\s+id|"
    r"account(?:\s+number)?|dob|date\s+of\s+birth)\b\s*[:#]\s*([^\n,;]{3,80})"
)
_LABEL_MAP = {
    "aadhaar": "AADHAAR",
    "ssn": "SSN",
    "social security": "SSN",
    "pan": "PAN",
    "passport": "PASSPORT",
    "card": "CARD",
    "card number": "CARD",
    "credit card": "CARD",
    "cvv": "CVV",
    "email": "EMAIL",
    "e-mail": "EMAIL",
    "phone": "PHONE",
    "mobile": "PHONE",
    "mrn": "MRN",
    "patient id": "MRN",
    "account": "ACCOUNT",
    "account number": "ACCOUNT",
    "dob": "DOB",
    "date of birth": "DOB",
}


def _checksum_ok(kind: str | None, value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if kind == "luhn":
        return luhn_valid(digits)
    if kind == "verhoeff":
        return len(digits) == 12 and verhoeff_valid(digits)
    return True


def _overlaps(start: int, end: int, spans: list[Finding]) -> bool:
    return any(start < item.end and end > item.start for item in spans)


def detect_pii(text: str) -> list[Finding]:
    if not text:
        return []
    found: list[tuple[int, int, int, str]] = []

    for label, priority, pattern, check in _RULES:
        for match in pattern.finditer(text):
            value = match.group(0)
            if not _checksum_ok(check, value):
                continue
            if label == "IBAN" and not _iban_shape(value):
                continue
            if label == "PAN" and not _pan_shape(value):
                continue
            found.append((priority, match.start(), match.end(), label))

    for match in _LABELED.finditer(text):
        key = re.sub(r"\s+", " ", match.group(1).lower())
        label = _LABEL_MAP.get(key, "SECRET")
        value_start = match.start(2)
        value = match.group(2).strip()
        if len(value) < 3:
            continue
        found.append((110, value_start, value_start + len(match.group(2).rstrip()), label))

    found.sort(key=lambda item: (-item[0], item[1], item[1] - item[2]))
    accepted: list[Finding] = []
    for _priority, start, end, label in found:
        if end <= start or _overlaps(start, end, accepted):
            continue
        accepted.append(Finding(start, end, label, _preview(text[start:end])))
    accepted.sort(key=lambda item: item.start)
    return accepted


def redact_text(text: str) -> tuple[str, list[Finding]]:
    findings = detect_pii(text)
    if not findings:
        return text, []
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor:finding.start])
        pieces.append(f"[{finding.label}]")
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces), findings


def _pan_shape(value: str) -> bool:
    # Fourth character of a PAN is a status letter, not a digit. Already
    # enforced by the regex; reject strings that are all one character class.
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value))


def _iban_shape(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if not 15 <= len(compact) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    remainder = 0
    for ch in numeric:
        remainder = (remainder * 10 + int(ch)) % 97
    return remainder == 1
