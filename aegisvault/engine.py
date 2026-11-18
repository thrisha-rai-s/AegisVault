"""Decision layer. Combines local detectors into one allow / redact / block result.

The original text is never written to the audit log. Only a short hash, the
labels that fired, and the decision are kept, under .aegis/ on this machine.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aegisvault.detectors.image_guard import ImageReport, WordBox, inspect_image
from aegisvault.detectors.injection import scan_injection
from aegisvault.detectors.pii import redact_text

_AUDIT = Path(".aegis") / "audit.jsonl"


@dataclass
class Decision:
    action: str
    sanitized_text: str
    pii: list[dict]
    injection: dict
    image: dict | None = None
    redacted_png: bytes | None = None
    summary: str = ""
    content_hash: str = ""
    notes: list[str] = field(default_factory=list)

    def public_dict(self) -> dict:
        return {
            "action": self.action,
            "sanitized_text": self.sanitized_text if self.action != "block" else "",
            "pii": self.pii,
            "injection": self.injection,
            "image": self.image,
            "summary": self.summary,
            "content_hash": self.content_hash,
            "notes": self.notes,
            "forward_allowed": self.action != "block",
        }


def _hash(text: str, image: bytes | None) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8", errors="replace"))
    if image:
        digest.update(image)
    return digest.hexdigest()[:16]


def _write_audit(decision: Decision) -> None:
    try:
        _AUDIT.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": decision.action,
            "hash": decision.content_hash,
            "pii_labels": [item["label"] for item in decision.pii],
            "injection_score": decision.injection.get("score", 0),
            "image": bool(decision.image),
        }
        with _AUDIT.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError:
        return


def inspect_content(
    text: str,
    image_bytes: bytes | None = None,
    words: list[WordBox] | None = None,
) -> Decision:
    sanitized, findings = redact_text(text or "")
    injection = scan_injection(text or "")
    image_report: ImageReport | None = None
    if image_bytes:
        image_report = inspect_image(image_bytes, words=words)

    action = "allow"
    notes: list[str] = []
    if findings:
        action = "redact"
        notes.append(f"Masked {len(findings)} sensitive span(s) in the prompt.")
    if injection.severity == "warn" and action != "block":
        action = "redact" if findings else "warn"
        notes.append("Prompt looks unusual. Review it before forwarding.")
    if injection.severity == "block":
        action = "block"
        notes.append("Prompt injection score is high enough to stop forwarding.")

    if image_report:
        if image_report.pii_labels or image_report.faces_redacted:
            if action == "allow":
                action = "redact"
            notes.append(
                f"Pixelated {image_report.regions_redacted} text region(s)"
                + (f" and {image_report.faces_redacted} face(s)." if image_report.faces_redacted else ".")
            )
        if image_report.injection_severity == "block":
            action = "block"
            notes.append("Text read from the image tried to override the model.")
        notes.extend(image_report.notes)

    if action == "allow" and not notes:
        notes.append("No sensitive text or injection pattern found. Metadata is still stripped from images.")

    summary = {
        "allow": "Clear to forward.",
        "warn": "Forward only if you accept the warning.",
        "redact": "Forward the masked copy, not the original.",
        "block": "Stopped on this machine. Nothing was forwarded.",
    }[action]

    decision = Decision(
        action=action,
        sanitized_text=sanitized,
        pii=[item.as_dict() for item in findings],
        injection=injection.as_dict(),
        image=image_report.as_dict() if image_report else None,
        redacted_png=image_report.redacted_png if image_report else None,
        summary=summary,
        content_hash=_hash(text or "", image_bytes),
        notes=notes,
    )
    _write_audit(decision)
    return decision
