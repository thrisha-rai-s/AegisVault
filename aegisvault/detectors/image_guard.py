"""On-device image inspection.

Reads text with a local OCR model (RapidOCR / ONNX Runtime) and blurs faces
with OpenCV's built-in detector. Sensitive words are pixelated in place.
Original bytes are not retained after the redacted image is produced.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps

from aegisvault.detectors.injection import scan_injection
from aegisvault.detectors.pii import detect_pii

_MAX_EDGE = 1600
_ocr_engine = None
_ocr_status = "unloaded"


@dataclass
class WordBox:
    text: str
    x: int
    y: int
    w: int
    h: int


@dataclass
class ImageReport:
    redacted_png: bytes
    ocr_text: str
    pii_labels: list[str] = field(default_factory=list)
    regions_redacted: int = 0
    faces_redacted: int = 0
    injection_score: int = 0
    injection_severity: str = "allow"
    notes: list[str] = field(default_factory=list)
    ocr_engine: str = "none"

    def as_dict(self) -> dict:
        return {
            "ocr_text_redacted": redact_ocr_preview(self.ocr_text),
            "pii_labels": self.pii_labels,
            "regions_redacted": self.regions_redacted,
            "faces_redacted": self.faces_redacted,
            "injection_score": self.injection_score,
            "injection_severity": self.injection_severity,
            "notes": self.notes,
            "ocr_engine": self.ocr_engine,
        }


def redact_ocr_preview(text: str) -> str:
    from aegisvault.detectors.pii import redact_text

    redacted, _findings = redact_text(text)
    return redacted


def _load_ocr():
    global _ocr_engine, _ocr_status
    if _ocr_status != "unloaded":
        return _ocr_engine
    try:
        from rapidocr_onnxruntime import RapidOCR

        _ocr_engine = RapidOCR()
        _ocr_status = "rapidocr"
    except Exception as exc:
        _ocr_engine = None
        _ocr_status = f"unavailable: {exc.__class__.__name__}"
    return _ocr_engine


def ocr_status() -> str:
    _load_ocr()
    return _ocr_status


def _prepare(image_bytes: bytes) -> Image.Image:
    with Image.open(io.BytesIO(image_bytes)) as incoming:
        image = ImageOps.exif_transpose(incoming)
        image = image.convert("RGB")
    image.thumbnail((_MAX_EDGE, _MAX_EDGE))
    return image


def _pixelate(image: Image.Image, box: tuple[int, int, int, int], factor: int = 8) -> None:
    x, y, w, h = box
    x = max(0, x)
    y = max(0, y)
    right = min(image.width, x + max(1, w))
    bottom = min(image.height, y + max(1, h))
    if right <= x or bottom <= y:
        return
    crop = image.crop((x, y, right, bottom))
    small_w = max(1, crop.width // factor)
    small_h = max(1, crop.height // factor)
    pixelated = crop.resize((small_w, small_h), Image.Resampling.BILINEAR)
    pixelated = pixelated.resize(crop.size, Image.Resampling.NEAREST)
    image.paste(pixelated, (x, y))


def _read_words(image: Image.Image) -> list[WordBox]:
    engine = _load_ocr()
    if engine is None:
        return []
    import numpy as np

    array = np.array(image)
    result, _elapsed = engine(array)
    words: list[WordBox] = []
    if not result:
        return words
    for item in result:
        # RapidOCR: [box_points, text, score]
        points, text, score = item[0], item[1], float(item[2])
        if score < 0.45 or not str(text).strip():
            continue
        xs = [point[0] for point in points]
        ys = [point[1] for point in points]
        x0, y0, x1, y1 = int(min(xs)), int(min(ys)), int(max(xs)), int(max(ys))
        words.append(WordBox(str(text), x0, y0, max(1, x1 - x0), max(1, y1 - y0)))
    return words


def _detect_faces(image: Image.Image) -> list[tuple[int, int, int, int]]:
    try:
        import cv2
        import numpy as np

        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        cascade = cv2.CascadeClassifier(cascade_path)
        if cascade.empty():
            return []
        gray = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
        faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
        if faces is None or len(faces) == 0:
            return []
        return [(int(x), int(y), int(w), int(h)) for (x, y, w, h) in faces]
    except Exception:
        return []


def _sensitive_words(words: list[WordBox]) -> tuple[set[int], list[str]]:
    if not words:
        return set(), []
    # Group tokens into lines by vertical center so "Card:" and the number
    # beside it are judged together.
    ordered = sorted(range(len(words)), key=lambda i: (words[i].y, words[i].x))
    lines: list[list[int]] = []
    for index in ordered:
        word = words[index]
        center = word.y + word.h / 2
        if lines and abs(center - (words[lines[-1][-1]].y + words[lines[-1][-1]].h / 2)) < max(word.h, 12) * 0.8:
            lines[-1].append(index)
        else:
            lines.append([index])

    hit: set[int] = set()
    labels: list[str] = []
    for line in lines:
        line.sort(key=lambda i: words[i].x)
        text = " ".join(words[i].text for i in line)
        findings = detect_pii(text)
        if not findings:
            continue
        cursor = 0
        spans = []
        for index in line:
            start = cursor
            cursor += len(words[index].text)
            spans.append((index, start, cursor))
            cursor += 1
        for finding in findings:
            labels.append(finding.label)
            for index, start, end in spans:
                if finding.start < end and finding.end > start:
                    hit.add(index)
    return hit, list(dict.fromkeys(labels))


def inspect_image(image_bytes: bytes, words: list[WordBox] | None = None) -> ImageReport:
    image = _prepare(image_bytes)
    notes: list[str] = ["Embedded image metadata was discarded."]
    engine_name = ocr_status() if words is None else "provided"
    if words is None:
        words = _read_words(image)
        if engine_name.startswith("unavailable"):
            notes.append("On-device OCR is unavailable, so text inside the image was not read.")
        elif not words:
            notes.append("No readable text was found in the image.")

    ocr_text = "\n".join(word.text for word in words)
    faces = _detect_faces(image)
    sensitive, labels = _sensitive_words(words)
    for index in sorted(sensitive):
        word = words[index]
        pad_x = int(word.h * 0.25)
        pad_y = int(word.h * 0.35)
        _pixelate(
            image,
            (word.x - pad_x, word.y - pad_y, word.w + pad_x * 2, word.h + pad_y * 2),
        )

    for box in faces:
        _pixelate(image, box, factor=10)
        # Soften the edge so the block does not look like a hard crop artifact.
        x, y, w, h = box
        region = image.crop((x, y, min(image.width, x + w), min(image.height, y + h)))
        region = region.filter(ImageFilter.GaussianBlur(radius=1.2))
        image.paste(region, (x, y))

    injection = scan_injection(ocr_text)
    if injection.severity == "block":
        # Cover the whole image when the pictured text is an injection.
        # The caller still receives the finding; the pixels are not forwarded.
        overlay = Image.new("RGB", image.size, (18, 22, 20))
        draw = ImageDraw.Draw(overlay)
        draw.text((24, 24), "Blocked by AegisVault", fill=(232, 220, 196))
        image = overlay
        notes.append("Pictured text matched a prompt-injection pattern, so the image was withheld.")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return ImageReport(
        redacted_png=buffer.getvalue(),
        ocr_text=ocr_text,
        pii_labels=labels,
        regions_redacted=len(sensitive),
        faces_redacted=len(faces),
        injection_score=injection.score,
        injection_severity=injection.severity,
        notes=notes,
        ocr_engine=engine_name,
    )


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    name = "segoeuib.ttf" if bold else "segoeui.ttf"
    try:
        return ImageFont.truetype(rf"C:\Windows\Fonts\{name}", size)
    except OSError:
        return ImageFont.load_default()


def sample_identity_card() -> bytes:
    """Synthetic card with obvious fake data, used by the demo and tests."""
    image = Image.new("RGB", (880, 520), (244, 239, 230))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 880, 84), fill=(28, 48, 42))
    draw.text((32, 28), "SAMPLE IDENTITY   ·   NOT A REAL DOCUMENT", fill=(232, 220, 196), font=_font(22, bold=True))
    draw.rounded_rectangle((36, 130, 230, 340), radius=18, fill=(214, 206, 196))
    draw.text((78, 210), "PHOTO", fill=(90, 80, 70), font=_font(22, bold=True))
    body = _font(28)
    lines = [
        (270, 140, "Name: Jordan Lee"),
        (270, 200, "Email: jordan.lee@example.com"),
        (270, 260, "Aadhaar: 2345 6789 0123"),
        (270, 320, "Card: 4111 1111 1111 1111"),
        (270, 380, "DOB: 04/12/1991"),
    ]
    for x, y, line in lines:
        draw.text((x, y), line, fill=(28, 32, 30), font=body)
    draw.text((32, 460), "Synthetic fixture for local redaction. No real person.", fill=(90, 90, 86), font=_font(18))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
