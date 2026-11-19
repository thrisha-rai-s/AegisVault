
from pathlib import Path

MAX_TEXT_LENGTH = 20000
MAX_IMAGE_SIZE = 10 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".bmp", ".tiff"
}


def validate_text(text):

    if not isinstance(text, str):
        raise ValueError("Input must be text.")

    if not text.strip():
        raise ValueError("Text cannot be empty.")

    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(
            f"Text cannot exceed {MAX_TEXT_LENGTH} characters."
        )

    return True


def validate_image(image_path):

    path = Path(image_path)

    if not path.exists() or not path.is_file():
        raise ValueError("Image file does not exist.")

    if path.suffix.lower() not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Unsupported image format.")

    if path.stat().st_size == 0:
        raise ValueError("Image file is empty.")

    if path.stat().st_size > MAX_IMAGE_SIZE:
        raise ValueError("Image cannot exceed 10 MB.")

    return True
