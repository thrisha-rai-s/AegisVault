
import argparse
from pathlib import Path
from collections import defaultdict

import cv2
import numpy as np
import pytesseract

from PIL import Image, ImageOps
from pytesseract import Output

from aegisvault.detection.text_scanner import scan_text


TESSERACT_PATH = Path(
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

if TESSERACT_PATH.exists():
    pytesseract.pytesseract.tesseract_cmd = str(TESSERACT_PATH)


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}


def mask_sensitive_regions(image_path, output_path=None):

    image_path = Path(image_path)

    if not image_path.exists():
        raise FileNotFoundError("Image file not found.")

    if image_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported image format.")

    # Load and correct image orientation
    with Image.open(image_path) as image:
        image = ImageOps.exif_transpose(image).convert("RGB")
        image_array = np.array(image)

    # OCR: Extract individual words and their positions
    ocr_data = pytesseract.image_to_data(
        image_array,
        output_type=Output.DICT,
        config="--psm 6"
    )

    # Group words belonging to the same text line
    lines = defaultdict(list)

    for i, word in enumerate(ocr_data["text"]):

        word = word.strip()

        if not word:
            continue

        try:
            confidence = float(ocr_data["conf"][i])
        except ValueError:
            continue

        if confidence < 0:
            continue

        key = (
            ocr_data["block_num"][i],
            ocr_data["par_num"][i],
            ocr_data["line_num"][i]
        )

        lines[key].append({
            "text": word,
            "x": ocr_data["left"][i],
            "y": ocr_data["top"][i],
            "w": ocr_data["width"][i],
            "h": ocr_data["height"][i]
        })

    masked_image = image_array.copy()
    detected_count = 0
    detected_categories = set()

    # Find sensitive text and blur its corresponding image regions
    for words in lines.values():

        words.sort(key=lambda item: item["x"])

        line_text = ""
        positions = []

        for word in words:

            start = len(line_text)

            if line_text:
                line_text += " "

            start = len(line_text)
            line_text += word["text"]
            end = len(line_text)

            positions.append({
                "start": start,
                "end": end,
                "box": word
            })

        findings = scan_text(line_text)

        for finding in findings:

            detected_count += 1

            category = finding.get(
                "category",
                finding.get("type", "SENSITIVE")
            )

            detected_categories.add(category)

            start = finding["start"]
            end = finding["end"]

            matched_words = [
                item["box"]
                for item in positions
                if item["start"] < end and item["end"] > start
            ]

            if not matched_words:
                continue

            # Create one bounding rectangle around the sensitive value
            x1 = min(item["x"] for item in matched_words)
            y1 = min(item["y"] for item in matched_words)

            x2 = max(
                item["x"] + item["w"]
                for item in matched_words
            )

            y2 = max(
                item["y"] + item["h"]
                for item in matched_words
            )

            # Add a small safety margin
            padding = 5

            x1 = max(0, x1 - padding)
            y1 = max(0, y1 - padding)

            x2 = min(masked_image.shape[1], x2 + padding)
            y2 = min(masked_image.shape[0], y2 + padding)

            # Blur the sensitive region
            region = masked_image[y1:y2, x1:x2]

            if region.size == 0:
                continue

            kernel = max(15, min(region.shape[0], region.shape[1]) // 2)

            if kernel % 2 == 0:
                kernel += 1

            blurred_region = cv2.GaussianBlur(
                region,
                (kernel, kernel),
                0
            )

            masked_image[y1:y2, x1:x2] = blurred_region

    # Save masked image separately
    if output_path is None:
        output_path = image_path.with_name(
            image_path.stem + "_masked.png"
        )
    else:
        output_path = Path(output_path)

    success = cv2.imwrite(
        str(output_path),
        cv2.cvtColor(masked_image, cv2.COLOR_RGB2BGR)
    )

    if not success:
        raise RuntimeError("Could not save the masked image.")

    return {
        "output_path": str(output_path),
        "total_detected": detected_count,
        "categories": sorted(detected_categories)
    }


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="AegisVault Image Masking System"
    )

    parser.add_argument(
        "image",
        help="Image file to mask"
    )

    args = parser.parse_args()

    try:

        result = mask_sensitive_regions(args.image)

        print("\n========== AEGISVAULT IMAGE MASKER ==========")

        print("Sensitive items detected:", result["total_detected"])

        print(
            "Categories:",
            ", ".join(result["categories"]) or "None"
        )

        print("Masked image saved at:", result["output_path"])

        print("\n=============================================")

    except Exception as error:
        print("\n[ERROR]", error)

