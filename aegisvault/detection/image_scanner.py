
import argparse
from pathlib import Path

import cv2
import numpy as np
import pytesseract

from PIL import Image, ImageOps

from aegisvault.detection.text_scanner import scan_text
from aegisvault.detection.injection_detector import analyze_prompt


# Default Windows Tesseract installation
TESSERACT_PATH = Path(
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

if TESSERACT_PATH.exists():
    pytesseract.pytesseract.tesseract_cmd = str(TESSERACT_PATH)


ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}

MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB


def extract_text_from_image(image_path):

    image_path = Path(image_path)

    if not image_path.exists():
        raise FileNotFoundError("Image file not found.")

    if image_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported image format.")

    if image_path.stat().st_size > MAX_IMAGE_SIZE:
        raise ValueError("Image size must not exceed 10 MB.")

    try:
        with Image.open(image_path) as image:

            image = ImageOps.exif_transpose(image)
            image = image.convert("RGB")

            # Convert image to grayscale
            image_array = np.array(image)

            gray = cv2.cvtColor(
                image_array,
                cv2.COLOR_RGB2GRAY
            )

            # Improve text visibility
            processed = cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                31,
                11
            )

            # Extract text using local OCR
            extracted_text = pytesseract.image_to_string(
                processed,
                lang="eng",
                config="--psm 6"
            )

            return extracted_text.strip()

    except pytesseract.TesseractNotFoundError as error:
        raise RuntimeError(
            "Tesseract OCR was not found. Install it and "
            "check its Windows PATH."
        ) from error

    except pytesseract.TesseractError as error:
        raise RuntimeError(
            f"OCR processing failed: {error}"
        ) from error


def scan_image(image_path):

    extracted_text = extract_text_from_image(image_path)

    # Scan extracted text for sensitive information
    pii_findings = scan_text(extracted_text)

    # Scan extracted text for prompt injection
    injection_result = analyze_prompt(extracted_text)

    return {
        "image_name": Path(image_path).name,
        "extracted_text": extracted_text,
        "pii_count": len(pii_findings),
        "pii_findings": pii_findings,
        "injection_result": injection_result,
        "security_decision": injection_result["decision"]
    }


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="AegisVault Local Image Security Scanner"
    )

    parser.add_argument(
        "image",
        help="Path to the image you want to scan"
    )

    args = parser.parse_args()

    print("\n========== AEGISVAULT IMAGE SCANNER ==========")

    try:

        result = scan_image(args.image)

        print("\nIMAGE:", result["image_name"])

        print("\nEXTRACTED TEXT:")
        print(result["extracted_text"] or "No text detected.")

        print("\nSENSITIVE INFORMATION:")

        if result["pii_findings"]:

            for finding in result["pii_findings"]:

                print(
                    f"[DETECTED] {finding['type']}: "
                    f"{finding['value']}"
                )

        else:
            print("No sensitive information detected.")

        print("\nTOTAL SENSITIVE ITEMS:", result["pii_count"])

        print("\nPROMPT INJECTION CHECK:")
        print("Decision:", result["security_decision"])

        for finding in result["injection_result"]["findings"]:

            print(
                f"[{finding['severity']}] "
                f"{finding['category']}: "
                f"{finding['matched_text']}"
            )

        print("\n==============================================")

    except Exception as error:

        print("\n[ERROR]", error)
