
import argparse
from pathlib import Path

from aegisvault.detection.text_scanner import scan_text
from aegisvault.detection.injection_detector import analyze_prompt
from aegisvault.detection.image_scanner import scan_image
from aegisvault.protection.image_masker import mask_sensitive_regions
from aegisvault.protection.input_validator import (
    validate_text,
    validate_image
)


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}


def mask_sensitive_text(text, findings):
    """Replace detected sensitive text with redaction labels."""

    masked_text = text

    # Replace from right to left so earlier positions remain valid.
    for finding in sorted(
        findings,
        key=lambda item: item["start"],
        reverse=True
    ):
        category = finding.get(
            "category",
            finding.get("type", "SENSITIVE")
        )

        masked_text = (
            masked_text[:finding["start"]]
            + f"[{category} REDACTED]"
            + masked_text[finding["end"]:]
        )

    return masked_text


def inspect_text(text):
    """Validate text, detect injection attempts and mask sensitive data."""

    if not isinstance(text, str) or not text.strip():
        return {
            "decision": "REVIEW",
            "message": "Empty or invalid input.",
            "safe_output": None,
            "pii_count": 0,
            "injection_findings": []
        }

    # Step 11.2: Validate text length and input format.
    try:
        validate_text(text)
    except ValueError as error:
        return {
            "decision": "REVIEW",
            "message": str(error),
            "safe_output": None,
            "pii_count": 0,
            "injection_findings": []
        }

    pii_findings = scan_text(text)
    injection_result = analyze_prompt(text)

    injection_decision = injection_result["decision"].upper()

    if injection_decision == "BLOCK":
        decision = "BLOCK"
        safe_output = None
        message = "Malicious prompt detected. Input blocked."

    elif injection_decision == "REVIEW":
        decision = "REVIEW"
        safe_output = None
        message = "Input requires security review."

    elif pii_findings:
        decision = "SANITIZE"
        safe_output = mask_sensitive_text(text, pii_findings)
        message = "Sensitive information detected and masked."

    else:
        decision = "SAFE"
        safe_output = text
        message = "No known security threats detected."

    return {
        "decision": decision,
        "message": message,
        "safe_output": safe_output,
        "pii_count": len(pii_findings),
        "injection_findings": injection_result["findings"]
    }


def inspect_image(image_path):
    """Validate an image, scan it and mask sensitive regions."""

    image_path = Path(image_path)

    # Step 11.2: Validate image existence, format and size.
    validate_image(image_path)

    scan_result = scan_image(image_path)

    injection_decision = (
        scan_result["injection_result"]["decision"].upper()
    )

    pii_count = scan_result["pii_count"]

    masked_image_path = None

    if injection_decision == "BLOCK":
        decision = "BLOCK"
        message = "Malicious instructions detected in image."

    elif injection_decision == "REVIEW":
        decision = "REVIEW"
        message = "Image requires security review."

    else:
        if pii_count > 0:
            mask_result = mask_sensitive_regions(image_path)
            masked_image_path = mask_result["output_path"]

            decision = "SANITIZE"
            message = "Sensitive information detected and image masked."

        else:
            decision = "SAFE"
            message = "No known security threats detected."

    return {
        "decision": decision,
        "message": message,
        "image_name": image_path.name,
        "pii_count": pii_count,
        "masked_image_path": masked_image_path
    }


def inspect_input(user_input):
    """Automatically select the correct security scanner."""

    input_path = Path(user_input)

    if input_path.is_file():
        if input_path.suffix.lower() in IMAGE_EXTENSIONS:
            return inspect_image(input_path)

    return inspect_text(user_input)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="AegisVault Semantic Firewall"
    )

    parser.add_argument(
        "input",
        help="Enter text or provide an image file path."
    )

    args = parser.parse_args()

    try:
        result = inspect_input(args.input)

        print("\n========== AEGISVAULT SEMANTIC FIREWALL ==========")

        print("Security Decision:", result["decision"])
        print("Message:", result["message"])

        if "pii_count" in result:
            print("Sensitive Items:", result["pii_count"])

        if result.get("safe_output") is not None:
            print("\nPROTECTED OUTPUT:")
            print(result["safe_output"])

        if result.get("masked_image_path"):
            print("\nMASKED IMAGE:")
            print(result["masked_image_path"])

        print("\n==================================================")

    except Exception as error:
        print("\n[ERROR]", error)
