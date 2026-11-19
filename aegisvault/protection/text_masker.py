
import re

from aegisvault.detection.text_scanner import scan_text


def mask_text(text):
    """
    Detect and replace sensitive information
    with category-specific placeholders.
    """

    findings = scan_text(text)

    if not findings:
        return {
            "original_text": text,
            "masked_text": text,
            "total_masked": 0,
            "categories": []
        }

    # Replace from right to left so earlier positions
    # remain unchanged.
    masked_text = text

    for finding in sorted(
        findings,
        key=lambda item: item["start"],
        reverse=True
    ):

        category = finding["type"]

        placeholder = f"[{category} REDACTED]"

        masked_text = (
            masked_text[:finding["start"]]
            + placeholder
            + masked_text[finding["end"]:]
        )

    categories = sorted(set(
        finding["type"] for finding in findings
    ))

    return {
        "original_text": text,
        "masked_text": masked_text,
        "total_masked": len(findings),
        "categories": categories
    }


if __name__ == "__main__":

    sample_text = """
    Hello! My name is Rahul.

    Email: student@gmail.com
    Phone: 9876543210
    Aadhaar: 1234 5678 9012
    Card: 4111 1111 1111 1111
    IP: 192.168.1.10
    """

    result = mask_text(sample_text)

    print("\n========== AEGISVAULT TEXT MASKER ==========")

    print("\nORIGINAL TEXT:")
    print(result["original_text"])

    print("\nPROTECTED TEXT:")
    print(result["masked_text"])

    print("\nSECURITY REPORT:")
    print("Total items masked:", result["total_masked"])
    print("Categories:", result["categories"])

