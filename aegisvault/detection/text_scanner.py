
import re


# Sensitive information patterns
PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

    "PHONE": r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",

    "AADHAAR_LIKE": r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",

    "CREDIT_CARD": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",

    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
}


def scan_text(text):

    findings = []

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    for category, pattern in PATTERNS.items():

        matches = re.finditer(pattern, text)

        for match in matches:

            value = match.group()

            # Validate credit card candidates using Luhn algorithm
            if category == "CREDIT_CARD":
                digits = re.sub(r"\D", "", value)

                if not 13 <= len(digits) <= 19:
                    continue

                if not luhn_check(digits):
                    continue

            # Validate IPv4 address ranges
            if category == "IP_ADDRESS":
                parts = value.split(".")

                if not all(0 <= int(part) <= 255 for part in parts):
                    continue

            findings.append({
                "type": category,
                "value": value,
                "start": match.start(),
                "end": match.end()
            })

    findings.sort(key=lambda item: item["start"])

    return findings


def luhn_check(number):

    digits = [int(digit) for digit in number]

    checksum = 0

    for index, digit in enumerate(reversed(digits)):

        if index % 2 == 1:
            digit *= 2

            if digit > 9:
                digit -= 9

        checksum += digit

    return checksum % 10 == 0


if __name__ == "__main__":

    sample_text = """
    My email is student@gmail.com.
    My phone number is 9876543210.
    My Aadhaar number is 1234 5678 9012.
    My card number is 4111 1111 1111 1111.
    Server IP is 192.168.1.10.
    """

    results = scan_text(sample_text)

    print("\n===== AEGISVAULT TEXT SCANNER =====")

    if results:
        for result in results:
            print(f"[DETECTED] {result['type']}: {result['value']}")
    else:
        print("No sensitive information detected.")
