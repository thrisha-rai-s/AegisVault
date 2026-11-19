
import os

from dotenv import load_dotenv
from openai import OpenAI

from aegisvault.semantic_firewall import inspect_text


load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-6.2-astra")


def get_openai_client():
    """Create an OpenAI client using the private API key."""

    if not OPENAI_API_KEY:
        raise RuntimeError("OpenAI API key not configured.")

    return OpenAI(
        api_key=OPENAI_API_KEY,
        timeout=30.0,
        max_retries=2
    )


def ask_openai(prompt):
    """Send sanitized text to OpenAI."""

    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    if len(prompt) > 20000:
        raise ValueError("Prompt is too long.")

    client = get_openai_client()

    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=prompt,
            max_output_tokens=500
        )

        answer = response.output_text

        if not answer:
            raise RuntimeError("Empty response from AI provider.")

        return answer

    except Exception:
        raise RuntimeError(
            "AI provider request failed. Check your API key, "
            "model access, billing and internet connection."
        ) from None


def secure_chat(user_prompt):
    """
    Inspect user input, call OpenAI only when permitted,
    and inspect the generated response before returning it.
    """

    # 1. Inspect user input.
    input_result = inspect_text(user_prompt)

    input_decision = input_result["decision"]

    # 2. Never send BLOCK or REVIEW input to OpenAI.
    if input_decision in ("BLOCK", "REVIEW"):
        return {
            "success": False,
            "decision": input_decision,
            "message": input_result["message"],
            "response": None,
            "pii_count": input_result["pii_count"]
        }

    # 3. Use only the protected output.
    safe_prompt = input_result.get("safe_output")

    if not safe_prompt:
        return {
            "success": False,
            "decision": "REVIEW",
            "message": "No safe input available.",
            "response": None,
            "pii_count": input_result["pii_count"]
        }

    # 4. Send the approved or sanitized prompt to OpenAI.
    try:
        ai_response = ask_openai(safe_prompt)
    except Exception:
        return {
            "success": False,
            "decision": "ERROR",
            "message": "Could not connect to the AI provider.",
            "response": None,
            "pii_count": input_result["pii_count"]
        }

    # 5. Inspect the AI-generated response.
    output_result = inspect_text(ai_response)

    output_decision = output_result["decision"]

    # 6. Never display a response marked BLOCK or REVIEW.
    if output_decision in ("BLOCK", "REVIEW"):
        return {
            "success": False,
            "decision": output_decision,
            "message": "AI response failed security inspection.",
            "response": None,
            "pii_count": input_result["pii_count"]
        }

    # 7. Display only the protected response.
    protected_response = output_result.get("safe_output")

    if not protected_response:
        return {
            "success": False,
            "decision": "REVIEW",
            "message": "AI response could not be safely displayed.",
            "response": None,
            "pii_count": input_result["pii_count"]
        }

    return {
        "success": True,
        "decision": input_decision,
        "message": input_result["message"],
        "response": protected_response,
        "pii_count": input_result["pii_count"]
    }
