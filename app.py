
from flask import Flask, render_template, request, send_from_directory
from pathlib import Path
from werkzeug.utils import secure_filename
from uuid import uuid4

from aegisvault.semantic_firewall import inspect_text, inspect_image
from aegisvault.audit_logger import (
    log_scan,
    get_recent_logs,
    get_audit_statistics
)


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / ".aegis" / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".bmp", ".tiff"
}


def render_home(**kwargs):
    return render_template(
        "index.html",
        audit_logs=get_recent_logs(10),
        audit_stats=get_audit_statistics(),
        **kwargs
    )


@app.route("/", methods=["GET"])
def home():
    return render_home()


@app.route("/scan", methods=["POST"])
def scan():

    scan_type = request.form.get("scan_type", "text")

    try:

        if scan_type == "text":

            user_text = request.form.get("user_text", "")

            result = inspect_text(user_text)

            log_scan(
                input_type="text",
                decision=result["decision"],
                pii_count=result["pii_count"],
                message=result["message"]
            )

            return render_home(
                result=result,
                scan_type="text"
            )

        elif scan_type == "image":

            uploaded_file = request.files.get("image")

            if not uploaded_file or not uploaded_file.filename:
                return render_home(
                    error="Please select an image.",
                    scan_type="image"
                )

            original_name = secure_filename(uploaded_file.filename)
            extension = Path(original_name).suffix.lower()

            if extension not in ALLOWED_EXTENSIONS:
                return render_home(
                    error="Unsupported image format.",
                    scan_type="image"
                )

            unique_name = f"{uuid4().hex}{extension}"
            image_path = UPLOAD_DIR / unique_name

            uploaded_file.save(image_path)

            if image_path.stat().st_size == 0:
                image_path.unlink(missing_ok=True)
                raise ValueError("The uploaded image is empty.")

            try:
                result = inspect_image(image_path)
            finally:
    # Remove the original uploaded image after processing.
             image_path.unlink(missing_ok=True)


            log_scan(
                input_type="image",
                decision=result["decision"],
                pii_count=result["pii_count"],
                message=result["message"]
            )

            if result.get("masked_image_path"):
                result["masked_image_url"] = (
                    "/masked/" +
                    Path(result["masked_image_path"]).name
                )

            return render_home(
                result=result,
                scan_type="image"
            )

        else:
            return render_home(error="Invalid scan type.")

    except Exception:

        app.logger.exception("Security scan failed")

        return render_home(
            error="The scan could not be completed. Check the terminal for details.",
            scan_type=scan_type
        )


@app.route("/masked/<filename>")
def masked_image(filename):

    if not filename.endswith("_masked.png"):
        return "Invalid image request.", 404

    return send_from_directory(
        UPLOAD_DIR,
        filename,
        as_attachment=False
    )


@app.errorhandler(413)
def file_too_large(error):
    return render_home(
        error="Image size must not exceed 10 MB."
    ), 413


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
