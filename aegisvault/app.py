"""Local HTTP gateway. Binds to 127.0.0.1 and does not call a cloud model
unless AEGIS_UPSTREAM_URL is set and the inspection decision allows it.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from aegisvault import __version__
from aegisvault.detectors.image_guard import ocr_status, sample_identity_card
from aegisvault.engine import inspect_content

_STATIC = Path(__file__).resolve().parent / "static"
_MAX_IMAGE = 8 * 1024 * 1024
_MAX_TEXT = 100_000

app = FastAPI(title="AegisVault", version=__version__)
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {
        "name": "AegisVault",
        "version": __version__,
        "bind": "127.0.0.1",
        "ocr": ocr_status(),
        "upstream_configured": bool(os.environ.get("AEGIS_UPSTREAM_URL")),
    }


@app.get("/api/sample-card")
def sample_card() -> Response:
    return Response(content=sample_identity_card(), media_type="image/png")


@app.post("/api/inspect")
async def inspect(
    text: str = Form(""),
    image: UploadFile | None = File(None),
) -> dict:
    if len(text) > _MAX_TEXT:
        raise HTTPException(status_code=413, detail="Prompt is too long for the local gateway.")
    image_bytes = None
    if image is not None and image.filename:
        image_bytes = await image.read()
        if len(image_bytes) > _MAX_IMAGE:
            raise HTTPException(status_code=413, detail="Image is larger than 8 MB.")
        if not image_bytes:
            image_bytes = None
    decision = inspect_content(text, image_bytes)
    payload = decision.public_dict()
    if decision.redacted_png:
        payload["redacted_image"] = "data:image/png;base64," + base64.b64encode(decision.redacted_png).decode("ascii")
    return payload


@app.post("/api/forward")
async def forward(text: str = Form(""), image: UploadFile | None = File(None)) -> dict:
    """Forward only the sanitized payload, and only when an upstream is configured.

    The browser cannot supply the upstream key. Set AEGIS_UPSTREAM_URL and
    AEGIS_UPSTREAM_KEY in the environment of this process.
    """
    upstream = os.environ.get("AEGIS_UPSTREAM_URL", "").rstrip("/")
    if not upstream:
        raise HTTPException(
            status_code=409,
            detail="No upstream is configured. Inspection stayed on this machine.",
        )
    if len(text) > _MAX_TEXT:
        raise HTTPException(status_code=413, detail="Prompt is too long for the local gateway.")
    image_bytes = None
    if image is not None and image.filename:
        image_bytes = await image.read()
        if len(image_bytes) > _MAX_IMAGE:
            raise HTTPException(status_code=413, detail="Image is larger than 8 MB.")
    decision = inspect_content(text, image_bytes)
    if decision.action == "block":
        body = decision.public_dict()
        body["forwarded"] = False
        return body

    content: list[dict] = [{"type": "text", "text": decision.sanitized_text}]
    if decision.redacted_png:
        encoded = base64.b64encode(decision.redacted_png).decode("ascii")
        content.append({"type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded}"}})
    request_body = {
        "model": os.environ.get("AEGIS_UPSTREAM_MODEL", "gpt-4o-mini"),
        "messages": [{"role": "user", "content": content if decision.redacted_png else decision.sanitized_text}],
    }
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("AEGIS_UPSTREAM_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    url = upstream if upstream.endswith("/chat/completions") else upstream + "/v1/chat/completions"
    async with httpx.AsyncClient(timeout=60) as client:
        remote = await client.post(url, json=request_body, headers=headers)
    body = decision.public_dict()
    body["forwarded"] = remote.status_code < 400
    body["upstream_status"] = remote.status_code
    try:
        body["upstream"] = remote.json()
    except Exception:
        body["upstream"] = {"raw": remote.text[:2000]}
    return body
