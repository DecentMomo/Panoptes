#!/usr/bin/env python3
"""Seed a demo account and two scans. Standard library only.

Usage: python scripts/seed_demo.py
Talks to http://localhost:8000 by default.
"""

from __future__ import annotations

import json
import time
import uuid
import zipfile
from http.cookiejar import CookieJar
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-python"
API = "http://127.0.0.1:8000"
EMAIL = "demo@panoptes.dev"
PASSWORD = "password123"
FIXED_CALC = """import ast

def calculate(expr: str) -> object:
    return ast.literal_eval(expr)
"""
NEW_FILE = """def leftover(expr: str) -> object:
    return eval(expr)
"""


def main() -> None:
    cookies = CookieJar()
    opener = build_opener(HTTPCookieProcessor(cookies))
    try:
        call(opener, cookies, "POST", "/auth/register", {"email": EMAIL, "password": PASSWORD})
    except HTTPError as exc:
        if exc.code != 409:
            raise
    call(opener, cookies, "POST", "/auth/login", {"email": EMAIL, "password": PASSWORD})
    project = call(
        opener,
        cookies,
        "POST",
        "/projects",
        {"name": "Demo", "description": "Seeded for screenshots"},
    )
    first = upload(opener, cookies, project["id"], zip_sample(exclude={"secrets.py"}), "demo.zip")
    wait_scan(opener, cookies, first["id"])
    findings = call(opener, cookies, "GET", f"/scans/{first['id']}/findings")
    explainable = [item for item in findings if "gitleaks" not in item["source_tools"]][:3]
    for item in explainable:
        call(opener, cookies, "POST", f"/findings/{item['id']}/explanation", {})
        wait_explanation(opener, cookies, item["id"])
    calc = next(
        item for item in findings if item["file_path"] == "calc.py" and item["rule_id"] == "B307"
    )
    call(
        opener,
        cookies,
        "PATCH",
        f"/findings/{calc['id']}/status",
        {"status": "false_positive", "reason": "intentional sample of eval in a demo"},
    )
    second = upload(opener, cookies, project["id"], zip_second(), "demo-fixed.zip")
    wait_scan(opener, cookies, second["id"])
    print(f"project={project['id']} base={first['id']} head={second['id']} calc={calc['id']}")


def zip_sample(*, exclude: set[str]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in SAMPLE.iterdir():
            if path.is_file() and path.name not in exclude:
                archive.write(path, path.name)
    return buffer.getvalue()


def zip_second() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in SAMPLE.iterdir():
            if not path.is_file() or path.name in {"secrets.py"}:
                continue
            if path.name == "calc.py":
                archive.writestr("calc.py", FIXED_CALC)
            else:
                archive.write(path, path.name)
        archive.writestr("leftover.py", NEW_FILE)
    return buffer.getvalue()


def upload(opener, cookies: CookieJar, project_id: int, payload: bytes, filename: str) -> dict:
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    return call(
        opener,
        cookies,
        "POST",
        f"/projects/{project_id}/scans",
        raw=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )


def wait_scan(opener, cookies: CookieJar, scan_id: int) -> dict:
    for _ in range(90):
        body = call(opener, cookies, "GET", f"/scans/{scan_id}")
        if body["status"] in {"completed", "partial", "failed"}:
            if body["status"] == "failed":
                raise RuntimeError(body.get("error_message") or "scan failed")
            return body
        time.sleep(2)
    raise TimeoutError(f"scan {scan_id} did not finish")


def wait_explanation(opener, cookies: CookieJar, finding_id: int) -> dict:
    for _ in range(90):
        body = call(opener, cookies, "GET", f"/findings/{finding_id}/explanation")
        if body["status"] in {"completed", "failed"}:
            return body
        time.sleep(2)
    raise TimeoutError(f"explanation {finding_id} did not finish")


def call(
    opener,
    cookies: CookieJar,
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    raw: bytes | None = None,
    content_type: str | None = None,
) -> dict:
    data = raw
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if content_type:
        headers["Content-Type"] = content_type
    csrf = csrf_token(cookies)
    if csrf and method in {"POST", "PATCH", "DELETE"}:
        headers["X-CSRF-Token"] = csrf
    request = Request(API + path, data=data, headers=headers, method=method)
    with opener.open(request) as response:
        body = response.read()
        if not body:
            return {}
        return json.loads(body.decode())


def csrf_token(cookies: CookieJar) -> str | None:
    for cookie in cookies:
        if cookie.name == "csrf_token":
            return cookie.value
    return None


if __name__ == "__main__":
    main()
