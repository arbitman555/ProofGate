"""Normal-behavior tests for the ProofGate demo target app.

These pin the intended behavior (happy paths and input handling), not the
planted vulnerabilities. Run with ``python -m pytest demo/target_app``.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app as flask_app  # noqa: E402


@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


def test_index_lists_endpoints(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["service"] == "proofgate-demo"
    assert "/download?file=<name>" in body["endpoints"]


def test_download_serves_public_file(client):
    resp = client.get("/download?file=hello.txt")
    assert resp.status_code == 200
    assert b"Hello from the ProofGate demo app." in resp.data


def test_download_missing_param_is_400(client):
    assert client.get("/download").status_code == 400


def test_download_missing_file_is_404(client):
    assert client.get("/download?file=no-such-file.txt").status_code == 404


def test_search_finds_user_by_substring(client):
    resp = client.get("/search?q=ali")
    assert resp.status_code == 200
    rows = resp.get_json()
    assert [row["username"] for row in rows] == ["alice"]


def test_search_hides_emails(client):
    resp = client.get("/search?q=bob")
    assert resp.status_code == 200
    rows = resp.get_json()
    assert len(rows) == 1
    assert "email" not in rows[0]
    assert rows[0]["bio"] == "Coffee first, code second."


def test_search_no_match_returns_empty_list(client):
    resp = client.get("/search?q=zzz-no-such-user")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_admin_export_lists_all_users(client):
    resp = client.get("/admin/export", headers={"X-Admin-Token": "demo-admin-token"})
    assert resp.status_code == 200
    rows = resp.get_json()
    assert sorted(row["username"] for row in rows) == ["alice", "bob", "carol"]


def test_admin_export_requires_token(client):
    assert client.get("/admin/export").status_code == 403


def test_download_rejects_traversal(client):
    assert client.get("/download?file=../app.py").status_code == 403


def test_search_injection_is_data_not_code(client):
    resp = client.get("/search", query_string={"q": "' OR '1'='1"})
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_avatar_serves_allowlisted_image(client):
    resp = client.get("/avatar?name=cat.png")
    assert resp.status_code == 200
    assert b"avatar:cat" in resp.data


def test_avatar_rejects_unknown_name(client):
    assert client.get("/avatar?name=evil.png").status_code == 404


def test_avatar_rejects_traversal(client):
    assert client.get("/avatar?name=../app.py").status_code == 404
    assert client.get("/avatar?name=../../etc/passwd").status_code == 404
