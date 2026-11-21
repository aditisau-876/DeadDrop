from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "DeadDrop"

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_protected_endpoints_require_authentication():
    paths = [
        ("GET", "/api/trustees"),
        ("GET", "/api/policies"),
        ("GET", "/api/assets"),
        ("POST", "/api/recovery"),
        ("POST", "/api/recovery-packages/challenge"),
    ]
    for method, path in paths:
        response = client.request(method, path, json={} if method == "POST" else None)
        assert response.status_code == 401, (method, path, response.text)
