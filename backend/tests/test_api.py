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


def test_create_trustee():
    response = client.post(
        "/api/trustees",
        json={
            "name": "Security Lead",
            "role": "Core Trustee",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "Security Lead"
    assert data["active"] is True


def test_create_policy():
    response = client.post(
        "/api/policies",
        json={
            "name": "Master Root Key",
            "description": "Emergency recovery policy",
            "policy_expression": (
                "(Security Lead AND CTO) OR "
                "(Auditor AND Threshold(2, Admins))"
            ),
            "trustee_ids": [
                "trustee-1",
                "trustee-2",
                "trustee-3",
                "trustee-4",
                "trustee-5",
            ],
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["name"] == "Master Root Key"
    assert data["version"] == 1
    assert data["epoch"] == 1