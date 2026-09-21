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

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "Security Lead"
    assert data["active"] is True


def test_create_policy():
    trustee_ids = []

    trustees = [
        {
            "name": "Security Lead",
            "role": "Core Trustee",
        },
        {
            "name": "CTO",
            "role": "Core Trustee",
        },
        {
            "name": "Operations Lead",
            "role": "Core Trustee",
        },
        {
            "name": "Security Engineer",
            "role": "Core Trustee",
        },
        {
            "name": "External Auditor",
            "role": "External Auditor",
        },
    ]

    for trustee in trustees:
        response = client.post(
            "/api/trustees",
            json=trustee,
        )

        assert response.status_code == 201

        data = response.json()
        trustee_ids.append(data["id"])

    response = client.post(
        "/api/policies",
        json={
            "name": "Master Root Key",
            "description": "Emergency recovery policy",
            "policy_expression": (
                "(Security Lead AND CTO) OR "
                "(Auditor AND Threshold(2, Admins))"
            ),
            "trustee_ids": trustee_ids,
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "Master Root Key"
    assert data["version"] == 1
    assert data["epoch"] == 1
    assert data["active"] is True
    assert data["trustee_ids"] == trustee_ids