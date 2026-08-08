import pytest
from fastapi.testclient import TestClient

from .main import app
from .model import heuristic_score


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_malicious_payload(client):
    payload = {
        "site_id": "site-1",
        "method": "POST",
        "path": "/graphql",
        "protocol": "graphql",
        "client_ip": "203.0.113.66",
        "content_type": "application/graphql",
        "body_len": 500000,
        "header_count": 5,
        "has_auth": False,
        "is_graphql": True,
        "graphql_depth": 30,
        "graphql_cost": 50000,
        "has_cookie": False,
        "has_api_key": False,
        "bot_score": 0.95,
        "ja4": "",
    }
    resp = client.post("/score", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["anomaly"] is True
    assert 0.0 <= body["score"] <= 1.0
    assert isinstance(body["label"], str)


def test_benign_payload(client):
    payload = {
        "site_id": "site-2",
        "method": "GET",
        "path": "/home",
        "protocol": "rest",
        "client_ip": "198.51.100.10",
        "content_type": "text/html",
        "body_len": 120,
        "header_count": 25,
        "has_auth": True,
        "is_graphql": False,
        "graphql_depth": 1,
        "graphql_cost": 2,
        "has_cookie": True,
        "has_api_key": True,
        "bot_score": 0.02,
        "ja4": "t13d123a",
    }
    resp = client.post("/score", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert 0.0 <= body["score"] <= 1.0
    assert isinstance(body["anomaly"], bool)
    assert isinstance(body["label"], str)


def test_malformed_json_returns_400(client):
    resp = client.post(
        "/score",
        content="{not valid json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400


def test_heuristic_scorer_ranges():
    class Req:
        pass

    benign = Req()
    benign.body_len = 50
    benign.header_count = 20
    benign.graphql_depth = 1
    benign.graphql_cost = 2
    benign.bot_score = 0.05
    benign.has_auth = True
    benign.is_graphql = False
    benign.has_cookie = True
    benign.has_api_key = True
    benign.method = "GET"
    benign.protocol = "rest"
    s = heuristic_score(benign)
    assert 0.0 <= s <= 1.0

    evil = Req()
    evil.body_len = 900000
    evil.header_count = 4
    evil.graphql_depth = 50
    evil.graphql_cost = 150000
    evil.bot_score = 0.98
    evil.has_auth = False
    evil.is_graphql = True
    evil.has_cookie = False
    evil.has_api_key = False
    evil.method = "TRACE"
    evil.protocol = "websocket"
    s = heuristic_score(evil)
    assert 0.0 <= s <= 1.0


def test_nan_inf_coerced_to_zero():
    class Req:
        pass

    r = Req()
    r.body_len = float("nan")
    r.header_count = float("inf")
    r.graphql_depth = 0
    r.graphql_cost = 0
    r.bot_score = float("nan")
    r.has_auth = True
    r.is_graphql = False
    r.has_cookie = True
    r.has_api_key = True
    r.method = "GET"
    r.protocol = "rest"
    raw = heuristic_score(r)
    assert 0.0 <= raw <= 1.0
