import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_PATH = MODEL_DIR / "model.joblib"

BENIGN_ROWS = 2000
MALICIOUS_ROWS = 400

BENIGN_METHODS = ["GET", "POST", "PUT", "DELETE", "GET", "GET", "POST", "HEAD"]
BENIGN_PATHS = ["/home", "/about", "/products", "/contact", "/blog", "/login", "/docs"]
MALICIOUS_METHODS = ["TRACE", "CONNECT", "PROPFIND", "POST", "PATCH"]
MALICIOUS_PATHS = ["/admin", "/etc/passwd", "/api/v1/exploit", "/../../etc", "/cmd"]
CONTENT_TYPES = ["application/json", "text/html", "application/x-www-form-urlencoded", "application/graphql"]


def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def _bounded(gen, low, high, size=None):
    if size is None:
        return float(gen.uniform(low, high))
    return gen.uniform(low, high, size=size)


def _pick(gen, choices, size=None):
    if size is None:
        return choices[int(gen.integers(0, len(choices)))]
    return [choices[int(i)] for i in gen.integers(0, len(choices), size=size)]


def make_rows(gen, n, malicious: bool):
    rows = []
    for _ in range(n):
        if malicious:
            body_len = _bounded(gen, 50_000, 2_000_000)
            graphql_depth = _bounded(gen, 12, 60)
            graphql_cost = _bounded(gen, 3000, 200_000)
            has_cookie = gen.random() < 0.05
            has_auth = gen.random() < 0.1
            has_api_key = gen.random() < 0.1
            bot_score = _bounded(gen, 0.6, 1.0)
            is_graphql = gen.random() < 0.6
            method = _pick(gen, MALICIOUS_METHODS)
            path = _pick(gen, MALICIOUS_PATHS)
            protocol = _pick(gen, ["rest", "graphql", "grpc", "websocket", "sse", "rest"])
            header_count = int(_bounded(gen, 2, 30))
            content_type = _pick(gen, CONTENT_TYPES)
        else:
            body_len = _bounded(gen, 0, 8_000)
            graphql_depth = _bounded(gen, 0, 6)
            graphql_cost = _bounded(gen, 0, 200)
            has_cookie = gen.random() < 0.95
            has_auth = gen.random() < 0.7
            has_api_key = gen.random() < 0.3
            bot_score = _bounded(gen, 0.0, 0.35)
            is_graphql = gen.random() < 0.2
            method = _pick(gen, BENIGN_METHODS)
            path = _pick(gen, BENIGN_PATHS)
            protocol = _pick(gen, ["rest", "graphql", "rest", "rest"])
            header_count = int(_bounded(gen, 8, 60))
            content_type = _pick(gen, CONTENT_TYPES)
        rows.append(
            {
                "body_len": body_len,
                "header_count": header_count,
                "graphql_depth": graphql_depth,
                "graphql_cost": graphql_cost,
                "bot_score": bot_score,
                "has_auth": float(has_auth),
                "is_graphql": float(is_graphql),
                "has_cookie": float(has_cookie),
                "has_api_key": float(has_api_key),
                "method": method,
                "path": path,
                "protocol": protocol,
                "content_type": content_type,
                "label": 1 if malicious else 0,
            }
        )
    return rows


def _feature_matrix(rows):
    features = []
    targets = []
    for row in rows:
        features.append(
            [
                row["body_len"],
                row["header_count"],
                row["graphql_depth"],
                row["graphql_cost"],
                row["bot_score"],
                row["has_auth"],
                row["is_graphql"],
                row["has_cookie"],
                row["has_api_key"],
            ]
        )
        targets.append(row["label"])
    return np.asarray(features, dtype=float), np.asarray(targets, dtype=int)


def main():
    gen = _rng(42)
    rows = make_rows(gen, BENIGN_ROWS, malicious=False) + make_rows(gen, MALICIOUS_ROWS, malicious=True)
    X, y = _feature_matrix(rows)

    model = HistGradientBoostingClassifier(
        max_iter=80,
        learning_rate=0.1,
        max_depth=5,
        min_samples_leaf=10,
        random_state=42,
    )
    model.fit(X, y)

    pred = model.predict_proba(X)
    prob = pred[:, 1]
    acc = float(((prob >= 0.5).astype(int) == y).mean())
    logger.info("Trained HistGradientBoostingClassifier on %d rows (acc=%.4f)", len(y), acc)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("Saved model to %s", MODEL_PATH)


if __name__ == "__main__":
    main()
