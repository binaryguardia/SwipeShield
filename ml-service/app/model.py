import logging
import math
import os
from pathlib import Path

import joblib

logger = logging.getLogger(__name__)

MODEL_FILENAME = "model.joblib"
MODEL_DIRNAME = "model"
MODEL_RELPATH = os.path.join(MODEL_DIRNAME, MODEL_FILENAME)

CANDIDATE_PATHS = (
    Path(__file__).resolve().parent / MODEL_DIRNAME / MODEL_FILENAME,
    Path.cwd() / MODEL_RELPATH,
    Path.cwd() / "app" / MODEL_DIRNAME / MODEL_FILENAME,
)

NON_BROWSER_PROTOCOLS = {"grpc", "websocket", "sse", "graphql"}
UNUSUAL_METHODS = {"PROPFIND", "TRACE", "CONNECT", "PATCH", "MOVE", "COPY"}

_model = None
_model_path = None


def _load_model():
    global _model, _model_path
    for path in CANDIDATE_PATHS:
        if path.is_file():
            try:
                _model = joblib.load(str(path))
                _model_path = path
                logger.info("Loaded ML model from %s", path)
                return _model
            except Exception as exc:  # noqa: BLE001 - pragma: no cover - defensive
                logger.warning("Failed to load model from %s: %s", path, exc)
    _model = None
    _model_path = None
    logger.warning(
        "No model file found at %s; falling back to heuristic scorer",
        [str(p) for p in CANDIDATE_PATHS],
    )
    return None


def _safe_float(value, default=0.0):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(value) or math.isinf(value):
        return default
    return value


def _safe_int(value, default=0):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return value


def _clamp01(value):
    if math.isnan(value) or math.isinf(value):
        return 0.0
    return max(0.0, min(1.0, value))


def heuristic_score(req) -> float:
    body_len = _safe_int(req.body_len)
    graphql_depth = _safe_int(req.graphql_depth)
    graphql_cost = _safe_int(req.graphql_cost)
    bot_score = _safe_float(req.bot_score)
    method = (req.method or "").upper()
    protocol = (req.protocol or "").lower()

    rule_score = 0.0

    if body_len > 100_000:
        rule_score += 0.45
    elif body_len > 10_000:
        rule_score += 0.25
    elif body_len > 1_000:
        rule_score += 0.10

    if graphql_depth > 15:
        rule_score += 0.40
    elif graphql_depth > 7:
        rule_score += 0.25
    elif graphql_depth > 3:
        rule_score += 0.10

    if graphql_cost > 5000:
        rule_score += 0.35
    elif graphql_cost > 1000:
        rule_score += 0.20
    elif graphql_cost > 100:
        rule_score += 0.10

    if not req.has_cookie:
        rule_score += 0.30

    if bot_score >= 0.8:
        rule_score += 0.40
    elif bot_score >= 0.5:
        rule_score += 0.20

    if protocol in NON_BROWSER_PROTOCOLS:
        rule_score += 0.20

    if method in UNUSUAL_METHODS:
        rule_score += 0.15

    if not req.has_auth and not req.has_api_key:
        rule_score += 0.10

    return _clamp01(rule_score)


def score(req):
    if _model is None:
        _load_model()

    if _model is not None:
        try:
            features = [
                _safe_float(req.body_len),
                _safe_float(req.header_count),
                _safe_float(req.graphql_depth),
                _safe_float(req.graphql_cost),
                _safe_float(req.bot_score),
                float(bool(req.has_auth)),
                float(bool(req.is_graphql)),
                float(bool(req.has_cookie)),
                float(bool(req.has_api_key)),
            ]
            pred = _model.predict_proba([features])[0]
            prob = pred[1] if len(pred) > 1 else pred[0]
            raw = _safe_float(prob)
        except Exception as exc:  # noqa: BLE001 - pragma: no cover - defensive
            logger.warning("Model prediction failed (%s); using heuristic", exc)
            raw = heuristic_score(req)
    else:
        raw = heuristic_score(req)

    final = _clamp01(raw)
    anomaly = final >= 0.7
    if anomaly:
        label = "anomaly"
    elif final >= 0.4:
        label = "suspicious"
    else:
        label = "benign"
    return final, anomaly, label


def reload():
    _load_model()
