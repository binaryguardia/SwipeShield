import logging
import math
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import model
from .schemas import ScoreRequest, ScoreResponse

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("swipeshield.ml")


@asynccontextmanager
async def _lifespan(app):
    model.reload()
    yield


app = FastAPI(title="SwipeShield ML Anomaly Scorer", lifespan=_lifespan)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/score", response_model=ScoreResponse)
async def score(request: Request):
    try:
        req = ScoreRequest.model_validate_json(await request.body())
    except (ValidationError, ValueError) as exc:
        logger.warning("Invalid /score request: %s", exc)
        return JSONResponse(status_code=400, content={"detail": "invalid JSON body"})

    value, anomaly, label = model.score(req)

    if math.isnan(value) or math.isinf(value):
        value = 0.0

    value = max(0.0, min(1.0, value))

    logger.info(
        "score site=%s method=%s path=%s protocol=%s anomaly=%s score=%.4f",
        req.site_id,
        req.method,
        req.path,
        req.protocol,
        anomaly,
        value,
    )

    return ScoreResponse(anomaly=anomaly, score=value, label=label)
