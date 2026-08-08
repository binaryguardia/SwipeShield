from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    site_id: str
    method: str
    path: str
    protocol: str = Field(description='"rest" | "graphql" | "grpc" | "websocket" | "sse"')
    client_ip: str
    content_type: str
    body_len: int
    header_count: int
    has_auth: bool
    is_graphql: bool
    graphql_depth: int = 0
    graphql_cost: int = 0
    has_cookie: bool
    has_api_key: bool
    bot_score: float
    ja4: str = ""


class ScoreResponse(BaseModel):
    anomaly: bool
    score: float
    label: str
