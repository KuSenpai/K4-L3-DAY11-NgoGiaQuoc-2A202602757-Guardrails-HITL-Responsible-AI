"""
Chat UI cho VinBank lab — FastAPI backend + 1 trang HTML.

Chạy từ gốc repo:

    python src/ui/server.py            # http://127.0.0.1:8000

Target:
  - blue         → pipeline CP3: RateLimit → InputGuardrail → LLM → OutputGuardrail
                   (+ audit log + monitoring, đúng như run_assignment_suite)
  - red          → create_red_agent_default()  (mềm, không guardrail)
  - red_advance  → create_red_agent_advance()  (guardrail cứng có sẵn)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parents[1]
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core.config import blue_provider_label, red_provider_label
from core.utils import chat_with_agent
from assignment.pipeline import (
    _run_request,
    build_observability,
    build_production_plugins,
)
from attacks.attacks import classify_attack_outcome, response_leaked_secrets

STATIC_DIR = Path(__file__).resolve().parent / "static"
TARGETS = ("blue", "red", "red_advance")

app = FastAPI(title="VinBank Guardrails Chat")


class ChatRequest(BaseModel):
    message: str = Field(default="", max_length=20000)
    target: str = "blue"
    user_id: str = Field(default="web-user", max_length=64)


class _State:
    """Giữ pipeline Blue + agent Red giữa các request (tạo lười khi cần)."""

    def __init__(self):
        self.reset()

    def reset(self):
        audit, monitor = build_observability()
        self.pipeline = {
            "plugins": build_production_plugins(use_llm_judge=False),
            "audit": audit,
            "monitor": monitor,
        }
        self.agents: dict[str, tuple] = {}
        self.counter = 0

    def next_request_id(self) -> str:
        self.counter += 1
        return f"ui-{self.counter:05d}"

    def blue_llm(self):
        if "blue" not in self.agents:
            from agents.agent import create_blue_agent

            # Plugins chạy trong _run_request (có user_id thật cho rate limiter)
            self.agents["blue"] = create_blue_agent(plugins=[])
        return self.agents["blue"]

    def red_agent(self, target: str):
        if target not in self.agents:
            if target == "red":
                from agents.agent import create_red_agent_default

                self.agents[target] = create_red_agent_default()
            else:
                from agents.guards_agent import create_red_agent_advance

                self.agents[target] = create_red_agent_advance()
        return self.agents[target]


state = _State()


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/info")
def info():
    return {
        "targets": {
            "blue": blue_provider_label(),
            "red": red_provider_label("default"),
            "red_advance": red_provider_label("advance"),
        },
        "plugin_order": [p.name for p in state.pipeline["plugins"]],
    }


@app.post("/api/chat")
async def chat(req: ChatRequest):
    if req.target not in TARGETS:
        raise HTTPException(400, f"target must be one of {TARGETS}")

    started = time.perf_counter()

    if req.target == "blue":
        pipeline = dict(state.pipeline, llm=state.blue_llm())
        result = await _run_request(
            pipeline,
            req.message,
            user_id=req.user_id or "web-user",
            request_id=state.next_request_id(),
            preview_chars=None,
        )
        payload = {
            "response": result["response_preview"],
            "blocked": result["blocked"],
            "layer": result["layer"],
            "redacted": result["redacted"],
            "leaked": response_leaked_secrets(result["response_preview"]),
        }
    else:
        agent, runner = state.red_agent(req.target)
        try:
            response, _ = await chat_with_agent(agent, runner, req.message)
        except Exception as e:
            raise HTTPException(502, f"{type(e).__name__}: {e}")
        outcome = classify_attack_outcome(req.message, response, target_name=req.target)
        payload = {
            "response": response,
            "blocked": outcome["blocked"],
            "layer": outcome["layer"],
            "redacted": False,
            "leaked": outcome["leaked"],
        }

    payload["target"] = req.target
    payload["latency_ms"] = round((time.perf_counter() - started) * 1000)
    return payload


@app.get("/api/metrics")
def metrics():
    monitor = state.pipeline["monitor"]
    monitor.check_metrics()
    return {
        "metrics": monitor.snapshot(),
        "audit": state.pipeline["audit"].logs[-20:][::-1],
    }


@app.post("/api/reset")
def reset():
    state.reset()
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
