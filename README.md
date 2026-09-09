# AccessFlow AI

**Bilingual Enterprise Access Request Assistant**

Capstone project for **SDA-AIE-213 — Large Language Model Application Engineering**  
**SDAIA Academy — September 2026**  
**Author:** Nada Abdulhadi Alamri

AccessFlow AI is a bilingual Arabic/English internal enterprise assistant for access governance. It answers grounded access-policy questions, checks a user's own request status, creates standard access requests through authorized tools, and escalates privileged or ambiguous requests to Security.

## Capstone track
**Track C — Internal IT Service Desk**, specialized into enterprise access governance.

## Architecture
- Router-first application.
- One `LLMClient` boundary for every model call.
- Two switchable zero-key HTTP model routes: `course-commercial` and `course-openweight`.
- Structured JSON routing, guard classification, access-request extraction, and judge outputs.
- Three tool risk classes: read-only, side-effecting, and terminal.
- Code-side authorization using authenticated session state.
- Bilingual guard wall and output leakage checks.
- Exact and calibrated semantic response caching.
- Full metering for model calls.
- Golden-set, held-out safety, judge calibration, regression gate, cost/latency comparison, and fault/fallback evidence.

## Run
Open `AccessFlow_AI_Capstone.ipynb` in Google Colab and choose **Runtime → Run all**. The notebook is self-contained and starts its bundled zero-key backend automatically.

## Files
```text
AccessFlow-AI/
├── AccessFlow_AI_Capstone.ipynb
├── accessflow_core.py
├── providers.py
├── gateway_server.py
├── README.md
├── EVALUATION_REPORT.md
├── BENCHMARKS.md
├── DECISIONS.md
├── prompts/
└── data/
```

## Reproducibility note
The default backend is a course-style zero-key HTTP simulator so the complete notebook can be rerun without credentials. Its HTTP contracts, structured outputs, usage accounting, prompt-cache evidence, routing, guardrails, retry/repair flow, tools, evaluation, and fault handling are executable evidence about this application harness. The reported quality numbers are not claims about external commercial model providers.

SDAIA Academy: https://github.com/SDAIAAcademy
