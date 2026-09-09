# Decisions Record

## Router-first architecture
FAQ, status, access-request and escalation traffic have different cost and risk profiles. A router-first design keeps the paths explicit and makes tool use auditable.

## Authorization outside the model
The model may classify or extract a request, but permission is decided only by `Session.authorize()` using authenticated session attributes. User text cannot promote its own authority.

## Model boundary
Every model operation uses the same `LLMClient` interface. The notebook configures two distinct HTTP routes without changing application logic.

## Reversed trade-off
Privileged requests were initially treated as refusals. The final design escalates legitimate privileged requests to Security instead. This preserves safety while giving employees a productive path.

## Cache design
Exact caching is scoped by prompt version, catalog version, backend, authenticated role and department. The semantic tier uses a threshold selected from labeled same-answer / different-answer pairs and is allowed only when the near-miss suite has zero wrong hits.
