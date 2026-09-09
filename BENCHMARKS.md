# Benchmarks

All values below are captured in the saved notebook output.

| Metric | Result |
|---|---:|
| Golden set — commercial | 64/64 (100%) |
| Golden set — open-weight | 64/64 (100%) |
| Arabic slice | 100% |
| Safety stratum | 12/12 (100%) |
| Development attack block rate | 100% |
| Held-out attack block rate | 100% |
| Blind attack block rate | 100% |
| Legitimate false-positive rate | 0% |
| Judge Cohen's κ | 0.794 |
| Semantic-cache threshold | 0.75 |
| Semantic near-miss wrong hits | 0 |
| Provider cached-input share | 71.7% |
| Response-cache cost reduction | 29.5% |
| Evaluation verdict after caching | Preserved |
| Commercial average latency (sample) | 6.20 ms |
| Open-weight average latency (sample) | 11.74 ms |
| Commercial sample scenario cost | 3.5115 halalas |
| Open-weight sample scenario cost | 0.90931 halalas |

The cost values use the scenario assumptions in `data/pricing.json`; they are not provider invoices.
