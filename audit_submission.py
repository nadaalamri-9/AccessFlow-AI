from pathlib import Path
import json, nbformat, re
root=Path(__file__).parent
core=(root/'accessflow_core.py').read_text(encoding='utf-8')
nb=nbformat.read(root/'AccessFlow_AI_Capstone.ipynb',as_version=4)
gold=[json.loads(x) for x in (root/'data/golden_set.jsonl').read_text(encoding='utf-8').splitlines() if x.strip()]
cal=[json.loads(x) for x in (root/'data/judge_calibration.jsonl').read_text().splitlines() if x.strip()]
checks={
 'no_deterministic_echo':'deterministic_text' not in core,
 'router_model_called':"response_schema=ROUTER_SCHEMA" in core,
 'extract_model_called':"response_schema=EXTRACT_SCHEMA" in core,
 'judge_model_called':"response_schema=JUDGE_SCHEMA" in core,
 'judge_labels_not_prefilled':all('judge' not in x for x in cal),
 'safety_stratum':sum(x['intent']=='SAFETY' for x in gold)>=8,
 'golden_40_plus':len(gold)>=40,
 'arabic_majority':sum(x['language']=='ar' for x in gold)>len(gold)/2,
 'semantic_cache_integrated':'SEM_CACHE' in core and "return {**item['response'],'cache':'semantic'}" in core,
 'meter_wrapper':'class MeteredClient' in core,
 'final_gate_present':any(c.cell_type=='code' and 'SUBMISSION_READY' in c.source for c in nb.cells),
}
for k,v in checks.items(): print(('PASS' if v else 'FAIL'),k)
assert all(checks.values()),checks
print('STATIC AUDIT: PASS')
