
import os
from accessflow_core import OpenAICompatibleClient, MeteredClient

def build_clients():
    base=os.environ.get("ACCESSFLOW_LLM_BASE_URL","http://127.0.0.1:8765/v1").rstrip("/")
    commercial_model=os.environ.get("ACCESSFLOW_COMMERCIAL_MODEL","course-commercial")
    open_model=os.environ.get("ACCESSFLOW_OPEN_MODEL","course-openweight")
    commercial=MeteredClient(OpenAICompatibleClient("commercial",base,commercial_model,20),"commercial")
    openw=MeteredClient(OpenAICompatibleClient("open_weight",base,open_model,20),"open_weight")
    return {
      "commercial":commercial,"open_weight":openw,
      "models_discovered":[commercial_model,open_model],"base_url":base,
      "commercial_model":commercial_model,"open_model":open_model
    }
