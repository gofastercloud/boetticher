#!/opt/litellm/bin/python
import json
import os
import sys

os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
import litellm


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1] or len(sys.argv[1]) > 256:
        return 2
    info = litellm.get_model_info(sys.argv[1])
    selected = {
        "mode": info.get("mode"),
        "supports_function_calling": info.get("supports_function_calling"),
        "supports_response_schema": info.get("supports_response_schema"),
        "max_input_tokens": info.get("max_input_tokens"),
        "max_output_tokens": info.get("max_output_tokens"),
    }
    print(json.dumps(selected, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
