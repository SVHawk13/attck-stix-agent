from typing import Any

from attck_stix_agent.util._path import to_path


def _is_path_valid(__path: Any) -> bool:
    try:
        _ = to_path(__path)
    except Exception:
        return False
    else:
        return True
