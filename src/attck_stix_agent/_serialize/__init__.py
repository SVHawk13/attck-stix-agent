import io
import json
from typing import Any

from stix2.v20.sdo import IntrusionSet

# TODO: add `external_references` once they can be unmarshalled
GROUP_KEEP_KEYS = (
    "id",
    "name",
    "description",
    "aliases",
    "object_marking_refs",
)


def group_to_dict(group: IntrusionSet) -> dict[str, Any]:
    group_dict: dict = {}
    for k, v in group.items():
        if k not in GROUP_KEEP_KEYS:
            continue
        group_dict[k] = v
    return group_dict
