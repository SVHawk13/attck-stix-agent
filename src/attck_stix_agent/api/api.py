from fastapi import FastAPI

from attck_stix_agent.attck import AttckStixManager

stix_manager: AttckStixManager = AttckStixManager()
api = FastAPI()


@api.get("/group/{group}/techniques")
def group_techniques(group: str, kill_chain: str | None = None) -> list[dict]:
    stix_techniques = stix_manager.techniques_used_by_group(group)
    techniques: list[dict] = [
        stix_manager.processor.technique_to_dict(technique, kill_chain=kill_chain)
        for technique in stix_techniques
    ]
    return techniques


@api.get("/group/{group}")
def get_group(group: str) -> dict:
    group_dict: dict = stix_manager.processor.group_to_dict(stix_manager.group(group))
    return group_dict


@api.get("/group")
def random_group() -> dict:
    group_dict: dict = stix_manager.processor.group_to_dict(stix_manager.group())
    return group_dict


@api.get("/groups")
def all_groups() -> list[dict]:
    groups: list[dict] = [
        stix_manager.processor.group_to_dict(group)
        for group in stix_manager.get_groups()
    ]
    return groups
