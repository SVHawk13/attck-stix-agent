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


@api.get("/group/{group}/software")
def group_software(group: str) -> dict[str, list[dict]]:
    stix_softwares = stix_manager.software_used_by_group(group)
    malwares = (
        stix_manager.processor.software_to_dict(malware)
        for malware in stix_softwares.pop("malware", [])
    )
    tools = (
        stix_manager.processor.software_to_dict(tool)
        for tool in stix_softwares.pop("tool", [])
    )
    return {
        "malware": list(malwares),
        "tools": list(tools),
    }


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


@api.get("/platforms")
def all_platforms() -> list[str]:
    return stix_manager.get_platforms()


@api.get("/platform/{name}")
def get_platform(name: str) -> dict[str, str | bool]:
    return stix_manager.platform_status(name)


@api.patch("/platform/{name}")
def update_platform(name: str, ignore: bool) -> None:
    stix_manager.update_platform(name, ignore=ignore)
