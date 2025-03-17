import random
from collections.abc import Generator, Iterable
from typing import ClassVar, Literal

from mitreattack.stix20 import MitreAttackData
from stix2.datastore.memory import MemoryStore
from stix2.v20.sdo import AttackPattern, IntrusionSet, Malware, Tool
from stix2.v20.sro import Relationship

from attck_stix_agent._serialize import StixProcessor
from attck_stix_agent._stix import StixImporter
from attck_stix_agent.exceptions import StixTypeMismatchError


class AttckStixManager:
    SUPPORTED_STIX_VERSIONS: ClassVar[tuple[str]] = ("2.0",)
    DEFAULT_STIX_VERSION: ClassVar[str] = "2.0"
    DEFAULT_STIX_SRC: ClassVar[str] = (
        "https://github.com/mitre/cti/raw/refs/heads/master/enterprise-attack/enterprise-attack.json"
    )

    def __init__(
        self, stix_location: str | None = None, stix_version: str | None = None
    ) -> None:
        if stix_version is None:
            stix_version = self.DEFAULT_STIX_VERSION
        if stix_location is None:
            stix_location = self.DEFAULT_STIX_SRC

        self.stix_version: str = stix_version
        self.attck_data: MitreAttackData = self._load_stix(
            stix_location, version=self.stix_version
        )
        self.processor: StixProcessor = StixProcessor()
        self._all_campaigns: list = []
        self._all_datacomponents: list = []
        self._all_datasources: list = []
        self._all_groups: list[IntrusionSet] = []
        self._all_matrices: list = []
        self._all_mitigations: list = []
        self._all_software: list = []
        self._all_subtechniques: list[AttackPattern] = []
        self._all_techniques: list[AttackPattern] = []
        self._all_tactics: list = []
        self._all_platforms: list[str] = []
        self._ignore_platforms: list[str] = []

    def _load_memory_store(self, path: str, stix_version: str) -> MemoryStore:
        importer = StixImporter(stix_version=stix_version, allow_custom=True)
        # Raises StixImportError on failure
        memory_store: MemoryStore = importer(path)
        return memory_store

    def _load_stix(self, location: str, version: str) -> MitreAttackData:
        memory_store = self._load_memory_store(location, stix_version=version)
        attck_data = MitreAttackData(src=memory_store)  # pyright: ignore [reportArgumentType]
        return attck_data

    @property
    def ignore_platforms(self) -> list[str]:
        return self._ignore_platforms

    @ignore_platforms.setter
    def ignore_platforms(self, platforms: list[str]) -> None:
        self._ignore_platforms = platforms

    def get_campaigns(self) -> list:
        if not self._all_campaigns:
            self._all_campaigns = self.attck_data.get_campaigns(
                remove_revoked_deprecated=True
            )
        return self._all_campaigns

    def get_datacomponents(self) -> list:
        if not self._all_datacomponents:
            self._all_datacomponents = self.attck_data.get_datacomponents(
                remove_revoked_deprecated=True
            )
        return self._all_datacomponents

    def get_datasources(self) -> list:
        if not self._all_datasources:
            self._all_datasources = self.attck_data.get_datasources(
                remove_revoked_deprecated=True
            )
        return self._all_datasources

    def get_groups(self) -> list[IntrusionSet]:
        if not self._all_groups:
            self._all_groups = self.attck_data.get_groups(
                remove_revoked_deprecated=True
            )
        return self._all_groups

    def random_group(self) -> IntrusionSet:
        if not self._all_groups:
            self._all_groups = self.attck_data.get_groups(
                remove_revoked_deprecated=True
            )
        group = random.choice(self._all_groups)  # noqa: S311
        if not isinstance(group, IntrusionSet):
            raise StixTypeMismatchError
        return group

    def group(self, group: str | None = None) -> IntrusionSet:
        if not group:
            return self.random_group()

        stix_group = self.attck_data.get_object_by_stix_id(group)
        if not isinstance(stix_group, IntrusionSet):
            raise StixTypeMismatchError
        return stix_group

    def get_matrices(self) -> list:
        if not self._all_matrices:
            self._all_matrices = self.attck_data.get_matrices(
                remove_revoked_deprecated=True
            )
        return self._all_matrices

    def get_mitigations(self) -> list:
        if not self._all_mitigations:
            self._all_mitigations = self.attck_data.get_mitigations(
                remove_revoked_deprecated=True
            )
        return self._all_mitigations

    def get_tools(self) -> list:
        software = self.attck_data.get_objects_by_type(
            "tool", remove_revoked_deprecated=True
        )
        return software

    def get_malware(self) -> list:
        malware = self.attck_data.get_objects_by_type(
            "malware", remove_revoked_deprecated=True
        )
        return malware

    def get_software(self) -> list:
        if not self._all_software:
            self._all_software = self.attck_data.get_software(
                remove_revoked_deprecated=True
            )
        return self._all_software

    def _filter_techniques(
        self, techniques: Iterable[AttackPattern]
    ) -> list[AttackPattern]:
        filtered_techniques: list[AttackPattern] = []
        ignore_platforms: set[str] = set(self.ignore_platforms)
        for technique in techniques:
            technique_platform: set[str] = set(technique.get("x_mitre_platforms", []))
            if not technique_platform.intersection(ignore_platforms):
                filtered_techniques.append(technique)
        return filtered_techniques

    def _filter_software_platform(
        self,
        softwares: Iterable[
            tuple[
                Literal["malware", "tool", "other"],
                dict[str, Malware | Tool | list[Relationship]],
            ]
        ],
    ) -> Generator[
        tuple[
            Literal["malware", "tool", "other"],
            dict[str, Malware | Tool | list[Relationship]],
        ],
        None,
        None,
    ]:
        ignore_platforms: set[str] = set(self.ignore_platforms)
        for software_data in softwares:
            software = software_data[1]["object"]
            technique_platform: set[str] = set(software.get("x_mitre_platforms", []))  # pyright: ignore [reportAttributeAccessIssue]
            if not technique_platform.intersection(ignore_platforms):
                yield software_data

    def get_subtechniques(self) -> list[AttackPattern]:
        if not self._all_subtechniques:
            self._all_subtechniques = self.attck_data.get_subtechniques(
                remove_revoked_deprecated=True
            )
        return self._filter_techniques(self._all_subtechniques)

    def get_techniques(self) -> list[AttackPattern]:
        if not self._all_techniques:
            self._all_techniques = self.attck_data.get_techniques(
                remove_revoked_deprecated=True
            )
        return self._filter_techniques(self._all_techniques)

    def get_tactics(self) -> list:
        if not self._all_tactics:
            self._all_tactics = self.attck_data.get_tactics(
                remove_revoked_deprecated=True
            )
        return self._all_tactics

    def get_platforms(self) -> list[str]:
        if not self._all_platforms:
            platforms = set()
            for technique in self.get_techniques():
                _platforms = technique.get("x_mitre_platforms", None)
                if _platforms is not None:
                    platforms.update(_platforms)
            self._all_platforms = sorted(platforms)
        return self._all_platforms

    def _get_techniques_used_by_group(
        self, group: str | IntrusionSet
    ) -> list[dict[str, AttackPattern | list[Relationship]]]:
        if not group:
            raise ValueError
        group_id: str = (
            group.get("id", "") if isinstance(group, IntrusionSet) else group
        )
        if not group_id:
            raise ValueError
        rel_maps: list[dict[str, AttackPattern | list[Relationship]]] = (
            self.attck_data.get_techniques_used_by_group(group_id)
        )
        techniques: Generator[AttackPattern, None, None] = (
            rel_map["object"] for rel_map in rel_maps
        )  # pyright: ignore [reportAssignmentType]
        to_keep_ids: Generator[str, None, None] = (
            p.id for p in self._filter_techniques(techniques)
        )

        return list(
            filter(lambda x: x.get("object", {}).get("id", "") in to_keep_ids, rel_maps)  # pyright: ignore [reportAttributeAccessIssue]
        )

    def techniques_used_by_group(
        self, group: str | IntrusionSet
    ) -> list[AttackPattern]:
        technique_maps = self._get_techniques_used_by_group(group)
        techniques = []
        for technique_map in technique_maps:
            technique = technique_map.get("object", None)
            if technique:
                techniques.append(technique)
        return techniques

    def _software_used_by_group(
        self, group: str | IntrusionSet
    ) -> Generator[
        tuple[
            Literal["malware", "tool", "other"],
            dict[str, Malware | Tool | list[Relationship]],
        ],
        None,
        None,
    ]:
        if not group:
            raise ValueError
        group_id: str = (
            group.get("id", "") if isinstance(group, IntrusionSet) else group
        )
        if not group_id:
            raise ValueError

        rel_maps: list[dict[str, Malware | Tool | list[Relationship]]] = (
            self.attck_data.get_software_used_by_group(group_id)
        )
        for rel_map in rel_maps:
            obj = rel_map.get("object", None)
            if isinstance(obj, Malware):
                obj_type = "malware"
            elif isinstance(obj, Tool):
                obj_type = "tool"
            else:
                obj_type = "other"
            yield (obj_type, rel_map)

    def software_used_by_group(
        self, group: str | IntrusionSet
    ) -> dict[str, list[Malware | Tool]]:
        software_data = self._filter_software_platform(
            self._software_used_by_group(group)
        )
        software: dict[str, list[Malware | Tool]] = {}
        for software_type, rel_map in software_data:
            software.setdefault(software_type, []).append(rel_map["object"])
        return software
