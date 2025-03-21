from collections.abc import Mapping, Sequence
from typing import ClassVar, TypeVar

from stix2.v20.sdo import AttackPattern, ExternalReference, IntrusionSet, Malware, Tool

from attck_stix_agent.util._citation import remove_citation

T = TypeVar("T")


class StixProcessor:
    DEFAULT_GROUP_KEEP_KEYS: ClassVar[tuple[str, ...]] = (
        "id",
        "name",
        "description",
        "aliases",
        "external_references",
    )
    DEFAULT_TECHNIQUE_KEEP_KEYS: ClassVar[tuple[str, ...]] = (
        "id",
        "name",
        "description",
        "kill_chain_phases",
        "external_references",
        "x_mitre_data_sources",
    )
    DEFAULT_MALWARE_KEEP_KEYS: ClassVar[tuple[str, ...]] = (
        "id",
        "name",
        "description",
        "labels",
        "external_references",
        "x_mitre_aliases",
        "x_mitre_platforms",
    )
    DEFAULT_TOOL_KEEP_KEYS: ClassVar[tuple[str, ...]] = (
        "id",
        "name",
        "description",
        "labels",
        "external_references",
        "x_mitre_aliases",
        "x_mitre_platforms",
    )

    def __init__(self) -> None:
        self.group_keep_keys: tuple[str, ...] = self.DEFAULT_GROUP_KEEP_KEYS
        self.technique_keep_keys: tuple[str, ...] = self.DEFAULT_TECHNIQUE_KEEP_KEYS
        self.malware_keep_keys: tuple[str, ...] = self.DEFAULT_MALWARE_KEEP_KEYS
        self.tool_keep_keys: tuple[str, ...] = self.DEFAULT_TOOL_KEEP_KEYS

    @classmethod
    def _clean_stix_dict(cls, __obj: T) -> T:
        return remove_citation(__obj)

    @classmethod
    def stix_to_dict(
        cls, stix_obj: Mapping, keep_keys: Sequence[str] | None = None
    ) -> dict[str, list | dict | str]:
        stix_dict: dict = {}
        for k, stix_val in stix_obj.items():
            if keep_keys and k not in keep_keys:
                continue
            if stix_val is None or isinstance(stix_val, str):
                stix_dict[k] = stix_val
            elif isinstance(stix_val, ExternalReference):
                stix_dict[k] = cls._external_ref_to_dict(stix_val)
            elif isinstance(stix_val, Sequence):
                new_stix_val = []
                for i in stix_val:
                    if isinstance(i, ExternalReference):
                        new_stix_val.append(cls._external_ref_to_dict(i))
                    else:
                        new_stix_val.append(i)
                stix_dict[k] = new_stix_val
            else:
                stix_dict[k] = stix_val
        return cls._clean_stix_dict(stix_dict)

    @staticmethod
    def kill_chain_phases(
        technique: AttackPattern, kill_chain: str | None = None
    ) -> dict[str, list[str]] | list[str]:
        """List all phases of all kill chains that the technique applies to.

        Args:
            technique (AttackPattern):
                A STIX technique entry.
            kill_chain (str, optional):
                Return only phases for the given kill_chain.
                All kill_chains are returned if None. Defaults to None.

        Raises:
            TypeError: `technique` is not an `AttackPattern`

        Returns:
            dict[str, list[str]] | list[str]:
                Mapping of kill chain names and the phases the technique applies to.
                A list of phases corresponding to `kill_chain` is returned if a
                `kill_chain` is given.
        """
        if not isinstance(technique, AttackPattern):
            raise TypeError

        kill_chain_phases: dict[str, list[str]] = {}
        for phase_obj in technique.get("kill_chain_phases", []):
            kill_chain_name: str = phase_obj.get("kill_chain_name", "unknown")
            phase_name: str = phase_obj.get("phase_name", "")
            phases: list[str] = kill_chain_phases.setdefault(kill_chain_name, [])
            if phase_name not in phases:
                phases.append(phase_name)
        if kill_chain:
            if kill_chain in kill_chain_phases.keys():
                return kill_chain_phases[kill_chain]
            return []
        return kill_chain_phases

    @staticmethod
    def _external_ref_to_dict(external_ref: ExternalReference) -> dict:
        return dict(external_ref)

    def group_to_dict(
        self, group: IntrusionSet, keep_keys: Sequence[str] | None = None
    ) -> dict:
        if keep_keys is None:
            keep_keys = self.technique_keep_keys
        return self.stix_to_dict(stix_obj=group, keep_keys=keep_keys)

    def technique_to_dict(
        self,
        technique: AttackPattern,
        keep_keys: Sequence[str] | None = None,
        kill_chain: str | None = None,
    ) -> dict:
        if keep_keys is None:
            keep_keys = self.technique_keep_keys

        technique_dict: dict = self.stix_to_dict(
            stix_obj=technique, keep_keys=keep_keys
        )
        if keep_keys is None or "kill_chain_phases" in keep_keys:
            kill_chain_phases: dict[str, list[str]] | list[str] = (
                self.kill_chain_phases(technique, kill_chain=kill_chain)
            )
            technique_dict["kill_chain_phases"] = kill_chain_phases
        return technique_dict

    def malware_to_dict(
        self, malware: Malware, keep_keys: Sequence[str] | None = None
    ) -> dict:
        if keep_keys is None:
            keep_keys = self.malware_keep_keys

        malware_dict: dict = self.stix_to_dict(stix_obj=malware, keep_keys=keep_keys)
        return malware_dict

    def tool_to_dict(self, tool: Tool, keep_keys: Sequence[str] | None = None) -> dict:
        if keep_keys is None:
            keep_keys = self.tool_keep_keys

        tool_dict: dict = self.stix_to_dict(stix_obj=tool, keep_keys=keep_keys)
        return tool_dict

    def software_to_dict(
        self, software: Malware | Tool, keep_keys: Sequence[str] | None = None
    ) -> dict:
        if isinstance(software, Malware):
            return self.malware_to_dict(software, keep_keys=keep_keys)
        elif isinstance(software, Tool):
            return self.tool_to_dict(software, keep_keys=keep_keys)
        else:
            raise TypeError
