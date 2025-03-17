from functools import partial
from os import PathLike
from pathlib import Path
from typing import Any, ClassVar

import requests
import stix2
from requests.exceptions import JSONDecodeError
from stix2 import MemoryStore
from stix2.v20.bundle import Bundle

from attck_stix_agent.exceptions import StixImportError
from attck_stix_agent.util import make_file_parent, read_and_parse_file, to_path
from attck_stix_agent.validators import _is_url_valid

DEFAULT_STIX_VERSION = "2.0"


class StixImporter:
    DEFAULT_STIX_VERSION: ClassVar[str] = DEFAULT_STIX_VERSION

    def __init__(
        self, stix_version: str | None = None, allow_custom: bool = False
    ) -> None:
        if stix_version:
            self.stix_version = stix_version
        self.allow_custom = allow_custom
        self.cache_src: bool = True
        self._cache_path: Path | None = None

    @property
    def cache_path(self) -> Path | None:
        return self._cache_path

    @cache_path.setter
    def cache_path(self, __path: Path | str | None) -> None:
        if __path is None:
            self._cache_path = __path
            return
        self._cache_path = to_path(__path)

    def _cache_stix_src(self, data: Bundle) -> None:
        if not self.cache_src or self.cache_path is None:
            return
        stix_file_name = f"cache-stix-v{self.stix_version}.json"
        stix_file = self.cache_path.joinpath(stix_file_name)
        make_file_parent(stix_file)
        if isinstance(data, Bundle):
            with stix_file.open("wt") as fh:
                data.fp_serialize(fh, pretty=False)
        else:
            raise NotImplementedError

    @property
    def stix_version(self) -> str:
        return getattr(self, "_stix_version", self.DEFAULT_STIX_VERSION)

    @stix_version.setter
    def stix_version(self, version: str) -> None:
        self._stix_version = version

    def _from_url(self, stix_url: str) -> dict:
        if not _is_url_valid(stix_url, check_host=True):
            msg = f"invalid url: '{stix_url}'"
            raise ValueError(msg)

        json_dict = None
        with requests.get(stix_url, timeout=60) as resp:
            try:
                resp.raise_for_status()
            except requests.HTTPError as e:
                msg = "Failed to import STIX content"
                raise StixImportError(msg) from e
            try:
                json_dict = resp.json()
            except JSONDecodeError as e:
                raise StixImportError from e

        if not json_dict:
            msg = "Imported STIX content contained no data"
            raise StixImportError(msg)
        if not isinstance(json_dict, dict):
            type_name = type(json_dict).__name__
            msg = f"STIX content imported as '{type_name}', expected 'dict'"
            raise StixImportError(msg)
        return json_dict

    def _from_file(
        self, stix_path: str | PathLike, allow_custom: bool = True
    ) -> bytes | str | Any:
        _stix_parser = partial(
            stix2.parse, allow_custom=allow_custom, version=self.stix_version
        )
        return read_and_parse_file(
            stix_path, mode="b", parser=_stix_parser, pass_handle=True
        )

    def _parse(
        self, data: dict, stix_version: str | None = None, allow_custom: bool = True
    ):
        stix_version = stix_version or self.stix_version

        # _ = data.pop("spec_version", None)
        stix_obj = stix2.parse(
            data=data,
            version=stix_version,
            allow_custom=allow_custom,
        )
        return stix_obj

    def _import_stix(self, __src, allow_custom: bool = True):
        stix_data: dict | Bundle | None = None

        if isinstance(__src, str):
            try:
                json_data = self._from_url(__src)
                stix_data = self._parse(json_data, allow_custom=allow_custom)
            except StixImportError:
                pass
            except ValueError:
                pass
            else:
                return stix_data
            stix_data = self._from_file(__src, allow_custom=allow_custom)
        else:
            raise NotImplementedError

        if stix_data is None:
            raise TypeError
        if isinstance(stix_data, Bundle):
            return stix_data
        elif isinstance(stix_data, dict):
            return self._parse(stix_data, allow_custom=allow_custom)
        else:
            raise TypeError

    def __call__(self, __src) -> MemoryStore:
        try:
            stix_data = self._import_stix(__src, allow_custom=self.allow_custom)
        except Exception as e:
            msg = "Failed to import STIX content"
            raise StixImportError(msg) from e
        else:
            self._cache_stix_src(stix_data)
            memory_store = MemoryStore()
            memory_store.add(stix_data)
            return memory_store
