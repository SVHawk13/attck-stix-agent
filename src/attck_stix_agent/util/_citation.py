import re
from collections.abc import Collection, Mapping
from functools import singledispatch
from types import NoneType


@singledispatch
def remove_citation(__obj):
    raise NotImplementedError


@remove_citation.register(str)  # pyright: ignore [reportArgumentType]
def _(__obj) -> str:
    pattern = r"\(Citation:\s*(.+?)\)"
    return re.sub(pattern, "", __obj)


@remove_citation.register(NoneType)  # pyright: ignore [reportArgumentType]
def _(__obj) -> None:
    return None


@remove_citation.register(Mapping)  # pyright: ignore [reportArgumentType]
def _(__obj) -> dict:
    new_obj = {}
    for k, v in __obj.items():
        new_obj[k] = remove_citation(v)
    return new_obj


@remove_citation.register(Collection)  # pyright: ignore [reportArgumentType]
def _(__obj) -> list:
    new_obj = [remove_citation(i) for i in __obj]
    return new_obj


__all__ = ["remove_citation"]
