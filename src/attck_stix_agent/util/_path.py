from collections.abc import Callable
from io import BufferedIOBase
from os import PathLike
from pathlib import Path
from typing import Any, Literal


def to_path(__path: str | PathLike) -> Path:
    if not isinstance(__path, (str, PathLike)):
        raise TypeError

    return Path(__path).expanduser().resolve()


def _read_file(
    __path: str | PathLike,
    mode: Literal["b", "t"],
    parser: Callable[[BufferedIOBase], Any] | None = None,
) -> bytes | str:
    fp: Path = to_path(__path)

    with fp.open(f"r{mode}") as fh:
        if parser is not None:
            if not isinstance(fh, BufferedIOBase):
                raise TypeError
            file_content = parser(fh)
        else:
            file_content = fh.read()

    return file_content


def read_file_bytes(__path: str | PathLike) -> bytes:
    file_content = _read_file(__path, mode="b")
    if not isinstance(file_content, bytes):
        raise TypeError
    return file_content


def read_file_text(__path: str | PathLike) -> str:
    file_content = _read_file(__path, mode="t")
    if not isinstance(file_content, str):
        raise TypeError
    return file_content


def read_file(__path: str | PathLike, as_str: bool = True) -> str | bytes:
    if as_str:
        return read_file_text(__path)
    return read_file_bytes(__path)


def read_and_parse_file(
    __path: str | PathLike,
    mode: Literal["b", "t"],
    parser: Callable[[str], Any]
    | Callable[[bytes], Any]
    | Callable[[BufferedIOBase], Any],
    pass_handle: bool = True,
) -> bytes | str | Any:
    if pass_handle:
        return _read_file(__path, mode=mode, parser=parser)

    file_content: bytes | str = _read_file(__path, mode=mode)
    return parser(file_content)


__all__ = [
    "to_path",
    "read_file",
    "read_file_text",
    "read_file_bytes",
    "read_and_parse_file",
]
