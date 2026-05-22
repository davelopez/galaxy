import struct
from typing import (
    IO,
    Optional,
)

CRYPT4GH_MAGIC = b"crypt4gh"
CRYPT4GH_VERSION = 1
CRYPT4GH_FILE_EXT = "crypt4gh"
CRYPT4GH_SUFFIX = f".{CRYPT4GH_FILE_EXT}"


def is_crypt4gh_file_ext(file_ext: str) -> bool:
    return file_ext == CRYPT4GH_FILE_EXT or file_ext.endswith(CRYPT4GH_SUFFIX)


def wrap_crypt4gh_file_ext(file_ext: str) -> str:
    if is_crypt4gh_file_ext(file_ext):
        return file_ext
    return f"{file_ext}{CRYPT4GH_SUFFIX}"


def unwrap_crypt4gh_file_ext(file_ext: str) -> Optional[str]:
    if file_ext == CRYPT4GH_FILE_EXT:
        return None
    if file_ext.endswith(CRYPT4GH_SUFFIX):
        return file_ext[: -len(CRYPT4GH_SUFFIX)]
    return None


def infer_crypt4gh_inner_file_ext(filename: str, registry) -> Optional[str]:
    if not filename.endswith(CRYPT4GH_SUFFIX):
        return None
    inner_filename = filename[: -len(CRYPT4GH_SUFFIX)]
    datatype = registry.get_datatype_from_filename(inner_filename)
    if datatype and datatype.file_ext not in ("data", "binary", "txt", "auto"):
        return datatype.file_ext
    return None


def infer_crypt4gh_file_ext(filename: str, registry, requested_ext: str = "auto") -> str:
    inner_file_ext = infer_crypt4gh_inner_file_ext(filename, registry)
    if inner_file_ext is not None:
        return wrap_crypt4gh_file_ext(inner_file_ext)
    if requested_ext != "auto":
        return wrap_crypt4gh_file_ext(requested_ext)
    return CRYPT4GH_FILE_EXT


def preserve_crypt4gh_inner_file_ext(
    guessed_ext: str,
    current_ext: Optional[str] = None,
    metadata_inner_ext: Optional[str] = None,
) -> str:
    """Preserve a known crypt4gh wrapper extension during datatype re-detection.

    Re-detection from object-store paths often loses the original filename suffix
    and can only sniff the generic ``crypt4gh`` wrapper. When that happens, keep
    the more specific wrapper if we already know it from the dataset extension or
    from computed ``crypt4gh_inner_ext`` metadata.
    """
    if guessed_ext != CRYPT4GH_FILE_EXT:
        return guessed_ext

    if current_ext and current_ext != CRYPT4GH_FILE_EXT and is_crypt4gh_file_ext(current_ext):
        return current_ext

    if metadata_inner_ext and metadata_inner_ext not in ("auto", "data", "binary", "txt", CRYPT4GH_FILE_EXT):
        return wrap_crypt4gh_file_ext(metadata_inner_ext)

    return guessed_ext


def read_crypt4gh_header(stream_or_path: str | IO[bytes]) -> bytes:
    close_stream = False
    stream: IO[bytes]
    if isinstance(stream_or_path, str):
        stream = open(stream_or_path, "rb")
        close_stream = True
    else:
        stream = stream_or_path

    try:
        prelude = stream.read(16)
        if len(prelude) != 16:
            raise ValueError("Header too small")

        magic, version, packet_count = struct.unpack("<8sII", prelude)
        if magic != CRYPT4GH_MAGIC:
            raise ValueError("Not a CRYPT4GH formatted file")
        if version != CRYPT4GH_VERSION:
            raise ValueError("Unsupported CRYPT4GH version")

        header = bytearray(prelude)
        for _ in range(packet_count):
            packet_len_bytes = stream.read(4)
            if len(packet_len_bytes) != 4:
                raise ValueError("Packet header too small")
            packet_len = int.from_bytes(packet_len_bytes, byteorder="little")
            if packet_len < 4:
                raise ValueError(f"Invalid packet length {packet_len}")
            packet = stream.read(packet_len - 4)
            if len(packet) != packet_len - 4:
                raise ValueError("Packet too small")
            header.extend(packet_len_bytes)
            header.extend(packet)

        return bytes(header)
    finally:
        if close_stream:
            stream.close()


def check_crypt4gh(file_path: str) -> bool:
    try:
        read_crypt4gh_header(file_path)
        return True
    except Exception:
        return False


__all__ = (
    "check_crypt4gh",
    "CRYPT4GH_FILE_EXT",
    "CRYPT4GH_MAGIC",
    "CRYPT4GH_SUFFIX",
    "CRYPT4GH_VERSION",
    "infer_crypt4gh_file_ext",
    "infer_crypt4gh_inner_file_ext",
    "is_crypt4gh_file_ext",
    "preserve_crypt4gh_inner_file_ext",
    "read_crypt4gh_header",
    "unwrap_crypt4gh_file_ext",
    "wrap_crypt4gh_file_ext",
)
