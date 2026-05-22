import base64
import os
from inspect import isclass
from typing import (
    Any,
    Optional,
)

from galaxy.datatypes.binary import Binary
from galaxy.datatypes.metadata import MetadataElement
from galaxy.datatypes.protocols import DatasetProtocol
from galaxy.util.crypt4gh import (
    check_crypt4gh,
    CRYPT4GH_FILE_EXT,
    CRYPT4GH_SUFFIX,
    infer_crypt4gh_file_ext,
    infer_crypt4gh_inner_file_ext,
    is_crypt4gh_file_ext,
    read_crypt4gh_header,
    unwrap_crypt4gh_file_ext,
    wrap_crypt4gh_file_ext,
)


class Crypt4GH(Binary):
    file_ext = CRYPT4GH_FILE_EXT
    display_behavior = "download"
    transparent_staging_enabled: bool = False
    crypt4gh_inner_datatype: Optional[Any] = None

    MetadataElement(
        name="crypt4gh_header",
        default="",
        desc="Crypt4GH header (Base64-encoded)",
        readonly=True,
        visible=True,
        optional=False,
        no_value="",
    )
    MetadataElement(
        name="crypt4gh_inner_ext",
        default="data",
        desc="Wrapped datatype extension",
        readonly=True,
        visible=True,
        optional=True,
        no_value="data",
    )

    def sniff(self, filename: str) -> bool:
        if not check_crypt4gh(filename):
            return False
        if self.file_ext == CRYPT4GH_FILE_EXT:
            # Generic wrapper can identify crypt4gh by header only, which allows
            # re-detection on object-store paths without original filename suffixes.
            return True
        return os.path.basename(filename).endswith(f".{self.file_ext}")

    def set_meta(self, dataset: DatasetProtocol, overwrite: bool = True, **kwd) -> None:
        header = read_crypt4gh_header(dataset.get_file_name())
        if overwrite or not dataset.metadata.element_is_set("crypt4gh_header"):
            dataset.metadata.crypt4gh_header = base64.b64encode(header).decode("ascii")
        dataset.metadata.crypt4gh_inner_ext = self._infer_inner_ext(dataset)

    def set_peek(self, dataset: DatasetProtocol, **kwd) -> None:
        if not dataset.dataset.purged:
            dataset.peek = f"Encrypted Crypt4GH dataset wrapping '{self._infer_inner_ext(dataset)}'"
            dataset.blurb = "encrypted"
        else:
            dataset.peek = "file does not exist"
            dataset.blurb = "file purged from disk"

    def display_peek(self, dataset: DatasetProtocol) -> str:
        return dataset.peek or "Encrypted Crypt4GH dataset"

    def matches_any(self, target_datatypes: list[Any]) -> bool:
        datatype_classes = tuple(datatype if isclass(datatype) else datatype.__class__ for datatype in target_datatypes)
        if datatype_classes and isinstance(self, datatype_classes):
            return True
        inner_datatype = self.crypt4gh_inner_datatype
        if self.transparent_staging_enabled and inner_datatype is not None:
            return inner_datatype.matches_any(target_datatypes)
        return False

    def _infer_inner_ext(self, dataset: DatasetProtocol) -> str:
        dataset_ext = unwrap_crypt4gh_file_ext(self.file_ext)
        if dataset_ext is not None:
            return dataset_ext
        dataset_ext = unwrap_crypt4gh_file_ext(dataset.extension)
        if dataset_ext is not None:
            return dataset_ext
        created_from_basename = getattr(dataset.dataset, "created_from_basename", None)
        if created_from_basename and created_from_basename.endswith(CRYPT4GH_SUFFIX):
            return created_from_basename[: -len(CRYPT4GH_SUFFIX)].rsplit(".", 1)[-1]
        return "data"


def build_crypt4gh_datatype(inner_datatype, transparent_staging_enabled: bool):
    datatype_class = type(
        f"{inner_datatype.__class__.__name__}Crypt4gh",
        (Crypt4GH,),
        {
            "file_ext": wrap_crypt4gh_file_ext(inner_datatype.file_ext),
            "crypt4gh_inner_datatype": inner_datatype,
            "transparent_staging_enabled": transparent_staging_enabled,
            "edam_format": getattr(inner_datatype, "edam_format", Crypt4GH.edam_format),
            "edam_data": getattr(inner_datatype, "edam_data", Crypt4GH.edam_data),
        },
    )
    return datatype_class()


__all__ = (
    "CRYPT4GH_FILE_EXT",
    "CRYPT4GH_SUFFIX",
    "Crypt4GH",
    "build_crypt4gh_datatype",
    "infer_crypt4gh_file_ext",
    "infer_crypt4gh_inner_file_ext",
    "is_crypt4gh_file_ext",
    "unwrap_crypt4gh_file_ext",
    "wrap_crypt4gh_file_ext",
)
