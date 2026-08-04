import base64
import tempfile
from types import SimpleNamespace
from typing import cast

from galaxy.datatypes.protocols import DatasetProtocol
from galaxy.datatypes.registry import (
    example_datatype_registry_for_sample,
    Registry,
)
from galaxy.datatypes.sniff import (
    FilePrefix,
    get_test_fname,
    guess_ext,
    handle_uploaded_dataset_file,
    handle_uploaded_dataset_file_internal,
)
from galaxy.datatypes.upload_util import handle_upload
from galaxy.util.crypt4gh import (
    infer_crypt4gh_inner_file_ext,
    preserve_crypt4gh_inner_file_ext,
    read_crypt4gh_header,
)
from .util import MockDatasetDataset


def test_infer_from_filename_crypt4gh():
    datatypes_registry = example_datatype_registry_for_sample()
    datatype = datatypes_registry.get_datatype_from_filename("mycool.fastq.crypt4gh")
    assert datatype is not None
    assert datatype.file_ext == "fastqsanger.c4gh"
    gz_datatype = datatypes_registry.get_datatype_from_filename("mycool.fastq.gz.crypt4gh")
    assert gz_datatype is not None
    assert gz_datatype.file_ext == "fastqsanger.gz.c4gh"


def test_infer_from_filename_c4gh():
    datatypes_registry = example_datatype_registry_for_sample()
    datatype = datatypes_registry.get_datatype_from_filename("mycool.fastq.c4gh")
    assert datatype is not None
    assert datatype.file_ext == "fastqsanger.c4gh"


def test_infer_inner_ext_from_plain_and_wrapped_filenames():
    datatypes_registry = example_datatype_registry_for_sample()
    assert infer_crypt4gh_inner_file_ext("mycool.bam", datatypes_registry) == "bam"
    assert infer_crypt4gh_inner_file_ext("mycool.bam.crypt4gh", datatypes_registry) == "bam"
    assert infer_crypt4gh_inner_file_ext("mycool.bam.c4gh", datatypes_registry) == "bam"
    assert infer_crypt4gh_inner_file_ext("mycool.bam.cfoobar4gh", datatypes_registry) == "bam"


def test_crypt4gh_detection():
    datatypes_registry = example_datatype_registry_for_sample()
    sniff_order = datatypes_registry.sniff_order
    assert guess_ext(get_test_fname("1.fastqsanger.crypt4gh"), sniff_order) == "fastqsanger.c4gh"


def test_guess_ext_for_crypt4gh_content_without_suffix_is_not_binary():
    datatypes_registry = example_datatype_registry_for_sample()
    sniff_order = datatypes_registry.sniff_order
    with tempfile.NamedTemporaryFile(suffix=".dat") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        assert guess_ext(temp_file.name, sniff_order) == "c4gh"


def test_preserve_crypt4gh_redetect_prefers_existing_wrapped_extension():
    assert (
        preserve_crypt4gh_inner_file_ext(
            guessed_ext="c4gh",
            current_ext="fasta.crypt4gh",
            metadata_inner_ext="fastqsanger",
        )
        == "fasta.crypt4gh"
    )


def test_preserve_crypt4gh_redetect_uses_metadata_when_current_is_generic():
    assert (
        preserve_crypt4gh_inner_file_ext(
            guessed_ext="c4gh",
            current_ext="c4gh",
            metadata_inner_ext="fastqsanger",
        )
        == "fastqsanger.c4gh"
    )


def test_preserve_crypt4gh_redetect_accepts_legacy_generic_guess():
    assert (
        preserve_crypt4gh_inner_file_ext(
            guessed_ext="crypt4gh",
            current_ext="crypt4gh",
            metadata_inner_ext="fastqsanger",
        )
        == "fastqsanger.c4gh"
    )


def test_handle_uploaded_dataset_file_internal_crypt4gh_without_crypt4gh_suffix():
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".bin") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        assert handle_uploaded_dataset_file(temp_file.name, datatypes_registry, ext="fastqsanger") == "fastqsanger.c4gh"


def test_handle_uploaded_dataset_file_internal_crypt4gh_uses_filename_when_ext_auto():
    datatypes_registry = example_datatype_registry_for_sample()
    assert (
        handle_uploaded_dataset_file(get_test_fname("1.fastqsanger.crypt4gh"), datatypes_registry) == "fastqsanger.c4gh"
    )


def test_handle_uploaded_dataset_file_internal_crypt4gh_uses_uploaded_file_name_hint():
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".tmp") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        file_prefix = FilePrefix(temp_file.name)
        response = handle_uploaded_dataset_file_internal(
            file_prefix, datatypes_registry, ext="auto", uploaded_file_name="uploaded.fastqsanger.crypt4gh"
        )
        assert response.ext == "fastqsanger.c4gh"


def test_handle_uploaded_dataset_file_internal_crypt4gh_uses_compact_uploaded_file_name_hint():
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".tmp") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        file_prefix = FilePrefix(temp_file.name)
        response = handle_uploaded_dataset_file_internal(
            file_prefix, datatypes_registry, ext="auto", uploaded_file_name="uploaded.fastqsanger.c4gh"
        )
        assert response.ext == "fastqsanger.c4gh"


def test_handle_upload_crypt4gh_uses_full_uploaded_filename():
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".tmp") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        response = handle_upload(
            datatypes_registry,
            temp_file.name,
            requested_ext="auto",
            name="uploaded.fastqsanger.crypt4gh",
            tmp_prefix="sniff_upload_",
            tmp_dir=None,
            check_content=True,
            link_data_only=False,
            in_place=False,
            auto_decompress=True,
            convert_to_posix_lines=False,
            convert_spaces_to_tabs=False,
        )

        assert response.ext == "fastqsanger.c4gh"
        assert response.datatype.file_ext == "fastqsanger.c4gh"


def test_handle_upload_crypt4gh_respects_user_selection():
    """User-selected datatype should take precedence over filename inference."""
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".tmp") as temp_file:
        # File contains fastqsanger data but user selects fasta
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        response = handle_upload(
            datatypes_registry,
            temp_file.name,
            requested_ext="fasta",  # User explicitly selects fasta
            name="uploaded.fastqsanger.crypt4gh",  # Filename suggests fastqsanger
            tmp_prefix="sniff_upload_",
            tmp_dir=None,
            check_content=True,
            link_data_only=False,
            in_place=False,
            auto_decompress=True,
            convert_to_posix_lines=False,
            convert_spaces_to_tabs=False,
        )

        # User selection should take precedence: fasta.c4gh, not fastqsanger.c4gh
        assert response.ext == "fasta.c4gh"
        assert response.datatype.file_ext == "fasta.c4gh"


def test_handle_uploaded_dataset_file_internal_crypt4gh_without_crypt4gh_suffix_ext_auto():
    datatypes_registry = example_datatype_registry_for_sample()
    with tempfile.NamedTemporaryFile(suffix=".bin") as temp_file:
        temp_file.write(open(get_test_fname("1.fastqsanger.crypt4gh"), "rb").read())
        temp_file.flush()
        assert handle_uploaded_dataset_file(temp_file.name, datatypes_registry, ext="auto") == "c4gh"


def test_crypt4gh_wrapper_matches_inner_datatype_only_when_staging_enabled():
    disabled_registry = example_datatype_registry_for_sample(enable_crypt4gh_transparent_staging=False)
    enabled_registry = example_datatype_registry_for_sample(enable_crypt4gh_transparent_staging=True)

    disabled_wrapper = disabled_registry.get_datatype_by_extension("fastqsanger.c4gh")
    enabled_wrapper = enabled_registry.get_datatype_by_extension("fastqsanger.c4gh")
    inner_datatype = enabled_registry.get_datatype_by_extension("fastqsanger")

    assert disabled_wrapper is not None
    assert enabled_wrapper is not None
    assert inner_datatype is not None
    assert disabled_wrapper.matches_any([inner_datatype]) is False
    assert enabled_wrapper.matches_any([inner_datatype]) is True


def test_crypt4gh_wrapper_matches_inner_datatype_when_enabled_via_registry_xml_roundtrip():
    source_registry = example_datatype_registry_for_sample(enable_crypt4gh_transparent_staging=True)

    with tempfile.NamedTemporaryFile(suffix=".xml") as temp_registry_xml:
        source_registry.to_xml_file(temp_registry_xml.name)

        reloaded_registry = Registry()
        reloaded_registry.load_datatypes(
            root_dir=".",
            config=temp_registry_xml.name,
            use_build_sites=False,
            use_converters=False,
            use_display_applications=False,
        )

    wrapper = reloaded_registry.get_datatype_by_extension("fastqsanger.c4gh")
    inner_datatype = reloaded_registry.get_datatype_by_extension("fastqsanger")

    assert wrapper is not None
    assert inner_datatype is not None
    assert wrapper.matches_any([inner_datatype]) is True


def test_crypt4gh_set_meta_extracts_header_only():
    datatypes_registry = example_datatype_registry_for_sample()
    crypt4gh_datatype = datatypes_registry.get_datatype_by_extension("fastqsanger.c4gh")
    assert crypt4gh_datatype is not None

    class MockMetadata(SimpleNamespace):
        def element_is_set(self, name):
            return hasattr(self, name)

    class MockDataset:
        extension = "fastqsanger.c4gh"

        def __init__(self, filename):
            self.dataset = MockDatasetDataset(filename)
            self.metadata = MockMetadata()
            self._filename = filename

        def get_file_name(self, sync_cache=True):
            return self._filename

    dataset = MockDataset(get_test_fname("1.fastqsanger.crypt4gh"))
    crypt4gh_datatype.set_meta(cast(DatasetProtocol, dataset))

    assert dataset.metadata.crypt4gh_inner_ext == "fastqsanger"
    assert dataset.metadata.crypt4gh_header
    assert dataset.metadata.crypt4gh_header == base64.b64encode(read_crypt4gh_header(dataset.get_file_name())).decode(
        "ascii"
    )
