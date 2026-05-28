"""Unit tests for crypt4gh staging plan and compute-environment wrapper."""

import json
import os
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Optional
from unittest import TestCase
from unittest.mock import MagicMock

from galaxy.job_execution.crypt4gh import (
    build_staging_plan,
    Crypt4GHComputeEnvironment,
    Crypt4GHExternalServiceUnavailable,
    Crypt4GHInputEntry,
    Crypt4GHOutputEntry,
    Crypt4GHStagingPlan,
    raise_if_crypt4gh_staging_external_service_unavailable,
    write_staging_manifest,
)

# ── Helpers ─────────────────────────────────────────────────────────────────


def _make_dataset(
    dataset_id: int, extension: str, file_path: str, uuid: str = "test-uuid", inner_ext: Optional[str] = None
):
    """Minimal dataset stub accepted by build_staging_plan helpers."""
    ds = SimpleNamespace(id=dataset_id, uuid=uuid, extension=extension)
    metadata = SimpleNamespace()
    if inner_ext:
        metadata.crypt4gh_inner_ext = inner_ext
        metadata.crypt4gh_header = "AAAA"  # dummy base64
    obj = SimpleNamespace(
        dataset=ds,
        extension=extension,
        metadata=metadata,
    )
    return obj


def _make_dataset_path(file_path: str):
    """Wrap a string path into a DatasetPath-like object."""

    class _DP(str):
        pass

    return _DP(file_path)


def _make_job_io(input_datasets, output_hdas_and_paths):
    """Stub for JobIO with the minimal interface used by build_staging_plan."""
    job_io = MagicMock()
    job_io.get_input_datasets.return_value = input_datasets

    # get_input_path returns the file path as a string wrapper
    def _get_input_path(ds):
        return _make_dataset_path(ds.dataset.id and f"/data/inputs/{ds.dataset.id}.dat" or "/data/inputs/0.dat")

    job_io.get_input_path.side_effect = _get_input_path
    job_io.get_output_hdas_and_fnames.return_value = output_hdas_and_paths
    return job_io


def _make_job_wrapper(job_id: int, working_dir: str, job_io):
    """Stub for MinimalJobWrapper with the minimal interface used by build_staging_plan."""
    job = SimpleNamespace(id=job_id)
    wrapper = MagicMock()
    wrapper.working_directory = working_dir
    wrapper.job_io = job_io
    wrapper.get_job.return_value = job
    return wrapper


# ── build_staging_plan ───────────────────────────────────────────────────────


class TestBuildStagingPlan:
    def test_no_crypt4gh_inputs_or_outputs_is_empty(self, tmp_path):
        plaintext_ds = _make_dataset(1, "fastqsanger", "/data/1.fastq")
        output_ds = _make_dataset(2, "tabular", "/data/2.tabular")
        job_io = _make_job_io(
            [plaintext_ds],
            {"out1": (output_ds, _make_dataset_path("/data/outputs/2.dat"))},
        )
        wrapper = _make_job_wrapper(42, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)
        assert not plan.has_crypt4gh_inputs
        assert not plan.has_crypt4gh_outputs
        assert not plan.has_crypt4gh_work
        assert plan.input_entries == []
        assert plan.output_entries == []

    def test_crypt4gh_input_is_captured(self, tmp_path):
        enc_ds = _make_dataset(1, "fastqsanger.crypt4gh", "/data/1.fastq.crypt4gh", inner_ext="fastqsanger")
        job_io = _make_job_io([enc_ds], {})
        wrapper = _make_job_wrapper(10, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)

        assert plan.has_crypt4gh_inputs
        assert len(plan.input_entries) == 1
        entry = plan.input_entries[0]
        assert entry.dataset_id == 1
        assert entry.inner_ext == "fastqsanger"
        assert entry.staged_path.startswith(str(tmp_path))
        assert entry.staged_path.endswith(".fastqsanger")
        assert "crypt4gh_staging" in entry.staged_path

    def test_crypt4gh_output_is_captured(self, tmp_path):
        enc_ds = _make_dataset(5, "fastqsanger.crypt4gh", "/data/5.crypt4gh")
        job_io = _make_job_io(
            [],
            {"out1": (enc_ds, _make_dataset_path("/data/outputs/5.dat"))},
        )
        wrapper = _make_job_wrapper(11, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)

        assert plan.has_crypt4gh_outputs
        assert len(plan.output_entries) == 1
        entry = plan.output_entries[0]
        assert entry.dataset_id == 5
        assert entry.final_path == "/data/outputs/5.dat"
        assert entry.staged_path.startswith(str(tmp_path))
        assert entry.should_encrypt is True

    def test_plaintext_output_not_captured(self, tmp_path):
        plain_ds = _make_dataset(7, "tabular", "/data/7.tabular")
        job_io = _make_job_io(
            [],
            {"out1": (plain_ds, _make_dataset_path("/data/outputs/7.dat"))},
        )
        wrapper = _make_job_wrapper(12, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)
        assert not plan.has_crypt4gh_outputs

    def test_staging_directory_location(self, tmp_path):
        enc_ds = _make_dataset(1, "fastqsanger.crypt4gh", "/data/1.crypt4gh")
        job_io = _make_job_io([enc_ds], {})
        wrapper = _make_job_wrapper(1, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)
        assert plan.staging_directory == os.path.join(str(tmp_path), "crypt4gh_staging")

    def test_manifest_path_location(self, tmp_path):
        enc_ds = _make_dataset(1, "fastqsanger.crypt4gh", "/data/1.crypt4gh")
        job_io = _make_job_io([enc_ds], {})
        wrapper = _make_job_wrapper(1, str(tmp_path), job_io)
        plan = build_staging_plan(wrapper)
        assert plan.manifest_path == os.path.join(str(tmp_path), "crypt4gh_manifest.json")


# ── write_staging_manifest ───────────────────────────────────────────────────


class TestWriteStagingManifest:
    def _make_plan(self, tmp_path):
        staging_dir = os.path.join(str(tmp_path), "crypt4gh_staging")
        manifest_path = os.path.join(str(tmp_path), "crypt4gh_manifest.json")
        plan = Crypt4GHStagingPlan(
            job_id=99,
            working_directory=str(tmp_path),
            staging_directory=staging_dir,
            manifest_path=manifest_path,
            input_entries=[
                Crypt4GHInputEntry(
                    dataset_id=1,
                    dataset_uuid="uuid-1",
                    encrypted_path="/data/1.crypt4gh",
                    staged_path=os.path.join(staging_dir, "input_1.fastqsanger"),
                    header_b64="AAAA",
                    inner_ext="fastqsanger",
                )
            ],
            output_entries=[
                Crypt4GHOutputEntry(
                    dataset_id=2,
                    dataset_uuid="uuid-2",
                    staged_path=os.path.join(staging_dir, "output_2.tabular"),
                    final_path="/data/outputs/2.dat",
                    inner_ext="tabular",
                    should_encrypt=True,
                )
            ],
        )
        return plan

    def test_writes_valid_json(self, tmp_path):
        plan = self._make_plan(tmp_path)
        write_staging_manifest(plan)
        assert os.path.exists(plan.manifest_path)
        with open(plan.manifest_path) as f:
            manifest = json.load(f)
        assert "staging_directory" in manifest
        assert len(manifest["inputs"]) == 1
        assert len(manifest["outputs"]) == 1

    def test_manifest_contains_no_private_keys(self, tmp_path):
        plan = self._make_plan(tmp_path)
        write_staging_manifest(plan)
        with open(plan.manifest_path) as f:
            content = f.read()
        assert "private" not in content.lower()
        assert "passphrase" not in content.lower()
        assert "secret" not in content.lower()

    def test_manifest_input_fields(self, tmp_path):
        plan = self._make_plan(tmp_path)
        write_staging_manifest(plan)
        with open(plan.manifest_path) as f:
            manifest = json.load(f)
        inp = manifest["inputs"][0]
        assert inp["encrypted_path"] == "/data/1.crypt4gh"
        assert inp["staged_path"] == plan.staging_directory + "/input_1.fastqsanger"
        assert inp["owner_email"] == ""

    def test_manifest_output_fields(self, tmp_path):
        plan = self._make_plan(tmp_path)
        write_staging_manifest(plan)
        with open(plan.manifest_path) as f:
            manifest = json.load(f)
        out = manifest["outputs"][0]
        assert out["staged_path"] == plan.staging_directory + "/output_2.tabular"
        assert out["final_path"] == "/data/outputs/2.dat"
        assert out["should_encrypt"] is True
        assert out["owner_email"] == ""


# ── Crypt4GHComputeEnvironment ────────────────────────────────────────────────


class TestCrypt4GHComputeEnvironment:
    def _make_inner_env(self, input_path="/data/enc.crypt4gh", output_path="/data/out.dat"):
        inner = MagicMock()
        inner.input_path_rewrite.return_value = input_path
        inner.output_path_rewrite.return_value = output_path
        return inner

    def _make_plan_with_input(self, dataset_id, staged_path):
        plan = Crypt4GHStagingPlan(
            job_id=1,
            working_directory="/tmp/job_1",
            staging_directory="/tmp/job_1/crypt4gh_staging",
            manifest_path="/tmp/job_1/crypt4gh_manifest.json",
            input_entries=[
                Crypt4GHInputEntry(
                    dataset_id=dataset_id,
                    dataset_uuid="uuid",
                    encrypted_path="/data/enc.crypt4gh",
                    staged_path=staged_path,
                    header_b64="AAAA",
                    inner_ext="fastqsanger",
                )
            ],
        )
        return plan

    def _make_plan_with_output(self, dataset_id, staged_path, final_path):
        plan = Crypt4GHStagingPlan(
            job_id=1,
            working_directory="/tmp/job_1",
            staging_directory="/tmp/job_1/crypt4gh_staging",
            manifest_path="/tmp/job_1/crypt4gh_manifest.json",
            output_entries=[
                Crypt4GHOutputEntry(
                    dataset_id=dataset_id,
                    dataset_uuid="uuid",
                    staged_path=staged_path,
                    final_path=final_path,
                    inner_ext="fastqsanger",
                    should_encrypt=True,
                )
            ],
        )
        return plan

    def _make_dataset(self, dataset_id):
        return SimpleNamespace(dataset=SimpleNamespace(id=dataset_id))

    def test_input_path_rewritten_for_crypt4gh(self):
        staged_path = "/tmp/job_1/crypt4gh_staging/input_1.fastqsanger"
        inner = self._make_inner_env()
        plan = self._make_plan_with_input(dataset_id=1, staged_path=staged_path)
        env = Crypt4GHComputeEnvironment(inner, plan)
        ds = self._make_dataset(dataset_id=1)
        assert env.input_path_rewrite(ds) == staged_path
        inner.input_path_rewrite.assert_not_called()

    def test_input_path_delegated_for_non_crypt4gh(self):
        inner = self._make_inner_env(input_path="/data/plain.dat")
        plan = self._make_plan_with_input(dataset_id=1, staged_path="/tmp/staged")
        env = Crypt4GHComputeEnvironment(inner, plan)
        ds = self._make_dataset(dataset_id=99)  # Different id — not in plan
        result = env.input_path_rewrite(ds)
        assert result == "/data/plain.dat"
        inner.input_path_rewrite.assert_called_once_with(ds)

    def test_output_path_rewritten_for_crypt4gh(self):
        staged_path = "/tmp/job_1/crypt4gh_staging/output_2.fastqsanger"
        inner = self._make_inner_env()
        plan = self._make_plan_with_output(dataset_id=2, staged_path=staged_path, final_path="/data/out.dat")
        env = Crypt4GHComputeEnvironment(inner, plan)
        ds = self._make_dataset(dataset_id=2)
        assert env.output_path_rewrite(ds) == staged_path
        inner.output_path_rewrite.assert_not_called()

    def test_output_path_delegated_for_non_crypt4gh(self):
        inner = self._make_inner_env(output_path="/data/plain_out.dat")
        plan = self._make_plan_with_output(dataset_id=2, staged_path="/tmp/staged", final_path="/data/out.dat")
        env = Crypt4GHComputeEnvironment(inner, plan)
        ds = self._make_dataset(dataset_id=99)  # Different id
        result = env.output_path_rewrite(ds)
        assert result == "/data/plain_out.dat"
        inner.output_path_rewrite.assert_called_once_with(ds)

    def test_other_methods_delegated(self):
        inner = self._make_inner_env()
        inner.working_directory.return_value = "/tmp/job_1/working"
        inner.tool_directory.return_value = "/opt/tool"
        plan = Crypt4GHStagingPlan(
            job_id=1,
            working_directory="/tmp/job_1",
            staging_directory="/tmp/job_1/crypt4gh_staging",
            manifest_path="/tmp/job_1/crypt4gh_manifest.json",
        )
        env = Crypt4GHComputeEnvironment(inner, plan)
        assert env.working_directory() == "/tmp/job_1/working"
        assert env.tool_directory() == "/opt/tool"


class TestCrypt4GHStagingExternalServiceFailure(TestCase):
    """Test detection of crypt4gh external service unavailability during job finalization."""

    def test_raises_external_service_failure_when_outputs_are_missing(self):
        """Raise exception when outputs_populated is missing and crypt4gh staging markers are in stderr."""
        with self.assertRaisesRegex(Crypt4GHExternalServiceUnavailable, "external service was unavailable"):
            raise_if_crypt4gh_staging_external_service_unavailable(
                "Traceback... [crypt4gh] stage-inputs failed (exit 1)",
                "/tmp/job/metadata/outputs_populated",
            )

    def test_no_exception_without_crypt4gh_marker(self):
        """Do not raise if stderr lacks crypt4gh staging failure markers."""
        raise_if_crypt4gh_staging_external_service_unavailable(
            "Traceback... unrelated failure",
            "/tmp/job/metadata/outputs_populated",
        )

    def test_no_exception_when_outputs_directory_exists(self):
        """Do not raise if outputs_populated directory exists, even with markers present."""
        with TemporaryDirectory() as test_directory:
            outputs_populated_path = os.path.join(test_directory, "outputs_populated")
            os.makedirs(outputs_populated_path, exist_ok=True)

            raise_if_crypt4gh_staging_external_service_unavailable(
                "Traceback... [crypt4gh] stage-inputs failed (exit 1)",
                outputs_populated_path,
            )
