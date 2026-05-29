"""Crypt4GH-aware job staging plan and compute-environment wrapper.

This module builds staging plans for jobs that consume or produce crypt4gh-encrypted
datasets. It defines a runner-agnostic manifest that the compute-side key service
reads to perform decrypt/encrypt operations. Galaxy never sees plaintext payload
bytes on the head node.

Manifest schema (non-secret — safe to write to working directory):
- job_id: job identifier
- working_directory: absolute path to job working directory
- staging_directory: absolute path to staging sub-directory
- inputs: list of encrypted-input descriptors (see Crypt4GHInputEntry)
- outputs: list of output descriptors (see Crypt4GHOutputEntry)

Private keys, passphrases, and decrypted payload bytes are never written here.
The runner-side key service resolves secrets from its own secure storage.
"""

import json
import os
from dataclasses import (
    dataclass,
    field,
)
from logging import getLogger
from typing import (
    Any,
    Optional,
    TYPE_CHECKING,
)

from galaxy.datatypes.crypt4gh import is_crypt4gh_file_ext
from galaxy.exceptions import MessageException
from galaxy.job_execution.compute_environment import ComputeEnvironment
from galaxy.util.crypt4gh import (
    check_crypt4gh,
    wrap_crypt4gh_file_ext,
)

if TYPE_CHECKING:
    from galaxy.jobs import MinimalJobWrapper


log = getLogger(__name__)

_STAGE_FAILURE_MARKERS = (
    "[crypt4gh] stage-inputs failed",
    "[crypt4gh] stage-outputs failed",
)


class Crypt4GHExternalServiceUnavailable(MessageException):
    """Raised when crypt4gh staging fails because the external service is unavailable."""


def raise_if_crypt4gh_staging_external_service_unavailable(job_stderr: str, outputs_populated_path: str) -> None:
    """Raise a dedicated exception when crypt4gh staging failed due to external service issues."""
    if os.path.exists(outputs_populated_path):
        return
    if not any(marker in job_stderr for marker in _STAGE_FAILURE_MARKERS):
        return
    raise Crypt4GHExternalServiceUnavailable(
        "Encrypted dataset staging failed because an external service was unavailable. "
        "Verify the configured crypt4gh re-encryption service is reachable and retry the job."
    )


@dataclass
class Crypt4GHInputEntry:
    """Describes a single encrypted input dataset and where it should be staged."""

    dataset_id: int
    dataset_uuid: str
    encrypted_path: str
    staged_path: str
    header_b64: str  # Base64-encoded raw crypt4gh header (non-secret)
    inner_ext: str
    owner_email: str = ""  # Galaxy user email — used by the re-encryptor to look up the user keypair


@dataclass
class Crypt4GHOutputEntry:
    """Describes a single job output and whether/where to encrypt it."""

    dataset_id: int
    dataset_uuid: str
    staged_path: str  # Where the tool writes plaintext
    final_path: str  # Where the (encrypted) output should end up
    inner_ext: str
    should_encrypt: bool = True  # Re-encrypt to crypt4gh after tool finishes
    owner_email: str = ""  # Galaxy user email — used by the re-encryptor to look up the user keypair


@dataclass
class Crypt4GHStagingPlan:
    """Runner-agnostic plan produced by the head node before job dispatch."""

    job_id: int
    working_directory: str
    staging_directory: str
    manifest_path: str
    input_entries: list[Crypt4GHInputEntry] = field(default_factory=list)
    output_entries: list[Crypt4GHOutputEntry] = field(default_factory=list)

    @property
    def has_crypt4gh_inputs(self) -> bool:
        return bool(self.input_entries)

    @property
    def has_crypt4gh_outputs(self) -> bool:
        return any(e.should_encrypt for e in self.output_entries)

    @property
    def has_crypt4gh_work(self) -> bool:
        return self.has_crypt4gh_inputs or self.has_crypt4gh_outputs

    def staged_input_path(self, dataset_id: int) -> Optional[str]:
        for entry in self.input_entries:
            if entry.dataset_id == dataset_id:
                return entry.staged_path
        return None

    def staged_output_path(self, dataset_id: int) -> Optional[str]:
        for entry in self.output_entries:
            if entry.dataset_id == dataset_id and entry.should_encrypt:
                return entry.staged_path
        return None

    @property
    def encrypted_output_staged_paths(self) -> dict[int, str]:
        """Map dataset_id → staged_path for every output marked should_encrypt."""
        return {e.dataset_id: e.staged_path for e in self.output_entries if e.should_encrypt}


def _get_dataset_id(dataset) -> int:
    """Extract integer dataset id from a dataset-like object."""
    ds = getattr(dataset, "dataset", dataset)
    return int(ds.id)


def _get_dataset_uuid(dataset) -> str:
    """Extract UUID string from a dataset-like object."""
    ds = getattr(dataset, "dataset", dataset)
    uuid = ds.uuid
    return str(uuid) if uuid is not None else ""


def _get_dataset_extension(dataset) -> str:
    """Return the file extension (datatype) of a dataset-like object."""
    ext = getattr(dataset, "extension", None)
    if ext is None:
        ext = getattr(getattr(dataset, "dataset", None), "extension", "data")
    return ext or "data"


def _get_inner_ext(dataset) -> str:
    """Return the inner (plaintext) extension for a crypt4gh-wrapped dataset."""
    from galaxy.datatypes.crypt4gh import unwrap_crypt4gh_file_ext

    ext = _get_dataset_extension(dataset)
    inner = unwrap_crypt4gh_file_ext(ext)
    if inner:
        return inner
    # Fall back to checking metadata
    header_meta = getattr(getattr(dataset, "metadata", None), "crypt4gh_inner_ext", None)
    return header_meta or "data"


def _get_header_b64(dataset) -> str:
    """Return the base64-encoded header from dataset metadata (may be empty)."""
    meta = getattr(dataset, "metadata", None)
    if meta is None:
        return ""
    return getattr(meta, "crypt4gh_header", "") or ""


def _get_owner_email(job) -> str:
    """Return the email of the Galaxy user who owns the job, or empty string."""
    user = getattr(job, "user", None)
    if user is None:
        return ""
    return getattr(user, "email", None) or ""


def build_staging_plan(
    job_wrapper: "MinimalJobWrapper",
    working_directory: Optional[str] = None,
    compute_environment: Optional[ComputeEnvironment] = None,
) -> "Crypt4GHStagingPlan":
    """Build a Crypt4GHStagingPlan from a job wrapper's inputs and outputs.

    Inspects each input and output dataset. For encrypted inputs it records the
    original encrypted path and a staged plaintext path inside the staging
    sub-directory. For outputs it records the staged plaintext path where the
    tool should write and the final dataset path where the encrypted form ends up.

    No private keys or decrypted bytes are ever written by this function.

    Args:
        job_wrapper: MinimalJobWrapper (or a compatible mock for testing).
        working_directory: Override the working directory; defaults to
            ``job_wrapper.working_directory``.

    Returns:
        A :class:`Crypt4GHStagingPlan` ready to be written as a manifest.
    """
    if working_directory is None:
        working_directory = job_wrapper.working_directory
    staging_directory = os.path.join(working_directory, "crypt4gh_staging")
    manifest_path = os.path.join(working_directory, "crypt4gh_manifest.json")

    job = job_wrapper.get_job()
    job_id = int(job.id)

    plan = Crypt4GHStagingPlan(
        job_id=job_id,
        working_directory=working_directory,
        staging_directory=staging_directory,
        manifest_path=manifest_path,
    )

    # ── Inputs ──────────────────────────────────────────────────────────────
    job_io = job_wrapper.job_io
    for dataset in job_io.get_input_datasets():
        ext = _get_dataset_extension(dataset)
        if not is_crypt4gh_file_ext(ext):
            continue
        encrypted_path = None
        if compute_environment is not None:
            encrypted_path = compute_environment.input_path_rewrite(dataset)
        if encrypted_path is None:
            encrypted_path = str(job_io.get_input_path(dataset))
        dataset_id = _get_dataset_id(dataset)
        inner_ext = _get_inner_ext(dataset)
        staged_name = f"input_{dataset_id}.{inner_ext}"
        staged_path = os.path.join(staging_directory, staged_name)
        plan.input_entries.append(
            Crypt4GHInputEntry(
                dataset_id=dataset_id,
                dataset_uuid=_get_dataset_uuid(dataset),
                encrypted_path=encrypted_path,
                staged_path=staged_path,
                header_b64=_get_header_b64(dataset),
                inner_ext=inner_ext,
                owner_email=_get_owner_email(job),
            )
        )

    # ── Outputs ─────────────────────────────────────────────────────────────
    for _output_name, (dataset, dataset_path) in job_io.get_output_hdas_and_fnames().items():
        ext = _get_dataset_extension(dataset)
        output_requires_crypt4gh = is_crypt4gh_file_ext(ext) or plan.has_crypt4gh_inputs
        if not output_requires_crypt4gh:
            continue
        final_path = None
        if compute_environment is not None:
            final_path = compute_environment.output_path_rewrite(dataset)

        # If runner rewriting points to a temporary false path, stage-outputs
        # must encrypt into the persisted real object-store path.
        dataset_false_path = getattr(dataset_path, "false_path", None)
        dataset_real_path = getattr(dataset_path, "real_path", None)
        if (
            final_path is not None
            and dataset_false_path
            and dataset_real_path
            and str(final_path) == str(dataset_false_path)
        ):
            final_path = str(dataset_real_path)

        if final_path is None:
            if dataset_real_path:
                final_path = str(dataset_real_path)
            else:
                final_path = str(dataset_path)
        dataset_id = _get_dataset_id(dataset)
        inner_ext = _get_inner_ext(dataset) if is_crypt4gh_file_ext(ext) else ext
        staged_name = f"output_{dataset_id}.{inner_ext}"
        staged_path = os.path.join(staging_directory, staged_name)
        plan.output_entries.append(
            Crypt4GHOutputEntry(
                dataset_id=dataset_id,
                dataset_uuid=_get_dataset_uuid(dataset),
                staged_path=staged_path,
                final_path=final_path,
                inner_ext=inner_ext,
                should_encrypt=True,
                owner_email=_get_owner_email(job),
            )
        )

    return plan


def write_staging_manifest(plan: Crypt4GHStagingPlan) -> None:
    """Write the minimal JSON manifest for the compute-side staging helper.

    The manifest is written to ``plan.manifest_path`` and contains only the
    fields needed by the helper to perform file I/O and service calls:
    - staging_directory: where to write staged files
    - inputs: encrypted_path, staged_path, owner_email for each input
    - outputs: staged_path, final_path, owner_email, should_encrypt for each output

    No private keys, passphrases, or decrypted payload bytes are included.
    """
    manifest: dict[str, Any] = {
        "staging_directory": plan.staging_directory,
        "inputs": [
            {
                "encrypted_path": e.encrypted_path,
                "staged_path": e.staged_path,
                "owner_email": e.owner_email,
            }
            for e in plan.input_entries
        ],
        "outputs": [
            {
                "staged_path": e.staged_path,
                "final_path": e.final_path,
                "owner_email": e.owner_email,
                "should_encrypt": e.should_encrypt,
            }
            for e in plan.output_entries
        ],
    }
    with open(plan.manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)


def rewrite_metadata_output_fnames_for_crypt4gh(
    job_wrapper: "MinimalJobWrapper", output_fnames, remote_working_directory=None
):
    """Rewrite metadata filename overrides to staged plaintext paths for crypt4gh outputs.

    When a job produces crypt4gh-encrypted outputs, the metadata computation
    must run against the *staged plaintext* files (before post-command
    re-encryption).  This function replaces each output
    :class:`~galaxy.job_execution.datasets.DatasetPath` whose dataset is
    marked for encryption with a clone pointing at the staged path, so that
    the metadata command reads decrypted content instead of encrypted bytes.

    Returns the original list unchanged when no crypt4gh outputs are present.
    """
    try:
        plan = build_staging_plan(job_wrapper, working_directory=remote_working_directory)
    except Exception:
        log.debug("Unable to build crypt4gh staging plan for metadata output rewrite", exc_info=True)
        return output_fnames

    if not plan.has_crypt4gh_outputs:
        return output_fnames

    staged_by_dataset_id = plan.encrypted_output_staged_paths
    if not staged_by_dataset_id:
        return output_fnames

    rewritten = []
    changed = False
    for dataset_path in output_fnames:
        dataset_id = getattr(dataset_path, "dataset_id", None)
        staged_path = staged_by_dataset_id.get(dataset_id) if isinstance(dataset_id, int) else None
        if staged_path and hasattr(dataset_path, "with_path_for_job"):
            rewritten.append(
                dataset_path.with_path_for_job(
                    staged_path,
                    false_extra_files_path=getattr(dataset_path, "false_extra_files_path", None),
                    false_metadata_path=getattr(dataset_path, "false_metadata_path", None),
                )
            )
            changed = True
        else:
            rewritten.append(dataset_path)

    return rewritten if changed else output_fnames


def wrap_compute_environment_for_tool_evaluation(
    job_wrapper: Any, compute_environment: ComputeEnvironment
) -> ComputeEnvironment:
    """Wrap compute environment to expose staged plaintext paths to tool evaluation.

    This wrapper should only be used when building tool command-line parameter
    paths. Runner-side staging command generation should continue using the
    original compute environment so encrypted input and final output paths are
    preserved in the manifest.
    """
    plan = build_staging_plan(job_wrapper, compute_environment=compute_environment)
    if not plan.has_crypt4gh_work:
        return compute_environment
    return Crypt4GHComputeEnvironment(compute_environment, plan)


def encrypted_output_paths_from_manifest(working_directory: str) -> set[str]:
    """Return real output paths expected to be encrypted for a job workdir."""
    output_paths: set[str] = set()
    manifest_path = os.path.join(working_directory, "crypt4gh_manifest.json")
    if not os.path.exists(manifest_path):
        return output_paths
    try:
        with open(manifest_path) as handle:
            manifest = json.load(handle)
        for output_entry in manifest.get("outputs", []):
            if not output_entry.get("should_encrypt", True):
                continue
            final_path = output_entry.get("final_path")
            if isinstance(final_path, str) and final_path:
                output_paths.add(os.path.realpath(final_path))
    except Exception:
        # Manifest parsing should not fail job finalization.
        return set()
    return output_paths


def wrap_output_dataset_if_crypt4gh(dataset, expected_output_paths: set[str]) -> bool:
    """Wrap extension and refresh metadata/peek when output is encrypted."""
    if dataset.dataset is None or dataset.dataset.purged:
        return False
    dataset_file_name = dataset.dataset.get_file_name()
    payload_is_crypt4gh = check_crypt4gh(dataset_file_name)
    expected_crypt4gh_output = os.path.realpath(dataset_file_name) in expected_output_paths
    if not (payload_is_crypt4gh or expected_crypt4gh_output):
        return False
    if not is_crypt4gh_file_ext(dataset.extension):
        dataset.extension = wrap_crypt4gh_file_ext(dataset.extension)
        dataset.init_meta()
    dataset.datatype.set_meta(dataset, overwrite=False)
    dataset.set_peek()
    return True


def enforce_crypt4gh_output_wrapping(output_dataset_associations, working_directory: str, sa_session) -> None:
    """Ensure encrypted outputs are represented as crypt4gh-wrapped datasets."""
    expected_output_paths = encrypted_output_paths_from_manifest(working_directory)
    for dataset_assoc in output_dataset_associations:
        dataset_links = (
            dataset_assoc.dataset.dataset.history_associations + dataset_assoc.dataset.dataset.library_associations
        )
        for dataset in dataset_links:
            if wrap_output_dataset_if_crypt4gh(dataset, expected_output_paths):
                sa_session.add(dataset)


class Crypt4GHComputeEnvironment(ComputeEnvironment):
    """Wraps any ComputeEnvironment and rewrites crypt4gh dataset paths.

    For inputs: crypt4gh-encrypted datasets are redirected to their staged
    plaintext paths so the tool receives plaintext.

    For outputs: datasets expected to be encrypted are redirected to their
    staged plaintext paths so the tool writes plaintext which is later
    re-encrypted by the runner-side key service.

    All other paths and methods are delegated to the wrapped environment.
    """

    def __init__(self, inner: ComputeEnvironment, plan: Crypt4GHStagingPlan):
        super().__init__()
        self._inner = inner
        self._plan = plan

    # ── Path rewrites ────────────────────────────────────────────────────────

    def input_path_rewrite(self, dataset):
        staged = self._plan.staged_input_path(_get_dataset_id(dataset))
        if staged is not None:
            return staged
        return self._inner.input_path_rewrite(dataset)

    def output_path_rewrite(self, dataset):
        staged = self._plan.staged_output_path(_get_dataset_id(dataset))
        if staged is not None:
            return staged
        return self._inner.output_path_rewrite(dataset)

    # ── Delegated methods ────────────────────────────────────────────────────

    def output_names(self):
        return self._inner.output_names()

    def input_extra_files_rewrite(self, dataset):
        return self._inner.input_extra_files_rewrite(dataset)

    def output_extra_files_rewrite(self, dataset):
        return self._inner.output_extra_files_rewrite(dataset)

    def input_metadata_rewrite(self, dataset, metadata_value):
        return self._inner.input_metadata_rewrite(dataset, metadata_value)

    def unstructured_path_rewrite(self, path):
        return self._inner.unstructured_path_rewrite(path)

    def working_directory(self):
        return self._inner.working_directory()

    def config_directory(self):
        return self._inner.config_directory()

    def env_config_directory(self):
        return self._inner.env_config_directory()

    def sep(self):
        return self._inner.sep()

    def new_file_path(self):
        return self._inner.new_file_path()

    def tool_directory(self):
        return self._inner.tool_directory()

    def version_path(self):
        return self._inner.version_path()

    def home_directory(self):
        return self._inner.home_directory()

    def tmp_directory(self):
        return self._inner.tmp_directory()

    def galaxy_url(self):
        return self._inner.galaxy_url()

    def get_file_sources_dict(self):
        return self._inner.get_file_sources_dict()


__all__ = (
    "build_staging_plan",
    "Crypt4GHExternalServiceUnavailable",
    "Crypt4GHComputeEnvironment",
    "Crypt4GHInputEntry",
    "Crypt4GHOutputEntry",
    "Crypt4GHStagingPlan",
    "enforce_crypt4gh_output_wrapping",
    "encrypted_output_paths_from_manifest",
    "raise_if_crypt4gh_staging_external_service_unavailable",
    "rewrite_metadata_output_fnames_for_crypt4gh",
    "wrap_output_dataset_if_crypt4gh",
    "wrap_compute_environment_for_tool_evaluation",
    "write_staging_manifest",
)
