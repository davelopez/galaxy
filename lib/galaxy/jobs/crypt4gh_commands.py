"""Shell-fragment builders for crypt4gh decrypt/encrypt/cleanup sequencing.

These functions produce shell command strings that wrap a tool invocation
with the necessary pre/post-processing for crypt4gh transparent staging:

  1. Pre-commands  : create staging directory; call the runner-side re-encryption
                     service to decrypt each encrypted input.
  2. Tool invocation (managed by CommandsBuilder in command_factory.py).
  3. Post-commands : call the runner-side re-encryption service to encrypt each
                     plaintext output; remove the staging directory.

The re-encryption service URL is read from
``job_wrapper.app.config.crypt4gh_reencryption_service_url``.  Galaxy never
places private keys, passphrases, or decrypted payload bytes in these commands.
"""

import os
import shlex
import shutil
from pathlib import Path
from typing import (
    Optional,
    TYPE_CHECKING,
)

from galaxy.job_execution.crypt4gh import (
    build_staging_plan,
    write_staging_manifest,
)

if TYPE_CHECKING:
    from galaxy.job_execution.crypt4gh import Crypt4GHStagingPlan


_HELPER_SCRIPT_NAME = "crypt4gh_staging_helper.py"


def _helper_source_path() -> str:
    """Return the in-repo source path of the compute-side staging helper."""
    return str(Path(__file__).resolve().parent.parent / "job_execution" / "crypt4gh_staging.py")


def _ensure_helper_script(local_working_directory: str) -> str:
    """Copy the helper script into the job working directory and return its path."""
    helper_path = os.path.join(local_working_directory, _HELPER_SCRIPT_NAME)
    source_path = _helper_source_path()
    shutil.copyfile(source_path, helper_path)
    return helper_path


def _remote_or_local_path(local_path: str, remote_script_directory: Optional[str]) -> str:
    """Return remote script-directory path when available, otherwise local path."""
    if not remote_script_directory:
        return local_path
    return os.path.join(remote_script_directory, os.path.basename(local_path))


def _get_service_url(job_wrapper) -> Optional[str]:
    """Return the re-encryption service URL from Galaxy config, or None."""
    config = getattr(getattr(job_wrapper, "app", None), "config", None)
    if config is not None:
        return getattr(config, "crypt4gh_reencryption_service_url", None)
    return None


def _get_compute_private_key_path(job_wrapper) -> Optional[str]:
    """Return optional compute-private-key path for worker-side plaintext staging."""
    config = getattr(getattr(job_wrapper, "app", None), "config", None)
    if config is not None:
        return getattr(config, "crypt4gh_compute_private_key_path", None)
    return None


def _python_helper_call(
    operation: str,
    helper_path: str,
    manifest_path: str,
    service_url: str,
    compute_private_key_path: Optional[str] = None,
) -> str:
    """Build a shell command invoking the compute-side staging helper by file path."""
    # These are relative to the job working directory where the command pipeline runs.
    tool_stdout_path = "./outputs/tool_stdout"
    tool_stderr_path = "./outputs/tool_stderr"
    key_env = ""
    if compute_private_key_path:
        key_env = f"GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY={shlex.quote(compute_private_key_path)} "
    return (
        f'{key_env}"$GALAXY_PYTHON" {shlex.quote(helper_path)}'
        f" {shlex.quote(operation)}"
        f" {shlex.quote(manifest_path)}"
        f" {shlex.quote(service_url)}"
        f" 1>> {shlex.quote(tool_stdout_path)}"
        f" 2>> {shlex.quote(tool_stderr_path)}"
        f' || {{ rc=$?; echo "[crypt4gh] {operation} failed (exit $rc)" >> {shlex.quote(tool_stderr_path)}; exit $rc; }}'
    )


def build_crypt4gh_pre_commands(
    plan: "Crypt4GHStagingPlan",
    helper_path: str,
    service_url: Optional[str] = None,
    compute_private_key_path: Optional[str] = None,
) -> Optional[str]:
    """Return the shell pre-command string for crypt4gh input staging.

    Creates the staging directory and calls the re-encryption service to
    decrypt all encrypted inputs listed in the manifest.

    Returns ``None`` if the plan has no crypt4gh inputs (no-op).
    """
    if not plan.has_crypt4gh_inputs:
        return None

    staging_dir = plan.staging_directory
    manifest_path = plan.manifest_path

    if not service_url:
        raise ValueError(
            "crypt4gh transparent staging is enabled but crypt4gh_reencryption_service_url is not configured."
        )

    helper_cmd = _python_helper_call(
        "stage-inputs",
        helper_path,
        manifest_path,
        service_url,
        compute_private_key_path=compute_private_key_path,
    )
    lines = [
        f"mkdir -p {shlex.quote(staging_dir)}",
        helper_cmd,
    ]
    return "; ".join(lines)


def build_crypt4gh_post_commands(
    plan: "Crypt4GHStagingPlan",
    helper_path: str,
    service_url: Optional[str] = None,
) -> Optional[str]:
    """Return the shell post-command string for crypt4gh output encryption.

    Calls the re-encryption service to encrypt plaintext outputs and then
    removes the staging directory.

    Returns ``None`` if the plan has no crypt4gh outputs (no-op).
    """
    if not plan.has_crypt4gh_outputs:
        return None

    staging_dir = plan.staging_directory
    manifest_path = plan.manifest_path

    if not service_url:
        raise ValueError(
            "crypt4gh transparent staging is enabled but crypt4gh_reencryption_service_url is not configured."
        )

    helper_cmd = _python_helper_call("stage-outputs", helper_path, manifest_path, service_url)
    lines = [
        helper_cmd,
        f"rm -rf {shlex.quote(staging_dir)}",
    ]
    return "; ".join(lines)


def inject_crypt4gh_commands(
    commands_builder,
    plan: "Crypt4GHStagingPlan",
    helper_path: str,
    service_url: Optional[str] = None,
    compute_private_key_path: Optional[str] = None,
) -> None:
    """Inject crypt4gh pre/post commands into a CommandsBuilder.

    Pre-commands (decrypt inputs) are prepended.
    Post-commands (encrypt outputs + cleanup) are appended.

    The required execution order is therefore:
      decrypt inputs → tool → encrypt outputs → cleanup plaintext

    Args:
        commands_builder: A :class:`galaxy.jobs.command_factory.CommandsBuilder`
            instance wrapping the tool command.
        plan: The staging plan describing inputs/outputs for this job.
        service_url: Base URL of the runner-side re-encryption service.
    """
    pre = build_crypt4gh_pre_commands(
        plan,
        helper_path=helper_path,
        service_url=service_url,
        compute_private_key_path=compute_private_key_path,
    )
    if pre:
        commands_builder.prepend_command(pre)

    post = build_crypt4gh_post_commands(plan, helper_path=helper_path, service_url=service_url)
    if post:
        commands_builder.append_command(post)


def inject_crypt4gh_staging_commands(
    commands_builder,
    job_wrapper,
    local_working_directory: str,
    remote_working_directory: Optional[str] = None,
    remote_script_directory: Optional[str] = None,
    compute_environment=None,
) -> None:
    """Build a staging plan and inject crypt4gh shell fragments when needed."""
    plan_working_directory = remote_working_directory or local_working_directory
    plan = build_staging_plan(
        job_wrapper,
        working_directory=plan_working_directory,
        compute_environment=compute_environment,
    )
    if not plan.has_crypt4gh_work:
        return

    local_helper_path = _ensure_helper_script(local_working_directory)
    local_manifest_path = os.path.join(local_working_directory, os.path.basename(plan.manifest_path))
    write_plan = type(plan)(
        job_id=plan.job_id,
        working_directory=plan.working_directory,
        staging_directory=plan.staging_directory,
        manifest_path=local_manifest_path,
        input_entries=plan.input_entries,
        output_entries=plan.output_entries,
    )
    write_staging_manifest(write_plan)
    service_url = _get_service_url(job_wrapper)
    compute_private_key_path = _get_compute_private_key_path(job_wrapper)
    helper_path = _remote_or_local_path(local_helper_path, remote_script_directory)
    manifest_path = _remote_or_local_path(local_manifest_path, remote_script_directory)
    remote_plan = type(plan)(
        job_id=plan.job_id,
        working_directory=plan.working_directory,
        staging_directory=plan.staging_directory,
        manifest_path=manifest_path,
        input_entries=plan.input_entries,
        output_entries=plan.output_entries,
    )
    inject_crypt4gh_commands(
        commands_builder,
        remote_plan,
        helper_path=helper_path,
        service_url=service_url,
        compute_private_key_path=compute_private_key_path,
    )


__all__ = (
    "build_crypt4gh_post_commands",
    "build_crypt4gh_pre_commands",
    "inject_crypt4gh_commands",
    "inject_crypt4gh_staging_commands",
)
