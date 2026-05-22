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

import shlex
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

# curl timeout in seconds for each service call (per-request wall clock limit)
_STAGE_INPUTS_TIMEOUT = 120
_STAGE_OUTPUTS_TIMEOUT = 300


def _get_service_url(job_wrapper) -> Optional[str]:
    """Return the re-encryption service URL from Galaxy config, or None."""
    config = getattr(getattr(job_wrapper, "app", None), "config", None)
    if config is not None:
        return getattr(config, "crypt4gh_reencryption_service_url", None)
    return None


def _curl_service_call(service_url: str, endpoint: str, manifest_path: str, timeout: int) -> str:
    """Build a shell curl command that POSTs manifest JSON content to an endpoint.

    Fails loudly (non-zero exit, message to stderr) if curl returns a non-2xx
    status or cannot connect.  Galaxy never passes private keys here.
    """
    url = service_url.rstrip("/") + "/" + endpoint.lstrip("/")
    safe_manifest_arg = shlex.quote("@" + manifest_path)
    return (
        f"curl -sf --max-time {timeout} -X POST {shlex.quote(url)}"
        f' -H "Content-Type: application/json"'
        f" --data-binary {safe_manifest_arg}"
        f' || {{ echo "[crypt4gh] {endpoint} failed" >&2; exit 1; }}'
    )


def build_crypt4gh_pre_commands(
    plan: "Crypt4GHStagingPlan",
    service_url: Optional[str] = None,
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

    curl_cmd = _curl_service_call(service_url, "stage-inputs", manifest_path, _STAGE_INPUTS_TIMEOUT)
    lines = [
        f"mkdir -p {shlex.quote(staging_dir)}",
        curl_cmd,
    ]
    return "; ".join(lines)


def build_crypt4gh_post_commands(
    plan: "Crypt4GHStagingPlan",
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

    curl_cmd = _curl_service_call(service_url, "stage-outputs", manifest_path, _STAGE_OUTPUTS_TIMEOUT)
    lines = [
        curl_cmd,
        f"rm -rf {shlex.quote(staging_dir)}",
    ]
    return "; ".join(lines)


def inject_crypt4gh_commands(
    commands_builder,
    plan: "Crypt4GHStagingPlan",
    service_url: Optional[str] = None,
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
    pre = build_crypt4gh_pre_commands(plan, service_url=service_url)
    if pre:
        commands_builder.prepend_command(pre)

    post = build_crypt4gh_post_commands(plan, service_url=service_url)
    if post:
        commands_builder.append_command(post)


def inject_crypt4gh_staging_commands(commands_builder, job_wrapper, working_directory: str) -> None:
    """Build a staging plan and inject crypt4gh shell fragments when needed."""
    plan = build_staging_plan(job_wrapper, working_directory=working_directory)
    if not plan.has_crypt4gh_work:
        return

    write_staging_manifest(plan)
    service_url = _get_service_url(job_wrapper)
    inject_crypt4gh_commands(commands_builder, plan, service_url=service_url)


__all__ = (
    "build_crypt4gh_post_commands",
    "build_crypt4gh_pre_commands",
    "inject_crypt4gh_commands",
    "inject_crypt4gh_staging_commands",
)
