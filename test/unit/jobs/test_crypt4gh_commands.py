"""Unit tests for crypt4gh pre/post command building."""

import pytest

import galaxy.jobs.crypt4gh_commands as commands_mod
from galaxy.job_execution.crypt4gh import (
    Crypt4GHInputEntry,
    Crypt4GHOutputEntry,
    Crypt4GHStagingPlan,
)
from galaxy.jobs.command_factory import CommandsBuilder
from galaxy.jobs.crypt4gh_commands import (
    build_crypt4gh_post_commands,
    build_crypt4gh_pre_commands,
    inject_crypt4gh_commands,
)

_SERVICE_URL = "http://127.0.0.1:47419"
_HELPER_PATH = "/tmp/job/crypt4gh_staging_helper.py"

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_input_plan(staging_dir="/tmp/job/crypt4gh_staging", manifest_path="/tmp/job/crypt4gh_manifest.json"):
    return Crypt4GHStagingPlan(
        job_id=1,
        working_directory="/tmp/job",
        staging_directory=staging_dir,
        manifest_path=manifest_path,
        input_entries=[
            Crypt4GHInputEntry(
                dataset_id=1,
                dataset_uuid="uuid-1",
                encrypted_path="/data/1.crypt4gh",
                staged_path=f"{staging_dir}/input_1.fastqsanger",
                header_b64="AAAA",
                inner_ext="fastqsanger",
            )
        ],
    )


def _make_output_plan(staging_dir="/tmp/job/crypt4gh_staging", manifest_path="/tmp/job/crypt4gh_manifest.json"):
    return Crypt4GHStagingPlan(
        job_id=1,
        working_directory="/tmp/job",
        staging_directory=staging_dir,
        manifest_path=manifest_path,
        output_entries=[
            Crypt4GHOutputEntry(
                dataset_id=2,
                dataset_uuid="uuid-2",
                staged_path=f"{staging_dir}/output_2.fastqsanger",
                final_path="/data/outputs/2.dat",
                inner_ext="fastqsanger",
                should_encrypt=True,
            )
        ],
    )


def _make_full_plan():
    plan = _make_input_plan()
    plan.output_entries = _make_output_plan().output_entries
    return plan


# ── build_crypt4gh_pre_commands ───────────────────────────────────────────────


class TestBuildCrypt4GHPreCommands:
    def test_returns_none_when_no_inputs(self):
        plan = _make_output_plan()
        assert build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL) is None

    def test_creates_staging_directory(self):
        plan = _make_input_plan()
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "mkdir" in cmd
        assert plan.staging_directory in cmd

    def test_calls_service_stage_inputs_endpoint(self):
        plan = _make_input_plan()
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "GALAXY_PYTHON" in cmd
        assert "PYTHONPATH" not in cmd
        assert _HELPER_PATH in cmd
        assert "stage-inputs" in cmd
        assert _SERVICE_URL in cmd

    def test_manifest_path_in_pre_command(self):
        plan = _make_input_plan()
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert plan.manifest_path in cmd
        assert "manifest_path" not in cmd

    def test_no_secrets_in_pre_commands(self):
        plan = _make_input_plan()
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "private" not in cmd.lower()
        assert "passphrase" not in cmd.lower()
        assert "secret" not in cmd.lower()

    def test_raises_when_no_service_url(self):
        plan = _make_input_plan()
        with pytest.raises(ValueError, match="crypt4gh_reencryption_service_url"):
            build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=None)

    def test_custom_service_url_used(self):
        plan = _make_input_plan()
        custom_url = "http://key-vault.internal:9000"
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=custom_url)
        assert cmd is not None
        assert custom_url in cmd

    def test_failure_handler_in_pre_command(self):
        """The shell fragment must exit non-zero on curl failure."""
        plan = _make_input_plan()
        cmd = build_crypt4gh_pre_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "exit $rc" in cmd
        assert "./outputs/tool_stdout" in cmd
        assert "./outputs/tool_stderr" in cmd
        assert "stage-inputs failed (exit $rc)" in cmd


# ── build_crypt4gh_post_commands ──────────────────────────────────────────────


class TestBuildCrypt4GHPostCommands:
    def test_returns_none_when_no_outputs(self):
        plan = _make_input_plan()
        assert build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL) is None

    def test_calls_service_stage_outputs_endpoint(self):
        plan = _make_output_plan()
        cmd = build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "GALAXY_PYTHON" in cmd
        assert _HELPER_PATH in cmd
        assert "stage-outputs" in cmd
        assert _SERVICE_URL in cmd

    def test_manifest_path_in_post_command(self):
        plan = _make_output_plan()
        cmd = build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert plan.manifest_path in cmd
        assert "manifest_path" not in cmd

    def test_cleans_up_staging_directory(self):
        plan = _make_output_plan()
        cmd = build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "rm" in cmd
        assert plan.staging_directory in cmd

    def test_no_secrets_in_post_commands(self):
        plan = _make_output_plan()
        cmd = build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "private" not in cmd.lower()
        assert "passphrase" not in cmd.lower()
        assert "secret" not in cmd.lower()

    def test_raises_when_no_service_url(self):
        plan = _make_output_plan()
        with pytest.raises(ValueError, match="crypt4gh_reencryption_service_url"):
            build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=None)

    def test_failure_handler_in_post_command(self):
        """The shell fragment must exit non-zero on curl failure."""
        plan = _make_output_plan()
        cmd = build_crypt4gh_post_commands(plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        assert cmd is not None
        assert "exit $rc" in cmd
        assert "./outputs/tool_stdout" in cmd
        assert "./outputs/tool_stderr" in cmd
        assert "stage-outputs failed (exit $rc)" in cmd


# ── inject_crypt4gh_commands ──────────────────────────────────────────────────


class TestInjectCrypt4GHCommands:
    def test_decrypt_before_tool_encrypt_after(self):
        plan = _make_full_plan()
        builder = CommandsBuilder("my_tool --input input.fastq --output output.fastq")
        inject_crypt4gh_commands(builder, plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        result = builder.build()

        decrypt_pos = result.index("stage-inputs")
        tool_pos = result.index("my_tool")
        encrypt_pos = result.index("stage-outputs")
        cleanup_pos = result.index("rm -rf")

        assert decrypt_pos < tool_pos
        assert tool_pos < encrypt_pos
        assert encrypt_pos < cleanup_pos

    def test_no_injection_when_no_crypt4gh_work(self):
        plan = Crypt4GHStagingPlan(
            job_id=1,
            working_directory="/tmp/job",
            staging_directory="/tmp/job/crypt4gh_staging",
            manifest_path="/tmp/job/crypt4gh_manifest.json",
        )
        tool_cmd = "my_tool --input x --output y"
        builder = CommandsBuilder(tool_cmd)
        inject_crypt4gh_commands(builder, plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        result = builder.build()
        assert "stage-inputs" not in result
        assert "stage-outputs" not in result

    def test_only_pre_injected_when_input_only(self):
        plan = _make_input_plan()
        builder = CommandsBuilder("tool_cmd")
        inject_crypt4gh_commands(builder, plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        result = builder.build()
        assert "stage-inputs" in result
        assert "stage-outputs" not in result

    def test_only_post_injected_when_output_only(self):
        plan = _make_output_plan()
        builder = CommandsBuilder("tool_cmd")
        inject_crypt4gh_commands(builder, plan, helper_path=_HELPER_PATH, service_url=_SERVICE_URL)
        result = builder.build()
        assert "stage-inputs" not in result
        assert "stage-outputs" in result


class TestInjectCrypt4GHStagingCommands:
    def test_uses_remote_script_paths_for_helper_and_manifest(self, monkeypatch):
        written = {}

        plan = _make_input_plan(
            staging_dir="/remote/job/crypt4gh_staging", manifest_path="/remote/job/crypt4gh_manifest.json"
        )

        def fake_build_staging_plan(*args, **kwargs):
            return plan

        def fake_write_staging_manifest(write_plan):
            written["manifest_path"] = write_plan.manifest_path
            written["staging_directory"] = write_plan.staging_directory

        monkeypatch.setattr(commands_mod, "build_staging_plan", fake_build_staging_plan)
        monkeypatch.setattr(commands_mod, "write_staging_manifest", fake_write_staging_manifest)
        monkeypatch.setattr(commands_mod, "_ensure_helper_script", lambda _wd: "/local/job/crypt4gh_staging_helper.py")
        monkeypatch.setattr(commands_mod, "_get_service_url", lambda _jw: _SERVICE_URL)

        builder = CommandsBuilder("tool_cmd")
        commands_mod.inject_crypt4gh_staging_commands(
            builder,
            job_wrapper=object(),
            local_working_directory="/local/job",
            remote_working_directory="/remote/job",
            remote_script_directory="/remote/job",
        )

        result = builder.build()
        assert '"$GALAXY_PYTHON" /remote/job/crypt4gh_staging_helper.py' in result
        assert "/remote/job/crypt4gh_manifest.json" in result
        assert written["manifest_path"] == "/local/job/crypt4gh_manifest.json"
        assert written["staging_directory"] == "/remote/job/crypt4gh_staging"
