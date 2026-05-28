"""Integration tests for crypt4gh transparent staging."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests

from galaxy_test.base.populators import (
    DatasetPopulator,
    skip_without_tool,
)
from galaxy_test.driver import integration_util

# Configuration for the crypt4gh_reencryptor service
REENCRYPTOR_HOST = "127.0.0.1"
REENCRYPTOR_PORT = 9987
REENCRYPTOR_BASE_URL = f"http://{REENCRYPTOR_HOST}:{REENCRYPTOR_PORT}"

# Galaxy functional test user email used for dataset ownership.
# The re-encryptor must have keys for this owner or rewrap_for_compute fails.
GALAXY_TEST_USER_EMAIL = "user@bx.psu.edu"

# crypt4gh file magic bytes
CRYPT4GH_MAGIC = b"crypt4gh"

# Repository root (two levels up from test/integration/)
GALAXY_REPO_DIR = Path(__file__).parent.parent.parent


class Crypt4GHServiceMockManager:
    """Manages the lifecycle of the mock crypt4gh_reencryptor service."""

    def __init__(self, temp_dir: Path, galaxy_repo_dir: Path):
        self.temp_dir = temp_dir
        self.galaxy_repo_dir = galaxy_repo_dir
        self.process: Optional[subprocess.Popen] = None
        self.service_ready = False

    def _env(self) -> dict:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.galaxy_repo_dir)
        return env

    def initialize(self, user_email: str = GALAXY_TEST_USER_EMAIL) -> None:
        """Initialize compute + user keypair for *user_email*."""
        cmd = [
            sys.executable,
            "-m",
            "scripts.crypt4gh_reencryptor",
            "init",
            "--user-email",
            user_email,
        ]
        result = subprocess.run(cmd, cwd=str(self.temp_dir), capture_output=True, text=True, env=self._env())
        if result.returncode != 0:
            raise RuntimeError(f"Failed to initialize crypt4gh service: {result.stderr}")

    def start(self) -> None:
        """Start the reencryptor service and wait for it to be ready."""
        cmd = [
            sys.executable,
            "-m",
            "scripts.crypt4gh_reencryptor",
            "serve",
            "--host",
            REENCRYPTOR_HOST,
            "--port",
            str(REENCRYPTOR_PORT),
        ]
        self.process = subprocess.Popen(
            cmd,
            cwd=str(self.temp_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self._env(),
        )
        self._wait_for_service()

    def _wait_for_service(self, timeout: int = 30) -> None:
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if requests.get(f"{REENCRYPTOR_BASE_URL}/health", timeout=2).status_code == 200:
                    self.service_ready = True
                    return
            except requests.RequestException:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"Crypt4GH service did not become ready within {timeout}s")

    def encrypt_dataset(self, input_path: Path, output_path: Path, user_email: str = GALAXY_TEST_USER_EMAIL) -> None:
        """Encrypt *input_path* with the user public key → *output_path*."""
        cmd = [
            sys.executable,
            "-m",
            "scripts.crypt4gh_reencryptor",
            "encrypt-dataset",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--user-email",
            user_email,
        ]
        result = subprocess.run(cmd, cwd=str(self.temp_dir), capture_output=True, text=True, env=self._env())
        if result.returncode != 0:
            raise RuntimeError(f"Failed to encrypt dataset: {result.stderr}")

    def stop(self) -> None:
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.service_ready = False


class Crypt4GHServiceMixin:
    """Shared one-time setup/teardown for the crypt4gh reencryptor mock service.

    Subclasses must also inherit from ``IntegrationTestCase`` and call
    ``super().setUpClass()`` / ``super().tearDownClass()`` appropriately.
    """

    service_manager: Optional[Crypt4GHServiceMockManager] = None
    temp_service_dir: Optional[Path] = None

    @classmethod
    def _start_crypt4gh_service(cls, prefix: str = "crypt4gh_test_") -> None:
        """Create the temp directory, initialize, and start the service.

        On failure the temporary directory is cleaned up so nothing leaks.
        """
        tmp = Path(tempfile.mkdtemp(prefix=prefix))
        try:
            mgr = Crypt4GHServiceMockManager(tmp, GALAXY_REPO_DIR)
            mgr.initialize()
            mgr.start()
            cls.service_manager = mgr
            cls.temp_service_dir = tmp
        except Exception:
            # Clean up the temp dir so it doesn't leak on startup failure.
            shutil.rmtree(tmp, ignore_errors=True)
            raise

    @classmethod
    def _stop_crypt4gh_service(cls) -> None:
        """Stop the service and remove the temporary directory."""
        if cls.service_manager:
            cls.service_manager.stop()
            cls.service_manager = None
        if cls.temp_service_dir:
            shutil.rmtree(cls.temp_service_dir, ignore_errors=True)
            cls.temp_service_dir = None


class TestCrypt4GHE2ETransparentStaging(Crypt4GHServiceMixin, integration_util.IntegrationTestCase):
    """End-to-end test: encrypted input → transparent tool execution → encrypted output.

    Validates:
    1. Tool runs transparently on an encrypted dataset without modification.
    2. Metadata is generated on plaintext during staging.
    3. Output is re-encrypted with the correct inner datatype.
    4. No unencrypted payload is accessible via the Galaxy API.
    """

    dataset_populator: DatasetPopulator

    @classmethod
    def handle_galaxy_config_kwds(cls, config):
        super().handle_galaxy_config_kwds(config)
        config["enable_crypt4gh_transparent_staging"] = True
        config["crypt4gh_reencryption_service_url"] = REENCRYPTOR_BASE_URL

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._start_crypt4gh_service(prefix="crypt4gh_e2e_")

    def setUp(self):
        super().setUp()
        self.dataset_populator = DatasetPopulator(self.galaxy_interactor)

    @classmethod
    def tearDownClass(cls):
        cls._stop_crypt4gh_service()
        super().tearDownClass()

    def _encrypt_input(self, test_data_filename: str) -> tuple[Path, Path]:
        """Encrypt a resolved test-data file and return (plaintext, encrypted) paths."""
        plaintext_path = Path(self.test_data_resolver.get_filename(test_data_filename))

        encrypted_dir = Path(tempfile.mkdtemp(prefix="crypt4gh_encrypt_"))
        encrypted_path = encrypted_dir / f"{plaintext_path.name}.crypt4gh"

        assert self.service_manager is not None
        self.service_manager.encrypt_dataset(plaintext_path, encrypted_path)
        return plaintext_path, encrypted_path

    def _upload_encrypted_dataset(self, history_id: str, test_data_filename: str) -> tuple[str, Path]:
        """Upload an encrypted test-data file and return (dataset_id, encrypted_path)."""
        _, encrypted_path = self._encrypt_input(test_data_filename)
        with open(encrypted_path, "rb") as fh:
            hda = self.dataset_populator.new_dataset(
                history_id,
                content=fh,
                name=encrypted_path.name,
                file_type="auto",
                auto_decompress=False,
                to_posix_lines=False,
                wait=True,
            )
        return hda["id"], encrypted_path

    def _assert_crypt4gh_dataset(self, history_id: str, dataset_id: str, inner_ext: Optional[str] = None) -> dict:
        """Assert dataset is crypt4gh-wrapped and optionally check expected inner type."""
        dataset_details = self.dataset_populator.get_history_dataset_details(history_id, dataset_id=dataset_id)
        extension = dataset_details["extension"]
        assert "crypt4gh" in extension, f"Expected crypt4gh wrapper extension, got {extension!r}"
        if inner_ext is not None:
            assert dataset_details["metadata_crypt4gh_inner_ext"] == inner_ext
        assert dataset_details["metadata_crypt4gh_header"] != ""

        raw_response = self.galaxy_interactor.get(f"datasets/{dataset_id}/display")
        assert raw_response.status_code == 200
        assert raw_response.content[:8] == CRYPT4GH_MAGIC, "BAM output was not crypt4gh-encrypted"
        return dataset_details

    def _wait_for_job_ok(self, job_id: str) -> dict:
        """Wait for a job and assert successful final state."""
        self.dataset_populator.wait_for_job(job_id, assert_ok=True)
        job = self.dataset_populator.get_job_details(job_id, full=True).json()
        assert job["state"] == "ok", f"Job failed: {job.get('stderr', '')}"
        return job

    @skip_without_tool("cat1")
    def test_transparent_staging_cases(self):
        """cat1 should transparently process encrypted inputs and re-encrypt outputs.

        Cases cover:
        - fastqsanger input/output wrapping and metadata propagation
        - bam output re-encryption with inner datatype preservation
        - plaintext leak prevention for text content
        """
        cases = [
            ("1.fastqsanger", "fastqsanger", "fastqsanger", None),
            ("3.bam", None, "bam", None),
            ("simple_line.txt", None, None, b"This is a line of text."),
        ]

        for test_data_filename, input_inner_ext, output_inner_ext, forbidden_plaintext in cases:
            history_id = self.dataset_populator.new_history()
            dataset_id, encrypted_path = self._upload_encrypted_dataset(history_id, test_data_filename)
            try:
                self._assert_crypt4gh_dataset(history_id, dataset_id, inner_ext=input_inner_ext)

                response = self.dataset_populator.run_tool(
                    "cat1",
                    {"input1": {"src": "hda", "id": dataset_id}},
                    history_id,
                    assert_ok=True,
                )
                job_id = response["jobs"][0]["id"]
                self._wait_for_job_ok(job_id)

                output_id = response["outputs"][0]["id"]
                output_details = self._assert_crypt4gh_dataset(history_id, output_id, inner_ext=output_inner_ext)
                output_ext = output_details["extension"]
                assert "crypt4gh" in output_ext, f"Expected crypt4gh wrapper extension, got {output_ext!r}"

                if forbidden_plaintext is not None:
                    raw = self.galaxy_interactor.get(f"datasets/{output_id}/display")
                    assert raw.status_code == 200
                    assert forbidden_plaintext not in raw.content, "Plaintext payload leaked in output download"
            except AssertionError as exc:
                raise AssertionError(f"Case failed for test_data_filename={test_data_filename!r}: {exc}") from exc
            finally:
                shutil.rmtree(encrypted_path.parent, ignore_errors=True)
