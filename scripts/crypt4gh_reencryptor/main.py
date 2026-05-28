"""Rich CLI for the mock Crypt4GH re-encryptor service.

This CLI supports the following tasks:
1. Initialize the service with a compute keypair and an initial user keypair.
2. Run the FastAPI service.
3. Encrypt test datasets.
4. Decrypt test datasets.
5. Register users with their Crypt4GH keypairs.

How to run this CLI:
1. Initialize keys:
    python -m scripts.crypt4gh_reencryptor init --user-email user@example.com
2. Start the service:
    python -m scripts.crypt4gh_reencryptor serve
3. Encrypt a test dataset:
    python -m scripts.crypt4gh_reencryptor encrypt-dataset --input plaintext.txt
4. Decrypt a test dataset:
    python -m scripts.crypt4gh_reencryptor decrypt-dataset --input plaintext.txt.crypt4gh
5. Register additional users:
    python -m scripts.crypt4gh_reencryptor register-user --user-email another@example.com
"""

import importlib
import logging
from pathlib import Path

import crypt4gh.keys
import crypt4gh.keys.c4gh
import crypt4gh.lib
import httpx
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

try:
    click = importlib.import_module("rich_click")
except ImportError:  # pragma: no cover - fallback for minimal environments
    click = importlib.import_module("click")

from .keys import get_registry

DEFAULT_KEYS_DIR = Path(".crypt4gh-reencryptor")
DEFAULT_COMPUTE_KEY = DEFAULT_KEYS_DIR / "compute.sec"

console = Console()


def _setup_logging(log_level: str) -> logging.Logger:
    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    return logging.getLogger("crypt4gh_reencryptor")


def _run_server(host: str, port: int, compute_key: str | None, log_level: str, reload: bool) -> None:
    log = _setup_logging(log_level)

    compute_key_source: str | None = None
    if compute_key is None and DEFAULT_COMPUTE_KEY.exists():
        compute_key = str(DEFAULT_COMPUTE_KEY)
        compute_key_source = "default"

    if not compute_key:
        raise click.ClickException(
            "No compute key found. Run 'python -m scripts.crypt4gh_reencryptor init' first or provide --compute-key."
        )

    if compute_key_source is None:
        compute_key_source = "--compute-key"
    registry = get_registry()
    try:
        # Suppress verbose crypt4gh key-loading logs (KDF, Ciphername, etc.)
        logging.getLogger("crypt4gh.keys").setLevel(logging.WARNING)
        logging.getLogger("crypt4gh.keys.c4gh").setLevel(logging.WARNING)
        registry.load_compute_keypair(compute_key)
    except Exception as exc:
        log.error("Failed to load compute keypair: %s", exc)
        raise click.ClickException(str(exc))

    # Auto-discover user keys from the keys directory
    user_emails: list[str] = []
    if DEFAULT_KEYS_DIR.exists():
        try:
            user_emails = registry.load_user_keys_from_dir(DEFAULT_KEYS_DIR)
        except Exception as exc:
            log.warning("Failed to load user keys from %s: %s", DEFAULT_KEYS_DIR, exc)

    if not user_emails:
        raise click.ClickException(
            "No registered users found. Run 'python -m scripts.crypt4gh_reencryptor init "
            "--user-email <email>' first or use 'register-user' to add one."
        )

    # Startup summary
    table = Table(title="Crypt4GH Re-encryptor Service", show_lines=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Host", host)
    table.add_row("Port", str(port))
    table.add_row("Log level", log_level)
    if compute_key_source:
        table.add_row("Compute key", f"{compute_key} ({compute_key_source})")
    else:
        table.add_row("Compute key", "[red]not configured (fallback mode)[/red]")
    if user_emails:
        user_emails_str = "\n".join(user_emails)
        table.add_row("Registered users", f"[yellow]{user_emails_str}[/yellow]")
    else:
        table.add_row("Registered users", "[red]none[/red]")
    console.print(table)

    uvicorn.run(
        "scripts.crypt4gh_reencryptor.app:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=reload,
    )


def _generate_keypair(prefix: Path, overwrite: bool = False) -> tuple[Path, Path]:
    """Generate a new Crypt4GH keypair (compute or user)."""
    sec_path = prefix.with_suffix(".sec")
    pub_path = prefix.with_suffix(".pub")
    if not overwrite and (sec_path.exists() or pub_path.exists()):
        raise click.ClickException(f"Refusing to overwrite existing keys at {prefix}")

    sec_path.parent.mkdir(parents=True, exist_ok=True)
    import contextlib
    import io

    # crypt4gh writes status messages to stderr; like "WARNING: The private key is not encrypted"
    # suppress those for cleaner CLI output
    with contextlib.redirect_stderr(io.StringIO()):
        crypt4gh.keys.c4gh.generate(
            str(sec_path),
            str(pub_path),
            passphrase=b"",
            comment=b"generated by crypt4gh_reencryptor",
        )
    return sec_path, pub_path


def _encrypt_file(input_path: Path, output_path: Path, recipient_public_key: bytes) -> None:
    """Encrypt a plaintext file with crypt4gh using a recipient public key."""
    import nacl.public as nacl_pub

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate ephemeral keypair for the sender
    ephemeral_sk_obj = nacl_pub.PrivateKey.generate()
    ephemeral_sk = bytes(ephemeral_sk_obj)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        crypt4gh.lib.encrypt(
            keys=[(0, ephemeral_sk, recipient_public_key)],
            infile=infile,
            outfile=outfile,
        )


def _decrypt_file(input_path: Path, output_path: Path, recipient_private_key: bytes) -> None:
    """Decrypt a crypt4gh encrypted file using a recipient private key."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        crypt4gh.lib.decrypt(
            keys=[(0, recipient_private_key, None)],
            infile=infile,
            outfile=outfile,
        )


@click.group(invoke_without_command=True)
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address for the FastAPI server.")
@click.option("--port", type=int, default=47419, show_default=True, help="Listen port for the FastAPI server.")
@click.option(
    "--compute-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to compute private key (.sec). Defaults to .crypt4gh-reencryptor/compute.sec if it exists.",
)
@click.option(
    "--log-level",
    default="info",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    show_default=True,
    help="Logging level for service logs.",
)
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (development only).")
@click.pass_context
def cli(ctx, host: str, port: int, compute_key: Path | None, log_level: str, reload: bool) -> None:
    """Mock Crypt4GH re-encryptor helper CLI.

    Running without a subcommand starts the FastAPI service.
    """
    if ctx.invoked_subcommand is None:
        _run_server(
            host=host,
            port=port,
            compute_key=str(compute_key) if compute_key else None,
            log_level=log_level.lower(),
            reload=reload,
        )


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address for the FastAPI server.")
@click.option("--port", type=int, default=47419, show_default=True, help="Listen port for the FastAPI server.")
@click.option(
    "--compute-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to compute private key (.sec). Defaults to .crypt4gh-reencryptor/compute.sec if it exists.",
)
@click.option(
    "--log-level",
    default="info",
    type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False),
    show_default=True,
    help="Logging level for service logs.",
)
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (development only).")
def serve(host: str, port: int, compute_key: Path | None, log_level: str, reload: bool) -> None:
    """Run the FastAPI re-encryptor service."""
    _run_server(
        host=host,
        port=port,
        compute_key=str(compute_key) if compute_key else None,
        log_level=log_level.lower(),
        reload=reload,
    )


def _user_key_prefix(keys_dir: Path, user_email: str) -> Path:
    """Derive a filesystem-safe key prefix from a user email."""
    safe_name = user_email.replace("@", "_at_").replace(".", "_")
    return keys_dir / f"user_{safe_name}"


@cli.command("init")
@click.option(
    "--keys-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=DEFAULT_KEYS_DIR,
    show_default=True,
    help="Directory where keypairs will be created.",
)
@click.option(
    "--user-email",
    default=None,
    help="Email for the initial user keypair. Prompted if not given and not --non-interactive.",
)
@click.option("--non-interactive", is_flag=True, default=False, help="Use defaults without interactive prompts.")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing key files.")
def init(keys_dir: Path, user_email: str | None, non_interactive: bool, overwrite: bool) -> None:
    """Initialize the service with a compute keypair and an initial user keypair.

    Generates the compute keypair (used by the service for re-encryption) and
    a user keypair tied to a Galaxy user email.  Additional users can be added
    later with 'register-user'.
    """
    console.print(Panel("[bold cyan]Crypt4GH Re-encryptor Setup[/bold cyan]", expand=False))

    keys_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Compute keypair
    console.print("\n[bold]Step 1:[/bold] Generating compute keypair...", end="")
    try:
        compute_sec, compute_pub = _generate_keypair(keys_dir / "compute", overwrite=overwrite)
    except click.ClickException:
        console.print(" [red]✗[/red]")
        raise
    console.print(" [green]✓[/green]")

    # Step 2: User keypair
    if user_email is None and not non_interactive:
        user_email = Prompt.ask("\n[bold]Step 2:[/bold] User email for initial keypair", default="user@example.com")

    user_sec: Path | None = None
    user_pub: Path | None = None

    if user_email:
        console.print(f"[bold]Step 2:[/bold] Generating user keypair for {user_email}...", end="")
        try:
            user_prefix = _user_key_prefix(keys_dir, user_email)
            user_sec, user_pub = _generate_keypair(user_prefix, overwrite=overwrite)
        except click.ClickException:
            console.print(" [red]✗[/red]")
            raise
        console.print(" [green]✓[/green]")
    else:
        console.print("\n[bold]Step 2:[/bold] Skipping user keypair (--non-interactive with no --user-email)")

    # Show generated keys
    table = Table(title="Generated Keys")
    table.add_column("Role", style="cyan")
    table.add_column("Private Key (.sec)", style="green")
    table.add_column("Public Key (.pub)", style="green")
    table.add_row("Compute", str(compute_sec), str(compute_pub))
    if user_sec and user_pub:
        table.add_row(f"User ({user_email})", str(user_sec), str(user_pub))
    console.print()
    console.print(table)

    # Show quick start guide
    console.print("\n[bold]Step 3:[/bold] Next steps")
    startup_commands = [
        "[cyan]1.[/cyan] Start the service:",
        "   python -m scripts.crypt4gh_reencryptor serve",
        "",
        "[cyan]2.[/cyan] Encrypt a test dataset:",
        "   python -m scripts.crypt4gh_reencryptor encrypt-dataset \\",
        "     --input plaintext.txt",
    ]
    if user_sec and user_pub:
        startup_commands += [
            "",
            "[cyan]3.[/cyan] Register additional users:",
            "   python -m scripts.crypt4gh_reencryptor register-user \\",
            "     --user-email another@example.com",
        ]
    else:
        startup_commands += [
            "",
            "[cyan]3.[/cyan] Register a user:",
            "   python -m scripts.crypt4gh_reencryptor register-user \\",
            "     --user-email user@example.com",
        ]
    console.print("\n".join(startup_commands))

    console.print(
        Panel(
            "[green]Setup complete![/green] Keys are ready in " + str(keys_dir),
            title="Ready",
            expand=False,
        )
    )


@cli.command("register-user")
@click.option(
    "--user-email",
    required=True,
    help="Galaxy user email address.",
)
@click.option(
    "--private-key",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to user private key (.sec). A new keypair is generated if not provided.",
)
@click.option(
    "--public-key",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to user public key (.pub). A new keypair is generated if not provided.",
)
@click.option(
    "--keys-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=DEFAULT_KEYS_DIR,
    show_default=True,
    help="Directory where generated keypairs will be stored.",
)
@click.option(
    "--service-url",
    default="http://127.0.0.1:47419",
    show_default=True,
    help="Re-encryptor API URL.",
)
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing key files.")
def register_user(
    user_email: str,
    private_key: Path | None,
    public_key: Path | None,
    keys_dir: Path,
    service_url: str,
    overwrite: bool,
) -> None:
    """Register a Galaxy user with their Crypt4GH keypair.

    If --private-key and --public-key are not provided, a new keypair is
    generated for the user and stored in the keys directory. The keypair is
    then registered with the running re-encryptor service.
    """
    if (private_key is None) != (public_key is None):
        raise click.ClickException("Provide both --private-key and --public-key, or neither to auto-generate.")

    if private_key is None:
        user_prefix = _user_key_prefix(keys_dir, user_email)
        console.print(f"[cyan]Generating keypair for {user_email}...[/cyan]", end="")
        try:
            private_key, public_key = _generate_keypair(user_prefix, overwrite=overwrite)
        except click.ClickException:
            console.print(" [red]✗[/red]")
            raise
        console.print(" [green]✓[/green]")

    try:
        private_key_hex = crypt4gh.keys.get_private_key(str(private_key), lambda: b"").hex()
        public_key_hex = crypt4gh.keys.get_public_key(str(public_key)).hex()
    except Exception as exc:
        raise click.ClickException(f"Failed to load keypair: {exc}")

    try:
        console.print(f"[cyan]Registering user {user_email}...[/cyan]", end="")
        resp = httpx.post(
            service_url.rstrip("/") + "/register-key",
            json={
                "user_email": user_email,
                "public_key_hex": public_key_hex,
                "private_key_hex": private_key_hex,
            },
            timeout=15,
        )
    except httpx.HTTPError as exc:
        console.print(" [red]✗[/red]")
        raise click.ClickException(f"Request failed: {exc}")

    if resp.status_code >= 400:
        console.print(" [red]✗[/red]")
        raise click.ClickException(f"Registration failed ({resp.status_code}): {resp.text}")

    console.print(" [green]✓[/green]")
    console.print(f"[green]Registered[/green] user {user_email}")


@cli.command("encrypt-dataset")
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to unencrypted input file.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path where encrypted file will be written. Defaults to <input>.crypt4gh.",
)
@click.option(
    "--user-email",
    default=None,
    help="Galaxy user email whose public key should be used. Resolved from the keys directory.",
)
@click.option(
    "--public-key",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to user public key file (.pub). Overrides --user-email if both are given.",
)
def encrypt_dataset(
    input_path: Path, output_path: Path | None, user_email: str | None, public_key: Path | None
) -> None:
    """Encrypt an unencrypted dataset file for use as test data.

    The resulting file can be used in manifest payloads for re-encryption testing.
    Specify --user-email to resolve the public key by email, or --public-key to
    provide the path directly. If neither is given, the first user key found in
    the keys directory is used.
    """
    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".crypt4gh")
    keys_dir = Path(".crypt4gh-reencryptor")
    if user_email is not None and public_key is None:
        # Resolve public key from user email
        public_key = _user_key_prefix(keys_dir, user_email).with_suffix(".pub")
        if not public_key.exists():
            raise click.ClickException(
                f"No public key found for {user_email!r} at {public_key}. "
                "Run 'init --user-email <email>' first or provide --public-key."
            )
    if public_key is None:
        user_keys = sorted(keys_dir.glob("user_*.pub"))
        if not user_keys:
            raise click.ClickException(
                "No --user-email or --public-key specified and no user key found in "
                f"{keys_dir}. Run 'init --user-email <email>' first or provide --public-key."
            )
        if len(user_keys) > 1:
            console.print(
                f"[yellow]Multiple user keys found, using {user_keys[0].name}.[/yellow] "
                "Use --user-email or --public-key to specify which one."
            )
        public_key = user_keys[0]

    try:
        recipient_public_key = crypt4gh.keys.get_public_key(str(public_key))
    except Exception as exc:
        raise click.ClickException(f"Failed to load public key from {public_key}: {exc}")

    try:
        console.print(f"[cyan]Encrypting {input_path.name}...[/cyan]", end="")
        _encrypt_file(input_path, output_path, recipient_public_key)
    except Exception as exc:
        console.print(" [red]✗[/red]")
        raise click.ClickException(f"Encryption failed: {exc}")
    console.print(" [green]✓[/green]")
    console.print(f"[green]Encrypted dataset:[/green] {output_path}")


@cli.command("decrypt-dataset")
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to encrypted input file.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path where decrypted file will be written. Defaults to <input> without .crypt4gh.",
)
@click.option(
    "--user-email",
    default=None,
    help="Galaxy user email whose private key should be used. Resolved from the keys directory.",
)
@click.option(
    "--private-key",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to user private key file (.sec). Overrides --user-email if both are given.",
)
def decrypt_dataset(
    input_path: Path, output_path: Path | None, user_email: str | None, private_key: Path | None
) -> None:
    """Decrypt a crypt4gh encrypted dataset file.

    The resulting file will be the plaintext version of the encrypted dataset.
    Specify --user-email to resolve the private key by email, or --private-key to
    provide the path directly. If neither is given, the first user key found in
    the keys directory is used.
    """
    if output_path is None:
        # Strip .crypt4gh suffix if present
        if input_path.suffix == ".crypt4gh":
            output_path = input_path.with_suffix("")
        else:
            output_path = input_path.with_suffix(input_path.suffix + ".decrypted")

    keys_dir = Path(".crypt4gh-reencryptor")
    if user_email is not None and private_key is None:
        # Resolve private key from user email
        private_key = _user_key_prefix(keys_dir, user_email).with_suffix(".sec")
        if not private_key.exists():
            raise click.ClickException(
                f"No private key found for {user_email!r} at {private_key}. "
                "Run 'init --user-email <email>' first or provide --private-key."
            )
    if private_key is None:
        user_keys = sorted(keys_dir.glob("user_*.sec"))
        if not user_keys:
            raise click.ClickException(
                "No --user-email or --private-key specified and no user key found in "
                f"{keys_dir}. Run 'init --user-email <email>' first or provide --private-key."
            )
        if len(user_keys) > 1:
            console.print(
                f"[yellow]Multiple user keys found, using {user_keys[0].name}.[/yellow] "
                "Use --user-email or --private-key to specify which one."
            )
        private_key = user_keys[0]

    try:
        recipient_private_key = crypt4gh.keys.get_private_key(str(private_key), lambda: b"")
    except Exception as exc:
        raise click.ClickException(f"Failed to load private key from {private_key}: {exc}")

    try:
        console.print(f"[cyan]Decrypting {input_path.name}...[/cyan]", end="")
        _decrypt_file(input_path, output_path, recipient_private_key)
    except Exception as exc:
        console.print(" [red]✗[/red]")
        raise click.ClickException(f"Decryption failed: {exc}")
    console.print(" [green]✓[/green]")
    console.print(f"[green]Decrypted dataset:[/green] {output_path}")


def main(argv=None) -> None:
    del argv
    cli(standalone_mode=True)


if __name__ == "__main__":
    main()
