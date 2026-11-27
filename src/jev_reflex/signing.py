"""Pluggable signing interface for policy files and audit decisions."""

from __future__ import annotations

import base64
import math
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ed25519


class Signer(Protocol):
    """Protocol for cryptographic signing and verification."""

    def sign(self, data: bytes) -> bytes:
        """Sign the given data and return the signature."""
        ...

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify that the signature matches the data using the public key."""
        ...


class Ed25519Signer:
    """Ed25519 signer using the cryptography library."""

    def __init__(self, private_key_path: Path | None = None) -> None:
        """Initialize the signer with a private key.

        Args:
            private_key_path: Path to the private key file. If None, generates a new keypair.
        """
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if private_key_path is None:
            # Generate a new keypair
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        else:
            # Load existing private key
            self.private_key = self._load_private_key(private_key_path)
            self.public_key = self.private_key.public_key()

    def _load_private_key(self, path: Path) -> ed25519.Ed25519PrivateKey:
        """Load a private key from a file."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        if not path.exists():
            raise FileNotFoundError(f"Private key file not found: {path}")

        with path.open("rb") as f:
            key_data = f.read()

        try:
            # Try PEM format first
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            private_key = load_pem_private_key(key_data, password=None)
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Key is not an Ed25519 private key")
            return private_key
        except Exception:
            # Try raw bytes format
            return ed25519.Ed25519PrivateKey.from_private_bytes(key_data)

    def sign(self, data: bytes) -> bytes:
        """Sign the given data using Ed25519."""
        signature = self.private_key.sign(data)
        return signature

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify the signature using only the supplied Ed25519 public key."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        try:
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key_obj.verify(signature, data)
            return True
        except (ValueError, InvalidSignature):
            return False

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in raw format."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self.public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    def get_public_key_pem(self) -> str:
        """Get the public key in PEM format."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self.public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def get_private_key_pem(self) -> str:
        """Get the private key in PEM format."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        return self.private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        ).decode()


class CosignSigner:
    """Local, detached key signatures using Cosign without public log uploads.

    Signatures are raw bytes, like Ed25519Signer. Cosign's base64 file format
    is converted at the CLI boundary. Keyless signing and bundles are separate
    protocols and are not used for private policy or audit data.
    """

    def __init__(
        self,
        private_key_path: Path | None = None,
        *,
        binary: str = "cosign",
        timeout: float = 30,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Cosign timeout must be positive and finite")
        self.private_key_path = (
            private_key_path.expanduser().resolve() if private_key_path else None
        )
        self.binary = binary
        self.timeout = timeout

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        from .context import sanitized_child_env

        try:
            # Callers supply fixed Cosign subcommands as an argument list.
            return subprocess.run(  # nosec B603
                [self.binary, *arguments],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=sanitized_child_env(),
                timeout=self.timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("Cosign is unavailable or exceeded its time limit") from None

    def sign(self, data: bytes) -> bytes:
        """Sign the given data using cosign."""
        if self.private_key_path is None:
            raise ValueError("Cosign signing requires a local private key")
        if not self.private_key_path.is_file():
            raise FileNotFoundError("Cosign private key file not found")
        with tempfile.TemporaryDirectory(prefix="jrx-cosign-") as directory:
            blob = Path(directory) / "blob"
            blob.write_bytes(data)
            result = self._run(
                [
                    "sign-blob",
                    "--key",
                    str(self.private_key_path),
                    "--yes",
                    "--tlog-upload=false",
                    "--use-signing-config=false",
                    "--new-bundle-format=false",
                    str(blob),
                ]
            )
            if result.returncode != 0:
                raise RuntimeError("Cosign signing failed")
            try:
                signature = base64.b64decode(result.stdout.strip(), validate=True)
            except ValueError:
                raise RuntimeError("Cosign returned an invalid signature") from None
            if not signature:
                raise RuntimeError("Cosign returned an empty signature")
            return signature

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a detached signature against a pinned key, entirely offline."""
        if not signature or not public_key:
            return False
        # load_public_key normalizes Ed25519 PEM keys to their 32 raw bytes.
        if len(public_key) == 32:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key).public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
        with tempfile.TemporaryDirectory(prefix="jrx-cosign-") as directory:
            root = Path(directory)
            (root / "blob").write_bytes(data)
            (root / "signature").write_bytes(base64.b64encode(signature))
            (root / "key.pem").write_bytes(public_key)
            return (
                self._run(
                    [
                        "verify-blob",
                        "--key",
                        str(root / "key.pem"),
                        "--signature",
                        str(root / "signature"),
                        "--offline",
                        "--insecure-ignore-tlog",
                        str(root / "blob"),
                    ]
                ).returncode
                == 0
            )


def load_public_key(public_key_path: Path) -> bytes:
    """Load a public key from a file.

    Args:
        public_key_path: Path to the public key file.

    Returns:
        The public key bytes.
    """
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key file not found: {public_key_path}")

    with public_key_path.open("rb") as f:
        key_data = f.read()

    return _public_key_bytes(key_data)


def verify_pinned_ed25519(data: bytes, signature: bytes, public_key_pem: str) -> bool:
    """Verify an Ed25519 signature against pinned PEM content, as remote fetches do."""
    return Ed25519Signer.verify(data, signature, _public_key_bytes(public_key_pem.encode()))


def _public_key_bytes(key_data: bytes) -> bytes:
    # Try to load as PEM first
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )

        public_key = load_pem_public_key(key_data)
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    except Exception:
        pass

    # Return raw bytes if PEM parsing fails
    return key_data


def sign_file(
    file_path: Path,
    signer: Signer,
    output_path: Path | None = None,
) -> Path:
    """Sign a file and write the signature to a .sig file.

    Args:
        file_path: Path to the file to sign.
        signer: Signer instance to use for signing.
        output_path: Optional path for the signature file. Defaults to file_path.sig.

    Returns:
        Path to the signature file.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File to sign not found: {file_path}")

    data = file_path.read_bytes()
    signature = signer.sign(data)

    if output_path is None:
        output_path = file_path.with_suffix(file_path.suffix + ".sig")

    output_path.write_bytes(signature)
    return output_path


def verify_file(
    file_path: Path,
    signature_path: Path,
    public_key: bytes,
    signer: Signer,
    *,
    data: bytes | None = None,
) -> bool:
    """Verify a file's signature.

    Args:
        file_path: Path to the file to verify.
        signature_path: Path to the signature file.
        public_key: Public key bytes for verification.
        signer: Signer instance to use for verification.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File to verify not found: {file_path}")

    if not signature_path.exists():
        raise FileNotFoundError(f"Signature file not found: {signature_path}")

    if data is None:
        data = file_path.read_bytes()
    signature = signature_path.read_bytes()

    return signer.verify(data, signature, public_key)
