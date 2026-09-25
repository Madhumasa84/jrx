"""Pluggable signing interface for policy files and audit decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


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

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify the signature using Ed25519."""
        try:
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key_obj.verify(signature, data)
            return True
        except (ValueError, InvalidSignature):
            return False

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in raw format."""
        return self.public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    def get_public_key_pem(self) -> str:
        """Get the public key in PEM format."""
        return self.public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def get_private_key_pem(self) -> str:
        """Get the private key in PEM format."""
        return self.private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
        ).decode()


class CosignSigner:
    """Cosign signer that shells out to the cosign CLI tool."""

    def __init__(self, private_key_path: Path | None = None) -> None:
        """Initialize the signer with a private key.

        Args:
            private_key_path: Path to the private key file (for cosign key reference).
        """
        self.private_key_path = private_key_path

    def sign(self, data: bytes) -> bytes:
        """Sign the given data using cosign."""
        raise NotImplementedError(
            "CosignSigner.sign is not yet implemented. Please use Ed25519Signer for now."
        )

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify the signature using cosign."""
        raise NotImplementedError(
            "CosignSigner.verify is not yet implemented. Please use Ed25519Signer for now."
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

    # Try to load as PEM first
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

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
