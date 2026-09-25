"""Tests for TLS transport with mutual authentication."""

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from jev_reflex.broker import BrokerClient, BrokerServer
from jev_reflex.config import BrokerTLSConfig, ReflexConfig


class TestTLSConfig:
    """Test TLS configuration validation."""

    def test_broker_tls_config_requires_all_fields(self) -> None:
        """Test that broker_tls config requires all certificate paths."""
        with pytest.raises(ValueError, match="broker_tls.cert_path is required"):
            BrokerTLSConfig(
                listen_addr="0.0.0.0:8443",
                cert_path="",
                key_path="/etc/jrx/server.key",
                client_ca_path="/etc/jrx/client-ca.crt",
            )

        with pytest.raises(ValueError, match="broker_tls.key_path is required"):
            BrokerTLSConfig(
                listen_addr="0.0.0.0:8443",
                cert_path="/etc/jrx/server.crt",
                key_path="",
                client_ca_path="/etc/jrx/client-ca.crt",
            )

        with pytest.raises(ValueError, match="broker_tls.client_ca_path is required"):
            BrokerTLSConfig(
                listen_addr="0.0.0.0:8443",
                cert_path="/etc/jrx/server.crt",
                key_path="/etc/jrx/server.key",
                client_ca_path="",
            )

    def test_broker_tls_config_validates_with_all_fields(self) -> None:
        """Test that broker_tls config validates with all required fields."""
        config = BrokerTLSConfig(
            listen_addr="0.0.0.0:8443",
            cert_path="/etc/jrx/server.crt",
            key_path="/etc/jrx/server.key",
            client_ca_path="/etc/jrx/client-ca.crt",
        )
        assert config.listen_addr == "0.0.0.0:8443"
        assert config.cert_path == "/etc/jrx/server.crt"
        assert config.key_path == "/etc/jrx/server.key"
        assert config.client_ca_path == "/etc/jrx/client-ca.crt"

    def test_jev_config_requires_broker_tls_for_broker_tls_transport(self) -> None:
        """Test that broker_tls config is required when transport='broker-tls'."""
        config = ReflexConfig()
        config.jev.transport = "broker-tls"
        config.jev.broker_tls = None

        with pytest.raises(
            ValueError, match="broker_tls configuration is required when transport='broker-tls'"
        ):
            # Trigger validation
            config.model_validate(config.model_dump())

    def test_valid_broker_tls_config_passes_validation(self) -> None:
        """Test that valid broker_tls config passes validation."""
        tls_config = BrokerTLSConfig(
            listen_addr="0.0.0.0:8443",
            cert_path="/etc/jrx/server.crt",
            key_path="/etc/jrx/server.key",
            client_ca_path="/etc/jrx/client-ca.crt",
        )

        config = ReflexConfig()
        config.jev.transport = "broker-tls"
        config.jev.broker_tls = tls_config

        # Should not raise
        validated = config.model_validate(config.model_dump())
        assert validated.jev.transport == "broker-tls"
        assert validated.jev.broker_tls is not None


class TestUnixSocketDefault:
    """Regression tests for unix-socket default behavior."""

    def test_default_transport_is_direct(self) -> None:
        """Test that default transport is 'direct' when not configured."""
        config = ReflexConfig()
        assert config.jev.transport == "direct"

    def test_broker_transport_uses_unix_socket_by_default(self) -> None:
        """Test that broker transport uses unix socket by default."""
        config = ReflexConfig()
        config.jev.transport = "broker"
        assert config.jev.socket == "~/.jev-reflex/reflex.sock"
        assert config.jev.broker_tls is None

    def test_unix_socket_path_expands_tilde(self) -> None:
        """Test that unix socket path expands tilde correctly."""
        from jev_reflex.broker import socket_path

        config = ReflexConfig()
        config.jev.transport = "broker"
        config.jev.socket = "~/.jev-reflex/reflex.sock"

        path = socket_path(config)
        assert str(path).startswith("/")
        assert not str(path).startswith("~")

    def test_broker_transport_without_tls_config_does_not_require_tls(self) -> None:
        """Test that broker transport without TLS config does not require TLS."""
        config = ReflexConfig()
        config.jev.transport = "broker"
        config.jev.broker_tls = None

        # Should not raise - broker transport without TLS is valid
        validated = config.model_validate(config.model_dump())
        assert validated.jev.transport == "broker"
        assert validated.jev.broker_tls is None


def _new_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_certificate(
    *,
    common_name: str,
    public_key: rsa.RSAPublicKey,
    issuer: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    is_ca: bool,
    extended_usage: ObjectIdentifier | None = None,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC).replace(tzinfo=None)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if not is_ca:
        names = [x509.DNSName(common_name)]
        if common_name == "localhost":
            names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if extended_usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([extended_usage]), critical=False)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


@pytest.mark.parametrize(
    "server_name,expected_running", [("localhost", True), ("other.example", False)]
)
def test_tls_broker_accepts_trusted_client_and_rejects_untrusted_client(
    tmp_path: Path,
    server_name: str,
    expected_running: bool,
) -> None:
    trusted_ca_key = _new_private_key()
    trusted_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JRX test CA")])
    trusted_ca = _make_certificate(
        common_name="JRX test CA",
        public_key=trusted_ca_key.public_key(),
        issuer=trusted_ca_name,
        issuer_key=trusted_ca_key,
        is_ca=True,
    )
    trusted_ca_path = tmp_path / "trusted-ca.pem"
    _write_certificate(trusted_ca_path, trusted_ca)

    rogue_ca_key = _new_private_key()
    rogue_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue test CA")])
    rogue_ca = _make_certificate(
        common_name="Rogue test CA",
        public_key=rogue_ca_key.public_key(),
        issuer=rogue_ca_name,
        issuer_key=rogue_ca_key,
        is_ca=True,
    )

    server_key = _new_private_key()
    server_certificate = _make_certificate(
        common_name=server_name,
        public_key=server_key.public_key(),
        issuer=trusted_ca.subject,
        issuer_key=trusted_ca_key,
        is_ca=False,
        extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    server_key_path = tmp_path / "server-key.pem"
    server_certificate_path = tmp_path / "server-cert.pem"
    _write_private_key(server_key_path, server_key)
    _write_certificate(server_certificate_path, server_certificate)

    client_key = _new_private_key()
    client_certificate = _make_certificate(
        common_name="trusted-client",
        public_key=client_key.public_key(),
        issuer=trusted_ca.subject,
        issuer_key=trusted_ca_key,
        is_ca=False,
        extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    client_key_path = tmp_path / "client-key.pem"
    client_certificate_path = tmp_path / "client-cert.pem"
    _write_private_key(client_key_path, client_key)
    _write_certificate(client_certificate_path, client_certificate)

    rogue_client_key = _new_private_key()
    rogue_client_certificate = _make_certificate(
        common_name="untrusted-client",
        public_key=rogue_client_key.public_key(),
        issuer=rogue_ca.subject,
        issuer_key=rogue_ca_key,
        is_ca=False,
        extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    rogue_client_key_path = tmp_path / "rogue-client-key.pem"
    rogue_client_certificate_path = tmp_path / "rogue-client-cert.pem"
    _write_private_key(rogue_client_key_path, rogue_client_key)
    _write_certificate(rogue_client_certificate_path, rogue_client_certificate)

    server_config = ReflexConfig(
        jev={
            "transport": "broker-tls",
            "broker_tls": {
                "listen_addr": "127.0.0.1:0",
                "cert_path": str(server_certificate_path),
                "key_path": str(server_key_path),
                "client_ca_path": str(trusted_ca_path),
            },
        }
    )
    service = BrokerServer(server_config, evaluator=object(), configured=True)

    async def exercise_mutual_tls() -> None:
        server = await service._start_tls_server()
        try:
            host, port = server.sockets[0].getsockname()[:2]

            def client_config(cert_path: Path, key_path: Path) -> ReflexConfig:
                return ReflexConfig(
                    jev={
                        "transport": "broker-tls",
                        "broker_tls": {
                            "listen_addr": f"{host}:{port}",
                            "cert_path": str(cert_path),
                            "key_path": str(key_path),
                            "client_ca_path": str(trusted_ca_path),
                        },
                    }
                )

            trusted_health = await asyncio.to_thread(
                BrokerClient(client_config(client_certificate_path, client_key_path)).health
            )
            untrusted_health = await asyncio.to_thread(
                BrokerClient(
                    client_config(rogue_client_certificate_path, rogue_client_key_path)
                ).health
            )

            assert trusted_health["running"] is expected_running
            assert trusted_health["jev_configured"] is expected_running
            assert untrusted_health["running"] is False
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(exercise_mutual_tls())
