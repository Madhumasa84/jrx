"""Tests for TLS transport with mutual authentication."""

import pytest

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
