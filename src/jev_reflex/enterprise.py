"""Verified OIDC identity and one-time, action-bound approvals."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import sqlite3
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

from .config import AccessConfig, ReflexConfig
from .redaction import redact_text


class AccessDenied(ValueError):
    """An identity, authorization, or approval check failed."""


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str]


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verified_identity(config: AccessConfig, token: str | None = None) -> Identity:
    """Validate a signed RS256 OIDC token from the host environment."""
    token = token if token is not None else os.environ.get("JRX_ID_TOKEN", "")
    if not token or len(token) > 16384:
        raise AccessDenied("A valid JRX_ID_TOKEN is required")
    try:
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = json.loads(_decode(encoded_header))
        claims = json.loads(_decode(encoded_claims))
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError("invalid token structure")
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError("unsupported token signature")
        response = requests.get(config.jwks_uri, timeout=5, allow_redirects=False)
        response.raise_for_status()
        key_set = response.json()
        keys = key_set.get("keys", []) if isinstance(key_set, dict) else []
        matches = [
            key
            for key in keys
            if isinstance(key, dict)
            and key.get("kid") == header["kid"]
            and key.get("kty") == "RSA"
            and key.get("alg", "RS256") == "RS256"
            and key.get("use", "sig") == "sig"
        ]
        if len(matches) != 1:
            raise ValueError("signing key unavailable")
        jwk = matches[0]
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_decode(jwk["e"]), "big"),
            int.from_bytes(_decode(jwk["n"]), "big"),
        ).public_key()
        if public_key.key_size < 2048:
            raise ValueError("signing key is too small")
        public_key.verify(
            _decode(encoded_signature),
            f"{encoded_header}.{encoded_claims}".encode("ascii"),
            padding.PKCS1v15(),
            SHA256(),
        )
        now = time.time()
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if claims.get("iss") != config.issuer or not isinstance(audiences, list):
            raise ValueError("issuer or audience invalid")
        if config.audience not in audiences or any(not isinstance(a, str) for a in audiences):
            raise ValueError("audience invalid")
        if len(audiences) > 1 and claims.get("azp") != config.audience:
            raise ValueError("authorized party invalid")
        if (
            not isinstance(claims.get("exp"), (int, float))
            or not math.isfinite(claims["exp"])
            or claims["exp"] <= now
        ):
            raise ValueError("token expired")
        if "nbf" in claims and (
            not isinstance(claims["nbf"], (int, float))
            or not math.isfinite(claims["nbf"])
            or claims["nbf"] > now
        ):
            raise ValueError("token not yet valid")
        if "iat" in claims and (
            not isinstance(claims["iat"], (int, float))
            or not math.isfinite(claims["iat"])
            or claims["iat"] > now + 60
        ):
            raise ValueError("token issued in the future")
        subject = claims.get("sub")
        roles = claims.get(config.roles_claim, [])
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise ValueError("subject invalid")
        if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
            raise ValueError("roles invalid")
        return Identity(subject=subject, roles=frozenset(roles))
    except (
        ValueError,
        binascii.Error,
        TypeError,
        KeyError,
        IndexError,
        InvalidSignature,
        requests.RequestException,
    ) as exc:
        raise AccessDenied("OIDC identity verification failed") from exc


def authorize(
    identity: Identity, config: AccessConfig, action: str, repository: str, environment: str
) -> None:
    if environment != config.environment:
        raise AccessDenied("Environment does not match the trusted access configuration")
    for rule in config.rules:
        if (
            rule.role in identity.roles
            and action in rule.actions
            and ("*" in rule.repositories or repository in rule.repositories)
            and ("*" in rule.environments or environment in rule.environments)
        ):
            return
    raise AccessDenied("Identity lacks permission for this repository and environment")


def _git(cwd: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise AccessDenied("A Git repository is required for action-bound approvals")
    return result.stdout


def action_binding(
    config: ReflexConfig, cwd: Path, argv: list[str], environment: str
) -> tuple[str, str]:
    """Bind approval to exact argv, Git state, effective policy, and environment."""
    root = Path(os.fsdecode(_git(cwd, "rev-parse", "--show-toplevel")).strip()).resolve()
    head = _git(root, "rev-parse", "HEAD").strip()
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    paths: set[str] = set()
    entries = status.split(b"\0")
    for entry in entries:
        if len(entry) >= 4:
            paths.add(os.fsdecode(entry[3:]))
    changed: dict[str, str] = {}
    for path in sorted(paths):
        candidate = root / path
        if candidate.is_symlink():
            changed[path] = f"symlink:{os.readlink(candidate)}"
        elif candidate.is_file():
            changed[path] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        else:
            changed[path] = "missing"
    payload = {
        "argv": argv,
        "cwd": str(cwd.resolve()),
        "repository": str(root),
        "head": head.decode("ascii"),
        "status": base64.b64encode(status).decode("ascii"),
        "changed": changed,
        "index": hashlib.sha256(_git(root, "diff", "--cached", "--binary")).hexdigest(),
        "environment": environment,
        "policy": config.model_dump(mode="json"),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return str(root), hashlib.sha256(canonical).hexdigest()


class ApprovalStore:
    def __init__(self, config: AccessConfig) -> None:
        self.config = config
        self.path = Path(config.approval_db).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _connect(self) -> sqlite3.Connection:
        if not self.path.exists():
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        details = self.path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
            or details.st_nlink != 1
        ):
            raise AccessDenied("Approval database must be a private, owned regular file")
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, requester TEXT NOT NULL, "
            "repository TEXT NOT NULL, environment TEXT NOT NULL, binding TEXT NOT NULL, "
            "summary TEXT NOT NULL, expires REAL NOT NULL, required INTEGER NOT NULL, "
            "consumed INTEGER NOT NULL DEFAULT 0)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS grants (approval_id TEXT NOT NULL, reviewer TEXT NOT NULL, "
            "granted REAL NOT NULL, PRIMARY KEY (approval_id, reviewer))"
        )
        return connection

    def request(
        self, identity: Identity, repository: str, environment: str, binding: str, summary: str
    ) -> str:
        if len(summary) > 1000 or redact_text(summary) != summary:
            raise AccessDenied("Approval command cannot be reviewed safely")
        approval_id = uuid.uuid4().hex
        required = 2 if environment in self.config.production_environments else 1
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    approval_id,
                    identity.subject,
                    repository,
                    environment,
                    binding,
                    summary,
                    time.time() + self.config.approval_ttl_seconds,
                    required,
                ),
            )
        return approval_id

    def pending(self, identity: Identity) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, requester, repository, environment, summary, expires, required "
                "FROM approvals WHERE consumed=0 AND expires>? ORDER BY expires",
                (time.time(),),
            ).fetchall()
            pending: list[dict[str, object]] = []
            for approval_id, requester, repository, environment, summary, expires, required in rows:
                if requester == identity.subject:
                    continue
                try:
                    authorize(identity, self.config, "review", repository, environment)
                except AccessDenied:
                    continue
                count = connection.execute(
                    "SELECT COUNT(*) FROM grants WHERE approval_id=?", (approval_id,)
                ).fetchone()[0]
                if count < required:
                    pending.append(
                        {
                            "id": approval_id,
                            "requester": requester,
                            "repository": repository,
                            "environment": environment,
                            "summary": summary,
                            "expires": expires,
                            "grants": count,
                            "required": required,
                        }
                    )
        return pending

    def grant(self, approval_id: str, identity: Identity) -> tuple[int, int]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT requester, repository, environment, expires, required, consumed "
                "FROM approvals WHERE id=?",
                (approval_id,),
            ).fetchone()
            if row is None or row[3] <= time.time() or row[5]:
                raise AccessDenied("Approval is missing, expired, or consumed")
            requester, repository, environment, _, required, _ = row
            authorize(identity, self.config, "review", repository, environment)
            if identity.subject == requester:
                raise AccessDenied("Requester cannot approve their own action")
            try:
                connection.execute(
                    "INSERT INTO grants VALUES (?, ?, ?)",
                    (approval_id, identity.subject, time.time()),
                )
            except sqlite3.IntegrityError as exc:
                raise AccessDenied("Reviewer has already approved this action") from exc
            count = connection.execute(
                "SELECT COUNT(*) FROM grants WHERE approval_id=?", (approval_id,)
            ).fetchone()[0]
        return count, required

    def consume(self, approval_id: str, identity: Identity, binding: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT requester, binding, expires, required, consumed FROM approvals WHERE id=?",
                (approval_id,),
            ).fetchone()
            if row is None or row[0] != identity.subject or row[1] != binding:
                raise AccessDenied("Approval does not match this requester or action")
            if row[2] <= time.time() or row[4]:
                raise AccessDenied("Approval is expired or already consumed")
            count = connection.execute(
                "SELECT COUNT(*) FROM grants WHERE approval_id=?", (approval_id,)
            ).fetchone()[0]
            if count < row[3]:
                raise AccessDenied("Approval is still waiting for reviewers")
            connection.execute("UPDATE approvals SET consumed=1 WHERE id=?", (approval_id,))
