"""Settings read from the environment (and the repo-root .env in local dev)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_dotenv(path: Path) -> None:
    """Local dev: load KEY=VALUE pairs from the repo-root .env without overriding real env vars."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    victim_url: str = "http://localhost:8000"
    executor_token: str = ""
    anthropic_api_key: str | None = None
    model: str = "claude-sonnet-5-5"
    poll_seconds: float = 2.0
    audit_path: str = "/tmp/centinela/audit.jsonl"
    audit_database_url: str | None = None  # Postgres; falls back to audit_path
    executor_database_url: str | None = None  # least-privilege role, case-2 actions
    office_cidr: str = "203.0.113.0/24"  # never blocked
    approver_token: str = ""  # when set, required to resolve approvals
    tts_voice: str = "es-CL-CatalinaNeural"  # Edge neural voice (fallback)
    eleven_labs_api_key: str = ""  # when set, ElevenLabs is the primary voice
    eleven_labs_voice_id: str = "6Gr4AVmTax1pMJO0lHRK"  # Catalina, Chilean
    eleven_labs_model: str = "eleven_flash_v2_5"
    # Google login (single shared demo org). Auth is "configured" only when all three
    # secrets are set; otherwise /dashboard stays open in demo mode (pitch fallback).
    google_client_id: str = ""
    google_client_secret: str = ""
    session_secret: str = ""
    public_url: str = ""  # behind Cloudflare+Render: builds the redirect URI
    # Bootstrap seed only: when the members table is empty these emails become the first admins.
    admin_emails: frozenset[str] = field(default_factory=frozenset)

    @property
    def auth_configured(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret and self.session_secret)

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv(REPO_ROOT / ".env")
        env = os.environ.get
        return cls(
            victim_url=env("VICTIM_URL", "http://localhost:8000"),
            executor_token=env("EXECUTOR_TOKEN", ""),
            anthropic_api_key=env("ANTHROPIC_API_KEY"),
            model=env("MODEL", "claude-sonnet-5-5"),
            poll_seconds=float(env("POLL_SECONDS", "2")),
            audit_path=env("AUDIT_PATH", "/tmp/centinela/audit.jsonl"),
            audit_database_url=env("AUDIT_DATABASE_URL"),
            executor_database_url=env("EXECUTOR_DATABASE_URL"),
            office_cidr=env("OFFICE_CIDR", "203.0.113.0/24"),
            approver_token=env("APPROVER_TOKEN", ""),
            tts_voice=env("TTS_VOICE", "es-CL-CatalinaNeural"),
            eleven_labs_api_key=env("ELEVEN_LABS_API_KEY", ""),
            eleven_labs_voice_id=env("ELEVEN_LABS_VOICE_ID", "6Gr4AVmTax1pMJO0lHRK"),
            eleven_labs_model=env("ELEVEN_LABS_MODEL", "eleven_flash_v2_5"),
            google_client_id=env("GOOGLE_CLIENT_ID", ""),
            google_client_secret=env("GOOGLE_CLIENT_SECRET", ""),
            session_secret=env("SESSION_SECRET", ""),
            public_url=env("PUBLIC_URL", "").rstrip("/"),
            admin_emails=frozenset(e.strip().lower() for e in env("ADMIN_EMAILS", "").split(",") if e.strip()),
        )
