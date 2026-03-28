"""
OTP seed management for SPA flow.
Reference implementation from Anchor project (server/code/vpn/otp.py).

In Sknock (Go):
  - Seeds stored in config file under [users.alice] otp_seed = "BASE32..."
    OR in a separate /etc/sknock/users.toml (mode 0600, root only)
  - No encryption at rest in v1 (no vault dependency); file permissions protect it
  - Go equivalent: github.com/pquerna/otp/totp
    totp.Validate(passcode, seed)  — validates with default 30s window
    totp.GenerateCode(seed, time.Now()) — generates current code (for client)
  - For user add: totp.Generate(totp.GenerateOpts{Issuer: "Sknock", AccountName: uid})
    → returns *otp.Key with Secret(), URL() (for QR)

pyotp reference (Python):
  pyotp.random_base32()           → generate seed
  pyotp.TOTP(seed).verify(code, valid_window=1)  → verify (±30s)
  pyotp.TOTP(seed).now()          → current code
  pyotp.totp.TOTP(seed).provisioning_uri(uid, issuer_name="Sknock")  → QR URL
"""
import pyotp


def generate_otp_seed() -> str:
    """Generate a new random TOTP seed (base32)."""
    return pyotp.random_base32()


def verify_otp(seed: str, otp_str: str) -> bool:
    """
    Validate a 6-digit TOTP code against the seed.
    valid_window=1 allows ±1 period (±30s) for clock skew.
    """
    if not seed:
        return False
    return bool(pyotp.TOTP(seed).verify(otp_str, valid_window=1))


def current_otp(seed: str) -> str:
    """Return the current TOTP code for a seed (used by the client)."""
    return pyotp.TOTP(seed).now()


def provisioning_url(seed: str, username: str, issuer: str = "Sknock") -> str:
    """Return an otpauth:// URL suitable for QR code generation."""
    return pyotp.totp.TOTP(seed).provisioning_uri(username, issuer_name=issuer)
