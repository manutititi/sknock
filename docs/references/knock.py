"""
UDP Knock Listener — SPA v2 (Single Packet Authorization).
Reference implementation from Anchor project (server/code/vpn/knock.py).

NOTE FOR SKNOCK: This is the Anchor VPN-specific listener.
In Sknock the logic after ECIES decryption changes:
  - Instead of WireGuard peer registration, look up rule by spa.wg_pubkey (rule name)
  - Execute the rule's action with {ip}, {uid}, {timestamp} substitution
  - Nonce anti-replay stays identical (sync.Map with TTL in Go)
  - OTP verification stays identical (TOTP via pquerna/otp in Go)
  - Silent-drop semantics on every failure stay identical

Processing pipeline (same in Sknock):
  1. parse_packet() — ECIES decryption + timestamp validation
  2. Nonce anti-replay (unique index / sync.Map TTL)
  3. OTP verification via user's seed
  4. Rule lookup (in Sknock: by rule name from packet)
  5. User permission check for rule (allowed_users list)
  6. Action execution (shell command with variable substitution)
  7. Schedule undo_action after undo_after seconds (if configured)

Any failure at any step is a silent drop (no response to sender).
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from db.client import get_collection
from vpn.otp import verify_otp
from vpn.spa import parse_packet, uid_to_ip, _OFF_NONCE, NONCE_SIZE

logger = logging.getLogger(__name__)


class KnockProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that handles SPA knock packets."""

    def __init__(self, subnet: str) -> None:
        self.subnet = subnet
        self._transport = None

    def connection_made(self, transport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        # Schedule processing in a thread executor to keep the event loop free
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr) -> None:
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self._process, data, addr)
        except Exception as exc:
            logger.debug("Knock: unexpected error from %s: %s", addr, exc)

    def _process(self, data: bytes, addr) -> None:
        """Synchronous packet processing — runs in a thread pool executor."""

        # Step 1: ECIES decrypt + timestamp validation (no seed_fn in v2)
        spa = parse_packet(data)
        if spa is None:
            return  # silent drop (wrong size, bad crypto, expired timestamp)

        # Step 2: anti-replay — nonce is at bytes _OFF_NONCE:_OFF_NONCE+NONCE_SIZE
        nonce_hex = data[_OFF_NONCE:_OFF_NONCE + NONCE_SIZE].hex()
        try:
            get_collection("vpn_nonces").insert_one({
                "nonce": nonce_hex,
                "created_at": datetime.now(timezone.utc),
            })
        except Exception:
            # Unique index violation → nonce already seen → replay attack → drop
            return

        # Step 3: OTP verification (server-side TOTP lookup)
        if not verify_otp(spa.uid, spa.otp):
            logger.warning("Knock: OTP failed for uid=%s from %s", spa.uid, addr)
            return

        # Steps 4-7: In Sknock, replace WireGuard logic with:
        #   rule = lookup_rule(spa.wg_pubkey)  # wg_pubkey field = rule name
        #   if rule is None: return (silent drop)
        #   if spa.uid not in rule.allowed_users: return (silent drop)
        #   cmd = rule.action.format(ip=addr[0], uid=spa.uid, timestamp=spa.timestamp)
        #   subprocess.run(cmd, shell=True)  # or exec via Go os/exec
        #   if rule.undo_after > 0:
        #       schedule(rule.undo_after, rule.undo_action.format(...))

        logger.info(
            "Knock: peer registered uid=%s src=%s",
            spa.uid, addr,
        )


async def start_knock_listener(host: str, port: int, subnet: str) -> None:
    """
    Start the SPA UDP knock listener.
    Runs until cancelled.

    In Sknock (Go): use net.ListenPacket("udp", addr) + goroutine per packet.
    Rate limiting via token bucket BEFORE crypto (protect X25519 cost).
    """
    loop = asyncio.get_event_loop()
    logger.info("SPA knock listener starting on udp %s:%d", host, port)

    transport, _ = await loop.create_datagram_endpoint(
        lambda: KnockProtocol(subnet),
        local_addr=(host, port),
    )
    logger.info("SPA knock listener active on udp %s:%d", host, port)

    try:
        await asyncio.Future()  # run forever (cancelled on server shutdown)
    finally:
        transport.close()
        logger.info("SPA knock listener stopped")
