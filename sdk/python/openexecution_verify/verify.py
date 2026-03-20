"""
OpenExecution Provenance Verification SDK v2.

Replaces HMAC-SHA256 with Ed25519/Ed448/ECDSA asymmetric signature verification.
Uses JCS-compatible canonicalization (recursive key sorting) that is byte-identical
to the backend JavaScript canonicalize() implementation.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from urllib.request import urlopen, Request
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    ECDSA,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

DEFAULT_API_URL = "https://api.openexecution.dev/api/v1"

# Hash output lengths in hex chars, for algorithm-aware genesis hash
_HASH_OUTPUT_LENGTHS = {
    "sha256": 64, "sha384": 96, "sha512": 128,
    "sha3-256": 64, "sha3-384": 96, "sha3-512": 128,
    "sha3_256": 64, "sha3_384": 96, "sha3_512": 128,
}


def _get_genesis_hash(hash_algorithm: str = "sha256") -> str:
    """Return the all-zeros genesis prev_hash for the given hash algorithm."""
    length = _HASH_OUTPUT_LENGTHS.get(hash_algorithm, 64)
    return "0" * length


def _normalize_timestamp(ts: str) -> str:
    """Normalize a timestamp to ISO 8601 format matching JS ``new Date(ts).toISOString()``.

    JS ``toISOString()`` always produces ``YYYY-MM-DDTHH:MM:SS.sssZ`` (UTC, 3-digit ms).
    """
    try:
        # Parse various ISO formats (with/without tz, fractional seconds, etc.)
        cleaned = ts.strip()
        # Handle PostgreSQL-style: "2026-03-11 12:00:00+00" → ISO
        if "T" not in cleaned and " " in cleaned:
            cleaned = cleaned.replace(" ", "T", 1)
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        dt_utc = dt.astimezone(timezone.utc)
        # Format to match JS toISOString(): YYYY-MM-DDTHH:MM:SS.sssZ
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"
    except (ValueError, AttributeError):
        # If parsing fails, return as-is (best-effort)
        return ts

# ---------------------------------------------------------------------------
# Supported hash algorithms (all via hashlib)
# ---------------------------------------------------------------------------
SUPPORTED_HASH_ALGORITHMS = {
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    # Accept both hyphenated (backend/JS convention) and underscored (Python hashlib) forms
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
}

# ---------------------------------------------------------------------------
# Supported signature algorithms
# ---------------------------------------------------------------------------
SUPPORTED_SIG_ALGORITHMS = {
    "ed25519",
    "ed448",
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
}

# Mapping from ecdsa curve name to curve class and hash class
_ECDSA_CURVES: Dict[str, tuple] = {
    "ecdsa-p256": (SECP256R1, SHA256),
    "ecdsa-p384": (SECP384R1, SHA384),
    "ecdsa-p521": (SECP521R1, SHA512),
}


# ---------------------------------------------------------------------------
# JCS-compatible canonicalization (byte-identical to backend JS version)
# ---------------------------------------------------------------------------

def _float_to_js_str(f: float) -> str:
    """Convert a float to match JS ``JSON.stringify`` number formatting.

    ECMAScript NumberToString rules:
    - Integer-like floats (f == int(f), |f| < 2^53): ``"123"`` (no decimal)
    - Fixed notation for values where the digit position n satisfies:
      k <= n <= 21 (integer-like) or -6 < n <= 0 (small decimals)
    - Exponential notation otherwise, with no leading zeros in exponent
    """
    if f != f or f == float("inf") or f == float("-inf"):
        return "null"
    if f == int(f) and abs(f) < 2**53:
        return str(int(f))
    # Get Python's shortest representation
    s = repr(f)
    if "e" not in s and "E" not in s:
        return s  # Fixed notation — Python and JS agree
    # Parse exponential notation
    base, exp_str = s.lower().split("e")
    exp_int = int(exp_str)
    abs_f = abs(f)
    # JS uses fixed notation for abs(value) in [1e-6, 1e21)
    if 1e-6 <= abs_f < 1e21:
        from decimal import Decimal
        # Use Decimal for precise fixed-point formatting
        fixed = format(Decimal(s), "f")
        if "." in fixed:
            fixed = fixed.rstrip("0").rstrip(".")
        return fixed
    # Keep exponential notation, normalize exponent (no leading zeros)
    return f"{base}e{'+' if exp_int >= 0 else ''}{exp_int}"


def canonicalize(obj: Any) -> str:
    """Produce a canonical JSON string using recursive key sorting.

    This implementation is byte-identical to the backend JavaScript
    ``canonicalize()`` function used by ``ProvenanceService``.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return json.dumps(obj)
    if isinstance(obj, float):
        return _float_to_js_str(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        # Omit keys with None values only if they represent JS undefined
        # (Python has no undefined, so all keys are included — matches JS behavior
        # where payloads come from JSON which has no undefined)
        pairs = [json.dumps(k) + ":" + canonicalize(obj[k]) for k in sorted_keys]
        return "{" + ",".join(pairs) + "}"
    return json.dumps(obj)


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------
def compute_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Hash *data* using the given algorithm and return the hex digest."""
    alg = SUPPORTED_HASH_ALGORITHMS.get(algorithm)
    if alg is None:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}. "
            f"Supported: {', '.join(sorted(SUPPORTED_HASH_ALGORITHMS))}"
        )
    return hashlib.new(alg, data).hexdigest()


# ---------------------------------------------------------------------------
# Signature verification helpers
# ---------------------------------------------------------------------------
def _decode_signature(signature: str) -> bytes:
    """Decode a signature from hex or base64."""
    try:
        return bytes.fromhex(signature)
    except ValueError:
        return base64.b64decode(signature)


def _load_public_key(
    key_material: Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey],
) -> Union[Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]:
    """Accept a PEM string, hex-encoded DER, raw DER bytes, or a loaded key object."""
    if isinstance(key_material, (Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey)):
        return key_material
    if isinstance(key_material, str):
        if key_material.startswith("-----BEGIN"):
            return load_pem_public_key(key_material.encode("utf-8"))
        # Assume hex-encoded DER (SPKI format)
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            return load_der_public_key(bytes.fromhex(key_material))
        except Exception:
            # Fall back to trying as PEM
            return load_pem_public_key(key_material.encode("utf-8"))
    if isinstance(key_material, bytes):
        if key_material.startswith(b"-----BEGIN"):
            return load_pem_public_key(key_material)
        # Try DER format
        try:
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            return load_der_public_key(key_material)
        except Exception:
            return load_pem_public_key(key_material)
    raise TypeError("Public key must be a PEM/hex string, bytes, or a loaded key object")


def verify_signature(
    data: bytes,
    signature: Union[str, bytes],
    public_key: Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey],
    algorithm: str = "ed25519",
) -> bool:
    """Verify an asymmetric signature.

    Args:
        data: The raw bytes that were signed.
        signature: Hex- or base64-encoded signature, or raw bytes.
        public_key: PEM-encoded public key (str/bytes) or a loaded key object.
        algorithm: One of ``ed25519``, ``ed448``, ``ecdsa-p256``, ``ecdsa-p384``,
                   ``ecdsa-p521``.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    if algorithm not in SUPPORTED_SIG_ALGORITHMS:
        raise ValueError(
            f"Unsupported signature algorithm: {algorithm}. "
            f"Supported: {', '.join(sorted(SUPPORTED_SIG_ALGORITHMS))}"
        )

    sig_bytes = signature if isinstance(signature, bytes) else _decode_signature(signature)
    key = _load_public_key(public_key)

    try:
        if algorithm == "ed25519":
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("Expected Ed25519PublicKey for algorithm 'ed25519'")
            key.verify(sig_bytes, data)
        elif algorithm == "ed448":
            if not isinstance(key, Ed448PublicKey):
                raise TypeError("Expected Ed448PublicKey for algorithm 'ed448'")
            key.verify(sig_bytes, data)
        elif algorithm.startswith("ecdsa-"):
            if not isinstance(key, EllipticCurvePublicKey):
                raise TypeError(f"Expected EllipticCurvePublicKey for algorithm '{algorithm}'")
            _, hash_cls = _ECDSA_CURVES[algorithm]
            key.verify(sig_bytes, data, ECDSA(hash_cls()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Main verifier class
# ---------------------------------------------------------------------------
class OpenExecutionVerifier:
    """OpenExecution Provenance Certificate Verification SDK (v2).

    Supports Ed25519 / Ed448 / ECDSA asymmetric verification with JCS
    canonicalization, per-layer algorithm selection, offline bundle
    verification, and extension attestation verification.
    """

    def __init__(self, api_url: str = DEFAULT_API_URL):
        self.api_url = api_url.rstrip("/")

    # ------------------------------------------------------------------
    # Online verification (backward-compatible API)
    # ------------------------------------------------------------------
    def verify_certificate(self, certificate_id: str) -> Dict[str, Any]:
        """Verify a provenance certificate via the OpenExecution API.

        This method is backward-compatible with SDK v1.

        Args:
            certificate_id: The UUID of the certificate to verify.

        Returns:
            A dictionary containing the verification result.

        Raises:
            ValueError: If the certificate is not found.
            RuntimeError: If the verification request fails.
        """
        url = f"{self.api_url}/provenance/verify/{certificate_id}"
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                return data.get("data", data)
        except HTTPError as e:
            if e.code == 404:
                raise ValueError(f"Certificate not found: {certificate_id}")
            raise RuntimeError(f"Verification request failed: {e.code}")

    # ------------------------------------------------------------------
    # Offline signature verification (asymmetric, replaces HMAC-SHA256)
    # ------------------------------------------------------------------
    @staticmethod
    def verify_signature_offline(
        certificate_data: dict,
        signature: str,
        public_key: Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey],
        algorithm: str = "ed25519",
        hash_algorithm: str = "sha256",
    ) -> bool:
        """Verify a certificate signature offline using asymmetric cryptography.

        Uses JCS canonicalization (recursive key sorting) to produce the
        canonical bytes, then verifies the signature directly against those
        bytes. Ed25519/Ed448 perform their own internal hashing — do NOT
        pre-hash before verification.

        Args:
            certificate_data: The certificate_data JSON object.
            signature: The stored certificate_signature (hex or base64).
            public_key: PEM-encoded public key or loaded key object.
            algorithm: Signature algorithm (``ed25519``, ``ed448``,
                       ``ecdsa-p256``, ``ecdsa-p384``, ``ecdsa-p521``).
            hash_algorithm: Hash algorithm (used only for ECDSA algorithms).

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        canonical = canonicalize(certificate_data).encode("utf-8")
        return verify_signature(canonical, signature, public_key, algorithm)

    # ------------------------------------------------------------------
    # Chain integrity verification (updated to use JCS canonicalization)
    # ------------------------------------------------------------------
    @staticmethod
    def verify_chain_integrity(
        events: List[Dict[str, Any]],
        hash_algorithm: str = "sha256",
    ) -> Dict[str, Any]:
        """Verify the integrity of a hash chain.

        Uses JCS canonicalization for event payload hashing.

        Args:
            events: A list of chain event dictionaries, ordered by seq.
            hash_algorithm: Hash algorithm to use (default ``sha256``).

        Returns:
            A dictionary with ``is_valid``, ``event_count``, and ``errors``.
        """
        genesis = _get_genesis_hash(hash_algorithm)
        errors: List[str] = []
        expected_prev = genesis
        expected_seq = 1

        for event in events:
            seq = event["seq"]

            # I1: Verify sequence numbers are strictly consecutive
            if seq != expected_seq:
                errors.append(
                    f"Event at position {expected_seq}: "
                    f"expected seq={expected_seq}, got seq={seq}"
                )

            if event.get("prev_hash") != expected_prev:
                errors.append(f"Event seq={seq}: prev_hash mismatch")

            payload = {
                "seq": seq,
                "event_type": event["event_type"],
                "actor_id": event.get("actor_id") or "system",
                "timestamp": _normalize_timestamp(event["created_at"]),
                "payload": event.get("payload", {}),
                "prev_hash": event.get("prev_hash", genesis),
            }
            canonical = canonicalize(payload).encode("utf-8")
            computed = compute_hash(canonical, hash_algorithm)

            if event.get("event_hash") != computed:
                errors.append(f"Event seq={seq}: event_hash mismatch")

            expected_prev = event.get("event_hash", "")
            expected_seq += 1

        return {
            "is_valid": len(errors) == 0,
            "event_count": len(events),
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Chain hash computation
    # ------------------------------------------------------------------
    @staticmethod
    def compute_chain_hash(
        event_hashes: List[str],
        hash_algorithm: str = "sha256",
    ) -> str:
        """Compute the chain hash from a list of event hashes.

        Args:
            event_hashes: Event hash hex strings in sequence order.
            hash_algorithm: Hash algorithm (default ``sha256``).

        Returns:
            The chain hash as a hex string.
        """
        return compute_hash("".join(event_hashes).encode("utf-8"), hash_algorithm)

    # ------------------------------------------------------------------
    # Per-layer algorithm verification
    # ------------------------------------------------------------------
    @staticmethod
    def verify_layer_signature(
        layer_data: dict,
        signature: str,
        public_key: Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey],
        algorithm: str = "ed25519",
        hash_algorithm: str = "sha256",
    ) -> bool:
        """Verify a single provenance layer's signature.

        Each layer in a certificate may use its own signing algorithm.
        Ed25519/Ed448 sign raw canonical bytes (internal hashing).

        Args:
            layer_data: The layer payload (dict).
            signature: The layer signature (hex or base64).
            public_key: PEM public key or loaded key object.
            algorithm: Signature algorithm for this layer.
            hash_algorithm: Hash algorithm (used only for ECDSA).

        Returns:
            ``True`` if valid.
        """
        canonical = canonicalize(layer_data).encode("utf-8")
        return verify_signature(canonical, signature, public_key, algorithm)

    # ------------------------------------------------------------------
    # Multi-layer certificate verification
    # ------------------------------------------------------------------
    @staticmethod
    def verify_certificate_layers(
        layers: List[Dict[str, Any]],
        public_keys: Dict[str, Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]],
    ) -> Dict[str, Any]:
        """Verify all layers in a certificate, each with its own algorithm.

        Each layer dict must contain:
        - ``layer_id``: Unique identifier for the layer.
        - ``data``: The layer payload.
        - ``signature``: Hex or base64 encoded signature.
        - ``algorithm``: Signature algorithm (e.g. ``ed25519``).
        - ``hash_algorithm`` (optional, default ``sha256``): Hash algorithm.
        - ``signer_id``: Key into *public_keys* to look up the public key.

        Args:
            layers: Ordered list of layer dicts.
            public_keys: Mapping of signer_id to public key material.

        Returns:
            Dict with ``is_valid``, ``layer_count``, ``results``, ``errors``.
        """
        results: List[Dict[str, Any]] = []
        errors: List[str] = []

        for layer in layers:
            layer_id = layer.get("layer_id", "unknown")
            signer_id = layer.get("signer_id", "")
            sig_alg = layer.get("algorithm", "ed25519")
            hash_alg = layer.get("hash_algorithm", "sha256")

            pk = public_keys.get(signer_id)
            if pk is None:
                errors.append(f"Layer {layer_id}: no public key for signer '{signer_id}'")
                results.append({"layer_id": layer_id, "valid": False, "error": "missing_key"})
                continue

            try:
                valid = OpenExecutionVerifier.verify_layer_signature(
                    layer["data"], layer["signature"], pk, sig_alg, hash_alg,
                )
            except Exception as exc:
                errors.append(f"Layer {layer_id}: {exc}")
                results.append({"layer_id": layer_id, "valid": False, "error": str(exc)})
                continue

            if not valid:
                errors.append(f"Layer {layer_id}: invalid signature")
            results.append({"layer_id": layer_id, "valid": valid})

        return {
            "is_valid": len(errors) == 0,
            "layer_count": len(layers),
            "results": results,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Offline bundle verification
    # ------------------------------------------------------------------
    def verify_bundle(
        self,
        bundle: Dict[str, Any],
        public_keys: Optional[Dict[str, Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]]] = None,
    ) -> Dict[str, Any]:
        """Verify a self-contained provenance bundle offline.

        Accepts two bundle formats:

        **Simple format** (JS SDK compatible)::

            {
                "certificate": { ... },
                "certificate_signature": "hex",
                "chain": { "events": [...], "hash_algorithm": "sha256", ... },
                "public_key": "PEM or hex",
                "attestations": [...]
            }

        **Advanced format** (multi-signer)::

            {
                "certificate": { "certificate_data": {...}, "certificate_signature": "hex", "signer_id": "platform" },
                "chain_events": [...],
                "layers": [...],
                "extensions": [...]
            }

        Args:
            bundle: The provenance bundle dict.
            public_keys: Mapping of signer_id to public key material.
                         Not required for simple format (uses ``public_key`` from bundle).

        Returns:
            Comprehensive verification result dict.
        """
        # Detect simple (JS-compatible) format
        is_simple = "certificate_signature" in bundle or "public_key" in bundle or (
            "chain" in bundle and isinstance(bundle.get("chain"), dict)
        )

        if is_simple:
            return self._verify_bundle_simple(bundle)

        return self._verify_bundle_advanced(bundle, public_keys or {})

    def _verify_bundle_simple(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a JS SDK compatible simple bundle."""
        errors: List[str] = []

        certificate = bundle.get("certificate", {})
        cert_sig = bundle.get("certificate_signature", "")
        chain = bundle.get("chain", {})
        public_key = bundle.get("public_key")
        attestations = bundle.get("attestations", [])

        sig_alg = chain.get("signature_algorithm", "ed25519") if chain else "ed25519"
        hash_alg = chain.get("hash_algorithm", "sha256") if chain else "sha256"

        # 1. Verify certificate signature
        cert_sig_valid = False
        if certificate and cert_sig and public_key:
            try:
                cert_sig_valid = self.verify_signature_offline(
                    certificate, cert_sig, public_key, sig_alg, hash_alg,
                )
            except Exception as exc:
                errors.append(f"Certificate signature verification error: {exc}")
        else:
            errors.append("Missing certificate, certificate_signature, or public_key")

        # 2. Verify chain integrity
        chain_events = chain.get("events", []) if isinstance(chain, dict) else []
        chain_integrity = {"is_valid": False, "event_count": 0, "errors": ["No chain events provided"]}
        if chain_events:
            chain_integrity = self.verify_chain_integrity(chain_events, hash_alg)
            if not chain_integrity["is_valid"]:
                errors.extend(chain_integrity["errors"])
        else:
            errors.append("Missing chain or chain.events")

        # 3. Chain hash cross-check
        chain_hash_valid = False
        cert_chain_hash = certificate.get("chain_hash") if isinstance(certificate, dict) else None
        if chain_events and cert_chain_hash:
            event_hashes = [e.get("event_hash", "") for e in chain_events]
            computed = self.compute_chain_hash(event_hashes, hash_alg)
            chain_hash_valid = computed == cert_chain_hash
            if not chain_hash_valid:
                errors.append(
                    f"Chain hash mismatch: computed {computed[:16]}..., "
                    f"expected {cert_chain_hash[:16]}..."
                )

        # 4. Verify extension attestations (data-level, not signature-level)
        attestation_results = None
        if attestations:
            attestation_results = []
            for att in attestations:
                att_type = att.get("type", "unknown")
                if att_type == "ContentIntegrity":
                    r = verify_content_integrity(att, hash_alg)
                elif att_type == "Timestamp":
                    r = verify_timestamp(att, hash_alg, public_key, sig_alg)
                elif att_type == "Blockchain":
                    r = verify_blockchain(att, cert_chain_hash)
                else:
                    r = {"valid": False, "reason": f"Unknown attestation type: {att_type}"}
                if not r.get("valid"):
                    errors.append(f"Attestation {att_type}: {r.get('reason', 'invalid')}")
                attestation_results.append({"type": att_type, **r})

        valid = (
            cert_sig_valid
            and chain_integrity["is_valid"]
            and chain_hash_valid
            and (attestation_results is None or all(r.get("valid") for r in attestation_results))
        )

        result: Dict[str, Any] = {
            "valid": valid,
            "certificate_signature_valid": cert_sig_valid,
            "chain_integrity": chain_integrity,
            "chain_hash_valid": chain_hash_valid,
            "errors": errors,
        }
        if attestation_results is not None:
            result["attestation_results"] = attestation_results
        return result

    def _verify_bundle_advanced(
        self,
        bundle: Dict[str, Any],
        public_keys: Dict[str, Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]],
    ) -> Dict[str, Any]:
        """Verify an advanced multi-signer bundle."""
        result: Dict[str, Any] = {
            "is_valid": True,
            "certificate": None,
            "chain": None,
            "layers": None,
            "extensions": None,
            "errors": [],
        }

        # --- Certificate signature ---
        cert = bundle.get("certificate", {})
        cert_data = cert.get("certificate_data", cert.get("data", {}))
        cert_sig = cert.get("certificate_signature", cert.get("signature", ""))
        cert_alg = cert.get("algorithm", "ed25519")
        cert_hash = cert.get("hash_algorithm", "sha256")
        cert_signer = cert.get("signer_id", "platform")

        pk = public_keys.get(cert_signer)
        if pk and cert_sig:
            cert_valid = self.verify_signature_offline(
                cert_data, cert_sig, pk, cert_alg, cert_hash,
            )
            result["certificate"] = {"valid": cert_valid}
            if not cert_valid:
                result["is_valid"] = False
                result["errors"].append("Certificate signature invalid")
        elif cert_sig and not pk:
            result["certificate"] = {"valid": False, "error": "missing_key"}
            result["is_valid"] = False
            result["errors"].append(f"No public key for certificate signer '{cert_signer}'")

        # --- Chain integrity ---
        chain_events = bundle.get("chain_events", [])
        chain_hash_alg = bundle.get("chain_hash_algorithm", "sha256")
        if chain_events:
            chain_result = self.verify_chain_integrity(chain_events, chain_hash_alg)
            result["chain"] = chain_result
            if not chain_result["is_valid"]:
                result["is_valid"] = False
                result["errors"].extend(chain_result["errors"])

        # --- Chain hash cross-check ---
        cert_chain_hash = cert_data.get("chain_hash") if isinstance(cert_data, dict) else None
        if chain_events and cert_chain_hash:
            event_hashes = [e.get("event_hash", "") for e in chain_events]
            computed_chain_hash = self.compute_chain_hash(event_hashes, chain_hash_alg)
            chain_hash_valid = computed_chain_hash == cert_chain_hash
            result["chain_hash_valid"] = chain_hash_valid
            if not chain_hash_valid:
                result["is_valid"] = False
                result["errors"].append(
                    f"Chain hash mismatch: computed {computed_chain_hash[:16]}..., "
                    f"expected {cert_chain_hash[:16]}..."
                )

        # --- Layers ---
        layers = bundle.get("layers", [])
        if layers:
            layer_result = self.verify_certificate_layers(layers, public_keys)
            result["layers"] = layer_result
            if not layer_result["is_valid"]:
                result["is_valid"] = False
                result["errors"].extend(layer_result["errors"])

        # --- Extensions ---
        extensions = bundle.get("extensions", [])
        if extensions:
            ext_result = self.verify_extension_attestations(extensions, public_keys)
            result["extensions"] = ext_result
            if not ext_result["is_valid"]:
                result["is_valid"] = False
                result["errors"].extend(ext_result["errors"])

        return result

    # ------------------------------------------------------------------
    # Extension attestation verification
    # ------------------------------------------------------------------
    @staticmethod
    def verify_extension_attestations(
        extensions: List[Dict[str, Any]],
        public_keys: Dict[str, Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]],
    ) -> Dict[str, Any]:
        """Verify extension attestation signatures.

        Each extension dict must contain:
        - ``extension_id``: Unique identifier.
        - ``data``: The attestation payload.
        - ``signature``: Hex or base64 encoded signature.
        - ``algorithm`` (optional, default ``ed25519``): Signature algorithm.
        - ``hash_algorithm`` (optional, default ``sha256``): Hash algorithm.
        - ``signer_id``: Key into *public_keys*.

        Args:
            extensions: List of extension attestation dicts.
            public_keys: Mapping of signer_id to public key material.

        Returns:
            Dict with ``is_valid``, ``count``, ``results``, ``errors``.
        """
        results: List[Dict[str, Any]] = []
        errors: List[str] = []

        for ext in extensions:
            ext_id = ext.get("extension_id", "unknown")
            signer_id = ext.get("signer_id", "")
            sig_alg = ext.get("algorithm", "ed25519")
            hash_alg = ext.get("hash_algorithm", "sha256")

            pk = public_keys.get(signer_id)
            if pk is None:
                errors.append(f"Extension {ext_id}: no public key for signer '{signer_id}'")
                results.append({"extension_id": ext_id, "valid": False, "error": "missing_key"})
                continue

            try:
                canonical = canonicalize(ext["data"]).encode("utf-8")
                valid = verify_signature(canonical, ext["signature"], pk, sig_alg)
            except Exception as exc:
                errors.append(f"Extension {ext_id}: {exc}")
                results.append({"extension_id": ext_id, "valid": False, "error": str(exc)})
                continue

            if not valid:
                errors.append(f"Extension {ext_id}: invalid signature")
            results.append({"extension_id": ext_id, "valid": valid})

        return {
            "is_valid": len(errors) == 0,
            "count": len(extensions),
            "results": results,
            "errors": errors,
        }


# ---------------------------------------------------------------------------
# Standalone extension attestation verifiers
# ---------------------------------------------------------------------------

def verify_content_integrity(
    attestation: Dict[str, Any],
    hash_algorithm: str = "sha256",
) -> Dict[str, Any]:
    """Verify a ContentIntegrity Merkle-tree attestation offline.

    Recomputes the Merkle root from ``leaves`` and compares to ``root_hash``.
    Uses RFC 6962 domain separation (0x00 leaf prefix, 0x01 node prefix)
    and odd-leaf promotion (no duplication).

    Args:
        attestation: Must contain ``type='ContentIntegrity'``, ``root_hash``,
                     and ``leaves`` (list of hex leaf hashes).
        hash_algorithm: Hash algorithm for internal nodes (default sha256).

    Returns:
        Dict with ``valid``, ``computed_root``, ``expected_root``.
    """
    if not attestation or attestation.get("type") != "ContentIntegrity":
        return {"valid": False, "reason": "Not a ContentIntegrity attestation"}

    root_hash = attestation.get("root_hash", attestation.get("merkle_root"))
    leaves = attestation.get("leaves", attestation.get("leaf_hashes"))
    if not root_hash:
        return {"valid": False, "reason": "Missing root_hash/merkle_root"}

    # Use attestation's stored hash_algorithm if available, fall back to parameter
    effective_algo = attestation.get("hash_algorithm", hash_algorithm)

    # Handle empty tree: backend returns all-zeros hash of correct length
    if not isinstance(leaves, list) or len(leaves) == 0:
        expected_len = _HASH_OUTPUT_LENGTHS.get(effective_algo, 64)
        empty_root = "0" * expected_len
        return {
            "valid": root_hash == empty_root,
            "computed_root": empty_root,
            "expected_root": root_hash,
        }

    alg = SUPPORTED_HASH_ALGORITHMS.get(effective_algo, effective_algo)
    leaf_prefix = b"\x00"
    node_prefix = b"\x01"

    # Hash leaves with domain separation
    level = [
        hashlib.new(alg, leaf_prefix + bytes.fromhex(leaf)).hexdigest()
        for leaf in leaves
    ]

    while len(level) > 1:
        next_level: List[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                combined = node_prefix + bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])
                next_level.append(hashlib.new(alg, combined).hexdigest())
            else:
                next_level.append(level[i])  # promote odd leaf
        level = next_level

    computed_root = level[0]
    return {
        "valid": computed_root == root_hash,
        "computed_root": computed_root,
        "expected_root": root_hash,
        "domain_separation": "rfc6962",
    }


def verify_timestamp(
    attestation: Dict[str, Any],
    hash_algorithm: str = "sha256",
    public_key: Optional[Union[str, bytes, Ed25519PublicKey, Ed448PublicKey, EllipticCurvePublicKey]] = None,
    signature_algorithm: str = "ed25519",
) -> Dict[str, Any]:
    """Verify a Timestamp attestation offline.

    Re-hashes the timestamp string and compares to the stored hash.
    If ``signed_timestamp`` and a public key are provided, also verifies
    the signature.

    Args:
        attestation: Must contain ``type='Timestamp'``, ``timestamp``, ``hash``.
        hash_algorithm: Hash algorithm (default sha256).
        public_key: Optional public key for signed_timestamp verification.
        signature_algorithm: Signature algorithm (default ed25519).

    Returns:
        Dict with ``valid``, ``hash_valid``, ``signature_valid``.
    """
    if not attestation or attestation.get("type") != "Timestamp":
        return {"valid": False, "reason": "Not a Timestamp attestation"}

    # Accept both SDK format (timestamp/hash) and backend format (anchored_at/anchor_hash)
    ts = attestation.get("timestamp") or attestation.get("anchored_at")
    expected_hash = attestation.get("hash") or attestation.get("anchor_hash")
    if not ts or not expected_hash:
        return {"valid": False, "reason": "Missing timestamp/anchored_at or hash/anchor_hash"}

    # For backend format (anchor_hash = sha256(signature + timestamp)), we can't recompute
    is_backend_format = bool(attestation.get("anchor_hash")) and not attestation.get("hash")
    if is_backend_format:
        hash_valid = isinstance(expected_hash, str) and len(expected_hash) > 0
    else:
        alg = SUPPORTED_HASH_ALGORITHMS.get(hash_algorithm, hash_algorithm)
        computed_hash = hashlib.new(alg, ts.encode("utf-8")).hexdigest()
        hash_valid = computed_hash == expected_hash

    signature_valid = None
    signed_ts = attestation.get("signed_timestamp")
    if signed_ts and public_key:
        try:
            signature_valid = verify_signature(
                ts.encode("utf-8"), signed_ts, public_key, signature_algorithm,
            )
        except Exception:
            signature_valid = False

    return {
        "valid": hash_valid and (signature_valid is None or signature_valid),
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
    }


def verify_blockchain(
    attestation: Dict[str, Any],
    expected_chain_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a Blockchain attestation offline.

    Can only confirm that ``chain_hash`` matches expected value.
    Full on-chain verification requires network access.

    Args:
        attestation: Must contain ``type='Blockchain'``, ``chain_hash``, ``tx_hash``.
        expected_chain_hash: Optional expected chain hash to compare.

    Returns:
        Dict with ``valid``, ``hash_match``, ``tx_hash``, ``network``.
    """
    if not attestation or attestation.get("type") != "Blockchain":
        return {"valid": False, "reason": "Not a Blockchain attestation"}

    # Accept both SDK (chain_hash) and backend (head_hash) field names
    chain_hash = attestation.get("chain_hash") or attestation.get("head_hash")
    tx_hash = attestation.get("tx_hash")
    if not tx_hash:
        return {"valid": False, "reason": "Missing tx_hash"}

    hash_match = (chain_hash == expected_chain_hash) if (expected_chain_hash and chain_hash) else None
    return {
        "valid": hash_match is None or hash_match,
        "hash_match": hash_match,
        "tx_hash": tx_hash,
        "network": attestation.get("network", "unknown"),
    }
