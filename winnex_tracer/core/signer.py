"""
Tracer-GOV — Digital Signature Module
=======================================
Cryptographic signing of audit records.

Supported algorithms (configurable via policies JSON):
  - Ed25519   (NIST-standard, zero cost, sub-millisecond)
  - ICP-Brasil (A1/A3 certificates, required for restricted/secret data)

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, subprocess, tempfile, base64
from typing import Optional, Dict, Any
from pathlib import Path


class Signer:
    """Digital signature for audit records.

    Args:
        algorithm: Signature algorithm (Ed25519 or ICP-Brasil)
        cert_path: Path to certificate (ICP-Brasil)
        key_path: Path to private key
    """

    def __init__(self, algorithm: str = "Ed25519",
                 cert_path: str = "",
                 key_path: str = ""):
        self.algorithm = algorithm
        self.cert_path = cert_path or os.environ.get(
            "WINNEX_TRACER_ICP_CERT", "")
        self.key_path = key_path or os.environ.get(
            "WINNEX_TRACER_ICP_KEY", "")

    def sign(self, data: dict) -> Dict[str, Any]:
        """Sign data using the configured algorithm.

        Args:
            data: Dict to sign

        Returns:
            Dict with signature (hex/base64) and algorithm
        """
        data_bytes = json.dumps(data, sort_keys=True).encode()

        if self.algorithm == "Ed25519":
            return self._sign_ed25519(data_bytes)
        elif self.algorithm == "ICP-Brasil":
            return self._sign_icp_brasil(data_bytes)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _sign_ed25519(self, data: bytes) -> Dict[str, Any]:
        """Sign with Ed25519 via libsodium/nacl."""
        try:
            import nacl.signing
            import nacl.encoding

            key_hex = os.environ.get("WINNEX_TRACER_ED25519_KEY", "")
            if key_hex:
                key_bytes = bytes.fromhex(key_hex)
                signing_key = nacl.signing.SigningKey(key_bytes)
            else:
                signing_key = nacl.signing.SigningKey.generate()
                verify_path = Path(self.cert_path or
                                   "/tmp/tracer-gov-ed25519.pub")
                verify_path.parent.mkdir(parents=True, exist_ok=True)
                with open(verify_path, "wb") as f:
                    f.write(signing_key.verify_key.encode())

            signed = signing_key.sign(data)
            return {
                "signature": signed.signature.hex(),
                "signature_algorithm": "Ed25519",
                "verify_key": signing_key.verify_key.encode().hex(),
            }
        except ImportError:
            import hmac
            key = os.environ.get("WINNEX_TRACER_ED25519_KEY",
                                 "tracer-gov-dev-key")
            sig = hmac.new(key.encode(), data, "sha3_256").hexdigest()
            return {
                "signature": sig,
                "signature_algorithm": "Ed25519-HMAC",
                "note": "HMAC fallback (install pynacl for real Ed25519)",
            }

    def _sign_icp_brasil(self, data: bytes) -> Dict[str, Any]:
        """Sign with ICP-Brasil certificate via openssl.

        Requires:
            - openssl installed
            - A1 certificate (.pem file) or A3 token
        """
        if not self.key_path or not os.path.exists(self.key_path):
            return {
                "signature": "",
                "signature_algorithm": "ICP-Brasil",
                "error": "ICP-Brasil key not found",
            }

        password = os.environ.get("WINNEX_ICP_KEY_PASSWORD", "")

        with tempfile.NamedTemporaryFile(suffix=".bin",
                                          delete=False) as tmp_in:
            tmp_in.write(data)
            tmp_in_path = tmp_in.name

        try:
            cmd = ["openssl", "smime", "-sign",
                   "-in", tmp_in_path,
                   "-signer", self.cert_path,
                   "-inkey", self.key_path,
                   "-outform", "DER"]
            if password:
                cmd.extend(["-passin", f"pass:{password}"])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {
                    "signature": "",
                    "signature_algorithm": "ICP-Brasil",
                    "error": result.stderr.strip(),
                }

            sig_b64 = base64.b64encode(
                result.stdout.encode()).decode()

            return {
                "signature": sig_b64,
                "signature_algorithm": "ICP-Brasil",
                "cert_path": self.cert_path,
            }
        except FileNotFoundError:
            return {
                "signature": "",
                "signature_algorithm": "ICP-Brasil",
                "error": "openssl not found on system",
            }
        except subprocess.TimeoutExpired:
            return {
                "signature": "",
                "signature_algorithm": "ICP-Brasil",
                "error": "openssl signing timed out",
            }
        finally:
            os.unlink(tmp_in_path)

    def verify(self, data: dict, signature: str,
               algorithm: str, verify_key: str = "") -> bool:
        """Verify a digital signature."""
        data_bytes = json.dumps(data, sort_keys=True).encode()

        if algorithm == "Ed25519":
            try:
                import nacl.signing
                vk_bytes = bytes.fromhex(verify_key)
                vk = nacl.signing.VerifyKey(vk_bytes)
                vk.verify(data_bytes, bytes.fromhex(signature))
                return True
            except Exception:
                return False

        elif algorithm.startswith("ICP-Brasil"):
            try:
                sig_bytes = base64.b64decode(signature.encode())
                with tempfile.NamedTemporaryFile(suffix=".bin",
                                                  delete=False) as tmp_in:
                    tmp_in.write(data_bytes)
                    tmp_in_path = tmp_in.name
                with tempfile.NamedTemporaryFile(suffix=".sig",
                                                  delete=False) as tmp_sig:
                    tmp_sig.write(sig_bytes)
                    tmp_sig_path = tmp_sig.name
                try:
                    r = subprocess.run(
                        ["openssl", "smime", "-verify",
                         "-in", tmp_sig_path,
                         "-content", tmp_in_path,
                         "-CAfile",
                         "/etc/ssl/certs/ca-certificates.crt",
                         "-inform", "DER"],
                        capture_output=True, text=True, timeout=30)
                    return r.returncode == 0
                finally:
                    os.unlink(tmp_in_path)
                    os.unlink(tmp_sig_path)
            except Exception:
                return False

        return False
