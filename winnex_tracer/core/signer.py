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


class SignatureGuaranteeError(RuntimeError):
    """A garantia de assinatura pedida não pode ser honrada.

    Levantada em vez de degradar para um algoritmo mais fraco. Ver
    `Signer._sign_ed25519` para o raciocínio completo.
    """


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

        A assinatura é uma garantia, não uma conveniência. Se o algoritmo
        pedido não pode ser honrado, esta função LEVANTA — não substitui por
        um algoritmo mais fraco. Ver `_sign_ed25519` para o motivo.

        Args:
            data: Dict to sign

        Returns:
            Dict with signature (hex/base64) and algorithm

        Raises:
            SignatureGuaranteeError: quando a garantia pedida não pode ser
                honrada (ex.: algoritmo de segurança inferior ao requerido).
        """
        data_bytes = json.dumps(data, sort_keys=True).encode()

        if self.algorithm == "Ed25519":
            return self._sign_ed25519(data_bytes)
        elif self.algorithm == "HMAC":
            return self._sign_hmac_explicit(data_bytes)
        elif self.algorithm == "ICP-Brasil":
            return self._sign_icp_brasil(data_bytes)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def _sign_ed25519(self, data: bytes) -> Dict[str, Any]:
        """Sign with Ed25519 via libsodium/nacl.

        FALHA ALTA quando a garantia não pode ser honrada. Não existe caminho
        alternativo silencioso.

        Por que não cair para HMAC:

          Ed25519 e HMAC provam coisas diferentes. Ed25519 prova QUEM assinou
          para qualquer portador da chave pública (não-repúdio). HMAC prova
          apenas que alguém com a chave SECRETA gerou aquilo — e o detentor
          da chave secreta é justamente quem teria poder de forjar. Cair para
          HMAC num sistema de auditoria troca "o operador não pode repudiar"
          por "confie no operador", sem que o chamador saiba.

          Um fallback que troca a garantia e retorna sucesso não é plano B;
          é erosão silenciosa da garantia fundamental. O registro continua
          parecendo válido e só falha sob contestação — no passado.

        Se HMAC é aceitável para um caso de uso, peça explicitamente:
        `Signer(algorithm="HMAC")`.
        """
        try:
            import nacl.signing
        except ImportError as exc:
            raise SignatureGuaranteeError(
                "Ed25519 signing requires PyNaCl: pip install pynacl. "
                "The signer refuses to fall back to HMAC: that would replace "
                "non-repudiation (verifiable by anyone with the public key) "
                "with a symmetric secret and report success. "
                'If a symmetric MAC is genuinely what you want, request it '
                'explicitly: Signer(algorithm="HMAC").'
            ) from exc

        key_hex = os.environ.get("WINNEX_TRACER_ED25519_KEY", "").strip()
        if not key_hex:
            file_hex = os.environ.get(
                "WINNEX_TRACER_ED25519_KEY_FILE", "").strip()
            if file_hex and os.path.exists(file_hex):
                with open(file_hex) as f:
                    key_hex = f.read().strip()
        if not key_hex:
            raise SignatureGuaranteeError(
                "WINNEX_TRACER_ED25519_KEY (or _FILE) not set. "
                "The signer never generates a throwaway key or falls back to "
                "a default: a record signed with an unknown or hardcoded key "
                "cannot be repudiated NOR trusted. "
                "Provide the key from the environment / secret manager."
            )
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise SignatureGuaranteeError(
                "WINNEX_TRACER_ED25519_KEY is not valid hex."
            ) from exc
        if len(key_bytes) != 32:
            raise SignatureGuaranteeError(
                f"Ed25519 seed must be 32 bytes, got {len(key_bytes)}. "
                "Generate with: python -c \"import nacl.signing,os; "
                "print(nacl.signing.SigningKey(os.urandom(32)).encode().hex())\""
            )

        signing_key = nacl.signing.SigningKey(key_bytes)
        signed = signing_key.sign(data)

        # Publica a chave de verificação para auditores externos. Falha de
        # escrita NÃO degrada a assinatura — a assinatura já está feita; mas
        # também não é silenciosa.
        verify_key_hex = signing_key.verify_key.encode().hex()
        try:
            verify_path = Path(self.cert_path or
                               "/tmp/tracer-gov-ed25519.pub")
            verify_path.parent.mkdir(parents=True, exist_ok=True)
            with open(verify_path, "w") as f:
                f.write(verify_key_hex)
        except OSError as exc:
            import warnings
            warnings.warn(
                f"signature produced, but the public verify key could not be "
                f"written to {self.cert_path or '/tmp/tracer-gov-ed25519.pub'}"
                f" ({exc}). Auditors must obtain it separately.",
                RuntimeWarning, stacklevel=2)

        return {
            "signature": signed.signature.hex(),
            "signature_algorithm": "Ed25519",
            "verify_key": verify_key_hex,
        }

    def _sign_hmac_explicit(self, data: bytes) -> Dict[str, Any]:
        """HMAC-SHA3-256 — apenas quando PEDIDO explicitamente.

        Só é alcançável com `Signer(algorithm="HMAC")`. Nunca como plano B de
        Ed25519. O resultado diz o que é: um MAC simétrico, não uma assinatura
        de não-repúdio. A chave é obrigatória e nunca tem default.
        """
        import hmac

        key = os.environ.get("WINNEX_TRACER_HMAC_KEY", "").strip()
        if not key:
            raise SignatureGuaranteeError(
                "algorithm='HMAC' requires WINNEX_TRACER_HMAC_KEY. "
                "There is no default key: a constant compiled into the source "
                "is a public key, and a public 'secret' forges nothing."
            )
        sig = hmac.new(key.encode(), data, "sha3_256").hexdigest()
        return {
            "signature": sig,
            "signature_algorithm": "HMAC-SHA3-256",
            "note": ("symmetric MAC, requested explicitly: proves possession "
                     "of the shared key, NOT non-repudiation. A verifier "
                     "needs the secret; an external auditor cannot check it "
                     "alone."),
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
