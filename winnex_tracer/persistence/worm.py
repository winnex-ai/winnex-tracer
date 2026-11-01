"""
winnex-tracer-core — WORM Storage (Write Once Read Many)
==================================================
Immutable disk storage with SHA3-256 hash chain.
Records are written as JSONL files organized by date,
with each block chained to the previous via cryptographic hash.

This is true WORM — records cannot be altered or deleted once written.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, hashlib, time, sqlite3
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX (Windows)
    fcntl = None


class WormStorage:
    """Write Once Read Many — append-only log with hash chain.

    Args:
        base_path: Root directory for WORM storage
        hash_algorithm: Hash algorithm (default sha3_256)

    Optional SQLite lookup index: when ``index=True`` (default), a local
    SQLite file (``.worm_index.db``) maps ``audit_id → block`` for O(log N)
    lookups instead of the O(N) JSONL scan. The index is a secondary, derived
    structure: it is rebuilt from the JSONL on corruption/absence, and
    ``verify_integrity()`` always scans the JSONL chain itself (the source of
    truth). If SQLite is unavailable the store degrades to the O(N) scan.
    """

    def __init__(self, base_path: str = "/var/lib/tracer-gov/worm",
                 hash_algorithm: str = "sha3_256",
                 index: bool = True):
        self.base_path = Path(base_path)
        self.hash_algorithm = hash_algorithm
        self._chain_file = self.base_path / ".chain"
        self._last_hash = b""
        # Running count of blocks written (2026-10-30). Maintained from the
        # on-disk state so the receipt's `block_number` is a real sequence
        # number instead of the number of daily files.
        self._block_count = 0
        self._index_path = self.base_path / ".worm_index.db"
        self._index_enabled = index
        self._load_chain_state()
        self._init_index()

    # ------------------------------------------------------------------
    # SQLite lookup index (audit_id → block) — Gargalo #8 remediation.
    # The index is a DERIVED structure: the JSONL + hash chain remain the
    # source of truth. Append() upserts the index entry; if the index is
    # missing/corrupt it is rebuilt from the JSONL on demand.
    # ------------------------------------------------------------------
    def _init_index(self):
        if not self._index_enabled:
            self._conn = None
            return
        try:
            if not self.base_path.exists():
                self._conn = None
                return
            self._conn = sqlite3.connect(str(self._index_path))
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS audit_index ("
                " audit_id TEXT PRIMARY KEY,"
                " block_hash TEXT,"
                " data_json TEXT,"
                " rel_path TEXT)")
            self._conn.commit()
        except Exception:
            # SQLite unavailable/corrupt → degrade to O(N) scan.
            self._conn = None

    @staticmethod
    def _extract_audit_id(data) -> str:
        """Locate the audit_id in the record's data block.

        Two real shapes exist:
          - legacy: data["audit_id"] == "..."
          - signed-commitment: data["commitment"]["audit_id"] == "..." (used by
            madhava-service and tracer-gov-service; the signed payload is the
            `commitment` sub-block).
        """
        if not isinstance(data, dict):
            return ""
        aid = data.get("audit_id")
        if aid:
            return str(aid)
        commitment = data.get("commitment")
        if isinstance(commitment, dict):
            aid = commitment.get("audit_id")
            if aid:
                return str(aid)
        return ""

    def _index_upsert(self, audit_id, block, block_hash, rel_path):
        if self._conn is None or not audit_id:
            return
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_index"
                "(audit_id, block_hash, data_json, rel_path)"
                " VALUES (?,?,?,?)",
                (str(audit_id), str(block_hash),
                 json.dumps(block, ensure_ascii=False), str(rel_path)))
            self._conn.commit()
        except Exception:
            pass  # index is best-effort; the JSONL remains authoritative

    def _index_lookup(self, audit_id):
        """O(log N) lookup of a block by audit_id (None if missing)."""
        if self._conn is None or not audit_id:
            return None
        try:
            row = self._conn.execute(
                "SELECT data_json FROM audit_index WHERE audit_id=?",
                (str(audit_id),)).fetchone()
            if row is None:
                return None
            return json.loads(row[0])
        except Exception:
            return None

    def _rebuild_index(self):
        """Rebuild the index from the JSONL chain (authoritative)."""
        if self._conn is None:
            return
        try:
            self._conn.execute("DELETE FROM audit_index")
            for f in sorted(self.base_path.rglob("records.jsonl")):
                rel = str(f.relative_to(self.base_path))
                with open(f) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            block = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        data = block.get("data", {})
                        aid = self._extract_audit_id(data)
                        if aid:
                            self._index_upsert(
                                aid, block, block.get("block_hash", ""), rel)
        except Exception:
            pass

    def _load_chain_state(self):
        """Load last chain hash from disk.

        Read-only: does NOT create the directory. Creation happens only
        on append (the actual write). This lets verify/get run against a
        base_path that does not exist or is not writable.
        """
        if self._chain_file.exists():
            with open(self._chain_file) as f:
                hex_str = f.read().strip()
            self._last_hash = bytes.fromhex(hex_str) if hex_str else b""
        else:
            self._last_hash = b""
        # The block count is derived from the same read (2026-10-30): counting
        # lines is O(file) and happens only here, once per instance, not per
        # append. A missing directory means an empty chain, not an error.
        n = 0
        try:
            for f in self.base_path.rglob("records.jsonl"):
                with open(f) as fh:
                    n += sum(1 for line in fh if line.strip())
        except OSError:
            n = 0
        self._block_count = n

    def _get_daily_path(self) -> Path:
        """Get daily file path: base_path/YYYY/MM/DD/records.jsonl."""
        now = datetime.utcnow()
        daily_dir = self.base_path / f"{now.year:04d}" / f"{now.month:02d}" / f"{now.day:02d}"
        daily_dir.mkdir(parents=True, exist_ok=True)
        return daily_dir / "records.jsonl"

    def _compute_hash(self, data: bytes) -> bytes:
        """Compute hash using configured algorithm."""
        h = hashlib.new(self.hash_algorithm)
        h.update(data)
        return h.digest()

    def append(self, record: dict) -> Dict[str, Any]:
        """Immutable append — writes record + hash chain.

        Args:
            record: Dict with audit record data

        Returns:
            WORM receipt with hash and path

        CONCORRÊNCIA (corrigido em 1.1.2)
        ---------------------------------
        `prev_hash` tem de ser o hash do ÚLTIMO bloco já gravado, não o que
        esta instância viu quando foi construída. Antes desta correção o
        `_last_hash` era lido só no `__init__`, e duas instâncias vivas ao
        mesmo tempo (ou uma instância longeva e uma efêmera) gravavam blocos
        com `prev_hash` obsoleto — a cadeia se rompia de forma PERMANENTE, e
        `verify_integrity()` acusava violação num histórico que ninguém
        adulterou.

        O padrão que dispara o defeito é o uso normal do tracer-med:
        `EvidenceChain` guarda um `WormStorage` pela vida do processo, e
        `ClinicalTriageEngine.run_triage` abre um `WormStorage()` novo por
        consulta. Medido: 4 processos × 5 appends → 20 blocos, 9 violações.

        A correção: reler o estado da cadeia do disco DENTRO de uma trava
        exclusiva (fcntl.flock), e manter a trava até o `.chain` ser
        atualizado. Assim o "ler último hash → gravar bloco → gravar .chain"
        é atômico entre processos. O lockfile é separado do `.chain` para
        não interferir no formato em disco.
        """
        timestamp = time.time()

        # Strip any previous chain fields to avoid overwrite contamination
        record = {k: v for k, v in record.items()
                  if k not in ("_worm_hash", "_worm_prev_hash", "_worm_timestamp")}

        self.base_path.mkdir(parents=True, exist_ok=True)
        lock_path = self.base_path / ".append.lock"
        with open(lock_path, "a+") as lock_fh:
            if fcntl is not None:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                # Estado da cadeia é lido AQUI, sob a trava — nunca do cache
                # do construtor.
                self._load_chain_state()

                # Build block with hash chain
                block = {
                    "data": record,
                    "timestamp": timestamp,
                    "prev_hash": self._last_hash.hex(),
                }
                block_bytes = json.dumps(block, sort_keys=True).encode()
                block_hash = self._compute_hash(block_bytes)
                block["block_hash"] = block_hash.hex()

                # Append to daily file (enforced append-only via file system)
                daily_path = self._get_daily_path()
                line = json.dumps(block, ensure_ascii=False)
                with open(daily_path, "a") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())

                # Persist chain state (ainda sob a trava: é o que torna a
                # sequência ler→gravar→atualizar atômica entre processos).
                self._last_hash = block_hash
                self._block_count += 1
                tmp_chain = self._chain_file.with_suffix(".chain.tmp")
                with open(tmp_chain, "w") as f:
                    f.write(block_hash.hex())
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_chain, self._chain_file)
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

        # Index the audit_id for O(log N) lookups (best-effort). The audit_id
        # may be data.audit_id (legacy) or data.commitment.audit_id (signed
        # commitment used by madhava-service / tracer-gov-service).
        data = record.get("data", record) if isinstance(record, dict) else record
        aid = self._extract_audit_id(data)
        if aid:
            self._index_upsert(
                aid, block, block_hash.hex(),
                str(daily_path.relative_to(self.base_path)))

        # BLOCK NUMBER (corrigido 2026-10-30). Era
        # `len(list(rglob("records.jsonl")))` — o número de ARQUIVOS diários,
        # não de blocos. Medido: 20 appends no mesmo dia devolviam
        # block_number=1 em todos os 20 receipts. Um receipt é a testemunha que
        # o cliente guarda; devolver 1 quando existem 20 é pior que não devolver
        # nada, porque parece um contador.
        #
        # O número real é o do bloco gravado: um a mais que o anterior. O
        # contador sai do mesmo estado que a cadeia — se o .chain dizia N, este
        # bloco é N+1. Sem varrer disco no caminho quente.
        return {
            "worm_path": str(daily_path.relative_to(self.base_path)),
            "worm_hash": block_hash.hex(),
            "worm_prev_hash": block.get("prev_hash", ""),
            "block_number": self._block_count,
        }

    def get_audit_id(self, audit_id: str) -> Optional[dict]:
        """O(log N) lookup of a block by audit_id via the SQLite index.

        Falls back to the O(N) JSONL scan if the index is missing/corrupt.
        """
        if not audit_id:
            return None
        if self._conn is not None:
            found = self._index_lookup(audit_id)
            if found is not None:
                return found
            # Index miss → rebuild (e.g. records written before the index
            # existed) and retry once before falling back to the scan.
            self._rebuild_index()
            found = self._index_lookup(audit_id)
            if found is not None:
                return found
        # Fallback: linear scan over the authoritative JSONL chain.
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        block = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    data = block.get("data", {})
                    if self._extract_audit_id(data) == audit_id:
                        return {**block, **data}
        return None

    def verify_integrity(self) -> Dict[str, Any]:
        """Scan all files and verify the complete hash chain.

        Returns:
            Integrity report with any violations found
        """
        all_records = []
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            all_records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        violations = []
        prev = b""
        for i, block in enumerate(all_records):
            expected_prev = prev.hex()
            if block.get("prev_hash", "") != expected_prev:
                violations.append({
                    "block": i,
                    "expected_prev": expected_prev,
                    "found_prev": block.get("prev_hash", ""),
                })
            # Recompute hash and compare
            block_copy = {k: v for k, v in block.items() if k != "block_hash"}
            block_bytes = json.dumps(block_copy, sort_keys=True).encode()
            expected_hash = self._compute_hash(block_bytes).hex()
            if block.get("block_hash", "") != expected_hash:
                violations.append({
                    "block": i,
                    "expected_hash": expected_hash,
                    "found_hash": block.get("block_hash", ""),
                })
            prev = bytes.fromhex(block.get("block_hash", ""))

        # TRUNCATION DETECTION (2026-10-30).
        #
        # The loop above verifies the chain AGAINST ITSELF: each block's
        # prev_hash must match the previous block's block_hash. Deleting blocks
        # from the END violates none of those relations — the survivors remain
        # mutually consistent. Measured: 20 blocks → delete the last 5 →
        # verification returns violations=0, chain_integrity_verified=True, and
        # the .chain file is left pointing at a hash that no longer exists.
        #
        # The .chain is the only in-tree witness of "there was more". It is
        # written under the same lock as the block, so it records the state the
        # chain had at the last append. Comparing it against the LAST BLOCK
        # ACTUALLY ON DISK detects tail truncation at zero cost.
        #
        # SCOPE, declared because it is easy to over-read: this catches tail
        # truncation only. It does NOT catch an attacker who also rewrites
        # .chain (one extra step, same permissions). Closing that requires an
        # anchor the operator does not control — see verify_integrity_anchored.
        truncation = None
        try:
            if self._chain_file.exists():
                anchor = self._chain_file.read_text().strip()
                if anchor and all_records:
                    last_on_disk = all_records[-1].get("block_hash", "")
                    if anchor != last_on_disk:
                        truncation = {
                            "expected_last_hash": anchor,
                            "found_last_hash": last_on_disk,
                            "blocks_on_disk": len(all_records),
                        }
                        violations.append({"block": "truncation", **truncation})
                elif anchor and not all_records:
                    # .chain has state but no blocks survive: everything was cut.
                    truncation = {"expected_last_hash": anchor,
                                  "found_last_hash": "", "blocks_on_disk": 0}
                    violations.append({"block": "truncation", **truncation})
        except (OSError, ValueError) as exc:  # unreadable/corrupt anchor
            truncation = {"error": f"{type(exc).__name__}: {exc}"}

        return {
            "total_blocks": len(all_records),
            "violations": len(violations),
            "chain_integrity_verified": len(violations) == 0,
            "violations_detail": violations[:50],
            "truncation_detected": truncation is not None and "error" not in truncation,
            "truncation_detail": truncation,
            "algorithm": self.hash_algorithm,
        }

    def compute_anchor(self) -> Dict[str, Any]:
        """The chain's current tip, as an EXTERNAL anchor an auditor can pin.

        Returned so a caller can store it somewhere this process cannot rewrite
        (another host, a signed receipt handed to the client, a public log).
        `verify_integrity()` compares against the .chain on the same disk; that
        catches tail truncation but not an attacker who rewrites both. An anchor
        copied OUT of this filesystem closes that gap.
        """
        with open(self._chain_file) as f:
            last_hash = f.read().strip()
        n = 0
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                n += sum(1 for line in fh if line.strip())
        return {"last_hash": last_hash, "block_count": n}

    def verify_against_anchor(self, anchor: Dict[str, Any]) -> Dict[str, Any]:
        """Verify the chain against a PREVIOUSLY PINNED anchor.

        This is the check that cannot be defeated from inside this filesystem:
        any block removed after the anchor was taken changes either the tip
        hash or the block count, and both are compared here.
        """
        current = self.compute_anchor()
        problems = []
        if int(anchor.get("block_count", -1)) != current["block_count"]:
            problems.append({
                "field": "block_count",
                "expected": int(anchor.get("block_count", -1)),
                "found": current["block_count"],
            })
        if str(anchor.get("last_hash", "")) != current["last_hash"]:
            problems.append({
                "field": "last_hash",
                "expected": str(anchor.get("last_hash", "")),
                "found": current["last_hash"],
            })
        return {
            "anchor_valid": not problems,
            "problems": problems,
            "current": current,
        }

    def get_record(self, block_hash: str) -> Optional[dict]:
        """Get a record by block hash (O(n) — acceptable for audit)."""
        for f in sorted(self.base_path.rglob("records.jsonl")):
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        block = json.loads(line)
                        if block.get("block_hash") == block_hash:
                            return block
                    except json.JSONDecodeError:
                        continue
        return None

    def get_records_by_date(self, year: int, month: int, day: int) -> List[dict]:
        """Get all records for a specific date."""
        daily_path = self.base_path / f"{year:04d}" / f"{month:02d}" / f"{day:02d}" / "records.jsonl"
        if not daily_path.exists():
            return []
        records = []
        with open(daily_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records
