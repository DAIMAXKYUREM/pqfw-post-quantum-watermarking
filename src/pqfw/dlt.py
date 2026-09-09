"""A permissioned, offline distributed ledger over the decryption receipts.

Why this exists
---------------
A hash chain proves that whoever holds *the file* has not edited its middle. It does
not stop the person who holds the file from replacing the whole thing: recompute every
hash and the chain links up perfectly. The witness-signed Merkle checkpoints in
``ledger.py`` close that hole for the ranges they cover, but there is still exactly one
copy of the chain, and one copy means one administrator.

The requirement is an audit layer where *no single administrator or compromised
account* can retroactively alter or erase a record. That needs more than one holder.
So the receipts live on **n independent validator nodes**, each of which:

* keeps its **own complete replica** of the chain,
* **independently validates** every receipt before accepting it -- the recipient's
  ML-DSA-65 signature, the fingerprint commitment, the link to its own current head,
* **votes** on each block by signing the block header with its own ML-DSA-65 key.

A block commits only when **k of n** validators have signed it. Corrupting one node
changes nothing: its replica diverges from the others, the divergence is detectable by
comparing heads, and the remaining nodes still reach quorum without it. To rewrite
history an attacker needs k nodes at once, which is the property the spec asks for.

Why not a public blockchain
---------------------------
The deployment constraint forbids it, and rightly: this must run air-gapped. There is
no mining, no token, no external network, no ordering service to fail. Validators are a
known, permissioned set fixed at enrollment -- the same construction Hyperledger Fabric
and Tendermint use, minus the parts that need the internet. The commit rule is a
straight k-of-n quorum over signatures, which is safe under the assumption the spec
implies: fewer than k of the nodes are compromised.

Blocks, not single entries
--------------------------
Receipts are batched into blocks with a header carrying the height, the previous block
hash, and a Merkle root over the block's receipts. That gives cheap inclusion proofs
for one receipt against a signed root, and it gives the validators a single object to
vote on.
"""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from pqfw import pqc
from pqfw.ledger import (
    GENESIS_HASH,
    Clock,
    Entry,
    Ledger,
    SystemClock,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)

BLOCK_LABEL = "pqfw/block/v1"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# blocks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Block:
    height: int
    prev_block_hash: str
    merkle_root: str
    """Over the receipts in *this* block -- what inclusion proofs are checked against."""
    state_root: str
    """Over every receipt the proposer holds, recomputed from contents rather than from
    stored hashes. Without it a validator that quietly rewrote an *older* receipt would
    still propose an identical-looking block: the tampered entry is not in the range
    this block covers, and the already-sealed block it does sit in has a fixed header.
    The state root is what makes an honest node refuse to endorse such a proposer."""
    from_seq: int
    to_seq: int
    at: str
    votes: list[str] = field(default_factory=list)
    """Hex ML-DSA-65 signatures over canonical(header()), one per validator that
    accepted the block. Unlabelled: a verifier holding the validator set tries each
    key, which is the question that actually matters and avoids disclosing which
    validators were reachable."""

    def header(self) -> dict[str, Any]:
        return {
            "label": BLOCK_LABEL,
            "height": self.height,
            "prev_block_hash": self.prev_block_hash,
            "merkle_root": self.merkle_root,
            "state_root": self.state_root,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "at": self.at,
        }

    def block_hash(self) -> str:
        return pqc.canonical_hash(self.header())

    def to_json(self) -> dict[str, Any]:
        return {**self.header(), "votes": self.votes}

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "Block":
        return Block(
            height=int(obj["height"]),
            prev_block_hash=obj["prev_block_hash"],
            merkle_root=obj["merkle_root"],
            state_root=obj["state_root"],
            from_seq=int(obj["from_seq"]),
            to_seq=int(obj["to_seq"]),
            at=obj["at"],
            votes=[str(v) for v in obj.get("votes", [])],
        )


@dataclass(frozen=True)
class ConsensusReport:
    """What the network agrees on, and where it does not."""

    nodes: int
    quorum: int
    height: int
    agreeing: list[int]
    diverged: list[int]
    valid: list[int]
    """Nodes whose own replica verifies: chain links intact and every recipient
    signature good."""
    node_heads: dict[int, str]
    committed: bool
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diverged and self.committed and not self.problems

    @property
    def honest_majority(self) -> bool:
        """Enough replicas that are both agreeing *and* internally valid.

        Agreement alone is not enough. Compromise two of three and the tampered pair
        agree with each other, so a head-count would call them the majority. But
        rewriting a receipt breaks the recipient's ML-DSA-65 signature over it, and no
        number of captured validators can forge that -- so the tampered replicas fail
        their own verification and are not counted. That is the property the
        requirement actually asks for.
        """
        return len(set(self.agreeing) & set(self.valid)) >= self.quorum

    def to_json(self) -> dict[str, Any]:
        return {
            "nodes": self.nodes,
            "quorum": self.quorum,
            "height": self.height,
            "agreeing": self.agreeing,
            "diverged": self.diverged,
            "valid": self.valid,
            "node_heads": {str(k): v for k, v in self.node_heads.items()},
            "committed": self.committed,
            "ok": self.ok,
            "honest_majority": self.honest_majority,
            "problems": self.problems,
        }


# ---------------------------------------------------------------------------
# a validator
# ---------------------------------------------------------------------------


class ValidatorNode:
    """One independent holder of the chain.

    It does not trust the submitter. Every receipt is re-verified against the
    recipient's own public key before this node will hold it, and every block header is
    recomputed from this node's own replica before this node will sign it. A node that
    signed whatever it was handed would add a signature but no security.
    """

    def __init__(self, index: int, sig_pk: bytes, sig_sk: bytes, clock: Clock | None = None):
        self.index = index
        self.sig_pk = sig_pk
        self._sig_sk = sig_sk
        self.ledger = Ledger(clock=clock or SystemClock())
        self.blocks: list[Block] = []

    # -- state ---------------------------------------------------------------

    def state_root(self) -> str:
        """Merkle root over every receipt this node holds, recomputed from contents.

        Recomputed, not read from the stored ``entry_hash``: an attacker who edits a
        record also updates that field, so trusting it would hide exactly the change
        this is here to expose.
        """
        if not self.ledger.entries:
            return GENESIS_HASH
        return merkle_root([e.compute_hash() for e in self.ledger.entries])

    @property
    def head(self) -> str:
        """This node's view of the tip: last committed block plus current state.

        Honest nodes always agree on it. A node whose replica has been edited does not,
        which is the whole detection mechanism.
        """
        return pqc.canonical_hash(
            {
                "block": self.blocks[-1].block_hash() if self.blocks else GENESIS_HASH,
                "state": self.state_root(),
            }
        )

    @property
    def height(self) -> int:
        return len(self.blocks)

    # -- consensus -----------------------------------------------------------

    def accept(self, record: dict[str, Any], signature: bytes, sig_pk: bytes) -> bool:
        """Independently validate a receipt, then hold its own copy of it.

        The deep copy is not defensive tidiness, it is what makes these replicas. Share
        one record object between the nodes and editing it at one node edits it at all
        of them -- the network would then look perfectly consistent while every copy had
        been rewritten at once, which is precisely the failure it exists to detect.

        False means this node rejected the receipt: it is not in this replica, and this
        node will not vote for any block claiming to contain it.
        """
        try:
            self.ledger.append(copy.deepcopy(record), signature, sig_pk)
        except ValueError:
            return False
        return True

    def propose(self, at: str) -> Block | None:
        """Build the next block from whatever this node holds and has not yet sealed."""
        start = self.blocks[-1].to_seq + 1 if self.blocks else 0
        pending = [e for e in self.ledger.entries if e.seq >= start]
        if not pending:
            return None
        return Block(
            height=len(self.blocks),
            prev_block_hash=self.blocks[-1].block_hash() if self.blocks else GENESIS_HASH,
            merkle_root=merkle_root([e.compute_hash() for e in pending]),
            state_root=self.state_root(),
            from_seq=start,
            to_seq=pending[-1].seq,
            at=at,
        )

    def vote(self, block: Block) -> str | None:
        """Sign the block only if this node's own replica reproduces it exactly.

        This is the whole point of replication. A node asked to endorse a block whose
        root it cannot recompute from its own entries refuses, so a rewritten history
        cannot collect signatures from honest nodes.
        """
        mine = self.propose(block.at)
        if mine is None:
            return None
        if (
            mine.height != block.height
            or mine.prev_block_hash != block.prev_block_hash
            or mine.merkle_root != block.merkle_root
            or mine.state_root != block.state_root
            or mine.from_seq != block.from_seq
            or mine.to_seq != block.to_seq
        ):
            return None
        return pqc.sig_sign(pqc.canonical(block.header()), self._sig_sk).hex()

    def commit(self, block: Block) -> None:
        self.blocks.append(block)

    # -- persistence ---------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "sig_pk": _b64(self.sig_pk),
            "ledger": self.ledger.to_json(),
            "blocks": [b.to_json() for b in self.blocks],
        }

    def load_json(self, obj: dict[str, Any]) -> None:
        self.ledger = Ledger.from_json(obj.get("ledger", {}), clock=self.ledger.clock)
        self.blocks = [Block.from_json(b) for b in obj.get("blocks", [])]


# ---------------------------------------------------------------------------
# the network
# ---------------------------------------------------------------------------


class LedgerNetwork:
    """n validators, k-of-n to commit. Offline, permissioned, no ordering service."""

    def __init__(
        self,
        keys: Sequence[tuple[bytes, bytes]],
        quorum: int,
        clock: Clock | None = None,
    ):
        if not keys:
            raise ValueError("a ledger network needs at least one validator")
        if not 1 <= quorum <= len(keys):
            raise ValueError(f"a {quorum}-of-{len(keys)} rule is not satisfiable")
        self.clock: Clock = clock or SystemClock()
        self.quorum = quorum
        self.nodes = [
            ValidatorNode(i, pk, sk, clock=self.clock) for i, (pk, sk) in enumerate(keys)
        ]

    @property
    def validator_public_keys(self) -> list[bytes]:
        return [n.sig_pk for n in self.nodes]

    # -- writing -------------------------------------------------------------

    def submit(self, record: dict[str, Any], signature: bytes, sig_pk: bytes) -> int:
        """Broadcast a receipt. Returns how many validators independently accepted it.

        Raises if fewer than the quorum would hold it -- a receipt a quorum will not
        accept is not in the ledger, and pretending otherwise is how an audit layer
        starts lying.
        """
        accepted = sum(node.accept(record, signature, sig_pk) for node in self.nodes)
        if accepted < self.quorum:
            raise ValueError(
                f"only {accepted} of {len(self.nodes)} validators accepted this receipt; "
                f"{self.quorum} required"
            )
        return accepted

    def seal_block(self) -> Block | None:
        """Propose the next block and collect votes. Commits at quorum, or not at all."""
        at = self.clock.now()
        proposal = self.nodes[0].propose(at)
        if proposal is None:
            return None

        votes = [v for v in (node.vote(proposal) for node in self.nodes) if v]
        if len(votes) < self.quorum:
            return None

        committed = Block(**{**proposal.__dict__, "votes": votes})
        for node in self.nodes:
            node.commit(committed)
        return committed

    # -- reading -------------------------------------------------------------

    def count_votes(self, block: Block) -> int:
        """Distinct recognised validators that signed this block header."""
        body = pqc.canonical(block.header())
        raw = []
        for vote in block.votes:
            try:
                raw.append(bytes.fromhex(vote))
            except ValueError:
                continue
        good = 0
        for pk in self.validator_public_keys:
            if any(pqc.sig_verify(body, sig, pk) for sig in raw):
                good += 1
        return good

    def consensus(self) -> ConsensusReport:
        """Compare every replica. Divergence is the signal a node has been tampered with."""
        heads = {n.index: n.head for n in self.nodes}
        tally: dict[str, list[int]] = {}
        for index, head in heads.items():
            tally.setdefault(head, []).append(index)
        majority_head, agreeing = max(tally.items(), key=lambda kv: len(kv[1]))
        diverged = sorted(i for i in heads if i not in agreeing)

        problems: list[str] = []
        valid: list[int] = []
        for node in self.nodes:
            report = node.ledger.verify_chain()
            if report.ok:
                valid.append(node.index)
            else:
                problems.append(f"validator {node.index}: {report.problems[0]}")

        trusted = sorted(set(agreeing) & set(valid))
        height = max((n.height for n in self.nodes), default=0)
        committed = True
        reference = next((n for n in self.nodes if n.index in trusted), None)
        if reference is not None and reference.blocks:
            committed = self.count_votes(reference.blocks[-1]) >= self.quorum
        elif height == 0:
            committed = False

        return ConsensusReport(
            nodes=len(self.nodes),
            quorum=self.quorum,
            height=height,
            agreeing=sorted(agreeing),
            diverged=diverged,
            valid=valid,
            node_heads=heads,
            committed=committed,
            problems=problems,
        )

    def canonical_ledger(self) -> Ledger:
        """The chain the honest majority holds. Reads go here, not to node 0."""
        report = self.consensus()
        trusted = set(report.agreeing) & set(report.valid)
        for node in self.nodes:
            if node.index in trusted:
                return node.ledger
        for node in self.nodes:
            if node.index in report.valid:
                return node.ledger
        return self.nodes[0].ledger

    def find_by_commitment(self, commitment: str) -> Entry | None:
        return self.canonical_ledger().find_by_commitment(commitment)

    def inclusion_proof(self, seq: int) -> tuple[Block, list[dict[str, str]]]:
        """Prove one receipt is under a committed, quorum-signed block root."""
        ledger = self.canonical_ledger()
        node = next(n for n in self.nodes if n.ledger is ledger)
        for block in node.blocks:
            if block.from_seq <= seq <= block.to_seq:
                covered = [
                    e for e in ledger.entries if block.from_seq <= e.seq <= block.to_seq
                ]
                index = next(i for i, e in enumerate(covered) if e.seq == seq)
                return block, merkle_proof([e.entry_hash for e in covered], index)
        raise KeyError(f"receipt {seq} is not in a committed block yet")

    def verify_inclusion(self, entry_hash: str, proof, block: Block) -> bool:
        return verify_merkle_proof(entry_hash, proof, block.merkle_root)

    # -- persistence ---------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        for node in self.nodes:
            (root / f"node{node.index:02d}.json").write_bytes(
                pqc.canonical(node.to_json())
            )

    def load(self, directory: str | Path) -> "LedgerNetwork":
        import json

        root = Path(directory)
        for node in self.nodes:
            path = root / f"node{node.index:02d}.json"
            if path.exists():
                node.load_json(json.loads(path.read_bytes()))
        return self

    # -- for the demo --------------------------------------------------------

    def corrupt_node(self, index: int, seq: int, field_name: str = "doc_hash") -> dict[str, Any]:
        """Compromise one validator: rewrite a record inside that node's replica only.

        This is the attack the requirement names -- a single administrator or a single
        compromised account. The point of running it is to show that it fails: the node
        diverges, the others still hold the original, and quorum is unaffected.
        """
        node = self.nodes[index]
        if not 0 <= seq < len(node.ledger.entries):
            raise IndexError(f"validator {index} has no receipt {seq}")
        entry = node.ledger.entries[seq]
        before = entry.record.get(field_name)
        entry.record[field_name] = pqc.sha3_hex(f"tampered:{before}".encode())
        entry.entry_hash = entry.compute_hash()
        return {"node": index, "seq": seq, "field": field_name, "before": before}
