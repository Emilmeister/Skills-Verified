import logging
import time
from collections.abc import Callable
from pathlib import Path

from skills_verified.core.models import Finding

logger = logging.getLogger(__name__)


def reduce_context(
    file_path: Path,
    seed_finding: Finding,
    repo_path: Path,
    probe: Callable[[str], bool],
    max_iterations: int = 50,
    timeout_seconds: float = 30.0,
) -> str:
    """Return a minimal fragment of file_path for which probe() still returns True.

    Delta-debugging-lite: iteratively removes chunks of lines while the probe
    keeps signalling the vulnerability. The seed_finding.line_number is kept
    as an anchor and never removed.
    """
    try:
        full_text = file_path.read_text(errors="ignore")
    except OSError:
        return ""

    lines = full_text.splitlines(keepends=True)
    if not lines:
        return full_text

    anchor_idx: int | None = None
    if seed_finding.line_number is not None:
        if 1 <= seed_finding.line_number <= len(lines):
            anchor_idx = seed_finding.line_number - 1
        else:
            logger.warning(
                "seed_finding anchor line %s out of range for %s",
                seed_finding.line_number,
                file_path,
            )
            return full_text

    if not _safe_probe(probe, full_text):
        return full_text

    kept = list(range(len(lines)))
    deadline = time.monotonic() + timeout_seconds
    iterations = 0
    n = 2

    while iterations < max_iterations and time.monotonic() < deadline:
        if len(kept) <= 1:
            break
        chunk_size = max(1, len(kept) // n)
        changed = False
        i = 0
        while i < len(kept):
            if time.monotonic() >= deadline or iterations >= max_iterations:
                break
            chunk = set(kept[i : i + chunk_size])
            if anchor_idx is not None:
                chunk.discard(anchor_idx)
            if not chunk:
                i += chunk_size
                continue
            candidate = [idx for idx in kept if idx not in chunk]
            candidate_text = "".join(lines[idx] for idx in candidate)
            iterations += 1
            if _safe_probe(probe, candidate_text):
                kept = candidate
                changed = True
                break
            i += chunk_size
        if not changed:
            if n >= len(kept):
                break
            n = min(n * 2, len(kept))

    return "".join(lines[idx] for idx in kept)


def _safe_probe(probe: Callable[[str], bool], text: str) -> bool:
    try:
        return bool(probe(text))
    except Exception:
        logger.debug("probe raised; treating as False", exc_info=True)
        return False
