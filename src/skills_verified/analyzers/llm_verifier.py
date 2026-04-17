import logging
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Finding

logger = logging.getLogger(__name__)

PatchGenerator = Callable[[Finding, str], str | None]


@dataclass
class VerificationResult:
    finding: Finding
    verified: bool
    verification_notes: str


class LlmVerifier:
    """Verify an LLM finding by generating a patch and checking that the
    deterministic analyzers stop reporting the same issue after the patch."""

    def __init__(
        self,
        static_analyzers: list[Analyzer],
        config=None,
        patch_generator: PatchGenerator | None = None,
    ):
        self.static_analyzers = static_analyzers
        self.config = config
        self._patch_generator = patch_generator

    def verify(self, repo_path: Path, llm_finding: Finding) -> VerificationResult:
        if not llm_finding.file_path:
            return VerificationResult(llm_finding, False, "no file_path on finding")

        target = repo_path / llm_finding.file_path
        if not target.is_file():
            return VerificationResult(llm_finding, False, "file not found in repo")

        try:
            content = target.read_text(errors="ignore")
        except OSError:
            return VerificationResult(llm_finding, False, "could not read file")

        line_count = len(content.splitlines())
        if llm_finding.line_number is not None and not (
            1 <= llm_finding.line_number <= line_count
        ):
            return VerificationResult(llm_finding, False, "line number out of range")

        baseline = self._findings_for_file(repo_path, llm_finding.file_path)
        if not self._matches_type(baseline, llm_finding):
            return VerificationResult(
                llm_finding,
                False,
                "no corroborating static finding (likely hallucination)",
            )

        patch = self._generate_patch(llm_finding, content)
        if patch is None or patch == content:
            return VerificationResult(
                llm_finding, False, "could not generate a patch that changes the file"
            )

        with tempfile.TemporaryDirectory(prefix="sv-verify-") as tmp:
            tmp_repo = Path(tmp) / "repo"
            try:
                shutil.copytree(repo_path, tmp_repo)
            except (OSError, shutil.Error) as e:
                return VerificationResult(
                    llm_finding, False, f"failed to copy repo: {e}"
                )
            patched_file = tmp_repo / llm_finding.file_path
            try:
                patched_file.write_text(patch)
            except OSError as e:
                return VerificationResult(
                    llm_finding, False, f"failed to apply patch: {e}"
                )
            after = self._findings_for_file(tmp_repo, llm_finding.file_path)
            if self._matches_type(after, llm_finding):
                return VerificationResult(
                    llm_finding, False, "patch applied but finding still reported"
                )
            return VerificationResult(
                llm_finding, True, "patch removes the static finding"
            )

    def _findings_for_file(self, repo_path: Path, rel_path: str) -> list[Finding]:
        results: list[Finding] = []
        for analyzer in self.static_analyzers:
            try:
                for f in analyzer.analyze(repo_path):
                    if f.file_path == rel_path:
                        results.append(f)
            except Exception:
                logger.debug("static analyzer failed during verification", exc_info=True)
        return results

    @staticmethod
    def _matches_type(findings: list[Finding], target: Finding) -> bool:
        target_title = (target.title or "").lower()
        for f in findings:
            if (f.title or "").lower() == target_title:
                return True
            if (
                target.line_number is not None
                and f.line_number is not None
                and abs(f.line_number - target.line_number) <= 5
            ):
                return True
        return False

    def _generate_patch(self, finding: Finding, content: str) -> str | None:
        if self._patch_generator is not None:
            try:
                return self._patch_generator(finding, content)
            except Exception:
                logger.exception("patch_generator failed")
                return None
        if self.config is None:
            return None
        try:
            from openai import OpenAI
        except ImportError:
            logger.warning("openai not installed; verifier cannot generate patches")
            return None
        client = OpenAI(base_url=self.config.url, api_key=self.config.key)
        prompt = (
            "You are a code fixer. Return ONLY the full patched file content, "
            "no markdown fences, no commentary. Fix the specified vulnerability "
            "while preserving all unrelated behavior.\n\n"
            f"Vulnerability: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"File: {finding.file_path}\n"
            f"Line: {finding.line_number}\n\n"
            "Original file:\n"
            f"{content}\n"
        )
        try:
            resp = client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            patched = resp.choices[0].message.content
            if not patched:
                return None
            return patched
        except Exception:
            logger.exception("LLM patch generation failed")
            return None


def filter_verified(
    verifier: LlmVerifier,
    repo_path: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Drop non-verified findings; annotate survivors with [verified] in description."""
    kept: list[Finding] = []
    for f in findings:
        result = verifier.verify(repo_path, f)
        if result.verified:
            f.description = f"[verified] {f.description}"
            kept.append(f)
        else:
            logger.info(
                "Dropped unverified LLM finding '%s' at %s:%s — %s",
                f.title, f.file_path, f.line_number, result.verification_notes,
            )
    return kept
