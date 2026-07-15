import logging
import re
from pathlib import Path

from skills_verified.analyzers.shell_utils import detect_shell_dialect
from skills_verified.core.analyzer import Analyzer
from skills_verified.core.models import Category, Diagnostic, Finding, Severity
from skills_verified.repo import collect_safe_files, safe_read_text

logger = logging.getLogger(__name__)

SCAN_EXTENSIONS = {".py", ".js", ".ts"}

# Maps permission category -> list of compiled regex patterns that indicate usage.
PERMISSION_PATTERNS: dict[str, list[re.Pattern]] = {
    "network": [
        re.compile(r"\brequests\."),
        re.compile(r"\burllib\."),
        re.compile(r"\bhttpx\."),
        re.compile(r"\bfetch\s*\("),
        re.compile(r"\bsocket\.socket\b"),
        re.compile(r"\bhttp\.client\b"),
    ],
    "filesystem": [
        re.compile(r"\bopen\s*\("),
        re.compile(r"\bPath\s*\("),
        re.compile(r"\bos\.path\b"),
        re.compile(r"\bshutil\."),
        re.compile(r"\bos\.remove\b"),
        re.compile(r"\bos\.unlink\b"),
        re.compile(r"\bos\.mkdir\b"),
        re.compile(r"\bos\.makedirs\b"),
        re.compile(r"\bos\.rename\b"),
    ],
    "shell": [
        re.compile(r"\bsubprocess\."),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bos\.popen\s*\("),
        re.compile(r"\bos\.exec"),
    ],
    "process": [
        re.compile(r"\bos\.kill\s*\("),
        re.compile(r"\bos\.fork\s*\("),
        re.compile(r"\bsignal\."),
        re.compile(r"\bmultiprocessing\."),
    ],
    "env": [
        re.compile(r"\bos\.environ\b"),
        re.compile(r"\bos\.getenv\b"),
        re.compile(r"\bdotenv\b"),
    ],
}

DANGEROUS_COMBINATION = {"network", "shell", "filesystem"}
PERMISSION_CATEGORIES = set(PERMISSION_PATTERNS)


class PrivilegeAnalyzer(Analyzer):
    name = "privilege"

    def __init__(self) -> None:
        self.diagnostics: list[Diagnostic] = []

    def is_available(self) -> bool:
        return True

    def analyze(self, repo_path: Path, **kwargs) -> list[Finding]:
        self.diagnostics = []
        context = kwargs.get("context")
        all_metadata = list(
            kwargs.get("metadata")
            or getattr(context, "metadata", [])
            or [
                item
                for item in (kwargs.get("platforms") or [])
                if hasattr(item, "permissions_declared")
            ]
        )

        if not all_metadata:
            return []

        findings: list[Finding] = []
        inventory_files = getattr(context, "files", None)
        if inventory_files is None:
            inventory_files = list(collect_safe_files(repo_path).files)
        files_by_root = self._index_files_by_skill_root(
            repo_path, inventory_files, all_metadata
        )
        for metadata in all_metadata:
            declared = set(metadata.permissions_declared or []) & PERMISSION_CATEGORIES
            if not declared:
                # Cannot compare without declarations.
                continue

            # Determine entry points to scan.  If the metadata provides
            # specific entry points, scan those; otherwise scan the entire
            # repo for the supported extensions.
            entry_points = getattr(metadata, "entry_points", None) or []
            skill_root = getattr(metadata, "skill_root", None)
            scoped_inventory = (
                files_by_root.get(Path(skill_root), [])
                if skill_root is not None
                else inventory_files
            )
            files_to_scan = self._collect_files(
                repo_path,
                entry_points,
                skill_root,
                scoped_inventory,
            )

            # Detect actual permission usage across scanned files.
            detected = self._detect_permissions(files_to_scan, repo_path)

            detected_categories = set(detected.keys())
            skill_name = getattr(metadata, "name", None) or "unknown"

            # Undeclared access: code uses permission not listed in declared.
            for perm in sorted(detected_categories - declared):
                sample_files = detected[perm][:3]
                sample_desc = ", ".join(sample_files)
                findings.append(
                    Finding(
                        title=f"Undeclared permission usage: {perm}",
                        description=(
                            f"Skill '{skill_name}' uses '{perm}' capabilities but does not "
                            f"declare this permission. Detected in: {sample_desc}."
                        ),
                        severity=Severity.HIGH,
                        category=Category.PERMISSIONS,
                        file_path=sample_files[0] if sample_files else None,
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.9,
                    )
                )

            # Over-privilege: declared but not actually used.
            for perm in sorted(declared - detected_categories):
                findings.append(
                    Finding(
                        title=f"Over-privileged declaration: {perm}",
                        description=(
                            f"Skill '{skill_name}' declares '{perm}' permission but "
                            f"no matching code patterns were detected. Consider removing "
                            f"the unnecessary permission declaration."
                        ),
                        severity=Severity.LOW,
                        category=Category.PERMISSIONS,
                        file_path=None,
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.7,
                    )
                )

            # Dangerous combination: network + shell + filesystem all used.
            if DANGEROUS_COMBINATION.issubset(detected_categories):
                findings.append(
                    Finding(
                        title="Dangerous permission combination detected",
                        description=(
                            f"Skill '{skill_name}' uses network, shell, and filesystem "
                            f"permissions together. This combination enables download-and-execute "
                            f"attack patterns and warrants careful review."
                        ),
                        severity=Severity.HIGH,
                        category=Category.PERMISSIONS,
                        file_path=None,
                        line_number=None,
                        analyzer=self.name,
                        confidence=0.85,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _index_files_by_skill_root(
        repo_path: Path,
        inventory_files: list[Path] | tuple[Path, ...],
        metadata_items: list,
    ) -> dict[Path, list[Path]]:
        roots = {
            Path(root)
            for metadata in metadata_items
            if (root := getattr(metadata, "skill_root", None)) is not None
        }
        indexed = {root: [] for root in roots}
        for path in inventory_files:
            try:
                relative = path.relative_to(repo_path)
            except ValueError:
                continue
            parent = relative.parent
            while True:
                if parent in roots:
                    indexed[parent].append(path)
                    break
                if parent == Path("."):
                    break
                parent = parent.parent
        return indexed

    def _collect_files(
        self,
        repo_path: Path,
        entry_points: list[Path],
        skill_root: Path | None = None,
        inventory_files: list[Path] | tuple[Path, ...] | None = None,
    ) -> list[Path]:
        """Collect files to scan for permission patterns."""
        inventory = collect_safe_files(repo_path) if inventory_files is None else None
        files = inventory.files if inventory is not None else inventory_files
        inventory_root = inventory.root if inventory is not None else repo_path
        supported = [
            path
            for path in files
            if path.suffix in SCAN_EXTENSIONS or detect_shell_dialect(path) is not None
        ]
        if not entry_points:
            if skill_root is None or skill_root == Path("."):
                return supported
            return [
                path
                for path in supported
                if (relative := path.relative_to(inventory_root)) == skill_root
                or skill_root in relative.parents
            ]

        allowed_roots: list[Path] = []
        for entry_point in entry_points:
            if entry_point.is_absolute() or ".." in entry_point.parts:
                continue
            allowed_roots.append(entry_point)

        selected: list[Path] = []
        for path in supported:
            relative = path.relative_to(inventory_root)
            if any(
                relative == root or root in relative.parents for root in allowed_roots
            ):
                selected.append(path)

        # Preserve the legacy fallback while keeping it inside the safe inventory.
        return selected or supported

    def _detect_permissions(
        self,
        files: list[Path],
        repo_path: Path,
    ) -> dict[str, list[str]]:
        """Scan files and return a mapping of detected permission -> list of relative file paths."""
        detected: dict[str, list[str]] = {}

        for file_path in files:
            try:
                content = safe_read_text(file_path, repo_path)
            except (OSError, ValueError) as exc:
                self.diagnostics.append(
                    Diagnostic(
                        code="privilege_file_read_failed",
                        message=f"Could not read file for permission analysis: {type(exc).__name__}",
                        analyzer=self.name,
                        path=(
                            file_path.relative_to(repo_path).as_posix()
                            if file_path.is_relative_to(repo_path)
                            else None
                        ),
                    )
                )
                continue

            try:
                rel_str = str(file_path.relative_to(repo_path))
            except ValueError:
                rel_str = str(file_path)

            if detect_shell_dialect(file_path) is not None:
                detected.setdefault("shell", [])
                if rel_str not in detected["shell"]:
                    detected["shell"].append(rel_str)

            for perm_name, patterns in PERMISSION_PATTERNS.items():
                for pat in patterns:
                    if pat.search(content):
                        detected.setdefault(perm_name, [])
                        if rel_str not in detected[perm_name]:
                            detected[perm_name].append(rel_str)
                        break  # One match per permission category per file suffices.

        return detected
