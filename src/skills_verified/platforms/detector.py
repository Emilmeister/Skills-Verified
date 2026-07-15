from pathlib import Path

from skills_verified.platforms.agent_skills import AgentSkillsProfile
from skills_verified.platforms.base import PlatformProfile
from skills_verified.platforms.claude_code import ClaudeCodeProfile
from skills_verified.platforms.codex import CodexProfile
from skills_verified.platforms.copilot import CopilotProfile
from skills_verified.platforms.cursor import CursorProfile
from skills_verified.platforms.gemini import GeminiProfile
from skills_verified.platforms.generic_mcp import GenericMCPProfile
from skills_verified.platforms.openclaw import OpenClawProfile


class PlatformDetector:
    def __init__(self) -> None:
        self._profiles: list[PlatformProfile] = [
            AgentSkillsProfile(),
            ClaudeCodeProfile(),
            OpenClawProfile(),
            CursorProfile(),
            CodexProfile(),
            GeminiProfile(),
            CopilotProfile(),
            GenericMCPProfile(),
        ]

    def detect(self, repo_path: Path) -> list[PlatformProfile]:
        """Return all platform profiles that match the given repository."""
        return [p for p in self._profiles if p.detect(repo_path)]
