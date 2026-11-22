"""Standard-library user-scoped desktop and command registration for the installer."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

MARKER = "# Managed by ThreatFusion AI installer"


def desktop_quote(value: str) -> str:
    # Desktop Exec parsing is not shell parsing. Escape both spec layers.
    if any(c in value for c in "\n\r\x00"):
        raise ValueError("invalid desktop path")
    value = value.replace("%", "%%")
    value = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("`", "\\`")
        .replace("$", "\\$")
    )
    return '"' + value.replace("\\", "\\\\") + '"'


def _managed_write(path: Path, content: str, mode: int) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and MARKER not in path.read_text()):
        return False
    # Never replace an unrelated executable or desktop entry.
    path.write_text(content)
    path.chmod(mode)
    return True


def install_user_integration(
    root: Path, *, home: Path | None = None, environment: dict | None = None
) -> dict:
    home = home or Path.home()
    env = os.environ if environment is None else environment
    data = Path(env.get("XDG_DATA_HOME", str(home / ".local/share")))
    bin_dir = home / ".local/bin"
    launcher = root / "start"
    command = bin_dir / "threatfusion-ai"
    command_ok = _managed_write(
        command,
        "#!/usr/bin/env bash\n"
        + MARKER
        + "\nexec "
        + shlex.quote(str(launcher))
        + ' "$@"\n',
        0o700,
    )
    desktop = data / "applications/io.github.ConquestorYa.ThreatFusionAI.desktop"
    desktop_ok = _managed_write(
        desktop,
        "[Desktop Entry]\n" + MARKER + "\nType=Application\nVersion=1.0\n"
        "Name=ThreatFusion AI\nComment=Local threat intelligence workspace\n"
        "Categories=Network;Security;\nTerminal=true\nIcon=security-high\n"
        "Exec=" + desktop_quote(str(launcher)) + "\n",
        0o600,
    )
    # Existing terminals cannot inherit a PATH change. New interactive shells can.
    path_line = "\n" + MARKER + '\nexport PATH="$HOME/.local/bin:$PATH"\n'
    if command_ok and str(bin_dir) not in env.get("PATH", "").split(os.pathsep):
        shell = Path(env.get("SHELL", "/bin/bash")).name
        profiles = [home / ".profile"]
        if shell == "bash":
            profiles.append(home / ".bashrc")
        elif shell == "zsh":
            profiles.append(home / ".zshrc")
        for profile in profiles:
            if not profile.is_symlink() and (
                not profile.exists() or MARKER not in profile.read_text()
            ):
                with profile.open("a") as handle:
                    handle.write(path_line)
        if shell == "fish":
            config = Path(env.get("XDG_CONFIG_HOME", str(home / ".config")))
            _managed_write(
                config / "fish/conf.d/threatfusion.fish",
                MARKER + '\nfish_add_path "$HOME/.local/bin"\n',
                0o600,
            )
    return {"command": command_ok, "desktop": desktop_ok}
