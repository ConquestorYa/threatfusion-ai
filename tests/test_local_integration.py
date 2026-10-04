import sys

import pytest


from threatfusion.local_integration import (
    MARKER,
    desktop_quote,
    install_user_integration,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux desktop/shell integration"
)


def test_integration_registers_command_and_desktop_and_preserves_shell_config(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "Install with spaces"
    root.mkdir()
    profile = home / ".bashrc"
    profile.write_text("# existing user preferences\n")
    env = {
        "PATH": "/usr/bin",
        "SHELL": "/bin/bash",
        "XDG_DATA_HOME": str(home / ".local/share"),
    }
    assert install_user_integration(root, home=home, environment=env) == {
        "command": True,
        "desktop": True,
    }
    command = home / ".local/bin/threatfusion-ai"
    assert str(root / "start") in command.read_text()
    assert command.stat().st_mode & 0o777 == 0o700
    desktop = (
        home / ".local/share/applications/io.github.ConquestorYa.ThreatFusionAI.desktop"
    )
    assert "Terminal=true" in desktop.read_text()
    assert 'Exec="' + str(root / "start") + '"' in desktop.read_text()
    assert profile.read_text().startswith("# existing user preferences\n")
    assert profile.read_text().count(MARKER) == 1
    install_user_integration(root, home=home, environment=env)
    assert profile.read_text().count(MARKER) == 1


def test_unrelated_files_and_links_are_preserved(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    command = home / ".local/bin/threatfusion-ai"
    command.parent.mkdir(parents=True)
    command.write_text("unrelated user command")
    data = home / "data"
    desktop = data / "applications/io.github.ConquestorYa.ThreatFusionAI.desktop"
    desktop.parent.mkdir(parents=True)
    target = home / "keep"
    target.write_text("unrelated desktop entry")
    desktop.symlink_to(target)
    result = install_user_integration(
        tmp_path / "install", home=home, environment={"XDG_DATA_HOME": str(data)}
    )
    assert result == {"command": False, "desktop": False}
    assert command.read_text() == "unrelated user command"
    assert target.read_text() == "unrelated desktop entry"
    assert not (home / ".profile").exists()


def test_fish_path_registration_and_existing_path(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "SHELL": "/bin/fish",
        "PATH": "/usr/bin",
        "XDG_CONFIG_HOME": str(home / "config"),
    }
    install_user_integration(tmp_path / "install", home=home, environment=env)
    assert (
        "fish_add_path" in (home / "config/fish/conf.d/threatfusion.fish").read_text()
    )
    other = tmp_path / "other"
    other.mkdir()
    install_user_integration(
        tmp_path / "install",
        home=other,
        environment={"PATH": str(other / ".local/bin")},
    )
    assert not (other / ".profile").exists()


def test_desktop_exec_escaping_handles_field_codes_and_shell_characters():
    quoted = desktop_quote('/test/a%f/$HOME/`echo hi`/"/\\/start')
    assert "%%f" in quoted
    assert "\\\\$HOME" in quoted
    assert "\\\\`" in quoted
    assert '\\\\"' in quoted
    assert "\\\\\\\\" in quoted
