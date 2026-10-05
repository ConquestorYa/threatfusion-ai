"""Prepare pinned RITA comparison assets in a new local directory, without sudo.

Downloaded upstream assets retain their own license and stay outside Git.
No installer, host service, feed collection or container is executed here.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path

VERSION = "v5.1.2"
ARCHIVE_SHA256 = "c77d99842877439dac5b460b4b17d081f21e32eab40263dfade32ccc81afaec0"
URL = f"https://github.com/activecm/rita/releases/download/{VERSION}/rita-{VERSION}.tar.gz"


def configure(original: str) -> str:
    replacements = [
        (r'"update_check_enabled": true', '"update_check_enabled": false'),
        (r'"online_feeds": \[.*?\]', '"online_feeds": []'),
        (r'"internal_subnets": \[.*?\]', '"internal_subnets": ["198.18.1.0/24"]'),
    ]
    text = original
    for pattern, replacement in replacements:
        text, count = re.subn(pattern, replacement, text, flags=re.S)
        if count != 1:
            raise ValueError("Unexpected upstream configuration layout")
    if text.split('"scoring":', 1)[1] != original.split('"scoring":', 1)[1]:
        raise ValueError("Scoring/modifier configuration unexpectedly changed")
    return text


def prepare(output: Path, archive: Path | None = None):
    if output.exists():
        raise FileExistsError("Existing runtime directory preserved; choose a new output directory")
    if archive:
        if archive.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Unexpected release archive size")
        data = archive.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(10 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("RITA release SHA-256 mismatch; no files extracted")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    package = output / "upstream-release.tar.gz"
    package.write_bytes(data)
    with tarfile.open(package) as tar:
        tar.extractall(output / "upstream", filter="data")
    upstream = output / "upstream" / f"rita-{VERSION}-installer" / "files"
    config = configure((upstream / "etc" / "config.hjson").read_text())
    (output / "config.hjson").write_text(config)
    (output / "rita-env").write_text("# No credentials; settings are passed explicitly by the lab wrapper.\n")
    (output / "threat_intel_feeds").mkdir()
    shutil.copyfile(upstream / "etc" / "http_extensions_list.csv", output / "http_extensions_list.csv")
    shutil.copyfile(upstream / "opt" / "LICENSE", output / "UPSTREAM_LICENSE")
    for name in ["rita_lab.sh", "rita-lab-compose.yml"]:
        shutil.copyfile(Path(__file__).with_name(name), output / name)
    (output / "rita_lab.sh").chmod(0o700)
    print(f"Prepared RITA {VERSION} lab assets: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    prepare(args.output_dir, args.archive)


if __name__ == "__main__":
    main()
