from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
NORMALIZER = PROJECT_ROOT / "scripts" / "normalize_sdist.py"


def test_normalize_sdist_makes_time_variant_archives_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    epoch = 1_700_000_000
    _write_sdist(first, timestamp=epoch + 10)
    _write_sdist(second, timestamp=epoch + 20)

    for path in (first, second):
        subprocess.run(
            [sys.executable, str(NORMALIZER), "--epoch", str(epoch), str(path)],
            check=True,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
        )

    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
        assert all(member.mtime == epoch for member in members)
        content = archive.extractfile("example-1.0.0/example.txt")
        assert content is not None
        assert content.read() == b"stable content\n"


def _write_sdist(path: Path, *, timestamp: int) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=timestamp) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("example-1.0.0")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.mtime = timestamp
                directory.pax_headers = {"mtime": f"{timestamp}.25"}
                archive.addfile(directory)

                content = b"stable content\n"
                member = tarfile.TarInfo("example-1.0.0/example.txt")
                member.mode = 0o644
                member.mtime = timestamp
                member.size = len(content)
                archive.addfile(member, fileobj=io.BytesIO(content))
