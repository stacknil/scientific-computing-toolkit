from __future__ import annotations

import argparse
import gzip
import os
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path


_VOLATILE_PAX_HEADERS = {"atime", "ctime", "mtime"}


def normalize_sdist(path: Path, *, epoch: int) -> None:
    if epoch < 0:
        raise ValueError("epoch must be non-negative")

    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"source distribution not found: {path}")
    if not resolved.name.endswith(".tar.gz"):
        raise ValueError(f"source distribution must end with .tar.gz: {path}")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=resolved.parent,
            prefix=f".{resolved.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            with tarfile.open(resolved, mode="r:gz") as source:
                members = sorted(source.getmembers(), key=lambda member: member.name)
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=temporary,
                    mtime=epoch,
                ) as compressed:
                    with tarfile.open(
                        fileobj=compressed,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as destination:
                        for member in members:
                            content = source.extractfile(member) if member.isfile() else None
                            try:
                                member.mtime = epoch
                                member.pax_headers = {
                                    key: value
                                    for key, value in member.pax_headers.items()
                                    if key not in _VOLATILE_PAX_HEADERS
                                }
                                destination.addfile(member, content)
                            finally:
                                if content is not None:
                                    content.close()

        temporary_path.replace(resolved)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize gzip and tar timestamps in Python source distributions.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Source distribution .tar.gz files.")
    parser.add_argument(
        "--epoch",
        type=int,
        default=None,
        help="Timestamp to record. Defaults to SOURCE_DATE_EPOCH.",
    )
    args = parser.parse_args(argv)

    epoch = args.epoch
    if epoch is None:
        value = os.environ.get("SOURCE_DATE_EPOCH")
        if value is None:
            parser.error("--epoch or SOURCE_DATE_EPOCH is required")
        try:
            epoch = int(value)
        except ValueError:
            parser.error("SOURCE_DATE_EPOCH must be an integer")

    for path in args.paths:
        normalize_sdist(path, epoch=epoch)
        print(f"normalized reproducible sdist: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
