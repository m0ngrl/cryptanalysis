"""High-level attack orchestration."""

from dataclasses import dataclass
from pathlib import Path

from cryptanalysis.analysis.ic import clean_text
from cryptanalysis.attacks.column_transposition import (
    ColumnAttackResult,
    attack_column_widths,
)
from cryptanalysis.attacks.periodic import (
    PeriodicCandidate,
    attack_periodic,
)
from cryptanalysis.attacks.row_transposition import (
    RowAttackResult,
    attack_row_widths,
)


@dataclass
class CipherAttackResult:
    """Combined attack results for one ciphertext."""

    source: Path
    periodic: list[PeriodicCandidate]
    row_transposition: list[RowAttackResult]
    column_transposition: list[ColumnAttackResult]


def attack_cipher(
    source: str | Path,
    minimum_period: int = 5,
    maximum_period: int = 8,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> CipherAttackResult:
    """Run all implemented attack families on one ciphertext."""

    source = Path(source)

    raw_text = source.read_text(
        encoding="utf-8",
        errors="replace",
    )

    ciphertext = clean_text(raw_text)

    print("  Periodic attacks...")

    periodic = attack_periodic(
        ciphertext,
        minimum_period=minimum_period,
        maximum_period=maximum_period,
    )

    if periodic:
        best = periodic[0]

        print(
            f"    Best: {best.cipher_type}, "
            f"period {best.period}, "
            f"key {best.key}, "
            f"score {best.score:.6f}"
        )
        print(
            f"    Preview: {best.plaintext[:100]}"
        )

    print("  Row transposition attacks...")

    row_results = attack_row_widths(
        ciphertext,
        minimum_width=minimum_period,
        maximum_width=maximum_period,
        top_n=top_n,
        workers=workers,
        chunk_size=chunk_size,
    )

    print("  Column transposition attacks...")

    column_results = attack_column_widths(
        ciphertext,
        minimum_width=minimum_period,
        maximum_width=maximum_period,
        top_n=top_n,
        workers=workers,
        chunk_size=chunk_size,
    )

    return CipherAttackResult(
        source=source,
        periodic=periodic,
        row_transposition=row_results,
        column_transposition=column_results,
    )


def attack_directory(
    input_directory: str | Path,
    output_directory: str | Path,
    minimum_period: int = 5,
    maximum_period: int = 8,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> list[Path]:
    """
    Attack every .txt ciphertext in a directory.

    Results are written immediately after each ciphertext
    completes so completed work survives an interrupted run.
    """

    from cryptanalysis.attack_report import (
        save_attack_result,
        save_best_plaintexts,
    )

    input_directory = Path(input_directory)
    output_directory = Path(output_directory)

    if not input_directory.exists():
        raise FileNotFoundError(input_directory)

    if not input_directory.is_dir():
        raise NotADirectoryError(input_directory)

    sources = sorted(
        input_directory.glob("*.txt")
    )

    saved_reports: list[Path] = []

    total = len(sources)

    for index, source in enumerate(
        sources,
        start=1,
    ):
        print()
        print("=" * 72)
        print(
            f"[{index}/{total}] "
            f"Attacking {source.name}"
        )
        print("=" * 72)

        result = attack_cipher(
            source=source,
            minimum_period=minimum_period,
            maximum_period=maximum_period,
            top_n=top_n,
            workers=workers,
            chunk_size=chunk_size,
        )

        report = save_attack_result(
            result,
            output_directory,
        )

        save_best_plaintexts(
            result,
            output_directory,
        )

        saved_reports.append(report)

        print()
        print(f"  SAVED: {report}")

    return saved_reports
