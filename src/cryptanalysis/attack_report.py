"""Persistence and reporting for cryptanalytic attacks."""

from pathlib import Path

from cryptanalysis.attacker import CipherAttackResult


def _display_permutation(
    permutation: tuple[int, ...],
) -> tuple[int, ...]:
    """Convert internal zero-based permutation to display form."""

    return tuple(
        value + 1
        for value in permutation
    )


def save_attack_result(
    result: CipherAttackResult,
    output_directory: str | Path,
) -> Path:
    """Save all retained attack candidates for one ciphertext."""

    output_directory = Path(output_directory)

    cipher_directory = (
        output_directory / result.source.stem
    )

    cipher_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path = (
        cipher_directory / "attack_report.txt"
    )

    lines: list[str] = []

    lines.append("Classical Cryptanalysis Attack Report")
    lines.append("=" * 36)
    lines.append("")
    lines.append(f"Source: {result.source}")
    lines.append("")

    # Periodic attacks
    lines.append("PERIODIC ATTACKS")
    lines.append("=" * 16)
    lines.append("")

    for rank, candidate in enumerate(
        result.periodic,
        start=1,
    ):
        lines.append(
            f"Candidate {rank}"
        )
        lines.append(
            f"Cipher: {candidate.cipher_type}"
        )
        lines.append(
            f"Period: {candidate.period}"
        )
        lines.append(
            f"Key: {candidate.key}"
        )
        lines.append(
            f"Score: {candidate.score:.6f}"
        )
        lines.append("Plaintext:")
        lines.append(candidate.plaintext)
        lines.append("")

    # Row transposition
    lines.append("ROW TRANSPOSITION")
    lines.append("=" * 17)
    lines.append("")

    for attack in result.row_transposition:
        lines.append(
            f"Width: {attack.width}"
        )
        lines.append(
            f"Search mode: {attack.search_mode}"
        )
        lines.append(
            "Permutations tested: "
            f"{attack.permutations_tested:,}"
        )
        lines.append(
            "Total permutations: "
            f"{attack.total_permutations:,}"
        )
        lines.append("")

        for rank, candidate in enumerate(
            attack.candidates,
            start=1,
        ):
            permutation = _display_permutation(
                candidate.permutation
            )

            lines.append(
                f"Candidate {rank}"
            )
            lines.append(
                f"Permutation: {permutation}"
            )
            lines.append(
                f"Score: {candidate.score:.6f}"
            )
            lines.append("Plaintext:")
            lines.append(candidate.plaintext)
            lines.append("")

    # Column transposition
    lines.append("COLUMN TRANSPOSITION")
    lines.append("=" * 20)
    lines.append("")

    for attack in result.column_transposition:
        lines.append(
            f"Width: {attack.width}"
        )
        lines.append(
            f"Search mode: {attack.search_mode}"
        )
        lines.append(
            "Permutations tested: "
            f"{attack.permutations_tested:,}"
        )
        lines.append(
            "Total permutations: "
            f"{attack.total_permutations:,}"
        )
        lines.append("")

        for rank, candidate in enumerate(
            attack.candidates,
            start=1,
        ):
            permutation = _display_permutation(
                candidate.permutation
            )

            lines.append(
                f"Candidate {rank}"
            )
            lines.append(
                f"Permutation: {permutation}"
            )
            lines.append(
                f"Score: {candidate.score:.6f}"
            )
            lines.append("Plaintext:")
            lines.append(candidate.plaintext)
            lines.append("")

    report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return report_path


def save_best_plaintexts(
    result: CipherAttackResult,
    output_directory: str | Path,
) -> None:
    """Save the best plaintext from each attack result separately."""

    output_directory = Path(output_directory)

    cipher_directory = (
        output_directory / result.source.stem
    )

    cipher_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    best_directory = cipher_directory / "best"

    best_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    if result.periodic:
        candidate = result.periodic[0]

        path = (
            best_directory
            / "periodic.txt"
        )

        path.write_text(
            candidate.plaintext + "\n",
            encoding="utf-8",
        )

    for attack in result.row_transposition:
        if not attack.candidates:
            continue

        candidate = attack.candidates[0]

        path = (
            best_directory
            / f"row_width_{attack.width}.txt"
        )

        path.write_text(
            candidate.plaintext + "\n",
            encoding="utf-8",
        )

    for attack in result.column_transposition:
        if not attack.candidates:
            continue

        candidate = attack.candidates[0]

        path = (
            best_directory
            / f"column_width_{attack.width}.txt"
        )

        path.write_text(
            candidate.plaintext + "\n",
            encoding="utf-8",
        )
