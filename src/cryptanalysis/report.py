"""Text report generation for classical cryptanalysis."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptanalysis.analyser import CipherAnalysis, analyse_cipher
from cryptanalysis.analysis.frequency import (
    format_frequency_table,
    format_ranked_frequency,
    generate_frequency_graph,
)
from cryptanalysis.analysis.kasiski import (
    format_kasiski_result,
)


@dataclass
class ReportResult:
    """Files generated for one ciphertext."""

    source: Path
    output_directory: Path
    report_path: Path
    frequency_graph_path: Path


def _heading(title: str, character: str = "=") -> str:
    """Return a text report heading."""

    return "\n".join(
        [
            title,
            character * len(title),
        ]
    )


def _format_periodic_ic(
    analysis: CipherAnalysis,
) -> str:
    """Format periodic IC results."""

    lines = [
        "Period  Average IC",
        "------  ----------",
    ]

    for result in analysis.period_ics:
        lines.append(
            f"{result.period:>6}  "
            f"{result.average_ic:.9f}"
        )

    return "\n".join(lines)


def _format_notes(
    analysis: CipherAnalysis,
    section: str,
) -> str:
    """Return notes belonging to one analysis section."""

    messages = [
        note.message
        for note in analysis.notes
        if note.section == section
    ]

    if not messages:
        return "No automated observations."

    return "\n".join(
        f"- {message}"
        for message in messages
    )


def _build_report_text(
    analysis: CipherAnalysis,
    frequency_graph_name: str,
) -> str:
    """Build the complete text report."""

    now = datetime.now(timezone.utc)

    lines: list[str] = []

    lines.extend(
        [
            _heading("CRYPTANALYSIS REPORT"),
            "",
            f"Source file: {analysis.source.name}",
            f"Generated: {now.isoformat()}",
            (
                "Original file characters: "
                f"{analysis.original_length}"
            ),
            (
                "Ciphertext A-Z characters: "
                f"{analysis.cleaned_length}"
            ),
            "",
        ]
    )

    # ---------------------------------------------------------
    # 1. INDEX OF COINCIDENCE
    # ---------------------------------------------------------

    lines.extend(
        [
            _heading(
                "1. INDEX OF COINCIDENCE",
                "-",
            ),
            "",
            (
                "Overall Index of Coincidence: "
                f"{analysis.ic.ic:.8f}"
            ),
            "",
            "Periodic IC analysis:",
            "",
            _format_periodic_ic(analysis),
            "",
            "Analysis notes:",
            _format_notes(analysis, "IC"),
            "",
        ]
    )

    # ---------------------------------------------------------
    # 2. FREQUENCY ANALYSIS
    # ---------------------------------------------------------

    lines.extend(
        [
            _heading(
                "2. FREQUENCY ANALYSIS",
                "-",
            ),
            "",
            (
                "English frequency distance: "
                f"{analysis.frequency_distance:.3f}"
            ),
            "",
            "Alphabetical frequency table:",
            "",
            format_frequency_table(
                analysis.frequency
            ),
            "",
            "Ranked frequency table:",
            "",
            format_ranked_frequency(
                analysis.frequency
            ),
            "",
            (
                "Frequency graph: "
                f"{frequency_graph_name}"
            ),
            "",
            "Analysis notes:",
            _format_notes(
                analysis,
                "Frequency",
            ),
            "",
        ]
    )

    # ---------------------------------------------------------
    # 3. KASISKI EXAMINATION
    # ---------------------------------------------------------

    lines.extend(
        [
            _heading(
                "3. KASISKI EXAMINATION",
                "-",
            ),
            "",
        ]
    )

    for result in analysis.kasiski:
        lines.extend(
            [
                (
                    f"{result.sequence_length}-gram "
                    "analysis"
                ),
                "~" * 30,
                "",
                format_kasiski_result(
                    result,
                    max_sequences=50,
                ),
                "",
            ]
        )

    lines.extend(
        [
            "Analysis notes:",
            _format_notes(
                analysis,
                "Kasiski",
            ),
            "",
        ]
    )

    # ---------------------------------------------------------
    # 4. INITIAL ASSESSMENT
    # ---------------------------------------------------------

    lines.extend(
        [
            _heading(
                "4. INITIAL ASSESSMENT",
                "-",
            ),
            "",
            _format_notes(
                analysis,
                "Assessment",
            ),
            "",
            (
                "NOTE: This assessment is generated from "
                "statistical evidence and should be treated "
                "as guidance for the attack stage rather "
                "than a definitive cipher classification."
            ),
            "",
        ]
    )

    # Placeholder for attack modules.
    lines.extend(
        [
            _heading(
                "5. CRYPTANALYSIS ATTACKS",
                "-",
            ),
            "",
            (
                "Attack modules have not yet been executed "
                "for this report."
            ),
            "",
        ]
    )

    return "\n".join(lines)


def generate_report(
    source: str | Path,
    output_root: str | Path,
    minimum_period: int = 5,
    maximum_period: int = 15,
) -> ReportResult:
    """
    Analyse one ciphertext and generate its report files.
    """

    source = Path(source)
    output_root = Path(output_root)

    analysis = analyse_cipher(
        source,
        minimum_period=minimum_period,
        maximum_period=maximum_period,
    )

    # Use the input filename without extension as its
    # individual results directory.
    output_directory = (
        output_root / source.stem
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    frequency_graph_path = (
        output_directory / "frequency.png"
    )

    generate_frequency_graph(
        analysis.frequency,
        frequency_graph_path,
    )

    report_path = (
        output_directory / "report.txt"
    )

    report_text = _build_report_text(
        analysis,
        frequency_graph_path.name,
    )

    report_path.write_text(
        report_text,
        encoding="utf-8",
    )

    return ReportResult(
        source=source,
        output_directory=output_directory,
        report_path=report_path,
        frequency_graph_path=frequency_graph_path,
    )


def generate_directory_reports(
    input_directory: str | Path,
    output_directory: str | Path,
    minimum_period: int = 5,
    maximum_period: int = 15,
) -> list[ReportResult]:
    """
    Generate reports for every .txt ciphertext in a directory.
    """

    input_directory = Path(input_directory)
    output_directory = Path(output_directory)

    if not input_directory.exists():
        raise FileNotFoundError(
            f"Input directory does not exist: "
            f"{input_directory}"
        )

    if not input_directory.is_dir():
        raise NotADirectoryError(
            f"Input path is not a directory: "
            f"{input_directory}"
        )

    ciphertext_files = sorted(
        path
        for path in input_directory.iterdir()
        if path.is_file()
        and path.suffix.lower() == ".txt"
    )

    results = []

    for source in ciphertext_files:
        print(f"Analysing {source.name}...")

        try:
            result = generate_report(
                source=source,
                output_root=output_directory,
                minimum_period=minimum_period,
                maximum_period=maximum_period,
            )

        except Exception as error:
            print(
                f"  ERROR: {source.name}: {error}"
            )
            continue

        results.append(result)

        print(
            f"  Report: {result.report_path}"
        )

    return results
