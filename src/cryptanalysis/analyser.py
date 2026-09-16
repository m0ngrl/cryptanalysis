"""High-level classical cipher analysis."""

from dataclasses import dataclass, field
from pathlib import Path

from cryptanalysis.analysis.frequency import (
    FrequencyResult,
    analyse_frequency,
    frequency_distance,
)
from cryptanalysis.analysis.ic import (
    ICResult,
    PeriodICResult,
    analyse_periods,
    calculate_ic,
    clean_text,
)
from cryptanalysis.analysis.kasiski import (
    KasiskiResult,
    analyse_kasiski_range,
    ranked_factors,
)


@dataclass
class AnalysisNote:
    """One human-readable analytical observation."""

    section: str
    message: str


@dataclass
class CipherAnalysis:
    """Combined analysis for one ciphertext."""

    source: Path
    original_length: int
    cleaned_length: int

    ic: ICResult
    period_ics: list[PeriodICResult]

    frequency: FrequencyResult
    frequency_distance: float

    kasiski: list[KasiskiResult]

    notes: list[AnalysisNote] = field(default_factory=list)


def analyse_cipher(
    source: str | Path,
    minimum_period: int = 5,
    maximum_period: int = 15,
) -> CipherAnalysis:
    """
    Perform all non-attack analysis on one ciphertext file.
    """

    source = Path(source)

    raw_text = source.read_text(
        encoding="utf-8",
        errors="replace",
    )

    cleaned = clean_text(raw_text)

    ic_result = calculate_ic(cleaned)

    period_results = analyse_periods(
        cleaned,
        minimum_period,
        maximum_period,
    )

    frequency_result = analyse_frequency(cleaned)

    kasiski_results = analyse_kasiski_range(
        cleaned,
        minimum_sequence_length=3,
        maximum_sequence_length=5,
        minimum_factor=minimum_period,
        maximum_factor=maximum_period,
    )

    analysis = CipherAnalysis(
        source=source,
        original_length=len(raw_text),
        cleaned_length=len(cleaned),
        ic=ic_result,
        period_ics=period_results,
        frequency=frequency_result,
        frequency_distance=frequency_distance(
            frequency_result
        ),
        kasiski=kasiski_results,
    )

    analysis.notes.extend(
        generate_notes(
            analysis,
            minimum_period,
            maximum_period,
        )
    )

    return analysis


def generate_notes(
    analysis: CipherAnalysis,
    minimum_period: int,
    maximum_period: int,
) -> list[AnalysisNote]:
    """
    Generate cautious human-readable observations.

    These are analytical hints, not definitive cipher
    classifications.
    """

    notes: list[AnalysisNote] = []

    notes.extend(
        _generate_ic_notes(
            analysis,
            minimum_period,
            maximum_period,
        )
    )

    notes.extend(
        _generate_frequency_notes(analysis)
    )

    notes.extend(
        _generate_kasiski_notes(
            analysis,
            minimum_period,
            maximum_period,
        )
    )

    notes.extend(
        _generate_combined_notes(analysis)
    )

    return notes


def _generate_ic_notes(
    analysis: CipherAnalysis,
    minimum_period: int,
    maximum_period: int,
) -> list[AnalysisNote]:
    """Interpret overall and periodic IC."""

    notes = []

    ic = analysis.ic.ic

    notes.append(
        AnalysisNote(
            section="IC",
            message=(
                f"Overall Index of Coincidence: {ic:.6f}."
            ),
        )
    )

    if ic >= 0.050:
        notes.append(
            AnalysisNote(
                section="IC",
                message=(
                    "The overall IC is substantially above the "
                    "approximately uniform random value. This is "
                    "consistent with preserved language structure, "
                    "as may occur with transposition or "
                    "monoalphabetic substitution."
                ),
            )
        )
    elif ic >= 0.042:
        notes.append(
            AnalysisNote(
                section="IC",
                message=(
                    "The overall IC is moderately above the "
                    "uniform random region. This may indicate "
                    "some retained language structure."
                ),
            )
        )
    else:
        notes.append(
            AnalysisNote(
                section="IC",
                message=(
                    "The overall IC is relatively low and closer "
                    "to the region expected from flattened letter "
                    "distributions. A periodic or polyalphabetic "
                    "substitution remains plausible."
                ),
            )
        )

    values = [
        result.average_ic
        for result in analysis.period_ics
    ]

    if values:
        highest = max(
            analysis.period_ics,
            key=lambda result: result.average_ic,
        )

        lowest = min(values)
        highest_value = max(values)
        spread = highest_value - lowest

        notes.append(
            AnalysisNote(
                section="IC",
                message=(
                    f"Periodic IC was tested for candidate key "
                    f"lengths {minimum_period}-{maximum_period}. "
                    f"The highest average IC occurred at period "
                    f"{highest.period} "
                    f"({highest.average_ic:.6f})."
                ),
            )
        )

        notes.append(
            AnalysisNote(
                section="IC",
                message=(
                    f"The spread between the highest and lowest "
                    f"periodic IC values was {spread:.6f}."
                ),
            )
        )

        if spread < 0.003:
            notes.append(
                AnalysisNote(
                    section="IC",
                    message=(
                        "Periodic IC values are very flat across "
                        "the tested range. No convincing candidate "
                        "period is indicated."
                    ),
                )
            )

    return notes


def _generate_frequency_notes(
    analysis: CipherAnalysis,
) -> list[AnalysisNote]:
    """Interpret frequency-analysis results."""

    notes = []

    ranked = analysis.frequency.ranked

    if ranked:
        top = ranked[:5]

        top_text = ", ".join(
            f"{item.letter} ({item.percentage:.2f}%)"
            for item in top
        )

        notes.append(
            AnalysisNote(
                section="Frequency",
                message=(
                    "Most frequent ciphertext letters: "
                    f"{top_text}."
                ),
            )
        )

    notes.append(
        AnalysisNote(
            section="Frequency",
            message=(
                "Absolute distance from the reference English "
                "letter-frequency distribution: "
                f"{analysis.frequency_distance:.3f}."
            ),
        )
    )

    # We deliberately avoid hard classification here.
    notes.append(
        AnalysisNote(
            section="Frequency",
            message=(
                "Frequency similarity alone does not prove a "
                "cipher type. Transposition preserves exact "
                "letter counts, while monoalphabetic substitution "
                "preserves the shape of the distribution but "
                "changes letter identities."
            ),
        )
    )

    return notes


def _generate_kasiski_notes(
    analysis: CipherAnalysis,
    minimum_period: int,
    maximum_period: int,
) -> list[AnalysisNote]:
    """Interpret Kasiski results."""

    notes = []

    for result in analysis.kasiski:
        n = result.sequence_length
        repeat_count = len(result.repeated_sequences)

        notes.append(
            AnalysisNote(
                section="Kasiski",
                message=(
                    f"{n}-gram analysis found "
                    f"{repeat_count} repeated sequences and "
                    f"{result.distance_count} pairwise distances."
                ),
            )
        )

        ranked = ranked_factors(result)

        nonzero = [
            factor
            for factor in ranked
            if factor.count > 0
        ]

        if nonzero:
            top = nonzero[:3]

            text = ", ".join(
                (
                    f"{item.factor} "
                    f"({item.count} distances, "
                    f"{item.percentage:.2f}%)"
                )
                for item in top
            )

            notes.append(
                AnalysisNote(
                    section="Kasiski",
                    message=(
                        f"Leading raw factors for {n}-grams: "
                        f"{text}."
                    ),
                )
            )
        else:
            notes.append(
                AnalysisNote(
                    section="Kasiski",
                    message=(
                        f"No repeated {n}-gram distance was "
                        f"divisible by candidate periods "
                        f"{minimum_period}-{maximum_period}."
                    ),
                )
            )

    # Give extra weight to the longest repeated sequences.
    longest = max(
        analysis.kasiski,
        key=lambda result: result.sequence_length,
        default=None,
    )

    if longest is not None:
        if len(longest.repeated_sequences) <= 1:
            notes.append(
                AnalysisNote(
                    section="Kasiski",
                    message=(
                        "Very little long repeated-sequence "
                        "evidence was found. Kasiski examination "
                        "does not provide a strong candidate "
                        "period."
                    ),
                )
            )

    return notes


def _generate_combined_notes(
    analysis: CipherAnalysis,
) -> list[AnalysisNote]:
    """
    Combine independent observations into an initial assessment.
    """

    notes = []

    periodic_values = [
        result.average_ic
        for result in analysis.period_ics
    ]

    periodic_spread = (
        max(periodic_values) - min(periodic_values)
        if periodic_values
        else 0.0
    )

    long_repeats = 0

    for result in analysis.kasiski:
        if result.sequence_length >= 5:
            long_repeats += len(
                result.repeated_sequences
            )

    if (
        analysis.ic.ic >= 0.050
        and periodic_spread < 0.003
        and long_repeats <= 1
    ):
        notes.append(
            AnalysisNote(
                section="Assessment",
                message=(
                    "The combination of a relatively high overall "
                    "IC, flat periodic IC results, and weak "
                    "long-sequence Kasiski evidence does not "
                    "strongly support a periodic substitution "
                    "cipher."
                ),
            )
        )

        notes.append(
            AnalysisNote(
                section="Assessment",
                message=(
                    "A frequency-preserving cipher such as "
                    "transposition, or a monoalphabetic "
                    "substitution, should therefore receive "
                    "priority during the attack stage."
                ),
            )
        )
    else:
        notes.append(
            AnalysisNote(
                section="Assessment",
                message=(
                    "The available statistical evidence does not "
                    "yet provide a sufficiently strong cipher "
                    "classification. Multiple attack families "
                    "should be tested."
                ),
            )
        )

    return notes
