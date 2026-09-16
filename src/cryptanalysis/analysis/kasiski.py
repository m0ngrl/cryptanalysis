"""Kasiski examination for periodic classical ciphers."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import combinations

from cryptanalysis.analysis.ic import clean_text


@dataclass
class RepeatedSequence:
    """One repeated ciphertext sequence."""

    sequence: str
    length: int
    positions: list[int]
    distances: list[int]


@dataclass
class FactorCount:
    """Number of Kasiski distances divisible by a candidate factor."""

    factor: int
    count: int
    percentage: float


@dataclass
class KasiskiResult:
    """Complete result for one n-gram length."""

    sequence_length: int
    repeated_sequences: list[RepeatedSequence]
    distance_count: int
    factor_counts: list[FactorCount]


def find_repeated_sequences(
    text: str,
    sequence_length: int,
) -> list[RepeatedSequence]:
    """
    Find all repeated sequences of a specified length.

    Positions are zero-based indexes into the cleaned ciphertext.
    Distances are calculated between every pair of occurrences.
    """

    if sequence_length < 2:
        raise ValueError("Sequence length must be at least 2")

    text = clean_text(text)

    positions_by_sequence: dict[str, list[int]] = defaultdict(list)

    for position in range(len(text) - sequence_length + 1):
        sequence = text[
            position:position + sequence_length
        ]

        positions_by_sequence[sequence].append(position)

    repeated = []

    for sequence, positions in positions_by_sequence.items():
        if len(positions) < 2:
            continue

        distances = [
            second - first
            for first, second in combinations(positions, 2)
        ]

        repeated.append(
            RepeatedSequence(
                sequence=sequence,
                length=sequence_length,
                positions=positions,
                distances=distances,
            )
        )

    # Most frequently repeated sequences first.
    # For equal occurrence counts, use alphabetical order
    # to keep reports deterministic.
    repeated.sort(
        key=lambda item: (
            -len(item.positions),
            item.sequence,
        )
    )

    return repeated


def count_distance_factors(
    repeated_sequences: list[RepeatedSequence],
    minimum_factor: int = 5,
    maximum_factor: int = 15,
) -> list[FactorCount]:
    """
    Count how often candidate key lengths divide Kasiski distances.

    A repeated sequence occurring at positions p1 and p2 has
    distance d = p2 - p1. For a periodic substitution cipher,
    factors of repeated-sequence distances can indicate possible
    key lengths.
    """

    if minimum_factor < 2:
        raise ValueError("Minimum factor must be at least 2")

    if maximum_factor < minimum_factor:
        raise ValueError(
            "Maximum factor must be >= minimum factor"
        )

    distances = [
        distance
        for item in repeated_sequences
        for distance in item.distances
    ]

    total = len(distances)

    factor_counter = Counter()

    for distance in distances:
        for factor in range(
            minimum_factor,
            maximum_factor + 1,
        ):
            if distance % factor == 0:
                factor_counter[factor] += 1

    results = []

    for factor in range(
        minimum_factor,
        maximum_factor + 1,
    ):
        count = factor_counter[factor]

        percentage = (
            (count / total) * 100
            if total
            else 0.0
        )

        results.append(
            FactorCount(
                factor=factor,
                count=count,
                percentage=percentage,
            )
        )

    return results


def analyse_kasiski(
    text: str,
    sequence_length: int,
    minimum_factor: int = 5,
    maximum_factor: int = 15,
) -> KasiskiResult:
    """Perform a Kasiski examination for one sequence length."""

    repeated = find_repeated_sequences(
        text,
        sequence_length,
    )

    factor_counts = count_distance_factors(
        repeated,
        minimum_factor,
        maximum_factor,
    )

    distance_count = sum(
        len(item.distances)
        for item in repeated
    )

    return KasiskiResult(
        sequence_length=sequence_length,
        repeated_sequences=repeated,
        distance_count=distance_count,
        factor_counts=factor_counts,
    )


def analyse_kasiski_range(
    text: str,
    minimum_sequence_length: int = 3,
    maximum_sequence_length: int = 5,
    minimum_factor: int = 5,
    maximum_factor: int = 15,
) -> list[KasiskiResult]:
    """Run Kasiski analysis over several n-gram lengths."""

    if maximum_sequence_length < minimum_sequence_length:
        raise ValueError(
            "Maximum sequence length must be >= minimum"
        )

    return [
        analyse_kasiski(
            text=text,
            sequence_length=length,
            minimum_factor=minimum_factor,
            maximum_factor=maximum_factor,
        )
        for length in range(
            minimum_sequence_length,
            maximum_sequence_length + 1,
        )
    ]


def ranked_factors(
    result: KasiskiResult,
) -> list[FactorCount]:
    """Return candidate factors ranked by number of matches."""

    return sorted(
        result.factor_counts,
        key=lambda item: (
            -item.count,
            item.factor,
        ),
    )


def format_kasiski_result(
    result: KasiskiResult,
    max_sequences: int = 50,
) -> str:
    """Create human-readable Kasiski output for reports."""

    lines = [
        f"Sequence length: {result.sequence_length}",
        (
            "Repeated sequences: "
            f"{len(result.repeated_sequences)}"
        ),
        f"Distances analysed: {result.distance_count}",
        "",
        "Repeated sequences:",
        "Sequence  Occurrences  Positions  Distances",
        "--------  -----------  ---------  ---------",
    ]

    for item in result.repeated_sequences[:max_sequences]:
        positions = ",".join(
            str(position)
            for position in item.positions
        )

        distances = ",".join(
            str(distance)
            for distance in item.distances
        )

        lines.append(
            f"{item.sequence:<8}  "
            f"{len(item.positions):>11}  "
            f"{positions:<9}  "
            f"{distances}"
        )

    if len(result.repeated_sequences) > max_sequences:
        omitted = (
            len(result.repeated_sequences)
            - max_sequences
        )

        lines.append(
            f"... {omitted} additional repeated sequences omitted"
        )

    lines.extend(
        [
            "",
            "Candidate key-length factors:",
            "Factor  Count  Percentage",
            "------  -----  ----------",
        ]
    )

    for item in ranked_factors(result):
        lines.append(
            f"{item.factor:>6}  "
            f"{item.count:>5}  "
            f"{item.percentage:>9.2f}%"
        )

    return "\n".join(lines)
