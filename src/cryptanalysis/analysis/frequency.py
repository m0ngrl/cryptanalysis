"""Letter frequency analysis for classical cryptanalysis."""

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt

from cryptanalysis.analysis.ic import clean_text


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Approximate English letter frequencies (%).
# Used only as a reference for comparison/interpretation.
ENGLISH_FREQUENCIES = {
    "A": 8.17,
    "B": 1.49,
    "C": 2.78,
    "D": 4.25,
    "E": 12.70,
    "F": 2.23,
    "G": 2.02,
    "H": 6.09,
    "I": 6.97,
    "J": 0.15,
    "K": 0.77,
    "L": 4.03,
    "M": 2.41,
    "N": 6.75,
    "O": 7.51,
    "P": 1.93,
    "Q": 0.10,
    "R": 5.99,
    "S": 6.33,
    "T": 9.06,
    "U": 2.76,
    "V": 0.98,
    "W": 2.36,
    "X": 0.15,
    "Y": 1.97,
    "Z": 0.07,
}


@dataclass
class LetterFrequency:
    """Frequency information for one letter."""

    letter: str
    count: int
    percentage: float


@dataclass
class FrequencyResult:
    """Complete frequency-analysis result."""

    length: int
    frequencies: list[LetterFrequency]

    @property
    def ranked(self) -> list[LetterFrequency]:
        """Return frequencies from most to least common."""
        return sorted(
            self.frequencies,
            key=lambda item: item.count,
            reverse=True,
        )


def analyse_frequency(text: str) -> FrequencyResult:
    """Calculate A-Z counts and percentages."""

    text = clean_text(text)
    total = len(text)
    counts = Counter(text)

    frequencies = []

    for letter in ALPHABET:
        count = counts.get(letter, 0)

        percentage = (
            (count / total) * 100
            if total
            else 0.0
        )

        frequencies.append(
            LetterFrequency(
                letter=letter,
                count=count,
                percentage=percentage,
            )
        )

    return FrequencyResult(
        length=total,
        frequencies=frequencies,
    )


def frequency_distance(result: FrequencyResult) -> float:
    """
    Calculate a simple distance between ciphertext frequencies
    and normal English frequencies.

    Lower values indicate that the frequency distribution is
    closer to ordinary English.

    This is useful as supporting evidence, but must not by
    itself be treated as cipher classification.
    """

    return sum(
        abs(
            item.percentage
            - ENGLISH_FREQUENCIES[item.letter]
        )
        for item in result.frequencies
    )


def generate_frequency_graph(
    result: FrequencyResult,
    output_path: str | Path,
) -> Path:
    """
    Save a graph comparing ciphertext and English frequencies.
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    letters = [
        item.letter
        for item in result.frequencies
    ]

    ciphertext_values = [
        item.percentage
        for item in result.frequencies
    ]

    english_values = [
        ENGLISH_FREQUENCIES[letter]
        for letter in letters
    ]

    x = range(len(letters))

    plt.figure(figsize=(14, 6))

    plt.bar(
        [i - 0.2 for i in x],
        ciphertext_values,
        width=0.4,
        label="Ciphertext",
    )

    plt.bar(
        [i + 0.2 for i in x],
        english_values,
        width=0.4,
        label="English",
    )

    plt.xticks(list(x), letters)

    plt.xlabel("Letter")
    plt.ylabel("Frequency (%)")
    plt.title("Ciphertext vs English Letter Frequency")
    plt.legend()

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

    return output_path


def format_frequency_table(result: FrequencyResult) -> str:
    """Create a text table suitable for the report."""

    lines = [
        "Letter  Count  Percentage",
        "------  -----  ----------",
    ]

    for item in result.frequencies:
        lines.append(
            f"{item.letter:^6}  "
            f"{item.count:>5}  "
            f"{item.percentage:>9.3f}%"
        )

    return "\n".join(lines)


def format_ranked_frequency(result: FrequencyResult) -> str:
    """Create a most-common-first frequency table."""

    lines = [
        "Rank  Letter  Count  Percentage",
        "----  ------  -----  ----------",
    ]

    for rank, item in enumerate(result.ranked, start=1):
        lines.append(
            f"{rank:>4}  "
            f"{item.letter:^6}  "
            f"{item.count:>5}  "
            f"{item.percentage:>9.3f}%"
        )

    return "\n".join(lines)
