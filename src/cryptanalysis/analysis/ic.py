"""Index of Coincidence analysis."""

from collections import Counter
from dataclasses import dataclass


@dataclass
class ICResult:
    """Result of an Index of Coincidence calculation."""

    length: int
    ic: float


@dataclass
class PeriodICResult:
    """IC results for a proposed periodic substitution length."""

    period: int
    column_ics: list[float]
    average_ic: float


def clean_text(text: str) -> str:
    """
    Return only alphabetic A-Z characters in uppercase.

    This keeps the analysis consistent when ciphertext files
    contain spaces, line breaks, or formatting.
    """
    return "".join(
        char.upper()
        for char in text
        if "A" <= char.upper() <= "Z"
    )


def calculate_ic(text: str) -> ICResult:
    """
    Calculate the Index of Coincidence.

    IC = sum(f_i * (f_i - 1)) / (N * (N - 1))
    """
    text = clean_text(text)
    n = len(text)

    if n < 2:
        return ICResult(length=n, ic=0.0)

    counts = Counter(text)

    numerator = sum(
        frequency * (frequency - 1)
        for frequency in counts.values()
    )

    denominator = n * (n - 1)

    return ICResult(
        length=n,
        ic=numerator / denominator,
    )


def calculate_period_ic(text: str, period: int) -> PeriodICResult:
    """
    Split ciphertext into `period` alphabets and calculate
    the IC of each alphabet.

    This corresponds to the type of periodic IC analysis
    performed by JKrypto.
    """
    if period < 1:
        raise ValueError("Period must be at least 1")

    text = clean_text(text)

    columns = [
        text[offset::period]
        for offset in range(period)
    ]

    column_ics = [
        calculate_ic(column).ic
        for column in columns
    ]

    average = (
        sum(column_ics) / len(column_ics)
        if column_ics
        else 0.0
    )

    return PeriodICResult(
        period=period,
        column_ics=column_ics,
        average_ic=average,
    )


def analyse_periods(
    text: str,
    minimum: int = 5,
    maximum: int = 15,
) -> list[PeriodICResult]:
    """
    Calculate periodic IC for a range of candidate key lengths.
    """
    if minimum < 1:
        raise ValueError("Minimum period must be at least 1")

    if maximum < minimum:
        raise ValueError("Maximum period must be >= minimum")

    return [
        calculate_period_ic(text, period)
        for period in range(minimum, maximum + 1)
    ]
