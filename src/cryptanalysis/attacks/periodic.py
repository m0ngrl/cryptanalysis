"""Attacks against periodic substitution ciphers.

Initially supports Vigenere and Beaufort attacks using
per-column Caesar frequency analysis.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptanalysis.analysis.ic import clean_text
from cryptanalysis.scoring import score_candidate


ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
    0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074,
]


@dataclass
class PeriodicCandidate:
    cipher_type: str
    period: int
    key: str
    shifts: tuple[int, ...]
    score: float
    plaintext: str


def _letter_number(char: str) -> int:
    return ord(char) - ord("A")


def _letter_char(value: int) -> str:
    return chr((value % 26) + ord("A"))


def decrypt_vigenere(
    ciphertext: str,
    shifts: tuple[int, ...],
) -> str:
    ciphertext = clean_text(ciphertext)

    output = []

    for index, char in enumerate(ciphertext):
        cipher_value = _letter_number(char)
        shift = shifts[index % len(shifts)]

        plain_value = (cipher_value - shift) % 26

        output.append(_letter_char(plain_value))

    return "".join(output)


def decrypt_beaufort(
    ciphertext: str,
    shifts: tuple[int, ...],
) -> str:
    """
    Standard Beaufort:

        C = K - P mod 26

    therefore:

        P = K - C mod 26
    """

    ciphertext = clean_text(ciphertext)

    output = []

    for index, char in enumerate(ciphertext):
        cipher_value = _letter_number(char)
        shift = shifts[index % len(shifts)]

        plain_value = (shift - cipher_value) % 26

        output.append(_letter_char(plain_value))

    return "".join(output)


def _chi_squared(values: list[int]) -> float:
    total = sum(values)

    if total == 0:
        return float("inf")

    score = 0.0

    for observed, frequency in zip(
        values,
        ENGLISH_FREQ,
    ):
        expected = total * frequency

        if expected > 0:
            score += (
                (observed - expected) ** 2
                / expected
            )

    return score


def _caesar_shift_score(
    column: str,
    shift: int,
) -> float:
    """
    Chi-squared score after treating 'shift' as a
    Vigenere encryption shift.

    Lower is better.
    """

    counts = [0] * 26

    for char in column:
        cipher_value = _letter_number(char)
        plain_value = (cipher_value - shift) % 26

        counts[plain_value] += 1

    return _chi_squared(counts)


def candidate_shifts_for_column(
    column: str,
    count: int = 4,
) -> list[int]:
    """
    Return the most plausible Caesar shifts for one
    Vigenere column.
    """

    candidates = [
        (
            _caesar_shift_score(column, shift),
            shift,
        )
        for shift in range(26)
    ]

    candidates.sort()

    return [
        shift
        for _, shift in candidates[:count]
    ]


def recover_vigenere_key(
    ciphertext: str,
    period: int,
) -> tuple[int, ...]:
    """
    Recover the individually best Caesar shift for
    every Vigenere column.
    """

    ciphertext = clean_text(ciphertext)

    shifts = []

    for offset in range(period):
        column = ciphertext[offset::period]

        best = candidate_shifts_for_column(
            column,
            count=1,
        )[0]

        shifts.append(best)

    return tuple(shifts)


def attack_vigenere(
    ciphertext: str,
    period: int,
) -> PeriodicCandidate:
    shifts = recover_vigenere_key(
        ciphertext,
        period,
    )

    plaintext = decrypt_vigenere(
        ciphertext,
        shifts,
    )

    key = "".join(
        _letter_char(shift)
        for shift in shifts
    )

    return PeriodicCandidate(
        cipher_type="vigenere",
        period=period,
        key=key,
        shifts=shifts,
        score=score_candidate(plaintext),
        plaintext=plaintext,
    )


def attack_beaufort(
    ciphertext: str,
    period: int,
) -> PeriodicCandidate:
    """
    Recover a Beaufort candidate.

    A Beaufort column can be related to a Caesar
    transformation. We simply test all 26 possible
    key letters for each column and select the one
    whose resulting plaintext distribution best
    matches English.
    """

    ciphertext = clean_text(ciphertext)

    shifts = []

    for offset in range(period):
        column = ciphertext[offset::period]

        candidates = []

        for key_value in range(26):
            counts = [0] * 26

            for char in column:
                cipher_value = _letter_number(char)

                plain_value = (
                    key_value - cipher_value
                ) % 26

                counts[plain_value] += 1

            candidates.append(
                (
                    _chi_squared(counts),
                    key_value,
                )
            )

        candidates.sort()

        shifts.append(
            candidates[0][1]
        )

    shifts_tuple = tuple(shifts)

    plaintext = decrypt_beaufort(
        ciphertext,
        shifts_tuple,
    )

    key = "".join(
        _letter_char(shift)
        for shift in shifts_tuple
    )

    return PeriodicCandidate(
        cipher_type="beaufort",
        period=period,
        key=key,
        shifts=shifts_tuple,
        score=score_candidate(plaintext),
        plaintext=plaintext,
    )


def attack_periodic(
    ciphertext: str,
    minimum_period: int = 5,
    maximum_period: int = 15,
) -> list[PeriodicCandidate]:
    """
    Try Vigenere and Beaufort for every requested period.
    """

    candidates = []

    for period in range(
        minimum_period,
        maximum_period + 1,
    ):
        candidates.append(
            attack_vigenere(
                ciphertext,
                period,
            )
        )

        candidates.append(
            attack_beaufort(
                ciphertext,
                period,
            )
        )

    candidates.sort(
        key=lambda candidate: candidate.score,
        reverse=True,
    )

    return candidates
