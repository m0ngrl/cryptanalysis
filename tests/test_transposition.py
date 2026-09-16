"""Tests for transposition attacks."""

from cryptanalysis.attacks.row_transposition import (
    decrypt_row_transposition,
    exhaustive_row_attack,
)


def test_identity_row_permutation():
    ciphertext = "ABCDEFGH"

    plaintext = decrypt_row_transposition(
        ciphertext,
        width=4,
        permutation=(0, 1, 2, 3),
    )

    assert plaintext == "ABCDEFGH"


def test_row_permutation():
    ciphertext = "ABCDEFGH"

    plaintext = decrypt_row_transposition(
        ciphertext,
        width=4,
        permutation=(2, 0, 3, 1),
    )

    assert plaintext == "CADBGEHF"


def test_incomplete_final_row():
    ciphertext = "ABCDEFG"

    plaintext = decrypt_row_transposition(
        ciphertext,
        width=4,
        permutation=(2, 0, 3, 1),
    )

    assert plaintext == "CADBGEF"


def test_exhaustive_search_count():
    result = exhaustive_row_attack(
        ciphertext="THISISATESTTEXT",
        width=3,
        top_n=3,
        workers=1,
    )

    assert result.permutations_tested == 6
    assert result.total_permutations == 6
    assert len(result.candidates) == 3
