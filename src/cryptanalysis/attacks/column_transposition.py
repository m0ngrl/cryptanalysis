"""Column-transposition cryptanalysis."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from itertools import permutations
from math import factorial
import os
from typing import Iterable

from cryptanalysis.analysis.ic import clean_text
from cryptanalysis.scoring import score_candidate


@dataclass
class ColumnCandidate:
    """One column-transposition candidate."""

    width: int
    permutation: tuple[int, ...]
    score: float
    plaintext: str


@dataclass
class ColumnAttackResult:
    """Result of attacking one column width."""

    width: int
    search_mode: str
    permutations_tested: int
    total_permutations: int
    candidates: list[ColumnCandidate]


def decrypt_column_transposition(
    ciphertext: str,
    width: int,
    permutation: tuple[int, ...],
) -> str:
    """
    Decrypt a standard columnar transposition.

    Plaintext is assumed to have been written left-to-right
    into rows of 'width' columns. Ciphertext was then produced
    by reading the columns in the order specified by permutation.

    permutation is zero-based.

    Incomplete final rows are supported.
    """

    ciphertext = clean_text(ciphertext)

    if width < 2:
        raise ValueError("Width must be at least 2")

    if len(permutation) != width:
        raise ValueError(
            "Permutation length must equal width"
        )

    if sorted(permutation) != list(range(width)):
        raise ValueError(
            "Permutation must contain every position exactly once"
        )

    length = len(ciphertext)

    if length == 0:
        return ""

    rows, remainder = divmod(length, width)

    # In the original plaintext grid, the first 'remainder'
    # columns contain one additional character.
    column_lengths = [
        rows + (1 if column < remainder else 0)
        for column in range(width)
    ]

    columns: list[str] = [""] * width

    position = 0

    # Ciphertext consists of columns concatenated in the
    # candidate permutation order.
    for column in permutation:
        column_length = column_lengths[column]

        columns[column] = ciphertext[
            position:position + column_length
        ]

        position += column_length

    # Reconstruct plaintext row-by-row.
    plaintext: list[str] = []

    maximum_height = max(column_lengths)

    for row in range(maximum_height):
        for column in range(width):
            if row < len(columns[column]):
                plaintext.append(columns[column][row])

    return "".join(plaintext)


def _chunks(
    iterable: Iterable[tuple[int, ...]],
    size: int,
) -> Iterable[list[tuple[int, ...]]]:
    """Yield lists of permutations in manageable chunks."""

    chunk: list[tuple[int, ...]] = []

    for item in iterable:
        chunk.append(item)

        if len(chunk) >= size:
            yield chunk
            chunk = []

    if chunk:
        yield chunk


def _evaluate_chunk(
    args: tuple[
        str,
        int,
        list[tuple[int, ...]],
        int,
    ],
) -> list[tuple[float, tuple[int, ...], str]]:
    """Evaluate one chunk and retain its local best candidates."""

    ciphertext, width, chunk, keep = args

    best: list[
        tuple[float, tuple[int, ...], str]
    ] = []

    for permutation in chunk:
        plaintext = decrypt_column_transposition(
            ciphertext,
            width,
            permutation,
        )

        score = score_candidate(plaintext)

        best.append(
            (score, permutation, plaintext)
        )

    best.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    return best[:keep]


def exhaustive_column_attack(
    ciphertext: str,
    width: int,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> ColumnAttackResult:
    """
    Exhaustively test every column permutation for one width.

    Multiprocessing is used because this is CPU-bound work.
    """

    ciphertext = clean_text(ciphertext)

    if width < 2:
        raise ValueError("Width must be at least 2")

    if top_n < 1:
        raise ValueError("top_n must be at least 1")

    if chunk_size < 1:
        raise ValueError(
            "chunk_size must be at least 1"
        )

    if workers is None:
        workers = os.cpu_count() or 1

    total = factorial(width)

    permutation_chunks = _chunks(
        permutations(range(width)),
        chunk_size,
    )

    worker_arguments = (
        (
            ciphertext,
            width,
            chunk,
            top_n,
        )
        for chunk in permutation_chunks
    )

    best_candidates: list[
        tuple[float, tuple[int, ...], str]
    ] = []

    with ProcessPoolExecutor(
        max_workers=workers
    ) as executor:
        for local_best in executor.map(
            _evaluate_chunk,
            worker_arguments,
        ):
            best_candidates.extend(local_best)

            best_candidates.sort(
                key=lambda item: item[0],
                reverse=True,
            )

            del best_candidates[top_n:]

    candidates = [
        ColumnCandidate(
            width=width,
            permutation=permutation,
            score=score,
            plaintext=plaintext,
        )
        for score, permutation, plaintext
        in best_candidates
    ]

    return ColumnAttackResult(
        width=width,
        search_mode="exhaustive",
        permutations_tested=total,
        total_permutations=total,
        candidates=candidates,
    )


def attack_column_widths(
    ciphertext: str,
    minimum_width: int = 5,
    maximum_width: int = 9,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> list[ColumnAttackResult]:
    """Exhaustively attack a range of practical column widths."""

    if maximum_width < minimum_width:
        raise ValueError(
            "maximum_width must be >= minimum_width"
        )

    results = []

    for width in range(
        minimum_width,
        maximum_width + 1,
    ):
        print(
            f"Column width {width}: "
            f"{factorial(width):,} permutations"
        )

        result = exhaustive_column_attack(
            ciphertext=ciphertext,
            width=width,
            top_n=top_n,
            workers=workers,
            chunk_size=chunk_size,
        )

        results.append(result)

        if result.candidates:
            best = result.candidates[0]

            display_permutation = tuple(
                value + 1
                for value in best.permutation
            )

            print(
                f"  Best score: "
                f"{best.score:.6f}"
            )

            print(
                f"  Best permutation: "
                f"{display_permutation}"
            )

            print(
                f"  Preview: "
                f"{best.plaintext[:100]}"
            )

    return results
