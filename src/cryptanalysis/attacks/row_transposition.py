"""Row-transposition cryptanalysis."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from itertools import permutations
from math import factorial
import os
from typing import Iterable

from cryptanalysis.analysis.ic import clean_text
from cryptanalysis.scoring import (
    COMMON_BIGRAMS,
    UNLIKELY_BIGRAMS,
    score_candidate,
)


@dataclass
class AdjacencyCandidate:
    """Fast row-transposition candidate based on column adjacency."""

    permutation: tuple[int, ...]
    adjacency_score: float


@dataclass
class OptimizedRowAttackResult:
    """Result from the optimized row-transposition search."""

    width: int
    search_mode: str
    permutations_tested: int
    total_permutations: int
    candidates: list[RowCandidate]


@dataclass
class RowCandidate:
    """One row-transposition candidate."""

    width: int
    permutation: tuple[int, ...]
    score: float
    plaintext: str


@dataclass
class RowAttackResult:
    """Result of attacking one row width."""

    width: int
    search_mode: str
    permutations_tested: int
    total_permutations: int
    candidates: list[RowCandidate]




def build_row_adjacency_matrix(
    ciphertext: str,
    width: int,
) -> list[list[float]]:
    """
    Build an English-likelihood matrix for source-column adjacency.

    matrix[a][b] measures how plausible it is for source column
    'a' to be immediately followed by source column 'b' in the
    plaintext rows.

    Only complete rows are used. This avoids incomplete-final-row
    complications during the fast scoring stage.
    """

    ciphertext = clean_text(ciphertext)

    if width < 2:
        raise ValueError("Width must be at least 2")

    complete_length = (
        len(ciphertext) // width
    ) * width

    text = ciphertext[:complete_length]

    rows = [
        text[start:start + width]
        for start in range(0, complete_length, width)
    ]

    matrix = [
        [0.0 for _ in range(width)]
        for _ in range(width)
    ]

    for left in range(width):
        for right in range(width):
            if left == right:
                continue

            pair_text = "".join(
                row[left] + row[right]
                for row in rows
            )

            # Each row contributes one candidate bigram.
            #
            # score_text() would also score the artificial boundary
            # between one row's pair and the next, so instead we score
            # each actual pair directly.
            score = 0.0

            for row in rows:
                pair = row[left] + row[right]

                score += COMMON_BIGRAMS.get(
                    pair,
                    0.0,
                )

                if pair in UNLIKELY_BIGRAMS:
                    score -= 5.0

            matrix[left][right] = (
                score / len(rows)
                if rows
                else 0.0
            )

    return matrix




def score_row_permutation_adjacency(
    permutation: tuple[int, ...],
    matrix: list[list[float]],
) -> float:
    """Score a row permutation using its adjacent source columns."""

    return sum(
        matrix[left][right]
        for left, right in zip(
            permutation,
            permutation[1:],
        )
    )



def optimized_exhaustive_row_attack(
    ciphertext: str,
    width: int,
    top_n: int = 10,
    finalists: int = 100,
) -> OptimizedRowAttackResult:
    """
    Exhaustively search row permutations using precomputed
    column-adjacency scores.

    Every permutation is tested using the cheap adjacency score.
    Only the best finalists are fully decrypted and evaluated
    using the complete English scorer.
    """

    ciphertext = clean_text(ciphertext)

    if width < 2:
        raise ValueError("Width must be at least 2")

    if top_n < 1:
        raise ValueError("top_n must be at least 1")

    if finalists < top_n:
        raise ValueError(
            "finalists must be >= top_n"
        )

    matrix = build_row_adjacency_matrix(
        ciphertext,
        width,
    )

    best_fast: list[AdjacencyCandidate] = []

    for permutation in permutations(range(width)):
        score = score_row_permutation_adjacency(
            permutation,
            matrix,
        )

        best_fast.append(
            AdjacencyCandidate(
                permutation=permutation,
                adjacency_score=score,
            )
        )

        # Periodically trim rather than sorting after every
        # permutation.
        if len(best_fast) >= finalists * 10:
            best_fast.sort(
                key=lambda item: item.adjacency_score,
                reverse=True,
            )

            del best_fast[finalists:]

    best_fast.sort(
        key=lambda item: item.adjacency_score,
        reverse=True,
    )

    best_fast = best_fast[:finalists]

    final_candidates: list[RowCandidate] = []

    for candidate in best_fast:
        plaintext = decrypt_row_transposition(
            ciphertext,
            width,
            candidate.permutation,
        )

        final_score = score_candidate(
            plaintext
        )

        final_candidates.append(
            RowCandidate(
                width=width,
                permutation=candidate.permutation,
                score=final_score,
                plaintext=plaintext,
            )
        )

    final_candidates.sort(
        key=lambda item: item.score,
        reverse=True,
    )

    return OptimizedRowAttackResult(
        width=width,
        search_mode="optimized-exhaustive",
        permutations_tested=factorial(width),
        total_permutations=factorial(width),
        candidates=final_candidates[:top_n],
    )





def decrypt_row_transposition(
    ciphertext: str,
    width: int,
    permutation: tuple[int, ...],
) -> str:
    """
    Apply a candidate row permutation.

    The permutation contains zero-based positions.

    Example:
        width = 4
        permutation = (2, 0, 3, 1)

    Cipher row:
        ABCD

    Candidate plaintext row:
        CADB
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

    output: list[str] = []

    for start in range(0, len(ciphertext), width):
        row = ciphertext[start:start + width]

        # Incomplete final rows require special handling because
        # some requested positions may not exist.
        for position in permutation:
            if position < len(row):
                output.append(row[position])

    return "".join(output)


def _evaluate_permutation(
    args: tuple[str, int, tuple[int, ...]],
) -> tuple[float, tuple[int, ...], str]:
    """
    Worker function used by multiprocessing.

    Must remain at module scope so it can be pickled.
    """

    ciphertext, width, permutation = args

    plaintext = decrypt_row_transposition(
        ciphertext,
        width,
        permutation,
    )

    score = score_candidate(plaintext)

    return score, permutation, plaintext


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
        plaintext = decrypt_row_transposition(
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


def exhaustive_row_attack(
    ciphertext: str,
    width: int,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> RowAttackResult:
    """
    Exhaustively test every row permutation for one width.

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

            # Keep memory bounded as results arrive.
            best_candidates.sort(
                key=lambda item: item[0],
                reverse=True,
            )

            del best_candidates[top_n:]

    candidates = [
        RowCandidate(
            width=width,
            permutation=permutation,
            score=score,
            plaintext=plaintext,
        )
        for score, permutation, plaintext
        in best_candidates
    ]

    return RowAttackResult(
        width=width,
        search_mode="exhaustive",
        permutations_tested=total,
        total_permutations=total,
        candidates=candidates,
    )


def attack_row_widths(
    ciphertext: str,
    minimum_width: int = 5,
    maximum_width: int = 9,
    top_n: int = 10,
    workers: int | None = None,
    chunk_size: int = 500,
) -> list[RowAttackResult]:
    """
    Exhaustively attack a range of practical row widths.

    Widths above 9 should normally use the heuristic/optimised
    attack that will be added separately.
    """

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
            f"Row width {width}: "
            f"{factorial(width):,} permutations"
        )

        result = exhaustive_row_attack(
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
