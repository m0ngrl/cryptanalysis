"""English-language scoring for cryptanalysis candidates."""

from collections import Counter
from dataclasses import dataclass
import math

from cryptanalysis.analysis.ic import clean_text


# Common English n-grams.
#
# These are deliberately kept internal so the cryptanalysis tool
# has no network or external data-file dependency.
#
# The values are relative weights rather than probabilities.
# Longer n-grams receive more weight because they are less likely
# to occur accidentally.

COMMON_BIGRAMS = {
    "TH": 4.0,
    "HE": 4.0,
    "IN": 3.5,
    "ER": 3.5,
    "AN": 3.5,
    "RE": 3.2,
    "ON": 3.2,
    "AT": 3.0,
    "EN": 3.0,
    "ND": 3.0,
    "TI": 3.0,
    "ES": 3.0,
    "OR": 3.0,
    "TE": 3.0,
    "OF": 3.0,
    "ED": 2.8,
    "IS": 2.8,
    "IT": 2.8,
    "AL": 2.8,
    "AR": 2.8,
    "ST": 2.8,
    "TO": 2.8,
    "NT": 2.8,
    "NG": 2.8,
    "SE": 2.8,
    "HA": 2.8,
    "AS": 2.8,
    "OU": 2.8,
    "IO": 2.6,
    "LE": 2.6,
    "VE": 2.6,
    "CO": 2.6,
    "ME": 2.6,
    "DE": 2.6,
    "HI": 2.6,
    "RI": 2.6,
    "RO": 2.6,
    "IC": 2.6,
    "NE": 2.6,
    "EA": 2.6,
    "RA": 2.6,
    "CE": 2.6,
    "LI": 2.6,
    "CH": 2.6,
    "LL": 2.4,
    "BE": 2.4,
    "MA": 2.4,
    "SI": 2.4,
    "OM": 2.4,
    "UR": 2.4,
}


COMMON_TRIGRAMS = {
    "THE": 12.0,
    "AND": 10.0,
    "ING": 9.0,
    "HER": 8.0,
    "ERE": 7.0,
    "ENT": 7.0,
    "THA": 7.0,
    "NTH": 6.5,
    "WAS": 6.5,
    "ETH": 6.0,
    "FOR": 6.0,
    "DTH": 5.5,
    "HAT": 5.5,
    "SHE": 5.5,
    "ION": 5.5,
    "TIO": 5.5,
    "VER": 5.0,
    "EST": 5.0,
    "ERS": 5.0,
    "ATI": 5.0,
    "HES": 5.0,
    "ALL": 5.0,
    "HIS": 5.0,
    "OFT": 5.0,
    "ITH": 5.0,
    "FTH": 4.5,
    "STH": 4.5,
    "OTH": 4.5,
    "RES": 4.5,
    "ONT": 4.5,
    "REA": 4.5,
    "NOT": 4.5,
    "EVE": 4.5,
    "WIT": 4.5,
    "ARE": 4.5,
    "BUT": 4.0,
    "ONE": 4.0,
    "OUR": 4.0,
    "OUT": 4.0,
    "YOU": 4.0,
}


COMMON_QUADGRAMS = {
    "TION": 24.0,
    "NTHE": 22.0,
    "THER": 22.0,
    "THAT": 20.0,
    "OFTH": 19.0,
    "FTHE": 19.0,
    "WITH": 18.0,
    "ATIO": 18.0,
    "MENT": 17.0,
    "IONS": 16.0,
    "THIS": 16.0,
    "HERE": 15.0,
    "OULD": 15.0,
    "IGHT": 15.0,
    "HAVE": 15.0,
    "HICH": 14.0,
    "WHIC": 14.0,
    "THEM": 14.0,
    "TING": 14.0,
    "ANDT": 13.0,
    "THEC": 13.0,
    "THEP": 13.0,
    "THES": 13.0,
    "INTH": 13.0,
    "ETHE": 13.0,
    "SAND": 12.0,
    "EDTH": 12.0,
    "THEI": 12.0,
    "THEA": 12.0,
    "EVER": 12.0,
    "FROM": 12.0,
}


# Sequences that are uncommon in ordinary English and therefore
# useful for penalising random-looking candidate plaintext.

UNLIKELY_BIGRAMS = {
    "QJ",
    "QZ",
    "QX",
    "JQ",
    "JX",
    "JZ",
    "ZQ",
    "ZX",
    "ZJ",
    "XQ",
    "XJ",
    "XK",
    "QG",
    "QF",
    "QH",
    "QV",
    "QW",
}


@dataclass
class ScoreResult:
    """Detailed English-language score."""

    total: float
    normalized: float

    bigram_score: float
    trigram_score: float
    quadgram_score: float

    unlikely_penalty: float

    bigram_hits: int
    trigram_hits: int
    quadgram_hits: int


def _score_ngrams(
    text: str,
    size: int,
    weights: dict[str, float],
) -> tuple[float, int]:
    """Score matching n-grams."""

    score = 0.0
    hits = 0

    for position in range(len(text) - size + 1):
        gram = text[position:position + size]

        weight = weights.get(gram)

        if weight is not None:
            score += weight
            hits += 1

    return score, hits


def _unlikely_bigram_penalty(
    text: str,
) -> float:
    """Penalise highly improbable English bigrams."""

    penalty = 0.0

    for position in range(len(text) - 1):
        bigram = text[position:position + 2]

        if bigram in UNLIKELY_BIGRAMS:
            penalty += 5.0

    return penalty


def score_text(text: str) -> ScoreResult:
    """
    Score a candidate plaintext for English-like structure.

    Higher scores are better.

    The normalized score allows candidates of different lengths
    to be compared more reasonably.
    """

    text = clean_text(text)

    if not text:
        return ScoreResult(
            total=0.0,
            normalized=0.0,
            bigram_score=0.0,
            trigram_score=0.0,
            quadgram_score=0.0,
            unlikely_penalty=0.0,
            bigram_hits=0,
            trigram_hits=0,
            quadgram_hits=0,
        )

    bigram_score, bigram_hits = _score_ngrams(
        text,
        2,
        COMMON_BIGRAMS,
    )

    trigram_score, trigram_hits = _score_ngrams(
        text,
        3,
        COMMON_TRIGRAMS,
    )

    quadgram_score, quadgram_hits = _score_ngrams(
        text,
        4,
        COMMON_QUADGRAMS,
    )

    penalty = _unlikely_bigram_penalty(text)

    total = (
        bigram_score
        + trigram_score
        + quadgram_score
        - penalty
    )

    normalized = (
        total / len(text)
        if text
        else 0.0
    )

    return ScoreResult(
        total=total,
        normalized=normalized,
        bigram_score=bigram_score,
        trigram_score=trigram_score,
        quadgram_score=quadgram_score,
        unlikely_penalty=penalty,
        bigram_hits=bigram_hits,
        trigram_hits=trigram_hits,
        quadgram_hits=quadgram_hits,
    )


def score_candidate(text: str) -> float:
    """
    Convenience function for attack modules.

    Returns only the normalized score.
    """

    return score_text(text).normalized
