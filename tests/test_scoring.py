"""Tests for English-language candidate scoring."""

from cryptanalysis.scoring import (
    score_candidate,
    score_text,
)


def test_empty_text():
    result = score_text("")

    assert result.total == 0.0
    assert result.normalized == 0.0


def test_score_is_deterministic():
    text = "THISISATESTOFENGLISHTEXT"

    first = score_candidate(text)
    second = score_candidate(text)

    assert first == second


def test_english_scores_above_scrambled_text():
    english = (
        "THISISANEXAMPLEOFENGLISHTEXTANDTHE"
        "WORDSINTHISMESSAGEHAVECOMMONENGLISH"
        "LETTERSEQUENCES"
    )

    scrambled = (
        "QZXJQXVRZQKXJQZPVXQJZKXQZJXQVKQZ"
        "XJQPVZKXQJZVXQKJZQXPVZJQXKZQVXJ"
    )

    english_score = score_candidate(english)
    scrambled_score = score_candidate(scrambled)

    assert english_score > scrambled_score


def test_common_ngrams_detected():
    result = score_text(
        "THETHEANDWITHINTHETEXT"
    )

    assert result.bigram_hits > 0
    assert result.trigram_hits > 0
    assert result.quadgram_hits > 0


def test_normalized_score():
    result = score_text(
        "THISISENGLISHTEXT"
    )

    assert result.normalized == (
        result.total / len("THISISENGLISHTEXT")
    )
