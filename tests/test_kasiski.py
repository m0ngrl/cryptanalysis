from cryptanalysis.analysis.kasiski import (
    analyse_kasiski,
    find_repeated_sequences,
    ranked_factors,
)


def test_repeated_sequence_detection():
    result = find_repeated_sequences(
        "ABCDEFABCDEF",
        3,
    )

    sequences = {
        item.sequence: item
        for item in result
    }

    assert "ABC" in sequences
    assert sequences["ABC"].positions == [0, 6]
    assert sequences["ABC"].distances == [6]


def test_multiple_occurrences():
    result = find_repeated_sequences(
        "ABCABCABC",
        3,
    )

    sequences = {
        item.sequence: item
        for item in result
    }

    abc = sequences["ABC"]

    assert abc.positions == [0, 3, 6]
    assert sorted(abc.distances) == [3, 3, 6]


def test_factor_detection():
    result = analyse_kasiski(
        "ABCDEABCDEABCDE",
        sequence_length=5,
        minimum_factor=2,
        maximum_factor=10,
    )

    factors = {
        item.factor: item.count
        for item in result.factor_counts
    }

    # Repeated ABCDE occurs at 0, 5 and 10,
    # producing distances 5, 10 and 5.
    assert factors[5] >= 3


def test_ranked_factors():
    result = analyse_kasiski(
        "ABCDEABCDEABCDE",
        sequence_length=5,
        minimum_factor=2,
        maximum_factor=10,
    )

    ranked = ranked_factors(result)

    assert len(ranked) == 9
    assert ranked[0].count >= ranked[-1].count
