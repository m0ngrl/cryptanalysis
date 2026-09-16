from cryptanalysis.analysis.frequency import (
    analyse_frequency,
    frequency_distance,
)


def test_frequency_length():
    result = analyse_frequency("AABBCC")

    assert result.length == 6


def test_frequency_counts():
    result = analyse_frequency("AAABBC")

    values = {
        item.letter: item.count
        for item in result.frequencies
    }

    assert values["A"] == 3
    assert values["B"] == 2
    assert values["C"] == 1
    assert values["Z"] == 0


def test_frequency_percentages():
    result = analyse_frequency("AABB")

    values = {
        item.letter: item.percentage
        for item in result.frequencies
    }

    assert values["A"] == 50.0
    assert values["B"] == 50.0


def test_ranked_frequency():
    result = analyse_frequency("AAABBCCCC")

    ranked = result.ranked

    assert ranked[0].letter == "C"
    assert ranked[0].count == 4

    assert ranked[1].letter == "A"
    assert ranked[1].count == 3

    assert ranked[2].letter == "B"
    assert ranked[2].count == 2


def test_frequency_distance():
    result = analyse_frequency(
        "THISISATESTOFENGLISHLETTERFREQUENCY"
    )

    distance = frequency_distance(result)

    assert distance >= 0
