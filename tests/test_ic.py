from cryptanalysis.analysis.ic import (
    calculate_ic,
    calculate_period_ic,
    clean_text,
)


def test_clean_text():
    assert clean_text("abc DEF!\n123") == "ABCDEF"


def test_repeated_character_ic():
    result = calculate_ic("AAAAAAAAAA")

    assert result.length == 10
    assert result.ic == 1.0


def test_unique_characters_ic():
    result = calculate_ic("ABCDEFGH")

    assert result.ic == 0.0


def test_periodic_ic():
    result = calculate_period_ic(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        5,
    )

    assert result.period == 5
    assert len(result.column_ics) == 5
