"""Command-line interface for cryptanalysis."""

import argparse
import sys
from pathlib import Path

from cryptanalysis.report import (
    generate_directory_reports,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""

    parser = argparse.ArgumentParser(
        prog="cryptanalysis",
        description=(
            "Batch classical cipher analysis and "
            "cryptanalysis."
        ),
    )

    parser.add_argument(
        "input",
        type=Path,
        help=(
            "Directory containing ciphertext .txt files."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("results"),
        help=(
            "Output directory (default: results)."
        ),
    )

    parser.add_argument(
        "--min-period",
        type=int,
        default=5,
        help="Minimum candidate key length (default: 5).",
    )

    parser.add_argument(
        "--max-period",
        type=int,
        default=15,
        help="Maximum candidate key length (default: 15).",
    )

    return parser


def main() -> int:
    """Program entry point."""

    parser = build_parser()
    args = parser.parse_args()

    if args.min_period < 2:
        parser.error(
            "--min-period must be at least 2"
        )

    if args.max_period < args.min_period:
        parser.error(
            "--max-period must be >= --min-period"
        )

    print("Classical Cryptanalysis")
    print("======================")
    print(f"Input:  {args.input}")
    print(f"Output: {args.output}")
    print(
        f"Periods: "
        f"{args.min_period}-{args.max_period}"
    )
    print()

    try:
        results = generate_directory_reports(
            input_directory=args.input,
            output_directory=args.output,
            minimum_period=args.min_period,
            maximum_period=args.max_period,
        )

    except (FileNotFoundError, NotADirectoryError) as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1

    print()
    print(
        f"Completed: {len(results)} report(s) generated."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
