# Classical Cryptanalysis

A Python toolkit for analysing and attacking classical ciphers.

The project performs statistical analysis of ciphertexts and provides automated attacks against several classical cipher families. It can process individual ciphertexts or batches of `.txt` files and ranks candidate plaintexts using English-language scoring.

The project stems from a uni cryptography course assessment that asked us to analyse and decrypt other groups encodings with recommended software. Th recommended software was single threaded and eventually drove me nuts. Therefore this cryptanalysis multi-threading program was made to be able to batch process a collection of encoded text files. I hope it serves other students well.

## Features

### Cipher analysis

The analysis system provides:

- Letter-frequency analysis
- Index of Coincidence (IC)
- Periodic Index of Coincidence
- Kasiski examination
- English frequency-distance scoring
- Automated initial assessment
- Batch report generation

### Cryptanalytic attacks

Implemented attack families include:

- Vigenère
- Beaufort
- Row transposition
- Column transposition

Transposition attacks use exhaustive permutation searches for practical key widths.

A substitution attack module exists in the project structure but is not yet implemented.

## Requirements

- Python 3.11 or newer
- `pip`
- Linux, macOS, or Windows

The project uses Python multiprocessing for computationally expensive transposition searches.

## Installation

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd cryptanalysis
```

### New virtual environment

If a virtual environment does not already exist:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

On Windows, activate the environment using the appropriate command for your shell.

### Existing virtual environment

If `.venv` already exists:

```bash
source .venv/bin/activate
pip install -e '.[dev]'
```

After installation, check the command-line interface:

```bash
cryptanalysis --help
```

## Project Structure

```text
cryptanalysis/
├── ciphers/
│   └── Group-1_assign-1_Cipher_1.txt
├── src/
│   └── cryptanalysis/
│       ├── analysis/
│       │   ├── frequency.py
│       │   ├── ic.py
│       │   └── kasiski.py
│       ├── attacks/
│       │   ├── column_transposition.py
│       │   ├── periodic.py
│       │   ├── row_transposition.py
│       │   └── substitution.py
│       ├── analyser.py
│       ├── attacker.py
│       ├── attack_report.py
│       ├── cli.py
│       ├── report.py
│       └── scoring.py
├── tests/
├── .gitignore
├── README.md
└── pyproject.toml
```

## Example Cipher

The repository includes one example ciphertext:

```text
ciphers/Group-1_assign-1_Cipher_1.txt
```

Other assignment ciphertexts and generated results are intentionally excluded from the repository.

## Analysis CLI

The installed `cryptanalysis` command performs statistical analysis on every `.txt` ciphertext in an input directory.

Basic usage:

```bash
cryptanalysis ciphers
```

Specify an output directory:

```bash
cryptanalysis ciphers -o results
```

Specify the candidate period range:

```bash
cryptanalysis ciphers \
    -o results \
    --min-period 5 \
    --max-period 8
```

The current CLI performs analysis and generates reports. It does **not** currently expose the cryptanalytic attack modules directly.

## Running an Attack

The attack system can be called from Python:

```bash
python - <<'PY'
from cryptanalysis.attacker import attack_cipher

result = attack_cipher(
    "ciphers/Group-1_assign-1_Cipher_1.txt",
    minimum_period=5,
    maximum_period=8,
    top_n=10,
)

print()
print("Attack complete.")
print(f"Periodic candidates: {len(result.periodic)}")
print(f"Row widths: {len(result.row_transposition)}")
print(f"Column widths: {len(result.column_transposition)}")
PY
```

This runs:

1. Vigenère attacks
2. Beaufort attacks
3. Exhaustive row-transposition attacks
4. Exhaustive column-transposition attacks

for the requested period/key-width range.

## Saving Attack Results

Attack results can be written to disk using `attack_report.py`:

```bash
python - <<'PY'
from cryptanalysis.attacker import attack_cipher
from cryptanalysis.attack_report import (
    save_attack_result,
    save_best_plaintexts,
)

result = attack_cipher(
    "ciphers/Group-1_assign-1_Cipher_1.txt",
    minimum_period=5,
    maximum_period=8,
    top_n=10,
)

report = save_attack_result(
    result,
    "attack_results",
)

save_best_plaintexts(
    result,
    "attack_results",
)

print(f"Saved report: {report}")
PY
```

The output structure is similar to:

```text
attack_results/
└── Group-1_assign-1_Cipher_1/
    ├── attack_report.txt
    └── best/
        ├── periodic.txt
        ├── row_width_5.txt
        ├── row_width_6.txt
        ├── row_width_7.txt
        ├── row_width_8.txt
        ├── column_width_5.txt
        ├── column_width_6.txt
        ├── column_width_7.txt
        └── column_width_8.txt
```

`attack_report.txt` contains retained candidates, scores, recovered keys or permutations, and plaintext.

The `best/` directory contains convenient copies of the highest-ranked plaintext for each attack result and transposition width.

## Batch Attacks

Every `.txt` ciphertext in a directory can be attacked with `attack_directory()`:

```bash
python - <<'PY'
from cryptanalysis.attacker import attack_directory

reports = attack_directory(
    input_directory="ciphers",
    output_directory="attack_results",
    minimum_period=5,
    maximum_period=8,
    top_n=10,
)

print()
print(f"Attack complete: {len(reports)} ciphertext(s)")
PY
```

Results are saved after each ciphertext completes so completed work is retained if a long batch run is interrupted.

## Keys and Permutations

### Vigenère and Beaufort

Periodic cipher candidates use an alphabetic key.

A report entry has the form:

```text
Cipher: vigenere
Period: 5
Key: ABCDE
Score: 1.234567
```

### Row and column transposition

For a transposition cipher, the recovered permutation acts as the key.

For example:

```text
Width: 7

Candidate 1
Key: (3, 2, 5, 6, 4, 1, 7)
Permutation: (3, 2, 5, 6, 4, 1, 7)
Score: 3.812923
```

The report uses a one-based permutation for readability.

## Candidate Scoring

Attack candidates are ranked using English-language scoring.

A larger score means a candidate appears more English-like according to the scoring model. The score is a ranking aid rather than proof that a decryption is correct.

A strong candidate normally has:

- recognisable English words
- coherent phrases or sentences
- plausible letter sequences
- a score noticeably above competing candidates

Candidate plaintexts should still be inspected manually.

## Transposition Search Complexity

Exhaustive transposition attacks test every possible permutation for a given width. The number of possibilities is `n!`.

| Width | Permutations |
| ---: | ---: |
| 5 | 120 |
| 6 | 720 |
| 7 | 5,040 |
| 8 | 40,320 |
| 9 | 362,880 |
| 10 | 3,628,800 |
| 11 | 39,916,800 |
| 12 | 479,001,600 |
| 15 | 1,307,674,368,000 |

Widths 5–8 are practical for exhaustive searching on a modern multicore system. Search cost grows extremely quickly beyond this range, so larger widths are better suited to heuristic or optimised search methods.

## Multiprocessing

Row and column transposition attacks use Python's `ProcessPoolExecutor` to evaluate permutation chunks across multiple CPU cores.

As a result, aggregate CPU time can be much greater than wall-clock time. For example:

```text
real    0m11.143s
user    6m15.732s
```

This means the job completed in roughly 11 seconds of elapsed time while worker processes collectively consumed approximately six minutes of CPU time.

## Analysis Techniques

### Frequency Analysis

Counts individual letters and compares the resulting distribution with expected English frequencies.

This can help identify ciphertexts that retain statistical characteristics of natural-language plaintext.

### Index of Coincidence

The Index of Coincidence measures how frequently identical letters occur relative to ciphertext length.

It is useful when distinguishing between different classes of classical cipher.

### Periodic Index of Coincidence

The ciphertext is separated into periodic columns for candidate periods. The IC of each column can reveal periodic structure associated with polyalphabetic ciphers.

### Kasiski Examination

Repeated sequences are located and the distances between occurrences are analysed. Factors of those distances can suggest possible periodic key lengths.

## Tests

Run the test suite with:

```bash
pytest
```

For verbose output:

```bash
pytest -v
```

The test suite covers core functionality including:

- frequency analysis
- Index of Coincidence
- Kasiski analysis
- scoring
- transposition operations

## Development

Check a module for syntax errors with:

```bash
python -m py_compile src/cryptanalysis/attacker.py
```

Multiple modules can be checked together:

```bash
python -m py_compile \
    src/cryptanalysis/attacker.py \
    src/cryptanalysis/attack_report.py
```

After modifying attack or scoring logic, run:

```bash
pytest
```

## Generated Files

Generated analysis and attack results are intentionally excluded from Git.

Examples include:

```text
results/
results_full/
results_old/
attack_results/
analysis_summary.txt
attacks_full_combined.txt
full_attack.log
```

These files can be regenerated from source ciphertexts.

## Current Limitations

- The CLI performs analysis but does not yet expose the attack system directly.
- Monoalphabetic substitution attacks are not yet implemented.
- Exhaustive transposition searching becomes impractical at large widths.
- Candidate scoring can produce false positives and requires manual verification.
- Cipher identification is advisory rather than definitive.
- The attack system tests multiple cipher families rather than automatically selecting one family.

## Possible Future Improvements

- Direct attack options in the CLI
- Monoalphabetic substitution solving
- Hill-climbing or simulated-annealing attacks
- Heuristic transposition attacks for large keys
- Automatic cipher-family selection
- Improved language scoring
- Resume/skip support for completed batch attacks
- JSON report output
- Combined analysis and attack reports

## Disclaimer

This project is intended for education, experimentation, and classical cryptography research.

The attacks demonstrated here concern historical/classical cipher systems and should not be confused with attacks against modern cryptographic systems.
