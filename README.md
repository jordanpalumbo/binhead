# binhead

**binhead** — Fast, focused binary header analysis for triage and inspection.

`binhead` is a lightweight command-line utility for inspecting binary file headers using entropy analysis, cryptographic hashing, magic number detection, and hex dumps. It supports both human-readable output and structured JSON for automation.

---

## Features

* 🔍 Magic number (file signature) detection
* 📊 Shannon entropy analysis (detect packed/encrypted data)
* 🔐 Cryptographic hashing (md5, sha1, sha256)
* 🧾 Hex + ASCII header dump
* 🧠 Decoded header text (multiple encodings)
* 📤 JSON output mode for tooling and pipelines
* 📝 Output to file with optional stdout tee

---

## Installation

Clone the repository and run directly with Python 3.10+:

```bash
git clone https://github.com/jordanpalumbo/binhead.git
cd binhead
python binhead.py --help
```


---

## Usage

```bash
 python3 binhead <file> [options]
```

### Common Examples

```bash
# Identify file type and entropy
binhead sample.exe --magic --entropy

# Hash header using SHA-256 (default)
binhead sample.bin --hash

# Hash header using MD5
binhead sample.bin --hash md5

# Hex dump with JSON output
binhead sample.bin --hex --json

# Write output to a file and stdout
binhead sample.bin --entropy --out report.txt --tee
```

---

## Output Modes

### Text Output (default)

Human-readable, formatted analysis for interactive use.

### JSON Output

Structured output suitable for scripting and automation:

```bash
binhead sample.bin --entropy --hash sha256 --json
```

---

## Why binhead?

`binhead` is designed for **triage** — helping you quickly answer:

* What kind of file is this really?
* Does this data look packed or encrypted?
* Have I seen this binary header before?

It is intentionally fast, dependency-free, and focused on header-level analysis.

---


