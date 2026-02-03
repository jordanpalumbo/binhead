#!/usr/bin/env python3

#----IMPORTS----
import argparse
import sys
import json
import math
import hashlib
from collections import Counter

version = "0.1.0"
header_size = 1024
bytes_per_line = 16

encodings = {
        "utf-8": "utf-8",
        "ascii": "ascii",
        "latin-1": "latin-1",
        "windows-1252": "windows-1252"
        }

magic_numbers = {
        'Windows Executable (EXE/DLL)': b"\x4D\x5A", 
        'ELF Executable': b"\x7FELF",
        'PNG Image Format': b"\x89PNG\r\n\x1A\n", 
        'JPEG Image Format': b"\xFF\xD8\xFF",
        'GIF Image Format [1]': b"GIF87a",
        'GIF Image Format [2]': b"GIF89a",
        'PDF Document': b"%PDF-",
        'ZIP Archive': b"PK\x03\x04",
        'ZIP Archive (Empty)': b"PK\x05\x06",
        'ZIP Archive (Spanned)': b"PK\x07\x08",
        'RAR Archive': b"Rar!\x1A\x07\x00",
        'GZIP Archive': b"\x1F\x8B"
        }


#----ARGUMENT PARSING----
def parse_arguments():
    """Parses command line arguments"""
    parser = argparse.ArgumentParser(
            description="binhead - Binary Header Analysis & Triage Tool",
            epilog=(
                "Analyze file headers using entropy analysis, cryptographic hashing,\n magic number detection, and hex inspection.\n"
                "Examples:\n"
                "  binhead sample.exe --magic --entropy --hash [FILENAME]"
                "  binhead sample.dll --hex --json --out output.json [FILENAME]"
                ),
            formatter_class=argparse.RawTextHelpFormatter
            )
    parser.add_argument(
            "file", 
            help="Binary filepath"
            )

    parser.add_argument(
            "-e", "--encoding",
            choices=encodings.keys(),
            default="utf-8",
            help="Decoding standard (default: UTF-8)"
            )
    parser.add_argument(
            "-s", "--size",
             type=int,
             default=header_size,
             help= "Header size in bytes (default: 1024)")

    parser.add_argument(
            "--hex",
            action="store_true",
            help="Display hex + ASCII dump instead of decoded text."
            )
    
    parser.add_argument(
            "--magic",
            action="store_true",
            help="Detect file type using magic numbers"
            )
    
    parser.add_argument(
            "--json",
            action="store_true",
            help="Output results in JSON format (no text output)"
            )

    parser.add_argument(
            "--out",
            metavar="FILE",
            help="Writes output to file instead of stdout"
            )

    parser.add_argument(
            "--tee",
            action="store_true",
            help="Write output to stdout and file"
            )

    parser.add_argument(
             "--entropy",
            action="store_true",
            help="Calculate Shannon entropy on the file header"
            )
    parser.add_argument(
            "--hash",
            nargs="?",
            const="sha256",
            choices=["sha256", "sha1", "md5"],
            help="Calculating hash of header (default: sha256)"
            )

    parser.add_argument(
            "--version",
            action="version",
            version=f"binhead {version}"
            )

    
    return parser.parse_args()

#----CORE LOGIC----
def read_header(filepath: str, size: int) -> bytes:
    """Reads fixed-size header from a binary file."""
    with open(filepath, "rb") as f:
        return f.read(size)

def decode_header(data: bytes, encoding: str) -> str:
    """Safely decode binary data using selected encoding"""
    return data.decode(encoding=encoding, errors="replace")

def detect_magic_numbers(data: bytes) -> str:
    """Detects file type using magic numbers"""
    for description, signature in magic_numbers.items():
        if data.startswith(signature):
            return description
    return "Unknown file type"

#----ENTROPY CALCULATIONS----
def calculate_entropy(data: bytes) -> float:
    """Calculating Shannon entropy (bits per byte)"""
    if not data:
        return 0.0
    
    counts = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)

def entropy_assessment(entropy: float) -> str:
    if entropy < 3.0:
        return "Low (structured or plaintext)"
    elif entropy < 6.0:
        return "Medium (compressed or mixed data)"
    else:
        return "High (likely packed or encrypted)"

#---HASHING----
def calculate_hash(data: bytes, algorithm: str) -> str:
    """Calculating hash of header bytes"""
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()

#----HEX DUMP----
def hex_dump(data: bytes) -> str:
    """Prints a hex + ASCII dump."""
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]

        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(
                chr(b) if 0x20 <= b <= 0x7E else "."
                for b in chunk
                )
        lines.append(f"{offset:08X} {hex_bytes:<48} | {ascii_bytes}|")

    return "\n".join(lines)

def hex_dump_json(data: bytes):
    lines = []

    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        
        lines.append( {
            "offset": f"{offset:08X}",
            "hex": " ".join(f"{b:02X}" for b in chunk),
            "ascii": "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            })

    return lines

#----OUTPUT HELPERS----
def section(title: str) -> str:
    return(
            f"\n{'=' * 60}\n"
            f"{title.upper():^60}\n"
            f"{'=' *60}\n"
            )
def write_output(content: str, outfile: str | None, tee: bool = False):
    if outfile:
        with open(outfile, 'w', encoding="utf-8") as f:
            f.write(content)

    if tee or not outfile:
        print(content)

#----JSON BUILDING----
def build_json_results(args, header: bytes):
    results = {
            "file": args.file,
            "header_size": len(header),
            "analysis": {}
            }
    if args.magic:
        results["analysis"]["magic"] = {
                "type": detect_magic_numbers(header)
                }
    if args.entropy:
        value = calculate_entropy(header)
        results["analysis"]["entropy"] = {
            "value": value,
            "assessment": entropy_assessment(value)
                }

    if args.hash:
        results["analysis"]["hash"] = {
                "algorithm": args.hash,
                "value": calculate_hash(header, args.hash)
                }

    if args.hex:
        results["analysis"]["hex"] = {
                "bytes_per_line": bytes_per_line,
                "dump": hex_dump_json(header)
                }
    else:
        results["analysis"] ["decoded"] = {
                "encoding": args.encoding,
                "text": decode_header(header, args.encoding)
                }
    return results

#----MAIN----
def main():
    args = parse_arguments()
    analysis_flags = any([
        args.magic,
        args.entropy,
        args.hash
    ])

    try:
        header = read_header(args.file, args.size)
    
    #JSON MODE
        if args.json:
            output = json.dumps(build_json_results(args, header), indent=2)
            write_output(output, args.out)
            return
    #TEXT MODE
        output = ""
        if args.magic:
            output += section("File Signature Detection")
            output += f"  Detected Type  : {detect_magic_numbers(header)}\n"
            output += f"  Header Size  :  {len(header)} bytes\n"

        if args.entropy:
            value = calculate_entropy(header)
            output += section("Entropy Analysis")
            output += f"  Entropy Value  :  {value} bits per byte\n"
            output += f"  Assessment  : {entropy_assessment(value)}\n"

        if args.hash:
            output += section("Hash Analysis")
            output += f"  Algorithm  : {args.hash.upper()}\n"
            output += f"  Hash  : {calculate_hash(header, args.hash)}\n"


        if args.hex:
            output += section("Hex Dump")
            output += hex_dump(header) + "\n"
        elif not analysis_flags and not args.hex:
            output += section("Decoded Header")
            output += decode_header(header, args.encoding)

        write_output(output, args.out, args.tee)

    except FileNotFoundError:
        sys.exit("Error: File not found.")

    except PermissionError:
        sys.exit("Error: Permission denied.")

    except Exception as e:
        sys.exit(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()

