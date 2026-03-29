"""
Static analyzer — non-AI artifact extraction.
Runs before the ADK pipeline and provides raw file data injected into session state.
"""

import hashlib
import math
import os
import re
import struct
from pathlib import Path


def compute_hashes(file_path: str) -> dict:
    """Compute MD5, SHA1, and SHA256 hashes of the file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def compute_entropy(file_path: str) -> float:
    """Compute Shannon entropy of the file (0.0 = uniform, 8.0 = fully random)."""
    counts = [0] * 256
    total = 0

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for byte in chunk:
                counts[byte] += 1
                total += 1

    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def extract_strings(file_path: str, min_len: int = 6) -> list[str]:
    """
    Extract printable ASCII strings from file.
    Caps at 60 strings, each truncated to 120 chars, to keep LLM context manageable.
    """
    printable = set(range(0x20, 0x7F))
    results = []

    with open(file_path, "rb") as f:
        data = f.read()

    current = []
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))

    seen = set()
    deduped = []
    for s in results:
        s = s[:120]  # truncate long strings (JS lines, encoded blobs, etc.)
        if s not in seen:
            seen.add(s)
            deduped.append(s)
        if len(deduped) >= 60:
            break

    return deduped


def parse_pe_headers(file_path: str) -> dict | None:
    """
    Parse PE headers if this is a PE executable.
    Returns None if the file is not a PE (e.g., JavaScript, scripts).
    """
    try:
        import pefile  # type: ignore
    except ImportError:
        return None

    try:
        pe = pefile.PE(file_path)
        imports = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                imports[dll_name] = [
                    imp.name.decode("utf-8", errors="replace")
                    for imp in entry.imports
                    if imp.name
                ]

        sections = [
            {
                "name": s.Name.decode("utf-8", errors="replace").strip("\x00"),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 4),
            }
            for s in pe.sections
        ]

        # Cap imports to keep context small — top 8 DLLs, 20 functions each
        imports_trimmed = {
            dll: fns[:20]
            for dll, fns in list(imports.items())[:8]
        }

        return {
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "imports": imports_trimmed,
            "sections": sections,
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        }
    except Exception:
        # Not a PE file or parsing failed
        return None


def run_yara(file_path: str, rules_dir: str = "yara_rules/") -> list[str]:
    """
    Run YARA rules against the file.
    Returns list of matching rule names. Returns empty list if yara-python not installed.
    """
    try:
        import yara  # type: ignore
    except ImportError:
        return []

    rules_path = Path(rules_dir)
    if not rules_path.exists():
        # Try relative to this file's location
        rules_path = Path(__file__).parent.parent / "yara_rules"

    if not rules_path.exists():
        return []

    matches = []
    for rule_file in rules_path.glob("*.yar"):
        try:
            rules = yara.compile(str(rule_file))
            rule_matches = rules.match(file_path)
            for match in rule_matches:
                matches.append(f"{match.rule} ({match.meta.get('severity', 'unknown')})")
        except Exception:
            continue

    return matches


def detect_file_type(file_path: str) -> str:
    """Detect file type using magic bytes and extension fallback."""
    try:
        import magic  # type: ignore
        return magic.from_file(file_path, mime=False)
    except Exception:
        pass

    # Fallback: check magic bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
        if header[:2] == b"MZ":
            return "PE32 executable"
        if header[:4] == b"\x7fELF":
            return "ELF executable"
        if header[:4] == b"PK\x03\x04":
            return "ZIP archive"
    except Exception:
        pass

    # Extension fallback
    ext = Path(file_path).suffix.lower()
    ext_map = {
        ".js": "JavaScript source",
        ".vbs": "VBScript source",
        ".ps1": "PowerShell script",
        ".bat": "Windows batch file",
        ".sh": "Shell script",
        ".py": "Python script",
        ".exe": "PE32 executable",
        ".dll": "PE32 DLL",
    }
    # Check the original filename for extension
    name = Path(file_path).name
    for known_ext, description in ext_map.items():
        if known_ext in name.lower():
            return description

    return "Unknown binary"


def extract_iocs(strings: list[str]) -> dict:
    """Extract IP addresses, domains, and URLs from the string list."""
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

    ips = set()
    domains = set()
    urls = set()

    combined = " ".join(strings)
    ips.update(ip_pattern.findall(combined))
    domains.update(domain_pattern.findall(combined))
    urls.update(url_pattern.findall(combined))

    # Filter out false positive domains (single-word, too short)
    domains = {d for d in domains if "." in d and len(d) > 4 and not d.endswith(".js")}

    return {
        "ips": sorted(ips)[:50],
        "domains": sorted(domains)[:50],
        "urls": sorted(urls)[:50],
    }


def analyze(file_path: str) -> dict:
    """
    Run full static analysis pipeline on a file.
    Returns a dict matching the StaticAgent output schema from AGENTS.md.
    """
    file_path = str(file_path)
    file_size = os.path.getsize(file_path)

    hashes = compute_hashes(file_path)
    entropy = compute_entropy(file_path)
    strings = extract_strings(file_path, min_len=6)
    pe_info = parse_pe_headers(file_path)
    yara_matches = run_yara(file_path)
    file_type = detect_file_type(file_path)
    iocs = extract_iocs(strings)

    return {
        "file_path": file_path,
        "file_size": file_size,
        "file_type": file_type,
        "hashes": hashes,
        "entropy": entropy,
        "strings": strings[:40],  # hard cap — 40 strings max injected into LLM
        "pe_info": pe_info,
        "yara_matches": yara_matches,
        "iocs": iocs,
    }
