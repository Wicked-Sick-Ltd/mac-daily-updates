#!/usr/bin/env python3
"""Spec: published trees must not disclose routed prefixes, transit subnets, or the edge deployment.

These checks fail while that disclosure is present in any git-tracked file and pass once
the disclosure is gone. They read the tracked worktree (the bytes a commit would publish).
Ancestor commits are intentionally not scanned: rewriting history is outside this spec.

The address classes come from the IANA IPv4 Special-Purpose Address Registry
(iana-ipv4-special-registry-1.csv, last-modified 2026-10-13). Globally Reachable
is False for every block stored below. The Shared Address Space row (RFC 6598)
is the block whose first octet is 100 and whose prefix length is 10. Python
3.12's ipaddress module treats that same block as neither private nor global
(/usr/lib/python3.12/ipaddress.py, IPv4Address.is_global and IPv4Network.is_global);
this file classifies with the registry rows directly.
"""

from __future__ import annotations

import re
import subprocess
import sys
import urllib.parse
from pathlib import Path


def _pack(a: int, b: int, c: int, d: int) -> int:
    return ((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) | (d & 0xFF)


# (network integer, prefix length). Globally Reachable = False in the registry.
_NOT_GLOBAL = (
    (_pack(0, 0, 0, 0), 8),
    (_pack(0, 0, 0, 0), 32),
    (_pack(10, 0, 0, 0), 8),
    (_pack(100, 64, 0, 0), 10),
    (_pack(127, 0, 0, 0), 8),
    (_pack(169, 254, 0, 0), 16),
    (_pack(172, 16, 0, 0), 12),
    (_pack(192, 0, 0, 0), 24),
    (_pack(192, 0, 0, 0), 29),
    (_pack(192, 0, 0, 8), 32),
    (_pack(192, 0, 0, 170), 32),
    (_pack(192, 0, 0, 171), 32),
    (_pack(192, 0, 2, 0), 24),
    (_pack(192, 88, 99, 2), 32),
    (_pack(192, 168, 0, 0), 16),
    (_pack(198, 18, 0, 0), 15),
    (_pack(198, 51, 100, 0), 24),
    (_pack(203, 0, 113, 0), 24),
    (_pack(240, 0, 0, 0), 4),
    (_pack(255, 255, 255, 255), 32),
)
_SHARED = (_pack(100, 64, 0, 0), 10)

_START = "PORTFOLIO_STATE:" + "START"
_END = "PORTFOLIO_STATE:" + "END"

_EDGE_LINK = "".join(("pf", "Sense"))
_CONTROLLER = "".join(("Uni", "Fi"))
_HYPERVISOR = "".join(("Prox", "mox"))
_SELF_HOSTED = "".join(("self-", "hosted"))
_SELF_HOSTED_SPACE = "".join(("self ", "hosted"))
_TRANSIT = "".join(("trans", "it"))
_ROUTED = "".join(("rou", "ted"))
_P2P = "".join(("p", "2p"))
_POINT = "".join(("point-to-", "point"))


def _mask(prefixlen: int) -> int:
    if prefixlen <= 0:
        return 0
    if prefixlen >= 32:
        return 0xFFFFFFFF
    return (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF


def _contained(parent: tuple[int, int], addr: int, prefixlen: int) -> bool:
    network, parent_len = parent
    if prefixlen < parent_len:
        return False
    bits = _mask(parent_len)
    return (addr & bits) == (network & bits)


def classify(addr: int, prefixlen: int) -> str:
    if _contained(_SHARED, addr, prefixlen):
        return "shared-address-space-ipv4"
    for block in _NOT_GLOBAL:
        if block == _SHARED:
            continue
        if _contained(block, addr, prefixlen):
            return "special-purpose-not-global-ipv4"
    return "globally-reachable-ipv4"


def normalize(text: str) -> str:
    text = text.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    text = text.replace("\ufeff", "")
    text = text.replace("\uff0e", ".").replace("\u3002", ".")

    def dec_entity(match: re.Match[str]) -> str:
        value = int(match.group(1))
        return chr(value) if value < 128 else match.group(0)

    def hex_entity(match: re.Match[str]) -> str:
        value = int(match.group(1), 16)
        return chr(value) if value < 128 else match.group(0)

    text = re.sub(r"&#(\d+);", dec_entity, text)
    text = re.sub(r"&#x([0-9a-fA-F]+);", hex_entity, text)
    text = urllib.parse.unquote(text)
    text = re.sub(r"(?i)\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", ".", text)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"(\d)\s+\.", r"\1.", text)
        text = re.sub(r"\.\s+(\d)", r".\1", text)
        text = re.sub(r"(\d)\s*/\s*(\d)", r"\1/\2", text)
    return text


_IPV4 = re.compile(
    r"(?<!\d)((?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})"
    r"(?:/([0-9]|[12][0-9]|3[0-2]))?(?!\d)"
)


def ipv4_literals(text: str) -> list[tuple[int, int, str]]:
    """Return (address, prefixlen, category) for each literal in normalized text."""
    found: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int, int]] = set()
    for match in _IPV4.finditer(normalize(text)):
        octets = [int(part) for part in match.group(1).split(".")]
        addr = _pack(*octets)
        prefixlen = int(match.group(2)) if match.group(2) is not None else 32
        key = (match.start(), addr, prefixlen)
        if key in seen:
            continue
        seen.add(key)
        found.append((addr, prefixlen, classify(addr, prefixlen)))
    return found


def _line_has_edge_link(line: str) -> bool:
    folded = normalize(line).casefold()
    if _EDGE_LINK.casefold() not in folded:
        return False
    link_words = (
        _TRANSIT.casefold(),
        _ROUTED.casefold(),
        _P2P.casefold(),
        _POINT.casefold(),
    )
    if any(word in folded for word in link_words):
        return True
    return re.search(r"/\d{1,2}\b", folded) is not None


def _line_has_controller(line: str) -> bool:
    folded = normalize(line).casefold()
    if _CONTROLLER.casefold() not in folded:
        return False
    return any(
        word in folded
        for word in (
            _HYPERVISOR.casefold(),
            _SELF_HOSTED.casefold(),
            _SELF_HOSTED_SPACE.casefold(),
        )
    )


def _line_has_prefix_prose(line: str) -> bool:
    folded = normalize(line).casefold()
    if re.search(r"/\d{1,2}\b", folded) is None:
        return False
    return _TRANSIT.casefold() in folded or _ROUTED.casefold() in folded


def edge_notes(text: str) -> list[tuple[int, str]]:
    notes: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if _line_has_edge_link(line):
            notes.append((number, "edge-link"))
        if _line_has_controller(line):
            notes.append((number, "hosted-controller"))
        if _line_has_prefix_prose(line):
            notes.append((number, "routed-or-transit-prefix-length"))
    return notes


def portfolio_regions(text: str) -> list[tuple[int, str]]:
    """Return (1-based start line, region text) for each sentinel region.

    A missing end marker keeps the remainder of the file inside the region so
    dropping the closer cannot hide the lines that follow the opener.
    """
    regions: list[tuple[int, str]] = []
    cursor = 0
    while True:
        start = text.find(_START, cursor)
        if start < 0:
            return regions
        end = text.find(_END, start + len(_START))
        if end < 0:
            chunk = text[start:]
            next_cursor = len(text)
        else:
            chunk = text[start:end]
            next_cursor = end + len(_END)
        start_line = text.count("\n", 0, start) + 1
        regions.append((start_line, chunk))
        cursor = next_cursor


def tracked_files(root: Path) -> list[Path]:
    listed = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=root,
        stderr=subprocess.DEVNULL,
    )
    paths: list[Path] = []
    for raw in listed.split(b"\0"):
        if not raw:
            continue
        paths.append(root / raw.decode("utf-8", "surrogateescape"))
    return paths


def _read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    data = path.read_bytes()
    if b"\0" in data:
        return None
    return data.decode("utf-8", "replace")


def scan_ipv4(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        for _addr, _prefix, category in ipv4_literals(line):
            failures.append(
                "FAIL test_tracked_files_have_no_ipv4_literals "
                f"path={path.as_posix()} line={number} category={category}"
            )
    # A literal split across two physical lines is still the same publication.
    lines = text.splitlines()
    for index in range(len(lines) - 1):
        joined = lines[index] + lines[index + 1]
        single = set(ipv4_literals(lines[index])) | set(ipv4_literals(lines[index + 1]))
        for literal in ipv4_literals(joined):
            if literal in single:
                continue
            _addr, _prefix, category = literal
            failures.append(
                "FAIL test_tracked_files_have_no_ipv4_literals "
                f"path={path.as_posix()} line={index + 1} category={category} span=2"
            )
    return failures


def scan_edge(path: Path, text: str) -> list[str]:
    return [
        "FAIL test_tracked_files_have_no_edge_deployment_notes "
        f"path={path.as_posix()} line={number} kind={kind}"
        for number, kind in edge_notes(text)
    ]


def scan_portfolio(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    for start_line, region in portfolio_regions(text):
        for number, line in enumerate(region.splitlines(), start_line):
            for _addr, _prefix, category in ipv4_literals(line):
                failures.append(
                    "FAIL test_portfolio_sentinel_has_no_network_disclosure "
                    f"path={path.as_posix()} line={number} category={category}"
                )
            for _note_line, kind in edge_notes(line):
                failures.append(
                    "FAIL test_portfolio_sentinel_has_no_network_disclosure "
                    f"path={path.as_posix()} line={number} kind={kind}"
                )
    return failures


def collect(root: Path) -> list[str]:
    failures: list[str] = []
    for path in tracked_files(root):
        text = _read_text(path)
        if text is None:
            continue
        relative = path.relative_to(root)
        failures.extend(scan_ipv4(relative, text))
        failures.extend(scan_edge(relative, text))
        failures.extend(scan_portfolio(relative, text))
    return failures


def _dotted(octets: tuple[int, int, int, int], prefix: int | None = None) -> str:
    text = ".".join(str(part) for part in octets)
    if prefix is not None:
        text += "/" + str(prefix)
    return text


def self_test() -> list[str]:
    """Prove the detectors fire on synthetic literals and stay quiet on prose.

    Octets are assembled at runtime. The two documentation rows used here are
    Globally Reachable False in the IANA registry. The shared-address sample
    sits in the RFC 6598 row. The remaining sample is not in that registry.
    """
    errors: list[str] = []

    def expect(condition: bool, name: str) -> None:
        if condition:
            print(f"PASS {name}")
        else:
            errors.append(f"FAIL {name}")
            print(errors[-1])

    public = ipv4_literals(_dotted((1, 2, 3, 4), 26))
    expect(
        public == [(_pack(1, 2, 3, 4), 26, "globally-reachable-ipv4")],
        "detector_classifies_non_registry_prefix_as_globally_reachable",
    )
    shared = ipv4_literals(_dotted((100, 64, 0, 1), 30))
    expect(
        shared == [(_pack(100, 64, 0, 1), 30, "shared-address-space-ipv4")],
        "detector_classifies_shared_address_space_prefix",
    )
    docs = ipv4_literals(_dotted((203, 0, 113, 5)))
    expect(
        docs == [(_pack(203, 0, 113, 5), 32, "special-purpose-not-global-ipv4")],
        "detector_classifies_documentation_range_as_not_global",
    )

    obfuscated = "1" + "[.]" + "2" + "[.]" + "3" + "[.]" + "4" + "/26"
    expect(
        ipv4_literals(obfuscated) == [(_pack(1, 2, 3, 4), 26, "globally-reachable-ipv4")],
        "detector_flags_bracket_dot_obfuscation",
    )
    percent = "1" + "%2E" + "2" + "%2E" + "3" + "%2E" + "4" + "/30"
    expect(
        any(item[2] == "globally-reachable-ipv4" for item in ipv4_literals(percent)),
        "detector_flags_percent_encoded_dots",
    )
    spaced = "1" + ". " + "2" + ". " + "3" + ". " + "4" + "/26"
    expect(
        ipv4_literals(spaced) == [(_pack(1, 2, 3, 4), 26, "globally-reachable-ipv4")],
        "detector_flags_whitespace_split_literal",
    )
    expect(ipv4_literals("Homebrew formulae and npm 10") == [], "detector_ignores_prose_without_network_literals")
    split_literal = scan_ipv4(Path("sample.txt"), "1.2." + "\n" + "3.4/26" + "\n")
    expect(
        any("span=2" in hit and "globally-reachable-ipv4" in hit for hit in split_literal),
        "detector_flags_literal_split_across_lines",
    )

    link = f"edge uses {_EDGE_LINK} {_P2P} {_TRANSIT}"
    expect(edge_notes(link) == [(1, "edge-link")], "edge_detector_flags_link_sentence")
    controller = f"{_SELF_HOSTED} {_CONTROLLER} on {_HYPERVISOR}"
    expect(
        edge_notes(controller) == [(1, "hosted-controller")],
        "edge_detector_flags_controller_sentence",
    )
    prose_prefix = f"{_ROUTED} block /26"
    expect(
        any(kind == "routed-or-transit-prefix-length" for _line, kind in edge_notes(prose_prefix)),
        "edge_detector_flags_routed_prefix_length_without_a_literal",
    )
    expect(edge_notes("npm global packages and VS Code extensions") == [], "edge_detector_ignores_unrelated_prose")

    hidden = f"<!-- {_START} -->\n{link}\n<!-- {_END} -->\nsafe\n"
    regions = portfolio_regions(hidden)
    expect(len(regions) == 1 and _EDGE_LINK in regions[0][1], "portfolio_region_includes_sentinel_body")
    unclosed = f"before\n{_START}\n{controller}\n"
    unclosed_regions = portfolio_regions(unclosed)
    expect(
        len(unclosed_regions) == 1 and _CONTROLLER in unclosed_regions[0][1],
        "portfolio_region_keeps_text_when_end_marker_is_absent",
    )
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(
        subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    )
    detector_errors = self_test()
    if detector_errors:
        print(f"SELFTEST failures={len(detector_errors)}")
        return 2
    print("SELFTEST ok")
    failures = collect(root)
    for line in failures:
        print(line)
    if failures:
        print(f"RESULT fail count={len(failures)} root={root}")
        return 1
    print(f"RESULT pass root={root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
