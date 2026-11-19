#!/usr/bin/env python3
"""Spec: published trees must not disclose routed prefixes, transit subnets, or the edge deployment.

These checks fail while that disclosure is present in any git-tracked file and pass once
the disclosure is gone. They read the tracked worktree (the bytes a commit would publish).
Ancestor commits are intentionally not scanned: rewriting history is outside this spec.
Literals are read from the whole file, including when whitespace wraps them
across lines. Deployment notes match when the words share a paragraph or a
list item. A NUL byte does not drop the rest of a file.

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
import tempfile
import urllib.parse
from collections.abc import Callable
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


def _line_index(text: str) -> list[int]:
    lines: list[int] = []
    line = 1
    for ch in text:
        lines.append(line)
        if ch == "\n":
            line += 1
    return lines


def _sub_tracked(
    pattern: re.Pattern[str],
    text: str,
    lines: list[int],
    repl: Callable[[re.Match[str]], str],
) -> tuple[str, list[int]]:
    parts: list[str] = []
    mapped: list[int] = []
    cursor = 0
    for match in pattern.finditer(text):
        parts.append(text[cursor:match.start()])
        mapped.extend(lines[cursor:match.start()])
        original = match.group(0)
        replacement = repl(match)
        if replacement == original:
            parts.append(original)
            mapped.extend(lines[match.start():match.end()])
        else:
            start_line = lines[match.start()] if lines else 1
            parts.append(replacement)
            mapped.extend([start_line] * len(replacement))
        cursor = match.end()
    parts.append(text[cursor:])
    mapped.extend(lines[cursor:])
    return "".join(parts), mapped


def _dec_entity(match: re.Match[str]) -> str:
    value = int(match.group(1))
    return chr(value) if value < 128 else match.group(0)


def _hex_entity(match: re.Match[str]) -> str:
    value = int(match.group(1), 16)
    return chr(value) if value < 128 else match.group(0)


def _percent(match: re.Match[str]) -> str:
    return urllib.parse.unquote(match.group(0))


def normalize_tracked(text: str) -> tuple[str, list[int]]:
    """Return normalized text and the 1-based source line of each output character."""
    lines = _line_index(text)
    chars: list[str] = []
    kept: list[int] = []
    for ch, line in zip(text, lines):
        if ch in "\u200b\u200c\u200d\ufeff":
            continue
        if ch in "\uff0e\u3002":
            ch = "."
        chars.append(ch)
        kept.append(line)
    text = "".join(chars)
    lines = kept
    text, lines = _sub_tracked(re.compile(r"&#(\d+);"), text, lines, _dec_entity)
    text, lines = _sub_tracked(re.compile(r"&#x([0-9a-fA-F]+);"), text, lines, _hex_entity)
    text, lines = _sub_tracked(re.compile(r"(?:%[0-9A-Fa-f]{2})+"), text, lines, _percent)
    text, lines = _sub_tracked(
        re.compile(r"(?i)\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}"),
        text,
        lines,
        lambda _match: ".",
    )
    text, lines = _sub_tracked(
        re.compile(r"\[\.\]|\(\.\)|\{\.\}"),
        text,
        lines,
        lambda _match: ".",
    )
    previous = None
    while previous != text:
        previous = text
        text, lines = _sub_tracked(
            re.compile(r"(\d)\s+\."),
            text,
            lines,
            lambda match: match.group(1) + ".",
        )
        text, lines = _sub_tracked(
            re.compile(r"\.\s+(\d)"),
            text,
            lines,
            lambda match: "." + match.group(1),
        )
        text, lines = _sub_tracked(
            re.compile(r"(\d)\s*/\s*(\d)"),
            text,
            lines,
            lambda match: match.group(1) + "/" + match.group(2),
        )
    if len(text) != len(lines):
        raise RuntimeError("normalize line map drifted")
    return text, lines


def normalize(text: str) -> str:
    return normalize_tracked(text)[0]


_IPV4 = re.compile(
    r"(?<!\d)((?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})"
    r"(?:/([0-9]|[12][0-9]|3[0-2]))?(?!\d)"
)


def _literals_in(normalized: str) -> list[tuple[int, int, str, int]]:
    found: list[tuple[int, int, str, int]] = []
    seen: set[tuple[int, int, int]] = set()
    for match in _IPV4.finditer(normalized):
        octets = [int(part) for part in match.group(1).split(".")]
        addr = _pack(*octets)
        prefixlen = int(match.group(2)) if match.group(2) is not None else 32
        key = (match.start(), addr, prefixlen)
        if key in seen:
            continue
        seen.add(key)
        found.append((addr, prefixlen, classify(addr, prefixlen), match.start()))
    return found


def ipv4_literals(text: str) -> list[tuple[int, int, str]]:
    """Return (address, prefixlen, category) for each literal in normalized text."""
    return [(addr, prefix, category) for addr, prefix, category, _start in _literals_in(normalize(text))]


def ipv4_hits(text: str) -> list[tuple[int, int, str, int]]:
    """Return (address, prefixlen, category, source line) for each literal in the whole text."""
    normalized, line_map = normalize_tracked(text)
    hits: list[tuple[int, int, str, int]] = []
    for addr, prefix, category, start in _literals_in(normalized):
        line = line_map[start] if start < len(line_map) else 1
        hits.append((addr, prefix, category, line))
    return hits


def _contains_term(folded: str, term: str) -> bool:
    """True when term is a whole word. An identifier that only spells the letters does not count."""
    return re.search(rf"(?<!\w){re.escape(term.casefold())}(?!\w)", folded) is not None


def _block_has_edge_link(block: str) -> bool:
    folded = normalize(block).casefold()
    if not _contains_term(folded, _EDGE_LINK):
        return False
    link_words = (_TRANSIT, _ROUTED, _P2P, _POINT)
    if any(_contains_term(folded, word) for word in link_words):
        return True
    return re.search(r"/\d{1,2}\b", folded) is not None


def _block_has_controller(block: str) -> bool:
    folded = normalize(block).casefold()
    if not _contains_term(folded, _CONTROLLER):
        return False
    return any(
        _contains_term(folded, word)
        for word in (_HYPERVISOR, _SELF_HOSTED, _SELF_HOSTED_SPACE)
    )


def _block_has_prefix_prose(block: str) -> bool:
    folded = normalize(block).casefold()
    if re.search(r"/\d{1,2}\b", folded) is None:
        return False
    return _contains_term(folded, _TRANSIT) or _contains_term(folded, _ROUTED)


def _notes_in_block(block: str) -> list[str]:
    kinds: list[str] = []
    if _block_has_edge_link(block):
        kinds.append("edge-link")
    if _block_has_controller(block):
        kinds.append("hosted-controller")
    if _block_has_prefix_prose(block):
        kinds.append("routed-or-transit-prefix-length")
    return kinds


_LIST_ITEM = re.compile(r"^[ \t]*(?:[-+*]|\d+[.)])\s+\S")


def logical_blocks(text: str) -> list[tuple[int, str]]:
    """Return (1-based line, text) for each paragraph and each list item.

    Blank lines separate blocks. A list item keeps its wrapped continuation
    lines and stops at the next item. The line is the first source line of
    the block.
    """
    rows = text.splitlines()
    blocks: list[tuple[int, str]] = []
    index = 0
    total = len(rows)
    while index < total:
        if not rows[index].strip():
            index += 1
            continue
        start = index
        index += 1
        while index < total and rows[index].strip() and _LIST_ITEM.match(rows[index]) is None:
            index += 1
        blocks.append((start + 1, "\n".join(rows[start:index])))
    return blocks


def edge_notes(text: str) -> list[tuple[int, str]]:
    notes: list[tuple[int, str]] = []
    for number, block in logical_blocks(text):
        for kind in _notes_in_block(block):
            notes.append((number, kind))
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
    """Decode a tracked file. A NUL byte does not exempt the rest of the bytes."""
    if not path.is_file():
        return None
    return path.read_bytes().decode("utf-8", "replace")


def scan_ipv4(path: Path, text: str) -> list[str]:
    failures: list[str] = []
    for _addr, _prefix, category, number in ipv4_hits(text):
        failures.append(
            "FAIL test_tracked_files_have_no_ipv4_literals "
            f"path={path.as_posix()} line={number} category={category}"
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
        for _addr, _prefix, category, line in ipv4_hits(region):
            number = line + start_line - 1
            failures.append(
                "FAIL test_portfolio_sentinel_has_no_network_disclosure "
                f"path={path.as_posix()} line={number} category={category}"
            )
        for block_line, block in logical_blocks(region):
            number = block_line + start_line - 1
            for kind in _notes_in_block(block):
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
        any("line=1 " in hit and "globally-reachable-ipv4" in hit for hit in split_literal),
        "detector_flags_literal_split_across_lines",
    )
    triple = "203." + "\n" + "0." + "\n" + "113.5/26" + "\n"
    triple_hits = scan_ipv4(Path("sample.txt"), triple)
    expect(
        any("line=1 " in hit and "special-purpose-not-global-ipv4" in hit for hit in triple_hits),
        "detector_flags_literal_split_across_three_lines",
    )

    link = f"edge uses {_EDGE_LINK} {_P2P} {_TRANSIT}"
    expect(edge_notes(link) == [(1, "edge-link")], "edge_detector_flags_link_sentence")
    controller = f"{_SELF_HOSTED} {_CONTROLLER} on {_HYPERVISOR}"
    expect(
        edge_notes(controller) == [(1, "hosted-controller")],
        "edge_detector_flags_controller_sentence",
    )
    wrapped = "\n".join((_SELF_HOSTED, f"{_CONTROLLER} Controller", f"on {_HYPERVISOR}"))
    expect(
        edge_notes(wrapped) == [(1, "hosted-controller")],
        "edge_detector_flags_controller_note_wrapped_across_lines",
    )
    padded = "npm global packages\n\n" + wrapped
    expect(
        edge_notes(padded) == [(3, "hosted-controller")],
        "edge_detector_keeps_wrapped_note_source_line",
    )
    listed = "\n".join((f"- {_SELF_HOSTED}", f"  {_CONTROLLER} Controller", f"  on {_HYPERVISOR}"))
    expect(
        edge_notes(listed) == [(1, "hosted-controller")],
        "edge_detector_flags_wrapped_list_item",
    )
    separate_items = "\n".join((f"- {_SELF_HOSTED}", f"- {_CONTROLLER} name"))
    expect(edge_notes(separate_items) == [], "edge_detector_does_not_join_separate_list_items")
    separate_paragraphs = "\n\n".join((_SELF_HOSTED, f"{_CONTROLLER} name"))
    expect(
        edge_notes(separate_paragraphs) == [],
        "edge_detector_does_not_join_across_blank_lines",
    )
    prose_prefix = f"{_ROUTED} block " + "/" + "26"
    expect(
        any(kind == "routed-or-transit-prefix-length" for _line, kind in edge_notes(prose_prefix)),
        "edge_detector_flags_routed_prefix_length_without_a_literal",
    )
    source_like = 'prose_prefix = f"{_ROUTED} block ' + "/" + '26"'
    expect(
        edge_notes(source_like) == [],
        "edge_detector_ignores_identifier_beside_a_prefix_length",
    )
    expect(edge_notes("npm global packages and VS Code extensions") == [], "edge_detector_ignores_unrelated_prose")
    payload = (_dotted((203, 0, 113, 5)) + "\n").encode("utf-8") + b"\0"
    handle = tempfile.NamedTemporaryFile()
    try:
        handle.write(payload)
        handle.flush()
        decoded = _read_text(Path(handle.name))
    finally:
        handle.close()
    expect(
        decoded is not None
        and any(item[2] == "special-purpose-not-global-ipv4" for item in ipv4_literals(decoded)),
        "nul_byte_does_not_skip_decoded_file",
    )
    region = f"<!-- {_START} -->\n{triple}{wrapped}\n<!-- {_END} -->\n"
    region_hits = scan_portfolio(Path("sample.md"), region)
    expect(
        any("special-purpose-not-global-ipv4" in hit for hit in region_hits),
        "portfolio_scan_flags_literal_split_across_three_lines",
    )
    expect(
        any("kind=hosted-controller" in hit for hit in region_hits),
        "portfolio_scan_flags_wrapped_controller_note",
    )
    own_source = Path(__file__).read_text(encoding="utf-8")
    own_path = Path("tests/agent_instruction_network_disclosure_test.py")
    expect(scan_ipv4(own_path, own_source) == [], "spec_source_has_no_ipv4_disclosure")
    expect(scan_edge(own_path, own_source) == [], "spec_source_has_no_edge_disclosure")
    expect(scan_portfolio(own_path, own_source) == [], "spec_source_has_no_portfolio_disclosure")

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
