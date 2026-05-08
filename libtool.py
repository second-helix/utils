import argparse
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

try:
    import lief
    HAS_LIEF = True
except Exception:
    lief = None
    HAS_LIEF = False


ARCHIVE_MAGIC = b"!<arch>\n"
MAX_OUTPUT_FILENAME_LEN = 256
COLLISION_HASH_LEN = 8


@dataclass
class ArchiveMember:
    raw_name: str
    name: str
    data: bytes
    index: int


@dataclass
class SymbolHit:
    member_name: str
    extracted_path: Optional[str]
    symbol_name: str
    kind: str   # "definition" / "reference" / "unknown"
    storage_class: Optional[str] = None
    section_number: Optional[int] = None


def sanitize_name(name: str) -> str:
    name = name.replace("\\", "_").replace("/", "_").replace(":", "_")
    name = re.sub(r"[^A-Za-z0-9_.@+\-]", "_", name)
    return name


def trim_from_left(name: str, max_len: int = MAX_OUTPUT_FILENAME_LEN) -> str:
    if len(name) <= max_len:
        return name
    return name[-max_len:]


def insert_suffix_before_extension(name: str, suffix: str) -> str:
    dot = name.rfind(".")
    if dot > 0:
        return f"{name[:dot]}{suffix}{name[dot:]}"
    return f"{name}{suffix}"


def build_output_obj_name(
    member_name: str,
    used_names: Set[str],
    max_len: int = MAX_OUTPUT_FILENAME_LEN,
) -> str:
    safe_name = sanitize_name(member_name)
    candidate = trim_from_left(safe_name, max_len=max_len)
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    hash_text = hashlib.sha1(member_name.encode("utf-8", errors="replace")).hexdigest()[:COLLISION_HASH_LEN]
    candidate = trim_from_left(
        insert_suffix_before_extension(safe_name, f"_{hash_text}"),
        max_len=max_len,
    )
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    counter = 2
    while True:
        candidate = trim_from_left(
            insert_suffix_before_extension(safe_name, f"_{hash_text}_{counter}"),
            max_len=max_len,
        )
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        counter += 1


def _parse_decimal_field(field: bytes, default: int = 0) -> int:
    s = field.decode("utf-8", errors="replace").strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default


def _normalize_archive_name(raw_name: str) -> str:
    raw_name = raw_name.rstrip()
    if raw_name.endswith("/"):
        raw_name = raw_name[:-1]
    return raw_name


def parse_msvc_archive(lib_path: Path) -> List[ArchiveMember]:
    data = lib_path.read_bytes()
    if not data.startswith(ARCHIVE_MAGIC):
        raise ValueError("Not a valid archive file: missing !<arch> magic")

    members: List[ArchiveMember] = []
    pos = len(ARCHIVE_MAGIC)
    index = 0

    longnames_table = None

    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        pos += 60

        name_field = hdr[0:16]
        size_field = hdr[48:58]
        fmag = hdr[58:60]

        if fmag != b"`\n":
            break

        raw_name = name_field.decode("utf-8", errors="replace")
        size = _parse_decimal_field(size_field)
        body = data[pos:pos + size]
        pos += size

        if pos % 2 == 1:
            pos += 1

        name = raw_name.rstrip()

        # GNU/BSD longname styles are included for tolerance,
        # though MSVC COFF archives often use special members.
        if name.startswith("//"):
            longnames_table = body
            continue

        if name.startswith("/"):
            special = name.strip()

            # First linker member, second linker member, longnames, etc.
            if special in ("/", "/SYM64", "/<HYBRIDMAP>/", "/<ECSYMBOLS>/"):
                index += 1
                continue

            # Reference into longnames table: "/123"
            if special[1:].isdigit() and longnames_table is not None:
                off = int(special[1:])
                end = longnames_table.find(b"/\n", off)
                if end == -1:
                    end = longnames_table.find(b"\x00", off)
                if end == -1:
                    end = len(longnames_table)
                resolved = longnames_table[off:end].decode("utf-8", errors="replace")
                name = resolved
            else:
                index += 1
                continue

        name = _normalize_archive_name(name)

        members.append(
            ArchiveMember(
                raw_name=raw_name,
                name=name,
                data=body,
                index=index
            )
        )
        index += 1

    return members


def parse_coff_symbols_with_lief(obj_bytes: bytes):
    if not HAS_LIEF:
        return None

    try:
        binary = lief.COFF.parse(list(obj_bytes))
        return binary
    except Exception:
        return None


def symbol_matches(
    candidate: str,
    target: str,
    ignore_case: bool = True,
    match_mode: str = "contains",
) -> bool:
    if ignore_case:
        candidate_cmp = candidate.casefold()
        target_cmp = target.casefold()
    else:
        candidate_cmp = candidate
        target_cmp = target

    if match_mode == "exact":
        return candidate_cmp == target_cmp

    if match_mode == "contains":
        return target_cmp in candidate_cmp

    raise ValueError(f"Unsupported match mode: {match_mode}")


def classify_symbol(sym) -> Tuple[str, Optional[int], Optional[str]]:
    """
    Rough classification:
    - section_number > 0 usually means the symbol is defined in a section
    - section_number == 0 usually means an undefined external reference
    - all other cases are marked as unknown
    """
    section_number = None
    storage_class = None

    try:
        section_number = int(sym.section_idx)
    except Exception:
        pass

    try:
        storage_class = str(sym.storage_class)
    except Exception:
        pass

    if section_number is not None:
        if section_number > 0:
            return "definition", section_number, storage_class
        if section_number == 0:
            return "reference", section_number, storage_class

    return "unknown", section_number, storage_class


def find_symbol_in_members(
    members: List[ArchiveMember],
    target_symbol: str,
    extract_dir: Path,
    extract_all_hits: bool = True,
    stop_after_definition: bool = False,
    try_disassemble: bool = False,
    match_mode: str = "contains",
):
    hits: List[SymbolHit] = []
    disasm_records = []
    used_output_names: Set[str] = set()

    for member in members:
        if not member.name.lower().endswith(".obj"):
            continue

        binary = parse_coff_symbols_with_lief(member.data)
        if binary is None:
            continue

        matched_syms = []
        try:
            symbols = list(binary.symbols)
        except Exception:
            symbols = []

        for sym in symbols:
            sym_name = None
            try:
                sym_name = sym.name
            except Exception:
                pass

            if not sym_name:
                continue

            kind, _, _ = classify_symbol(sym)
            if kind != "definition":
                continue

            if symbol_matches(
                sym_name,
                target_symbol,
                ignore_case=True,
                match_mode=match_mode,
            ):
                matched_syms.append(sym)

        if not matched_syms:
            continue

        extracted_name = build_output_obj_name(member.name, used_output_names)
        extracted_path = extract_dir / extracted_name
        if extract_all_hits:
            extracted_path.write_bytes(member.data)

        for sym in matched_syms:
            kind, secno, storage = classify_symbol(sym)
            hit = SymbolHit(
                member_name=member.name,
                extracted_path=str(extracted_path) if extract_all_hits else None,
                symbol_name=getattr(sym, "name", target_symbol),
                kind=kind,
                storage_class=storage,
                section_number=secno,
            )
            hits.append(hit)

            if try_disassemble and kind == "definition":
                try:
                    lines = []
                    try:
                        insts = binary.disassemble(sym.name)
                    except Exception:
                        insts = []

                    for inst in insts:
                        try:
                            lines.append(str(inst))
                        except Exception:
                            lines.append(repr(inst))

                    if lines:
                        disasm_records.append((member.name, sym.name, lines))
                except Exception:
                    pass

        if stop_after_definition and any(h.kind == "definition" for h in hits):
            break

    return hits, disasm_records


def build_report_text(
    lib_path: Path,
    target_symbol: str,
    members: List[ArchiveMember],
    hits: List[SymbolHit],
    has_lief: bool,
    disasm_records,
    match_mode: str,
):
    report = []
    report.append(f"Target library: {lib_path}")
    report.append(f"Target symbol: {target_symbol}")
    report.append(f"Match mode: {match_mode}")
    report.append(f"LIEF available: {has_lief}")
    report.append(f"Archive members: {len(members)}")
    report.append("")

    obj_members = [m for m in members if m.name.lower().endswith(".obj")]
    report.append(f"Object members: {len(obj_members)}")
    report.append("")

    if not has_lief:
        report.append("WARNING: LIEF is not available. COFF symbol parsing was skipped.")
        report.append("The script can only enumerate archive members in this mode.")
        report.append("")

    report.append(f"Definition hits: {len(hits)}")
    report.append("")

    if hits:
        report.append("Hits:")
        for h in hits:
            report.append(f"  member: {h.member_name}")
            report.append(f"  symbol: {h.symbol_name}")
            report.append(f"  kind: {h.kind}")
            report.append(f"  section_number: {h.section_number}")
            report.append(f"  storage_class: {h.storage_class}")
            report.append(f"  extracted_path: {h.extracted_path}")
            report.append("")
    else:
        report.append("No matching definition found.")
        report.append("")

    if disasm_records:
        report.append("Disassembly:")
        report.append("")
        for member_name, sym_name, lines in disasm_records:
            report.append(f"  {member_name} :: {sym_name}")
            for line in lines:
                report.append(f"    {line}")
            report.append("")

    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="COFF .lib symbol utils"
    )
    parser.add_argument("-l", "--lib", required=True, help="Path to .lib archive")
    parser.add_argument(
        "-s",
        "--symbol",
        help="Target symbol string. Required unless --list-only is used. Default mode matches definition symbols containing this string."
    )
    parser.add_argument(
        "-o",
        "--out",
        default=".",
        help="Output directory for matched object files. Defaults to the current directory."
    )
    parser.add_argument(
        "-e",
        "--exact",
        action="store_true",
        help="Use exact match. The full symbol name must be identical to --symbol."
    )
    parser.add_argument(
        "-L",
        "--list-only",
        action="store_true",
        help="List archive members without symbol parsing. Does not require --symbol."
    )
    parser.add_argument(
        "-S",
        "--stop-after-definition",
        action="store_true",
        help="Stop after first probable definition hit"
    )
    parser.add_argument(
        "-n",
        "--no-extract",
        action="store_true",
        help="Do not extract matched object files"
    )
    parser.add_argument(
        "-d",
        "--disasm",
        action="store_true",
        help="Try to disassemble matched definition symbols via LIEF"
    )

    args = parser.parse_args()

    if not args.list_only and not args.symbol:
        parser.error("the following arguments are required: -s/--symbol")

    lib_path = Path(args.lib).resolve()
    extract_dir = Path(args.out).resolve()
    match_mode = "contains"
    if args.exact:
        match_mode = "exact"

    if not lib_path.exists():
        print(f"LIB file not found: {lib_path}")
        sys.exit(1)

    try:
        members = parse_msvc_archive(lib_path)
    except Exception as e:
        print(f"Failed to parse archive: {e}")
        sys.exit(1)

    if args.list_only:
        obj_count = 0
        other_count = 0
        for m in members:
            kind = "obj" if m.name.lower().endswith(".obj") else "other"
            if kind == "obj":
                obj_count += 1
            else:
                other_count += 1
            print(f"{m.index:05d}  {kind:5}  {m.name}  ({len(m.data)} bytes)")
        print(f"[+] Total members: {len(members)}")
        print(f"[+] Object members: {obj_count}")
        print(f"[+] Non-object members: {other_count}")
        return

    if not args.no_extract:
        try:
            extract_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"Failed to create output directory: {extract_dir}: {e}")
            sys.exit(1)

    if not HAS_LIEF:
        print("[!] LIEF is not installed or failed to import.")
        print("[!] Archive parsing succeeded, but COFF symbol analysis is unavailable.")
        print("[!] Install it with: pip install lief")

    hits, disasm_records = find_symbol_in_members(
        members=members,
        target_symbol=args.symbol,
        extract_dir=extract_dir,
        extract_all_hits=not args.no_extract,
        stop_after_definition=args.stop_after_definition,
        try_disassemble=args.disasm and HAS_LIEF,
        match_mode=match_mode,
    )

    report_text = build_report_text(
        lib_path=lib_path,
        target_symbol=args.symbol,
        members=members,
        hits=hits,
        has_lief=HAS_LIEF,
        disasm_records=disasm_records,
        match_mode=match_mode,
    )

    print(report_text)


if __name__ == "__main__":
    main()
