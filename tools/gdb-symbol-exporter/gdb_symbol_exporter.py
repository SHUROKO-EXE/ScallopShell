#!/usr/bin/env python3
"""Standalone GDB-backed JSON symbol exporter.

This file is intentionally independent of the QEMU plugin code. Run it with
normal Python; it launches GDB in batch mode and uses GDB's Python runtime only
for inspecting the target and producing JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
PRODUCER = "gdb-python-json-symbol-exporter"
PRODUCER_VERSION = "0.1.0"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export symbols from a binary as JSON using GDB in batch mode.",
    )
    parser.add_argument("--binary", required=True, help="Target binary to inspect.")
    parser.add_argument(
        "--output",
        "-o",
        help="Write JSON to this path. Defaults to stdout.",
    )
    parser.add_argument(
        "--gdb",
        default=os.environ.get("GDB", "gdb"),
        help="GDB executable to launch. Defaults to $GDB or 'gdb'.",
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--minimal-only",
        action="store_true",
        help="Export only GDB minimal symbols.",
    )
    selection.add_argument(
        "--functions",
        action="store_true",
        help="Export only function symbols from 'info functions'.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    binary = Path(args.binary).expanduser()
    if not binary.exists():
        print(f"error: binary does not exist: {binary}", file=sys.stderr)
        return 2

    output_path = Path(args.output).expanduser() if args.output else None
    tmp_output = None
    if output_path is None:
        fd, tmp_name = tempfile.mkstemp(prefix="gdb-symbols-", suffix=".json")
        os.close(fd)
        tmp_output = Path(tmp_name)
        destination = tmp_output
    else:
        destination = output_path

    config = {
        "binary": str(binary.resolve()),
        "output": str(destination),
        "include_minimal": not args.functions,
        "include_functions": not args.minimal_only,
    }

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as script:
        script_path = Path(script.name)
        script.write(_make_gdb_script(Path(__file__).resolve(), config))

    try:
        cmd = [
            args.gdb,
            "--batch",
            "--quiet",
            "--nx",
            "--nh",
            str(binary),
            "-x",
            str(script_path),
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print(proc.stderr or proc.stdout or "gdb failed", file=sys.stderr)
            return proc.returncode

        if output_path is None and tmp_output is not None:
            sys.stdout.write(tmp_output.read_text(encoding="utf-8"))
    finally:
        try:
            script_path.unlink()
        except OSError:
            pass
        if tmp_output is not None:
            try:
                tmp_output.unlink()
            except OSError:
                pass

    return 0


def _make_gdb_script(exporter_path: Path, config: dict[str, Any]) -> str:
    return textwrap.dedent(
        f"""
        import importlib.util

        spec = importlib.util.spec_from_file_location("gdb_symbol_exporter", {str(exporter_path)!r})
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.run_inside_gdb({json.dumps(config)!r})
        """
    )


def run_inside_gdb(config_json: str) -> None:
    import gdb  # type: ignore

    config = json.loads(config_json)
    warnings: list[str] = []
    errors: list[str] = []
    info_files = _execute(gdb, "info files", warnings, errors)
    objects = _objects(gdb, info_files, warnings)

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "producer": {
            "name": PRODUCER,
            "version": PRODUCER_VERSION,
            "gdb_version": _gdb_version(gdb, warnings),
        },
        "target": _target_info(info_files, config["binary"]),
        "architecture": _architecture(gdb, warnings),
        "objects": objects,
        "symbols": [],
        "warnings": warnings,
        "errors": errors,
    }

    symbols: list[dict[str, Any]] = []
    if config["include_minimal"]:
        symbols.extend(_minimal_symbols(gdb, warnings, errors))
    if config["include_functions"]:
        symbols.extend(_function_symbols(gdb, warnings, errors))

    object_ids = _object_id_map(objects)
    document["symbols"] = _deduplicate_symbols(_attach_object_ids(symbols, object_ids))
    document["warnings"] = warnings
    document["errors"] = errors

    output = Path(config["output"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _execute(gdb: Any, command: str, warnings: list[str], errors: list[str]) -> str:
    try:
        return gdb.execute(command, to_string=True)
    except Exception as exc:  # GDB exceptions do not share a stable base type.
        errors.append(f"{command!r} failed: {exc}")
        return ""


def _gdb_version(gdb: Any, warnings: list[str]) -> str | None:
    try:
        return gdb.VERSION
    except Exception as exc:
        warnings.append(f"could not read gdb.VERSION: {exc}")
        return None


def _architecture(gdb: Any, warnings: list[str]) -> str | None:
    output = _execute(gdb, "show architecture", warnings, [])
    quoted_match = re.search(r'currently\s+"([^"]+)"', output)
    if quoted_match:
        return quoted_match.group(1)
    match = re.search(r"currently\s+(\S+)", output)
    if match:
        return match.group(1).strip('".()')
    stripped = output.strip()
    return stripped or None


def _target_info(info: str, binary: str) -> dict[str, Any]:
    target: dict[str, Any] = {
        "path": binary,
        "absolute_path": str(Path(binary).resolve()),
    }

    type_match = re.search(r"file type\s+([^.\n]+)", info)
    if type_match:
        target["file_type"] = type_match.group(1).strip()

    entry_match = re.search(r"Entry point:\s+(0x[0-9a-fA-F]+)", info)
    if entry_match:
        target["entry_point"] = entry_match.group(1)

    return target


def _objects(gdb: Any, info_files: str, warnings: list[str]) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    sections = _sections_from_info_files(info_files)
    try:
        for index, objfile in enumerate(gdb.objfiles()):
            filename = getattr(objfile, "filename", None)
            object_id = f"obj-{index}"
            objects.append(
                {
                    "id": object_id,
                    "file_path": filename,
                    "real_path": str(Path(filename).resolve()) if filename else None,
                    "is_main_executable": index == 0,
                    "is_shared_library": index != 0,
                    "static_base": _static_base_from_sections(sections),
                    "runtime_base": None,
                    "sections": sections if index == 0 else [],
                }
            )
    except Exception as exc:
        warnings.append(f"could not enumerate objfiles: {exc}")
    return objects


def _sections_from_info_files(info: str) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    pattern = re.compile(
        r"^\s*(?P<start>0x[0-9a-fA-F]+)\s+-\s+"
        r"(?P<end>0x[0-9a-fA-F]+)\s+is\s+"
        r"(?P<name>\S+)"
    )
    for line in info.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        if end <= start:
            continue
        name = match.group("name")
        sections.append(
            {
                "name": name,
                "static_address": f"0x{start:x}",
                "runtime_address": None,
                "size": end - start,
                "permissions": _section_permissions(name),
            }
        )
    return sections


def _section_permissions(name: str) -> str:
    executable_sections = {
        ".init",
        ".plt",
        ".plt.got",
        ".plt.sec",
        ".text",
        ".fini",
    }
    writable_sections = {
        ".data",
        ".bss",
        ".got",
        ".got.plt",
        ".dynamic",
        ".init_array",
        ".fini_array",
    }
    if name in executable_sections:
        return "rx"
    if name in writable_sections:
        return "rw"
    return "r"


def _static_base_from_sections(sections: list[dict[str, Any]]) -> str | None:
    starts = [int(section["static_address"], 16) for section in sections if section.get("static_address")]
    if not starts:
        return None
    return f"0x{min(starts):x}"


def _minimal_symbols(gdb: Any, warnings: list[str], errors: list[str]) -> list[dict[str, Any]]:
    output = _execute(gdb, "maint print msymbols", warnings, errors)
    symbols: list[dict[str, Any]] = []
    current_object: str | None = None

    pattern = re.compile(
        r"^\[\s*(?P<index>\d+)\]\s+"
        r"(?P<code>\S+)\s+"
        r"(?P<address>0x[0-9a-fA-F]+)\s+"
        r"(?P<name>.+?)\s+section\s+"
        r"(?P<section>\S+)"
        r"(?:\s+(?P<trailer>.*))?$"
    )

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        object_match = re.match(r"Object file\s+(.+):$", line)
        if object_match:
            current_object = object_match.group(1)
            continue

        match = pattern.match(line)
        if not match:
            continue

        code = match.group("code")
        section = match.group("section")
        symbols.append(
            {
                "name": match.group("name").strip(),
                "address": match.group("address"),
                "static_address": match.group("address"),
                "kind": _minimal_kind(code, section),
                "source": "minimal",
                "object": current_object,
                "section": section,
                "binding": _binding_from_code(code),
                "raw_type": code,
                "extra": (match.group("trailer") or "").strip() or None,
            }
        )

    if not symbols:
        warnings.append("no minimal symbols were parsed from 'maint print msymbols'")
    return symbols


def _function_symbols(gdb: Any, warnings: list[str], errors: list[str]) -> list[dict[str, Any]]:
    output = _execute(gdb, "info functions", warnings, errors)
    symbols: list[dict[str, Any]] = []
    current_file: str | None = None
    non_debugging = False

    debug_pattern = re.compile(r"^(?P<line>\d+):\s*(?P<signature>.+?);?$")
    non_debug_pattern = re.compile(r"^(?P<address>0x[0-9a-fA-F]+)\s+(?P<name>\S+)$")

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line == "All defined functions:":
            continue
        if line == "Non-debugging symbols:":
            current_file = None
            non_debugging = True
            continue
        file_match = re.match(r"File\s+(.+):$", line)
        if file_match:
            current_file = file_match.group(1)
            non_debugging = False
            continue

        debug_match = debug_pattern.match(line)
        if debug_match and not non_debugging:
            signature = debug_match.group("signature").strip()
            symbols.append(
                {
                    "name": _function_name_from_signature(signature),
                    "address": None,
                    "static_address": None,
                    "kind": "function",
                    "source": "debug",
                    "file": current_file,
                    "line": int(debug_match.group("line")),
                    "signature": signature,
                }
            )
            continue

        non_debug_match = non_debug_pattern.match(line)
        if non_debug_match:
            symbols.append(
                {
                    "name": non_debug_match.group("name"),
                    "address": non_debug_match.group("address"),
                    "static_address": non_debug_match.group("address"),
                    "kind": "function",
                    "source": "non_debug",
                    "file": None,
                    "line": None,
                    "signature": None,
                }
            )

    if not symbols:
        warnings.append("no function symbols were parsed from 'info functions'")
    return symbols


def _minimal_kind(code: str, section: str) -> str:
    if code.lower() == "t" or section in {".text", ".init", ".fini", ".plt"}:
        return "function"
    if code.lower() == "b":
        return "bss"
    if code.lower() == "d":
        return "data"
    if code.lower() == "s":
        return "stub"
    return "unknown"


def _binding_from_code(code: str) -> str:
    if code.isupper():
        return "global"
    if code.islower():
        return "local"
    return "unknown"


def _function_name_from_signature(signature: str) -> str:
    before_args = signature.split("(", 1)[0].strip()
    if not before_args:
        return signature
    return before_args.split()[-1].lstrip("*&")


def _object_id_map(objects: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for obj in objects:
        object_id = obj.get("id")
        if not object_id:
            continue
        for key in ("file_path", "real_path"):
            path = obj.get(key)
            if path:
                mapping[str(path)] = str(object_id)
    return mapping


def _attach_object_ids(symbols: list[dict[str, Any]], object_ids: dict[str, str]) -> list[dict[str, Any]]:
    for symbol in symbols:
        object_path = symbol.get("object")
        if object_path and object_path in object_ids:
            symbol["object_id"] = object_ids[object_path]
        elif object_ids and not symbol.get("object_id"):
            symbol["object_id"] = next(iter(object_ids.values()))
    return symbols


def _deduplicate_symbols(symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, Any, Any, Any]] = set()
    result: list[dict[str, Any]] = []
    for symbol in symbols:
        key = (
            symbol.get("name"),
            symbol.get("address"),
            symbol.get("source"),
            symbol.get("file") or symbol.get("object"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(symbol)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
