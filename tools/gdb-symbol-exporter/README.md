# GDB Symbol Exporter

Standalone JSON symbol exporter that launches GDB in batch mode. It is kept
outside the QEMU plugin code and does not link against or import plugin code.

## Usage

```sh
python3 tools/gdb-symbol-exporter/gdb_symbol_exporter.py \
  --binary tests/hello_world/hello_world \
  --output symbols.json
```

The Scallop UI launcher writes the default symbol file automatically before
starting QEMU:

```text
std::filesystem::temp_directory_path() / "scallop_symbols_<binary-stem>.json"
```

The QEMU plugin loads that path by default. To override it manually, pass either
`symbols_json=` or the shorter `symbols=` plugin argument:

```sh
-plugin /path/to/librefactorscallop.so,symbols_json=/path/to/symbols.json
```

Use `--minimal-only` to export only GDB minimal symbols, or `--functions` to
export only function symbols reported by `info functions`.

When `--output` is omitted, JSON is written to stdout.

The top-level JSON document contains:

- `schema_version`
- `producer`
- `target`
- `architecture`
- `objects`
- `symbols`
- `warnings`
- `errors`

The exporter is intentionally pragmatic. It parses GDB's stable command output
for `maint print msymbols` and `info functions` rather than attempting exhaustive
DWARF modeling.
