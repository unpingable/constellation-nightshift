"""Bounded source-shape gate, not a Rust parser or runtime qualification.

These retained classic interfaces are transitional obligations. Restrict their
whole subprocess expression, including argument order and process modifiers,
until their modern semantic replacements have been independently qualified.
"""

import pathlib
import re
import sys


def check(source, operation):
    # Preserve string bytes; ignore only whitespace outside string literals.
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s]', source)
    compact = "".join(tokens)
    expected = (
        'Command::new(&self.program).args(['
        f'"{operation}","replay",'
        '"--profile",&profile.path().to_string_lossy(),'
        '"--evidence",&evidence.path().to_string_lossy(),'
        '"--receipt",&receipt.path().to_string_lossy(),'
        '"--output","-",]).output().map_err('
    )
    if compact.count('Command::new') != 1 or expected not in compact:
        return False
    pin = 'ifprogram.file_name().and_then(|name|name.to_str())!=Some("nq-monitor"){returnErr('
    return pin in compact


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    failed = False
    for module, operation in (
        ("repository_qualification", "campaign-stage-qualification"),
        ("reservation_qualification", "campaign-stage-realization"),
    ):
        source = root / "crates/nightshiftd/src" / f"{module}.rs"
        if not check(source.read_text(), operation):
            print(f"restricted replay check failed: {module}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
