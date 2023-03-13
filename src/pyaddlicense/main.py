"""pyaddlicense adds license headers to the begining of source files.

pyaddlicense will add a license to the top of any file given as an arguement, if
they are found to be missing one. If a folder is given, pyaddlicense will
recursively move through the entire sub-directory structure, adding a license
to the top of every file missing one. It will respect .gitignore by default.

Typical usage example:

  `pyaddlicense -o 'John Smith'` src/`

Usage with custom ignore:

  `pyaddlicense -o 'John Smith'` src/ -i build/`
"""

import argparse
import dataclasses
import logging
import sys
import textwrap
from datetime import datetime, timezone
from io import TextIOWrapper
from pathlib import Path
from typing import Iterable, List, NoReturn

import pathspec
from rich.console import Console

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


console = Console()


_YEAR_MACRO = "{{ .YEAR }}"
_HOLDER_MACRO = "{{ .HOLDER }}"

_DEFAULT_LICENSE = f"(c) Copyright {_YEAR_MACRO} {_HOLDER_MACRO}. All rights reserved."

_DEFAULT_IGNORE = {".git/"}


_COLOR_MAUVE = "#cba6f7"
_COLOR_PINK = "#f5c2e7"
_COLOR_RED = "#f38ba8"
_COLOR_PEACH = "#fab387"
_COLOR_GREEN = "#a6e3a1"
_COLOR_LAVENDER = "#b4befe"


@dataclasses.dataclass
class GlobalSettings:
    """A holding singleton type for accessing and storing data whilst running recursively

    Instance Attributes:
        - check: if check is True, we only check if a license is present in every file given
        - license: the license (without comment tokens) to place into files that are found not to have one
        - read_gitignore: if read_gitignore is True, we will read any .gitignore found and add it to the current set
        - silent: if True, we won't print any output to console (though we may still log)
        - root: the path that the command was initially run from.
        - files_changed: when running in check mode, we will increment this count for every file that is missing
          a license
        - files_missing: when running in standard mode, we will increment this count for every file that is
          modified (i.e. a license is added)
    """

    check: bool
    license: str
    read_gitignore: bool
    silent: bool
    root: Path
    files_changed: int
    files_missing: int


@dataclasses.dataclass
class IgnoreHelper:
    """A dataclass representing .gitignore semantics.

    Instance Attributes:
        - relative_to: The Path where the .gitignore was initially found (for relative rules)
        - spec: The pathspec representing the rules in the .gitignore instance
    """

    relative_to: Path
    spec: pathspec.GitIgnoreSpec

    def matches_path(self, path: Path) -> bool:
        """Returns whether path matches against this set of .gitignore rules"""
        absolute_path = path.resolve()

        absolute_match = self.spec.match_file(absolute_path)

        if absolute_match:
            return True

        relative_path = absolute_path.relative_to(self.relative_to)
        return self.spec.match_file(relative_path)


def get_args_parser() -> argparse.ArgumentParser:
    """Returns the cli options parser for pyaddlicense"""
    parser = argparse.ArgumentParser(
        "pyaddlicense",
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(prog, width=120, max_help_position=60),
        description=textwrap.dedent(
            """
            A python version of addlicense. Adds copyright lines to files that don't have them.

            If neither of -l or -f are set, the default license used is: {}
            """.format(
                _DEFAULT_LICENSE
            )
        ),
    )

    parser.add_argument(
        "--check",
        "-c",
        help="check only: verify any copyright header exists on all files and exit with non-zero code if any are missing",
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
    )

    parser.add_argument(
        "--ignore",
        "-i",
        help="ignore: file patterns to ignore, for example: -ignore *.go -ignore build/* NOTE: by default pyaddlicense will attempt to respect all the .gitignore files that it encounters, you can disable this with --ignore-gitignore",
        default=[],
        nargs="*",
        required=False,
    )

    parser.add_argument(
        "--ignore-gitignore",
        help="ignore-gitignore: by default, pyaddlicense will attempt to respect all the .gitignore files it finds, adding this flag disables that",
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
    )

    license_group = parser.add_mutually_exclusive_group()

    license_group.add_argument(
        "--license-file",
        "-f",
        help="license file: path to a license file pyaddlicense should use. Supports basic macros of: {{ .YEAR }} and {{ .HOLDER }} for year and holder respectively)",
        type=argparse.FileType("r"),
        default=None,
        required=False,
    )

    license_group.add_argument(
        "--license",
        "-l",
        help="license: the license to use. Supports basic macros of: {{ .YEAR }} and {{ .HOLDER }} for year and holder respectively)",
        default=None,
        required=False,
    )

    parser.add_argument(
        "--holder",
        "-o",
        help="holder/owner: the license holder. This is a required flag. For example: -h 'John Smith' or -h 'Example Company LLC'",
        required=True,
    )

    parser.add_argument(
        "--silent",
        "-s",
        help="silent mode: suppress all terminal output",
        required=False,
        default=False,
        action=argparse.BooleanOptionalAction,
    )

    parser.add_argument(
        "src", help="source: the files or directories that pyaddlicense should be recursively run on", nargs="*"
    )

    return parser


def macro_license(license: str, holder: str, year: int | None = None) -> str:
    """Returns license with the following macros filled:
    - {{ .YEAR }}: Replaced with the current year.
    - {{ .HOLDER }}: Replaced with the holder of the copyright.
    """

    if year is None:
        year = datetime.now(timezone.utc).year

    license = license.replace(_YEAR_MACRO, str(year), -1)
    license = license.replace(_HOLDER_MACRO, holder, -1)

    return license


class BothLicenseOptionsGivenError(Exception):
    """Raised when both license options are given."""

    pass


def get_license_template(license: str | None, license_file: TextIOWrapper | None) -> str:
    """Returns the configured license template as a str. This can be one of:
    - license (given via the CLI flag -l)
    - The contents of the file at license_file (given via the CLI flag -f)
    - The `pyaddlicense` default.
    """

    if license is not None and license_file is not None:
        raise BothLicenseOptionsGivenError
    elif license_file:
        return license_file.read()
    elif license:
        return license
    else:
        return _DEFAULT_LICENSE


def convert_namespace_to_global_settings(args: argparse.Namespace, cwd: Path) -> GlobalSettings:
    """Converts the parsed argument namespace into a set of GlobalSettings. It will macro the license that it finds."""
    try:
        template_license = get_license_template(args.license, args.license_file)
    except BothLicenseOptionsGivenError:
        console.print(
            f"[{_COLOR_RED}]ERROR: Please give only one of -l (--license) or -f (--license-file)[/{_COLOR_RED}]"
        )
        sys.exit(1)

    macrod_license = macro_license(template_license, args.holder)

    if not macrod_license.endswith("\n"):
        macrod_license += "\n"

    return GlobalSettings(
        check=args.check,
        license=macrod_license,
        read_gitignore=not args.ignore_gitignore,
        silent=args.silent,
        root=cwd,
        files_changed=0,
        files_missing=0,
    )


def create_ignorespec_from_gitignore(dir_path: Path) -> pathspec.GitIgnoreSpec:
    """Returns an pathspec.GitIgnoreSpec from the .gitignore in the current directory or an
    empty one if it doesn't exist.
    """

    ignore_path = dir_path / ".gitignore"

    if not ignore_path.exists():
        return pathspec.GitIgnoreSpec.from_lines([])

    logger.debug(f"reading .gitignore at: {ignore_path}")

    with ignore_path.open() as ignore_file:
        no_whitespace = [line.strip() for line in ignore_file.readlines()]
        no_comments = [expr for expr in no_whitespace if not expr.startswith("#")]
        no_empty_lines = [expr for expr in no_comments if expr != ""]

    return pathspec.GitIgnoreSpec.from_lines(no_empty_lines)


def comment_license_header(license: str, start: str, mid: str, end: str) -> str:
    """Returns license as a block-level comment.

    NOTE: Any languages without a block-level comment need to just specify mid and
    both start and end will be ignored.

    Args:
        license: The (pre-macroed) license string to add to a file missing one.
        start: The character sequence required to start a block-level comment.
        mid: The character sequence required to continue a block-level comment.
        end: The character sequence required to end a block-level comment.

    Examples:
        If we took the following Javascript (JS) snippet:
            /**
            * I am a
            * block level
            * comment.
            */

        This is equivalent to:
            <START>
            <MID> I am a
            <MID> block level
            <MID> comment.
            <END>
    """
    full_license = ""

    if start != "":
        full_license += f"{start}\n"

    for line in license.splitlines():
        full_license += f"{mid}{line}\n"

    if not full_license.endswith("\n"):
        full_license += "\n"

    if end != "":
        full_license += f"{end}\n"

    return full_license


def create_license_header(path: Path, templated_license: str) -> None | str:
    """Checks the given path suffix to convert the given templated_license into a block-comment in various languages.
    It returns None if the Path suffix does not match a known language and processing will be skipped.
    """
    match path.suffix:
        case ".c" | ".h" | ".gv" | ".java" | ".scala" | ".kt" | ".kts":
            return comment_license_header(templated_license, "/*", " * ", " */")
        case ".js" | ".mjs" | ".cjs" | ".jsx" | ".tsx" | ".css" | ".scss" | ".sass" | ".ts":
            return comment_license_header(templated_license, "/**", " * ", " */")
        case ".cc" | ".cpp" | ".cs" | ".go" | ".hcl" | ".hh" | ".hpp" | ".m" | ".mm" | ".proto" | ".rs" | ".swift" | ".dart" | ".groovy" | ".v" | ".sv":
            return comment_license_header(templated_license, "", "// ", "")
        case ".py" | ".sh" | ".yaml" | ".yml" | ".dockerfile" | "dockerfile" | ".rb" | "gemfile" | ".tcl" | ".tf" | ".bzl" | ".pl" | ".pp" | "build" | ".php":
            return comment_license_header(templated_license, "", "# ", "")
        case ".el" | ".lisp":
            return comment_license_header(templated_license, "", ";; ", "")
        case ".erl":
            return comment_license_header(templated_license, "", "% ", "")
        case ".hs" | ".sql" | ".sdl":
            return comment_license_header(templated_license, "", "-- ", "")
        case ".html" | ".xml" | ".vue" | ".wxi" | ".wxl" | ".wxs":
            return comment_license_header(templated_license, "<!--", " ", "-->")
        case ".ml" | ".mli" | ".mll" | ".mly":
            return comment_license_header(templated_license, "(**", "   ", "*)")
        case _:
            return None


_INDICATOR_STRINGS = [
    "copyright",
    "mozilla public",
    "spdx-license-identifier",
    "do not edit",
    "code generated",
    "lockfile",
]


def file_has_license_or_is_generated(path: Path) -> bool:
    """Returns whether the file at path has a license already or whether it is autogenerated.

    NOTE: This is not perfect since it simply checks whether the first 1000 characters
    in the file contain any of _INDICATOR_STRINGS.
    """
    n = 1000
    file_size_bytes = path.stat().st_size

    if file_size_bytes < 1000:
        n = file_size_bytes

    with path.open("r") as f:
        start = f.read(n).lower()
        for indicator in _INDICATOR_STRINGS:
            if indicator in start:
                return True

    return False


_MAX_SIZE_BYTES = 1_000_000  # 1mb.
_HASH_BANG_STARTS = [
    "#!",  # Shell
    "<?xml",  # XML
    "<!doctype",  # HTML
    "# encoding",  # Ruby
    "# frozen_string_literal:",  # Ruby
    "<?php",  # PHP
    "# escape",  # Dockerfile (https://docs.docker.com/engine/reference/builder/#parser-directives)
    "# syntax",  # Dockerfile (https://docs.docker.com/engine/reference/builder/#parser-directives)
]


def get_updated_file_contents(file_lines: List[str], license: str) -> str:
    """Returns the full file represented by file_lines with license placed into the correct position (this is
    usually the top, but for shell scripts, XML and various other filetypes it could be further down).
    """
    updated_file = ""

    cursor = 0
    if len(file_lines) > 0:
        while True:
            if any([file_lines[cursor].startswith(hb) for hb in _HASH_BANG_STARTS]):
                updated_file += file_lines[cursor]
                cursor += 1
            else:
                break

    # Write the license.
    updated_file += license

    # Do we have any lines left?
    if cursor < len(file_lines):
        if not file_lines[cursor].startswith("\n"):
            updated_file += "\n"

        # Rest...
        for line in file_lines[cursor:]:
            updated_file += line

    return updated_file


def add_license_to_file(path: Path, license: str) -> None:
    """Attempts to add license to the file at path. If the file is larger that 1mb, this will not do any modification."""
    file_size_bytes = path.stat().st_size

    if file_size_bytes > _MAX_SIZE_BYTES:
        logger.error(f"file: {path} is too large (>1mb)")
        return

    # Figure out where to insert the license, then write the rest of the file.
    with path.open("r+") as file:
        file_lines = file.readlines()

        updated_contents = get_updated_file_contents(file_lines, license)

        # Write
        file.seek(0, 0)
        file.write(updated_contents)
        file.flush()


def process_file(path: Path, global_settings: GlobalSettings) -> None:
    """Processes the file at path, according to global_settings."""
    # Check if we recognise this file type and can generate a header for it.
    file_specific_license = create_license_header(path, global_settings.license)

    if file_specific_license is None:
        return

    exists_or_generated = file_has_license_or_is_generated(path)

    if exists_or_generated:
        return

    if global_settings.check:
        global_settings.files_missing += 1

        if not global_settings.silent:
            console.print(
                f"[{_COLOR_RED}]license missing from:[/{_COLOR_RED}] [{_COLOR_PINK}]{path.relative_to(global_settings.root)}[/{_COLOR_PINK}]"
            )
    else:
        add_license_to_file(path, file_specific_license)
        global_settings.files_changed += 1

        if not global_settings.silent:
            console.print(
                f"[{_COLOR_PEACH}]adding license to:[/{_COLOR_PEACH}] [{_COLOR_PINK}]{path.relative_to(global_settings.root)}[/{_COLOR_PINK}]"
            )


def process(path: Path, global_settings: GlobalSettings, ignore_patterns: Iterable[IgnoreHelper]) -> None:
    """Processes the file at path, according to global_settings and ignore_patterns.

    This is called recursively for every path found during a run, so ignore_patterns may grow over time.
    """
    for pattern in ignore_patterns:
        if pattern.matches_path(path):
            return

    if path.is_file():
        process_file(path, global_settings)
        return

    updated_ignore_patterns = [pattern for pattern in ignore_patterns]
    if global_settings.read_gitignore:
        this_spec = create_ignorespec_from_gitignore(path)

        if len(this_spec) > 0:
            updated_ignore_patterns += [IgnoreHelper(relative_to=path, spec=this_spec)]

    for child_path in path.iterdir():
        process(child_path, global_settings, updated_ignore_patterns)


def main() -> NoReturn:
    logger.debug(sys.argv)

    root_path = Path.cwd()

    parser = get_args_parser()
    args = parser.parse_args(sys.argv[1:])

    global_settings = convert_namespace_to_global_settings(args, root_path)

    root_path = Path.cwd()

    ignore_spec = pathspec.GitIgnoreSpec.from_lines(_DEFAULT_IGNORE)
    ignore_spec += pathspec.GitIgnoreSpec.from_lines(args.ignore)

    initial_ignore = IgnoreHelper(
        relative_to=root_path,
        spec=ignore_spec,
    )

    to_process: Iterable[Path] = []

    if len(args.src) <= 0:
        to_process += [root_path]
    else:
        to_process = [Path(p).resolve() for p in args.src]

    def process_fn():
        [process(path, global_settings, [initial_ignore]) for path in to_process]

    if global_settings.silent:
        process_fn()
    else:
        console.print(f"[{_COLOR_LAVENDER} bold]>>> Welcome to pyaddlicense![/{_COLOR_LAVENDER} bold] :rocket:")

        process_str = ""
        if global_settings.check:
            process_str = f"[{_COLOR_LAVENDER}]Checking...[/{_COLOR_LAVENDER}]"
        else:
            process_str = f"[{_COLOR_LAVENDER}]Processing...[/{_COLOR_LAVENDER}]"

        with console.status(process_str, spinner="dots"):
            process_fn()

        if global_settings.check:
            if global_settings.files_missing > 0:
                console.print(
                    f"[{_COLOR_MAUVE} bold]Complete![/{_COLOR_MAUVE} bold] [{_COLOR_RED}]{global_settings.files_missing} files are missing a license.[/{_COLOR_RED}] :collision:"
                )
            else:
                console.print(
                    f"[{_COLOR_MAUVE} bold]Complete![/{_COLOR_MAUVE} bold] [{_COLOR_GREEN}]No files require changes.[/{_COLOR_GREEN}] :sparkles:"
                )
        else:
            if global_settings.files_changed > 0:
                console.print(
                    f"[{_COLOR_MAUVE} bold]Complete![/{_COLOR_MAUVE} bold] [{_COLOR_PEACH}]{global_settings.files_changed} files changed.[/{_COLOR_PEACH}] :ewe:"
                )
            else:
                console.print(
                    f"[{_COLOR_MAUVE} bold]Complete![/{_COLOR_MAUVE} bold] [{_COLOR_GREEN}]No files changed.[/{_COLOR_GREEN}] :sparkles:"
                )

    if global_settings.check and global_settings.files_missing > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
