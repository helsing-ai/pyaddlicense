# pyaddlicense

pyaddlicense adds license headers to any source file it finds that does not have one. By default it respects `.gitignore` and doesn't touch autogenerated files.

It is inspired by [addlicense](https://github.com/google/addlicense), but includes more features and can be used in environments that might not have `go` or `docker`.

Default Example:
```
pyaddlicense -o 'Example Company'
```

## Installation

We recommend installing `pyaddlicense` globally via `uv` so that it remains in an isolated environment:
```
uv tool install pyaddlicense
```

## Usage and flags

### Default

By default, only the `-o` (or `--owner`) flag is required to say who the holder/owner of the license is:

```
pyaddlicense -o 'Example Company'
```

This will recursively search every file and every directory from the current one and add the default license to every file where a license is missing any the file isn't autogenerated. This will respect any .gitignore entries.

The default license is: `(c) Copyright {{ .HOLDER }} {{ .YEAR }}. All rights reserved.` where both `{{ .HOLDER }}` and `{{ .YEAR }}` are macros that will be replaced by the string given as `-o` and the current year respectively.

### Check mode

If you just want to see what files are missing licenses, you can use the `-c` (or `--check`) flag:

```
pyaddlicense -o 'Example Company' -c
```

### Custom Ignore

You can additional files or folders to ignore with the `-i` (or `--ignore`) flag:

```
pyaddlicense -o 'Example Company' -i pyproject.toml
```

NOTE: This will be _additional_ to `.gitignore`, if you want to disable `.gitignore` checking and completely manage the ignore rules yourself, also set `--ignore-gitignore=0`.

### Custom license

If you want to use your own license, there are two options.

*Option 1:* Use the `-l` flag to pass the license as a string (which can also include macros, as detailed in the Default section):
```
pyaddlicense -o 'Example Company' -l '{{ .HOLDER }} {{ .YEAR }}. Absolutely no rights reserved and no warranty given.'
```

*Option 2:* Use the `-f` flag to pass the license as a file (which can also include macros, as detailed in the Default section):
```
pyaddlicense -o 'Example Company' -f ~/licenses/norightsreserved.tpl
```

### Silent mode

You can disable console output via the `-s` (or `--silent`) flag. This is useful for integrating `pyaddlicense` into a linting/CI pipeline without warping the logs too much:
```
pyaddlicense -o 'Example Company' -c -s
```
(When running in `check mode` (detailed above), `pyaddlicense` will have a *non-zero exit code* if files are found that need changes)

## Development

*NOTE:* Local development requires `uv` to be installed.

Clone this repo:

```
git clone git@github.com:helsing-ai/pyaddlicense.git
```

Install our dependencies:

```
uv sync
```

### Testing:

Run the tests via:
```
uv run pytest tests
```

### Linting:

Lint any changes with:
```
uv run ruff check --fix .
uv run ruff format .
uv run mypy src tests
```
