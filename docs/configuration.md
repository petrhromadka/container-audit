# Configuration file

`container-audit` can read default options from a TOML file so you don't have
to repeat flags on every run. The file is optional: with no file and no
`--config`, behaviour is identical to passing flags alone.

## Discovery

- If `--config PATH` is given, that file is read. It is an error if the file
  is missing or malformed.
- Otherwise the current working directory is searched, in order, for:
  1. `container-audit.toml`
  2. `.container-audit.toml`

  The first file found is used. If neither exists, no config is loaded.

## Keys

All keys are optional. An unknown key or a wrong value type is a hard error.

| Key                | Type            | Meaning                                                              |
| ------------------ | --------------- | -------------------------------------------------------------------- |
| `ignore`           | list of strings | Check ids whose findings are suppressed.                             |
| `min_severity`     | string          | Hide findings below this severity (`info`/`low`/`medium`/`high`/`critical`). |
| `fail_on`          | string          | Exit 1 if any finding is at or above this severity (`none`/`low`/`medium`/`high`/`critical`). |
| `format`           | string          | Output format (`text`/`json`/`markdown`/`sarif`).                    |
| `include_host`     | boolean         | Include the real hostname in the report.                             |
| `include_stopped`  | boolean         | Also audit stopped containers.                                       |

## Precedence

CLI flag > config file > built-in default.

- `min_severity`, `fail_on`, `format`: a CLI flag wins; otherwise the config
  value is used; otherwise the built-in default (`info`, `none`, `text`).
- `ignore`: the effective ignore set is the **union** of the config `ignore`
  list and any `--ignore` flags.
- `include_host`, `include_stopped`: enabled if either the flag is passed or
  the config sets the key to `true`.

## Example

```toml
# container-audit.toml
ignore = ["writable-rootfs", "root-user"]
min_severity = "low"
fail_on = "high"
format = "json"
include_host = false
include_stopped = true
```
