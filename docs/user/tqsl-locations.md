<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Bring station locations from TQSL

Compare your TQSL locations with the QG Trust store:

```sh
qg-trust location tqsl
```

Each location is new, the same, different, or refused. A different location shows both values for each changed field. Fix a refused location in TQSL, then run the command again. Use `--json` for machine-readable output.

Add selected new locations by name, or add all new locations:

```sh
qg-trust location tqsl --add Home --add Portable
qg-trust location tqsl --all
```

Locations already in the store are never overwritten. By default, the command uses `TQSLDIR` when it is set and nonempty. Otherwise, it uses `%APPDATA%\TrustedQSL` on Windows and `$HOME/.tqsl` on other systems. If TQSL uses a different folder, give its path with `--folder`. For example, on macOS:

```sh
qg-trust location tqsl --folder "$HOME/Library/Application Support/TrustedQSL"
```
