# Historical test directory

The executable scripts in this directory predate the flat-INI qeli architecture and are
not CI or release inputs. In particular, scripts that connect as root to fixed lab hosts,
target `vpn-obfuscated`, write JSON configuration, or install retired systemd units are
disabled and exit before opening a network connection.

Current verification lives in the component test suites, `qeli/tests`, GitHub Actions,
and maintained checks such as `scripts/test_native_recipes.py`.
The standalone `scripts/lab_sync_build.py` command is retired: it stopped
working services, killed processes by name and rewrote shared lab inputs.
Its importable helpers remain for historical consumers; those consumers
are not isolated release gates. Run lab checks only in an owned isolated
fixture. `benchmark_results.json` is a historical measurement record.
