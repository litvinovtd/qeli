# Historical test directory

The executable scripts in this directory predate the flat-INI qeli architecture and are
not CI or release inputs. In particular, scripts that connect as root to fixed lab hosts,
target `vpn-obfuscated`, write JSON configuration, or install retired systemd units are
disabled and exit before opening a network connection.

Current verification lives in the component test suites, `qeli/tests`, GitHub Actions,
and maintained scripts such as `scripts/lab_sync_build.py` and
`scripts/test_native_recipes.py`. `benchmark_results.json` is retained only as a
historical measurement record.
