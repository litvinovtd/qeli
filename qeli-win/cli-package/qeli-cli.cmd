@echo off
setlocal DisableDelayedExpansion
"%~dp0bin\qeli-cli.exe" %*
exit /b %errorlevel%
