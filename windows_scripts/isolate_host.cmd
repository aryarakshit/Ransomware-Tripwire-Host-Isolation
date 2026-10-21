@echo off
REM =========================================================================
REM  Wazuh Active Response Wrapper: isolate_host.cmd
REM  Invoked by Wazuh Agent upon triggering canary detection rules (100201-100203)
REM =========================================================================

powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%~dp0isolate_host.ps1"
exit /b %ERRORLEVEL%
