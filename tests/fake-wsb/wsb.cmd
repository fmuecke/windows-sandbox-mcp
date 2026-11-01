@pwsh -NoProfile -NonInteractive -File "%~dp0fake-wsb.ps1" %*
@exit /b %ERRORLEVEL%
