@echo off

setlocal ENABLEDELAYEDEXPANSION

set tz=%~1

if not "%tz%"=="" (
    if exist %SystemRoot%\system32\tzutil.exe (
        %SystemRoot%\system32\tzutil.exe /s "%tz%"
    ) else (
        CONTROL.EXE TIMEDATE.CPL,,/Z %tz%
    )
)

:END