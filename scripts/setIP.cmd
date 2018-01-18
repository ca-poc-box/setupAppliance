@echo off

setlocal ENABLEDELAYEDEXPANSION

set mac=%1
set policy=%2
set name=

if not [%3]==[""] (
  set ipaddr=addr=%3
)

if not [%4]==[""] (
  set netmask=mask=%4
)

if not [%5]==[""] (
  set gateway=gateway=%5 gwmetric=1
)

set dns1=%6
set dns2=%7

rem determine network adapter
for /f "delims=" %%a in ('getmac /fo csv /nh /v') do (
    set line=%%a&set line=!line:"=,!
    for /f "delims=,,, tokens=1,3" %%b in ("!line!") do (
        set name=%%b
        set mactest=%%c
        if "!mac!"=="!mactest!" (
            GOTO :SetIP
        )
    )
)
GOTO :END

:SetIP
if not "%name%"=="" (
  if not [%policy%]==[""] (
    if "%policy%" == "static" (
      netsh interface ip set address "%name%" static !ipaddr! !netmask! !gateway!
      netsh interface ip delete dns "%name%" all >null"
      if not [%dns1%] == [""] (
          netsh interface ip add dns "%name%" %dns1% validate=no
      )
	    
      if not [%dns2%] == [""] (
	  netsh interface ip add dns %name% %dns2% index=2 validate=no
      )

    ) else (
      netsh interface ip set address "%name%" dhcp
      netsh interface ip set dns "%name%" dhcp
    )
  )
)

:END