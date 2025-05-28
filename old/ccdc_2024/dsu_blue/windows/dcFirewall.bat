@ECHO OFF
setlocal EnableDelayedExpansion

:: Get Domain Information
:: Domain Controller names in %domainConts[]%
:: Domain Controller IPs in %domainContsIPs[]%
:: Domain Computer names in %domainComps[]%
:: Domain Computer names in %domainCompsIPs[]%

:: Get DC IPs (Including self)
set i=0
for /f "skip=6 tokens=1-3" %%a in ('net group "Domain Controllers" /domain') do (
    if "%%a %%b %%c"=="The command completed" goto :dc_end
    call :dc_process_single !i! %%a
    set /A i+=1
    if "%%b" == "" goto :dc_end
    call :dc_process_single !i! %%b
    set /A i+=1
    if "%%c" == "" goto :dc_end
    call :dc_process_single !i! %%c
    set /A i+=1
)

:dc_end
set /A i-=1
set k=0
for /l %%d in (0,1,!i!) do (
    for /f "skip=4 tokens=2" %%e in ('nslookup !domainConts[%%d]!') do (
        if "%%e"=="" goto :eof
        set domainContsIPs[!k!]=%%e
        set /A k+=1
    )
)
set /A k-=1
echo Domain Controllers
for /L %%g in (0,1,!k!) do (
    echo !domainContsIPs[%%g]!
)
echo =================

goto :start_comps

:dc_process_single
if "%~2"=="" goto :eof
set trim=%2
set trim=%trim:~0,-1%
set domainConts[%~1]=!trim!
goto :eof

:start_comps
set i=0
for /f "skip=6 tokens=1-3" %%a in ('net group "Domain Computers" /domain') do (
    if "%%a %%b %%c"=="The command completed" goto :end

    call :process_single !i! %%a
    set /A i+=1
    if "%%b" == "" goto :end
    call :process_single !i! %%b
    set /A i+=1
    if "%%c" == "" goto :end
    call :process_single !i! %%c
    set /A i+=1
)

:end
set /A i-=1
set j=0
for /L %%d in (0,1,!i!) do (
    for /f "skip=4 tokens=2" %%e in ('nslookup !domainComps[%%d]!') do (
        if "%%e"=="" goto :eof
        set domainCompsIPs[!j!]=%%e
        set /A j+=1
    )
)
set /A j-=1
echo Domain Computers
for /L %%g in (0,1,!j!) do (
    echo !domainCompsIPs[%%g]!
)
echo =================
pause
goto :add_DCs_to_Computers

:process_single
if "%~2"=="" goto :eof
set trim=%2
set trim=%trim:~0,-1%
set domainComps[%~1]=!trim!
goto :eof

:add_DCs_to_Computers
for /L %%z in (0,1,!k!) do (
    set /A j+=1
    set domainCompsIPs[!j!]=!domainContsIPs[%%z]!
)


:rules
:: RDP Server
netsh advfirewall firewall add rule name= "RDP In" dir=in action=allow protocol=TCP localport=3389 program=%SystemRoot%\System32\svchost.exe service=TermService > nul
:: Ping
netsh advfirewall firewall add rule name= "Ping In" dir=in action=allow protocol=icmpv4 remoteip=10.120.0.0/16 > nul
:: DNS Server
netsh advfirewall firewall add rule name= "DNS In" dir=in action=allow protocol=UDP localport=53 remoteip=LocalSubnet > nul
netsh advfirewall firewall add rule name= "DNS Out" dir=out action=allow protocol=UDP remoteport=53 remoteip=dns > nul

for /L %%y in (0,1,!j!) do (
	set remoteIP=!remoteIP!!DomainCompsIPs[%%y]!,
)
set remoteIP=%remoteIP:~0,-1%
echo Adding Domain Rules for %remoteIP%
REM Domain Computer Rules
REM Kerberos Server
netsh advfirewall firewall add rule name= "Kerberos TCP In" dir=in action=allow protocol=TCP localport=88 remoteip=!remoteIP! > nul
netsh advfirewall firewall add rule name= "Kerberos UDP In" dir=in action=allow protocol=UDP localport=88 remoteip=!remoteIP! > nul
netsh advfirewall firewall add rule name= "Kerberos UDP Out" dir=out action=allow protocol=UDP remoteport=88 remoteip=!remoteIP! > nul
REM SMB Server
netsh advfirewall firewall add rule name= "SMB In" dir=in action=allow protocol=TCP localport=445 remoteip=!remoteIP! > nul
netsh advfirewall firewall add rule name= "SMB out" dir=out action=allow protocol=TCP remoteport=445 remoteip=!remoteIP! > nul
REM RPC Endpoint Mapper/WMI
netsh advfirewall firewall add rule name= "RPC Map/WMI In" dir=in action=allow protocol=TCP localport=135 remoteip=!remoteIP! > nul
netsh advfirewall firewall add rule name= "RPC Map/WMI Out" dir=out action=allow protocol=TCP remoteip=!remoteIP! > nul
REM RPC
REM Dynamic (ephemeral), not sure how to do this
REM W32Time
netsh advfirewall firewall add rule name= "W32Time In" dir=in action=allow protocol=UDP localport=123 remoteip=!remoteIP! > nul
echo Domain Computer Rules Complete
for /L %%y in (0,1,!k!) do (
	set remoteDCIP=!remoteDCIP!!DomainContsIPs[%%y]!,
)
set remoteDCIP=%remoteDCIP:~0,-1%
echo Adding DC Rules for %remoteDCIP%
:: Inter-DC File Replication
netsh advfirewall firewall add rule name= "TCP DC File Replication In" dir=in action=allow protocol=TCP localport=139 remoteip=!RemoteDCIP! > nul
netsh advfirewall firewall add rule name= "TCP DC File Replication Out" dir=out action=allow protocol=TCP remoteport=139 remoteip=!RemoteDCIP! > nul
netsh advfirewall firewall add rule name= "UDP DC File Replication In" dir=in action=allow protocol=UDP localport=138 remoteip=!RemoteDCIP! > nul
netsh advfirewall firewall add rule name= "UDP DC File Replication Out" dir=out action=allow protocol=UDP remoteport=138 remoteip=!RemoteDCIP! > nul
echo Domain Controller Rules Complete
pause