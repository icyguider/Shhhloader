# Shhhloader
Shhhloader is a SysWhispers Shellcode Loader that is currently a Work in Progress. It takes raw shellcode as input and compiles a C++ stub that has been integrated with SysWhispers in order to bypass AV/EDR. The included python builder will work on any Linux system that has Mingw-w64 installed. 

The tool has been confirmed to successfully load Meterpreter and a Cobalt Strike beacon on fully updated systems with Windows Defender enabled. The project itself is still in a PoC/WIP state, as it currently doesn't work with all payloads.

**1/21/22 EDIT: Shhhloader now uses process hollowing! See below for updated usage. Staged Meterpreter and Cobalt Strike beacons have been confirmed to work. Stageless payloads are currently not working, so stay tuned for further updates!**

```
┳┻|
┻┳|
┳┻|
┻┳|
┳┻| _
┻┳| •.•)  - Shhhhh, AV might hear us! 
┳┻|⊂ﾉ   
┻┳|
usage: Shhhloader.py [-h] [-p explorer.exe] [-o a.exe] file

ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER

positional arguments:
  file                  File containing raw shellcode

optional arguments:
  -h, --help            show this help message and exit
  -p explorer.exe, --process explorer.exe
                        Process to inject into (Default: explorer.exe)
  -o a.exe, --outfile a.exe
                        Name of compiled file
```
Video Demo: https://www.youtube.com/watch?v=HE7L5R4iTOk

Features:
* Process Hollowing
* XOR Encryption with Dynamic Key Generation
* Sandbox Evasion via Loaded DLL Enumeration

Tested and Confirmed Working on:
* Windows 10 21H1 (10.0.19043)
* Windows 10 20H2 (10.0.19042)
* Windows Server 2019 (10.0.17763)

Scan Results as of 1/21/22 (x64 Meterpreter): https://antiscan.me/scan/new/result?id=VmGJxUdXVcYr

![Scan](https://antiscan.me/images/result/VmGJxUdXVcYr.png)

Greetz & Credit:
* Jthuraisamy for his amazing project SysWhispers: https://github.com/jthuraisamy/SysWhispers
* OutFlank for creating InlineWhispers (Mingw-w64 Compatible SysWhispers): https://github.com/outflanknl/InlineWhispers
* FalconForceTeam for their syscall generation tool that supports SysWhispers2: https://github.com/FalconForceTeam/SysWhispers2BOF
* Snovvcrash for their NimHollow project, which I used as a template for process hollowing: https://github.com/snovvcrash/NimHollow
