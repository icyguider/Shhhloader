# Shhhloader
Shhhloader is a SysWhispers Shellcode Loader that is currently a Work in Progress. It takes raw shellcode as input and compiles a C++ stub that has been integrated with SysWhispers in order to bypass AV/EDR. The included python builder will work on any Linux system that has Mingw-w64 installed. 

The tool has been confirmed to successfully load a Cobalt Strike beacon on fully updated systems with Windows Defender enabled. The project itself is still in a PoC/WIP state, as it currently doesn't work with all payloads. 

```
┳┻|
┻┳|
┳┻|
┻┳|
┳┻| _
┻┳| •.•)  - Shhhhh, AV might hear us! 
┳┻|⊂ﾉ   
┻┳|
usage: Shhhloader.py [-h] [-o a.exe] file

ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER

positional arguments:
  file                  File containing raw shellcode

optional arguments:
  -h, --help            show this help message and exit
  -o a.exe, --outfile a.exe
                        Name of compiled file
```
Video Demo: https://www.youtube.com/watch?v=ttCRiobmulU

Features:
* XOR Encryption with Dynamic Key Generation
* Sandbox Evasion via Loaded DLL Enumeration

Tested and Confirmed Working on:
* Windows 10 21H1 (10.0.19043)
* Windows 10 20H2 (10.0.19042)
* Windows Server 2019 (10.0.17763)

Greetz & Credit:
* Jthuraisamy for his amazing project SysWhispers: https://github.com/jthuraisamy/SysWhispers
* OutFlank for creating InlineWhispers (Mingw-w64 Compatible SysWhispers): https://github.com/outflanknl/InlineWhispers
* FalconForceTeam for their syscall generation tool that supports SysWhispers2: https://github.com/FalconForceTeam/SysWhispers2BOF
