#include <Windows.h>
#include <iostream>

#include "../../ThirdParty/detours/include/detours.h"

#pragma comment(lib,"../../ThirdParty/detours/lib.X86/detours.lib")


int main(int argc, char* argv[])
{
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    std::string nameEXE;
    if (argc > 1)
    {
        nameEXE = argv[1];
    }
    else
    {
        std::cout << "Input EXE Name:";
        std::cin >> nameEXE;
    }
    LPCSTR nameDll = "ExHIBIT_KeyFinder.dll";
    DetourCreateProcessWithDllsA(nameEXE.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi, 1, &nameDll, NULL);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}