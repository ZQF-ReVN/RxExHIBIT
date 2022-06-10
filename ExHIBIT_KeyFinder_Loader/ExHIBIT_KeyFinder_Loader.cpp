#include <Windows.h>
#include <iostream>
#include <detours.h>

STARTUPINFOA si;
PROCESS_INFORMATION pi;

int main(int argc, char* argv[])
{
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