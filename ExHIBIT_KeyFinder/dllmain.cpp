#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

VOID  __declspec(dllexport) WINAPI MyFunc()
{

}

FILE* streamconsole;
BOOL consoleState = FALSE;
BOOL processKeyState = FALSE;
DWORD findAddr;
DWORD retAddr;
DWORD dstCallAddr;

typedef HMODULE(WINAPI* pLoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
pLoadLibraryExA orgLoadLibraryExA = LoadLibraryExA;

DWORD MemSearch(DWORD beginAddr, VOID* searchCode, INT lenOfCode, BOOL clockWise)
{
	for (beginAddr; 1; )
	{
		if (beginAddr < 0x7FFF0000 && beginAddr > 0x00010000)
		{
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID)beginAddr, lenOfCode, PAGE_EXECUTE_READWRITE, &oldProtect);
			if (!memcmp(searchCode, (void*)beginAddr, lenOfCode))
			{
				return beginAddr;
			}

			if (clockWise)
			{
				beginAddr++;
			}
			else
			{
				beginAddr--;
			}
		}
		else
		{
			return 0;
		}
	}
}

VOID SetConsole()
{
	if (!consoleState)
	{
		AllocConsole();
		AttachConsole(ATTACH_PARENT_PROCESS);
		freopen_s(&streamconsole, "CONIN$", "r+t", stdin);
		freopen_s(&streamconsole, "CONOUT$", "w+t", stdout);
		SetConsoleTitleW(L"ExHIBIT_KeyFinder by Dir-A");

		std::cout.setf(std::ios::uppercase);

		consoleState = TRUE;
	}

}

VOID ProcessKey(LPSTR fullPath, DWORD keyFileAddr,DWORD key)
{
	SetConsole();
	keyFileAddr += 0x8;
	std::string rldName = fullPath;
	if (!processKeyState)
	{
		std::cout << "def.rld: " << "0x" << std::hex << key << std::endl;
		FILE* fp;
		errno_t err = fopen_s(&fp, "key_def.bin", "wb+");
		if (err == 0)
		{
			if (fp != 0)
			{
				fwrite((void*)keyFileAddr, 1, 0x400, fp);
				fflush(fp);
				fclose(fp);
				std::cout << "keyfile--->key_def.bin" << std::endl << std::endl;
				processKeyState = TRUE;
			}
		}
	}
	else
	{
		std::cout << "rld:     " << "0x" << std::hex << key << std::endl;
		FILE* fp;
		errno_t err = fopen_s(&fp, "key.bin", "wb+");
		if (err == 0)
		{
			if (fp != 0)
			{
				fwrite((void*)keyFileAddr, 1, 0x400, fp);
				fflush(fp);
				fclose(fp);
				std::cout << "keyfile--->key.bin" << std::endl << std::endl;
			}
		}
		std::cout << "Copy Key And Check Game Install Folder To Get Keyfile" << std::endl;
		system("pause");
		ExitProcess(0);
	}

}

VOID __declspec(naked) GetKey()
{
	DWORD key;
	DWORD keyFileAddr;
	LPSTR fullPath;
	__asm
	{
		pushad
		pushfd
		mov eax,[esp+0x30]
		mov key,eax
		mov keyFileAddr,ecx
		mov eax,[esp+0x38]
		mov fullPath,eax
	}
	ProcessKey(fullPath, keyFileAddr, key);
	__asm
	{
		popfd
		popad
		call dstCallAddr
		jmp retAddr
	}
}

VOID WriteHookCode(DWORD oldAddr, DWORD tarAddr)
{
	DWORD oldProtect = 0;
	VirtualProtect((LPVOID)oldAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	DWORD rawAddr = tarAddr - oldAddr - 5;
	BYTE code[7] = { 0xE9,0x00,0x00,0x00,0x00 };

	memcpy(&code[1], &rawAddr, 4);
	memcpy((void*)oldAddr, code, 5);
}

VOID StartHOOK(HMODULE hDll)
{
	BYTE searchString[] = { 0x6C,0x6F,0x61,0x64,0x52,0x6C,0x64,0x00 };
	findAddr = MemSearch((DWORD)hDll + 0x1000, searchString, sizeof(searchString), 1);

	BYTE searchPushStr[] = { 0x68,0x00,0x00,0x00,0x00 };
	memcpy(&searchPushStr[1], &findAddr, 4);
	findAddr = MemSearch(findAddr, searchPushStr, sizeof(searchPushStr), 0);

	BYTE searchCall[] = { 0xE8 };
	findAddr = MemSearch(findAddr, searchCall, sizeof(searchCall), 0);
	findAddr = MemSearch(findAddr - 1, searchCall, sizeof(searchCall), 0);

	retAddr = findAddr + 5;
	DWORD rawAddr = 0;
	memcpy(&rawAddr, (VOID*)(findAddr + 1), 4);
	dstCallAddr = (rawAddr + findAddr + 5);

	WriteHookCode(findAddr, (DWORD)GetKey);
}

HMODULE WINAPI newLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	LPCSTR tarDll = "resident.dll";
	HMODULE hDll = orgLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	if (!strcmp(lpLibFileName, tarDll))
	{
		StartHOOK(hDll);
	}
	return hDll;
}

VOID StartFinder()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)orgLoadLibraryExA, newLoadLibraryExA);
	DetourTransactionCommit();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		StartFinder();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}