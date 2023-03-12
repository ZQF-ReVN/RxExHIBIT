#include <Windows.h>
#include <iostream>
#include <Shlwapi.h>

#include "../../ThirdParty/detours/include/detours.h"

#pragma comment(lib,"../../ThirdParty/detours/lib.X86/detours.lib")
#pragma comment(lib, "shlwapi.lib")


static HANDLE g_hSTD_OUT = NULL;
static LPCSTR g_lpHookDllName = "resident.dll";


typedef VOID(__thiscall* pDecodeScript)(PDWORD pThis, DWORD isDecode, PDWORD pScript, SIZE_T szScript, DWORD dwKey);
pDecodeScript RawDecodeScript = nullptr;

typedef HMODULE(WINAPI* pLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
pLoadLibraryExA RawLoadLibraryExA = LoadLibraryExA;


BOOL WriteHookCode(DWORD dwRawAddress, DWORD dwNewAddress, SIZE_T szHookCode);
DWORD MemSearch(DWORD pFind, SIZE_T szFind, PBYTE pToFind, SIZE_T szToFind, BOOL backward = FALSE);
BOOL DetourAttachFunc(PVOID ppRawFunc, PVOID pNewFunc);
BOOL DetourDetachFunc(PVOID ppRawFunc, PVOID pNewFunc);


VOID __fastcall NewDecodeScript(PDWORD pThis, DWORD dwEDX, DWORD isDecode, PDWORD pScript, SIZE_T szScript, DWORD dwKey)
{
	static DWORD countScript = 0;
	static WCHAR lpStringOut[0xFF] = { 0 };
	switch (countScript)
	{
	case 0:
	{
		HANDLE hFile = CreateFileW(L"key_def.bin", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, pThis + 2, 0x400, NULL, NULL);
			FlushFileBuffers(hFile);
			CloseHandle(hFile);

			wsprintfW(lpStringOut, L"def.rld: 0x%X\n", dwKey);
			WriteConsoleW(g_hSTD_OUT, lpStringOut, lstrlenW(lpStringOut), NULL, NULL);
			WriteConsoleW(g_hSTD_OUT, L"keyfile ---> key_def.bin\n\n", 26, NULL, NULL);
		}
		else
		{
			WriteConsoleW(g_hSTD_OUT, L"Create key_def.bin Failde!!", 27, NULL, NULL);
		}
	}
	break;

	case 1:
	{
		HANDLE hFile = CreateFileW(L"key.bin", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFile, pThis + 2, 0x400, NULL, NULL);
			FlushFileBuffers(hFile);
			CloseHandle(hFile);

			wsprintfW(lpStringOut, L"rld:     0x%X\n", dwKey);
			WriteConsoleW(g_hSTD_OUT, lpStringOut, lstrlenW(lpStringOut), NULL, NULL);
			WriteConsoleW(g_hSTD_OUT, L"keyfile ---> key.bin\n\n", 22, NULL, NULL);
		}
		else
		{
			WriteConsoleW(g_hSTD_OUT, L"Create key.bin Failde!!\n", 24, NULL, NULL);
		}
	}
	break;

	case 2:
	{
		WriteConsoleW(g_hSTD_OUT, L"Check Game Directory!!", 22, NULL, NULL);
		DetourDetachFunc(&RawDecodeScript, NewDecodeScript);
	}
	break;
	}

	countScript++;
	return RawDecodeScript(pThis, isDecode, pScript, szScript, dwKey);
}

DWORD FindDecodeScript(HMODULE hmImageBase)
{
	//Find Decode Function
	DWORD find = NULL;
	DWORD pFunc = NULL;

	//Find String "loadRld"
	BYTE toFindString[] = { 0x6C,0x6F,0x61,0x64,0x52,0x6C,0x64,0x00 };
	find = MemSearch((DWORD)hmImageBase + 0x1000, 0x4000000, toFindString, sizeof(toFindString));

	//Find Push offset"loadRld"
	BYTE toFindPushStr[] = { 0x68,0x00,0x00,0x00,0x00 };
	memcpy(toFindPushStr + 1, &find, 4);
	find = MemSearch(find + 0, 0x4000000, toFindPushStr, sizeof(toFindPushStr), TRUE);

	//Find Call Decode Function
	BYTE toFindCall[] = { 0xE8 };
	find = MemSearch(find + 0, 0x4000000, toFindCall, sizeof(toFindCall), TRUE);
	find = MemSearch(find - 1, 0x4000000, toFindCall, sizeof(toFindCall), TRUE);

	//Get Function Addr
	pFunc = *(PDWORD)(find + 1) + find + 5;

	return pFunc;
}

HMODULE WINAPI NewLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE hDll = RawLoadLibraryExA(lpLibFileName, hFile, dwFlags);

	if (!strcmp(lpLibFileName, g_lpHookDllName))
	{
		RawDecodeScript = (pDecodeScript)FindDecodeScript(hDll);
		DetourAttachFunc(&RawDecodeScript, NewDecodeScript);
		DetourDetachFunc(&RawLoadLibraryExA, NewLoadLibraryExA);

		AllocConsole();
		AttachConsole(ATTACH_PARENT_PROCESS);

		g_hSTD_OUT = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	return hDll;
}

VOID StartFinder()
{
	DetourAttachFunc(&RawLoadLibraryExA, NewLoadLibraryExA);
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		StartFinder();
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

VOID  __declspec(dllexport) DirA(){}

BOOL WriteMemory(LPVOID lpAddress, LPCVOID lpBuffer, SIZE_T nSize)
{
	DWORD old = 0;
	BOOL protect = VirtualProtectEx(GetCurrentProcess(), lpAddress, nSize, PAGE_EXECUTE_READWRITE, &old);
	BOOL written = WriteProcessMemory(GetCurrentProcess(), lpAddress, lpBuffer, nSize, NULL);

	if (protect && written) return TRUE;

	MessageBoxW(NULL, L"WriteMemory Failed!!", NULL, NULL);

	return FALSE;
}

BOOL WriteHookCode(DWORD dwRawAddress, DWORD dwNewAddress, SIZE_T szHookCode)
{
	UCHAR code[0xF];
	memset(code, 0x90, 0xF);

	*(UCHAR*)(code + 0) = 0xE9;
	*(DWORD*)(code + 1) = dwNewAddress - dwRawAddress - 5;

	if (WriteMemory((LPVOID)dwRawAddress, &code, szHookCode)) return TRUE;

	MessageBoxW(NULL, L"WriteHookCode Failed!!", NULL, NULL);

	return FALSE;
}

DWORD MemSearch(DWORD pFind, SIZE_T szFind, PBYTE pToFind, SIZE_T szToFind, BOOL backward)
{
	if ((pFind >= 0x7FFF0000) || (pFind <= 0x00010000) || !szToFind) return NULL;

	if (!backward)
	{
		for (size_t ite = 0; ite < szFind; ite++)
		{
			if (!memcmp(pToFind, (void*)pFind++, szToFind)) return (pFind - 1);
		}
	}
	else
	{
		for (size_t ite = 0; ite < szFind; ite++)
		{
			if (!memcmp(pToFind, (void*)pFind--, szToFind)) return (pFind + 1);
		}
	}

	MessageBoxW(NULL, L"MemSearch Failed!!", NULL, NULL);
	ExitProcess(0);
	return NULL;
}


BOOL DetourAttachFunc(PVOID ppRawFunc, PVOID pNewFunc)
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	LONG erroAttach = DetourAttach((PVOID*)ppRawFunc, pNewFunc);
	LONG erroCommit = DetourTransactionCommit();

	if (erroAttach == NO_ERROR && erroCommit == NO_ERROR) return false;

	MessageBoxW(NULL, L"DetourAttach Failed!!", NULL, NULL);

	return true;
}

BOOL DetourDetachFunc(PVOID ppRawFunc, PVOID pNewFunc)
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	LONG erroDetach = DetourDetach((PVOID*)ppRawFunc, pNewFunc);
	LONG erroCommit = DetourTransactionCommit();

	if (erroDetach == NO_ERROR && erroCommit == NO_ERROR) return false;

	MessageBoxW(NULL, L"DetourDetachFunc Failed!!", NULL, NULL);

	return true;
}
