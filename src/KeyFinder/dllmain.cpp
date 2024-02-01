#include <Rut/RxCmd.h>
#include <Rut/RxFile.h>
#include <RxHook/Hook.h>
#include <RxHook/Mem.h>
#include <RxHook/API_DEF.h>


struct UxMemoryCryptor
{
	void* pVtable;
	uint32_t uiKey;
	uint8_t aTable[1024];
};

typedef void(__thiscall* Fn_DecryptRLD)(UxMemoryCryptor* pCryptor, uint32_t isDecode, uint32_t pScript, uint32_t szScript, uint32_t uiKey);

static Fn_DecryptRLD sg_fnDecryptRLD = nullptr;
static Rut::RxHook::Fn_LoadLibraryExA sg_fnLoadLibraryExA = ::LoadLibraryExA;


static void __fastcall DecryptRLD_Hook(UxMemoryCryptor* pCryptor, uint32_t dwEDX, uint32_t isDecode, uint32_t pScript, uint32_t szScript, uint32_t uiKey)
{
	static uint32_t call_times = 0;

	switch (call_times)
	{
	case 0:
	{
		try
		{
			Rut::RxFile::Binary ofs_def_table{ L"key_def.bin" ,Rut::RIO_WRITE };
			ofs_def_table << pCryptor->aTable;

			Rut::RxFile::Text ofs_def_key{ L"key_def.txt" ,Rut::RIO_WRITE, Rut::RFM_ANSI };
			char key_str_buf[0x10];
			::sprintf_s(key_str_buf, 0x10, "0x%08X", pCryptor->uiKey);
			ofs_def_key << key_str_buf;

			Rut::RxCmd::Put(L"KeyFinder: save key_def.bin / key_def.txt to current directory\n");
		}
		catch (const std::runtime_error& err)
		{
			Rut::RxCmd::Put(L"KeyFinder: save file error!\n");
		}
	}
	break;

	case 1:
	{
		try
		{
			Rut::RxFile::Binary ofs_def_table{ L"key.bin" ,Rut::RIO_WRITE };
			ofs_def_table << pCryptor->aTable;

			Rut::RxFile::Text ofs_def_key{ L"key.txt" ,Rut::RIO_WRITE, Rut::RFM_ANSI };
			char key_str_buf[0x10];
			::sprintf_s(key_str_buf, 0x10, "0x%08X", pCryptor->uiKey);
			ofs_def_key << key_str_buf;

			Rut::RxCmd::Put(L"KeyFinder: save key.bin / key.txt to current directory\n");
		}
		catch (const std::runtime_error& err)
		{
			Rut::RxCmd::Put(L"KeyFinder: save file error!\n");
		}
	}
	break;
	}

	call_times++;
	return sg_fnDecryptRLD(pCryptor, isDecode, pScript, szScript, uiKey);
}

static uint8_t* FindFnDecodeScript(HMODULE hImageBase)
{
	//Step1 Find String "loadRld"
	uint8_t find_data_loadRld[] = { 0x6C,0x6F,0x61,0x64,0x52,0x6C,0x64,0x00 };
	uint8_t* str_loadRld_ptr = (uint8_t*)Rut::RxHook::MemSearch((uint8_t*)hImageBase + 0x1000, 0x4000000, find_data_loadRld, sizeof(find_data_loadRld));

	//Step2 Find Push "loadRld" Opcode Address
	uint8_t find_data_pushstr[] = { 0x68,0x00,0x00,0x00,0x00 };
	::memcpy(find_data_pushstr + 1, &str_loadRld_ptr, 4);
	uint8_t* push_loadRld_ptr = (uint8_t*)Rut::RxHook::MemSearch(str_loadRld_ptr, 0x4000000, find_data_pushstr, sizeof(find_data_pushstr), true);

	//Step3 Find Call DecodeScript Opcode Address
	uint8_t find_data_call[] = { 0xE8 };
	// Find First Call Address
	uint8_t* first_call_ptr = (uint8_t*)Rut::RxHook::MemSearch(push_loadRld_ptr, 0x4000000, find_data_call, sizeof(find_data_call), true);
	// Find Second Call Address (call DecodeScript)
	uint8_t* call_DecodeScript_ptr = (uint8_t*)Rut::RxHook::MemSearch(first_call_ptr - 1, 0x4000000, find_data_call, sizeof(find_data_call), true);

	//Step4 Get DecodeScript Function Address
	uint8_t* fn_DecodeScript_ptr = *(uint32_t*)(call_DecodeScript_ptr + 1) + call_DecodeScript_ptr + 5;

	return fn_DecodeScript_ptr;
}

static HMODULE WINAPI LoadLibraryExA_Hook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE dll_handle = sg_fnLoadLibraryExA(lpLibFileName, hFile, dwFlags);

	if (!::strcmp(lpLibFileName, "resident.dll"))
	{
		sg_fnDecryptRLD = (Fn_DecryptRLD)::FindFnDecodeScript(dll_handle);
		Rut::RxHook::Detours::Begin();
		Rut::RxHook::Detours::Attach(&sg_fnDecryptRLD, ::DecryptRLD_Hook);
		Rut::RxHook::Detours::Detach(&sg_fnLoadLibraryExA, ::LoadLibraryExA_Hook);
		Rut::RxHook::Detours::Commit();
	}

	return dll_handle;
}

static void StartHook()
{
	Rut::RxCmd::Alloc(L"KeyFinder");
	Rut::RxHook::Detours::AttrachDirectly(&sg_fnLoadLibraryExA, ::LoadLibraryExA_Hook);
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		::StartHook();
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
