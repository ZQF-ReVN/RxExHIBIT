#include <iostream>

#include <Rut/RxCmd.h>
#include <RxHook/Hook.h>


int wmain(int argc, wchar_t* argv[])
{
	try
	{
		Rut::RxCmd::Arg arg;
		arg.AddCmd(L"-exe", L"exe path");
		arg.AddExample(L"-exe ExHIBIT.exe");
		if (arg.Load(argc, argv) == false) { return 0; }

		STARTUPINFOW si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		si.cb = sizeof(si);

		const char* dll_name = "KeyFinder.dll";
		if (Rut::RxHook::CreateProcessWithDlls(arg[L"-exe"].ToWStrView().data(), CREATE_SUSPENDED, 1, &dll_name, &si, &pi))
		{
			if (pi.hThread)
			{
				ResumeThread(pi.hThread);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
			}
		}
		else
		{
			throw std::runtime_error("Loader: inject dll to game failed!");
		}
	}
	catch (const std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
	}
}