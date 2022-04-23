#pragma once
 
/*
	Bliblioteka memory honeypot
	Autor: Regz.pl
 
	Przykład:
		memory_honeypot::add();
		memory_honeypot::add();
		memory_honeypot::add();
 
		while (true)
		{
			if(memory_honeypot::check())
				MessageBox(NULL, "Znaleziono skaner", "Błąd", MB_OK);
 
			Sleep(15);
		}
 
	Test:
		Uruchom Cheat Engine i wyszukaj dowolną wartość a funkcja check zwróci prawdę.
*/
 
#include <Windows.h>
#include <Psapi.h>
#include <vector>
 
namespace memory_honeypot
{
	static std::vector<void*> honeypots;
	static std::vector<DWORD> types { PAGE_READWRITE,PAGE_READONLY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ } ;
 
	void add()
	{
		honeypots.push_back(VirtualAlloc(nullptr, (rand() % 0x1000) + 0x10, MEM_RESERVE | MEM_COMMIT, types[rand() % types.size()]));
	}
 
	int check()
	{
		for (void* honeypot : honeypots)
		{
			PSAPI_WORKING_SET_EX_INFORMATION info = { honeypot, 0 };
			if (K32QueryWorkingSetEx(GetCurrentProcess(), &info, sizeof(PSAPI_WORKING_SET_EX_INFORMATION)) && info.VirtualAttributes.Valid == true)
				return 1;
		}
		return 0;
	}
}
