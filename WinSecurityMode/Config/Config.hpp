//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//

#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>
#include <stdio.h>
#include <sddl.h>

#include <aclapi.h>
#include <NTSecAPI.h>

using namespace std;

namespace Config {
	class Profile {
	public:
		Profile()
		{
			// MessageBox(0,L"Config",L"",0);
			nameW = L"this is a profile";
			nameA = "this is a profile";
			// FuncAddr = static_cast<void*>(ObjectAddr2);
		}

		const wchar_t* nameW;
		const char* nameA;
		VOID* FuncAddr;

		static VOID StaticAddr()
		{

		}
		PVOID ObjectAddr()
		{
			return 0x0000;
		}
		VOID ObjectAddr2()
		{

		}
		static VOID ErrorMessage()
		{
			wchar_t buf[256];
			FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				buf, (sizeof(buf) / sizeof(wchar_t)), NULL);

			wprintf(L"%s\n", buf);
		}

		static std::string convert(LPCSTR str) {
			return std::string(str);
		}
	};


#define wprintError(...) {wprintf(L"[-] ");wprintf(__VA_ARGS__);Config::Profile::ErrorMessage(); }

}
