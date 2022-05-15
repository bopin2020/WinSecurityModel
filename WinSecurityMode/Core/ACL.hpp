//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//

#include "../Config/Config.hpp"

#include <Psapi.h>

#define PrintLastError(A) {wprintf(A);}

namespace Core {
	class Acl {
	public:
#pragma region SecurityDescriptorMy


		Acl()
		{
			
		}


		/*
		GetFileSecurity
		https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfilesecuritya
		*/
		PSECURITY_DESCRIPTOR GetFileSecuInfo(LPCSTR filename)
		{
			std::ifstream f(Config::Profile::convert(filename));
			if (!f.good())
			{
				cout << "file not found\n";
				return NULL;
			}

			DWORD len = 0;
			SECURITY_DESCRIPTOR sd;
			// SECURITY_INFORMATION   
			// owner of an object
			// primary group of an object
			// DACL of an object
			// SACL of an object
			if (GetFileSecurityA(filename,
				OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
				0,
				0,
				&len)) {
				// https://github.com/rsenn/c-utils/blob/9753ee3231635bd373eb76dc0c1e432d47740dd5/lib/path/path_access.c
				if (GetFileSecurityA(filename,
					OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
					&sd,
					len,
					&len) == FALSE) {
					return NULL;
				}
			}
			return &sd;
		}


		/*
		GetSecurityInfo();
		SetEntriesInAclW();
		*/


#pragma endregion
	};

	class Collection {
	public:
		static BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel)
		{
			BOOL bReturnValue = TRUE;

			DWORD dwProtectionLevel = 0;
			LPCWSTR pwszProtectionName = NULL;

			if (!ProcessGetProtectionLevel(dwProcessId, &dwProtectionLevel))
				return FALSE;

			*ppwszProtectionLevel = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
			if (!*ppwszProtectionLevel)
				return FALSE;

			switch (dwProtectionLevel)
			{
			case PROTECTION_LEVEL_WINTCB_LIGHT:
				pwszProtectionName = L"PsProtectedSignerWinTcb-Light";
				break;
			case PROTECTION_LEVEL_WINDOWS:
				pwszProtectionName = L"PsProtectedSignerWindows";
				break;
			case PROTECTION_LEVEL_WINDOWS_LIGHT:
				pwszProtectionName = L"PsProtectedSignerWindows-Light";
				break;
			case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
				pwszProtectionName = L"PsProtectedSignerAntimalware-Light";
				break;
			case PROTECTION_LEVEL_LSA_LIGHT:
				pwszProtectionName = L"PsProtectedSignerLsa-Light";
				break;
			case PROTECTION_LEVEL_WINTCB:
				pwszProtectionName = L"PsProtectedSignerWinTcb";
				break;
			case PROTECTION_LEVEL_CODEGEN_LIGHT:
				pwszProtectionName = L"PsProtectedSignerCodegen-Light";
				break;
			case PROTECTION_LEVEL_AUTHENTICODE:
				pwszProtectionName = L"PsProtectedSignerAuthenticode";
				break;
			case PROTECTION_LEVEL_PPL_APP:
				pwszProtectionName = L"PsProtectedSignerPplApp";
				break;
			case PROTECTION_LEVEL_NONE:
				pwszProtectionName = L"None";
				break;
			default:
				pwszProtectionName = L"Unknown";
				bReturnValue = FALSE;
			}
			if(dwProtectionLevel != PROTECTION_LEVEL_NONE)
				wprintf(L"%d \tPPL Level: %s\n", dwProcessId,pwszProtectionName);
			return bReturnValue;
		}

		static BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel)
		{
			BOOL bReturnValue = FALSE;

			HANDLE hProcess = NULL;
			PROCESS_PROTECTION_LEVEL_INFORMATION level = { 0 };

			if (!(hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
			{
				PrintLastError(L"OpenProcess");
				goto end;
			}

			if (!GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &level, sizeof(level)))
			{
				PrintLastError(L"GetProcessInformation");
				goto end;
			}

			*pdwProtectionLevel = level.ProtectionLevel;
			bReturnValue = TRUE;

		end:
			if (hProcess)
				CloseHandle(hProcess);

			return bReturnValue;
		}

		static BOOL WalkThroughPPLProcesses()
		{
			DWORD aProcesses[1024], cbNeeded, cProcesses;
			unsigned int i;

			if (!K32EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
			{
				return 1;
			}
			cProcesses = cbNeeded / sizeof(DWORD);
			for (i = 0; i < cProcesses; i++)
			{
				if (aProcesses[i] != 0)
				{
					LPWSTR addr = (LPWSTR)malloc(MAX_PATH);
					ProcessGetProtectionLevelAsString(aProcesses[i],&addr);
				}
			}
		}
	};
}