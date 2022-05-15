//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//

#include "../Config/Config.hpp"
#include <Lmcons.h>

namespace Core {
	class Token {
	public:
		/*
		https://github.com/BackupHouse/PrimaryTokenTheft
		ImpersonateLoggedOnUser()
		*/
		BOOL StealTokenSpawn(string programName)
		{

		}

		BOOL SetPrivilege(
			HANDLE hToken,          // access token handle
			LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
			BOOL bEnablePrivilege   // to enable or disable privilege
		)
		{
			TOKEN_PRIVILEGES tp;
			LUID luid;

			if (!LookupPrivilegeValue(
				NULL,            // lookup privilege on local system
				lpszPrivilege,   // privilege to lookup 
				&luid))        // receives LUID of privilege
			{
				printf("[-] LookupPrivilegeValue error: %u\n", GetLastError());
				return FALSE;
			}

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			if (bEnablePrivilege)
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			else
				tp.Privileges[0].Attributes = 0;

			// Enable the privilege or disable all privileges.

			if (!AdjustTokenPrivileges(
				hToken,
				FALSE,
				&tp,
				sizeof(TOKEN_PRIVILEGES),
				(PTOKEN_PRIVILEGES)NULL,
				(PDWORD)NULL))
			{
				printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
				return FALSE;
			}

			if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

			{
				printf("[-] The token does not have the specified privilege. \n");
				return FALSE;
			}

			return TRUE;
		}


		string get_username()
		{
			TCHAR username[UNLEN + 1];
			DWORD username_len = UNLEN + 1;
			GetUserName(username, &username_len);
			wstring username_w(username);
			string username_s(username_w.begin(), username_w.end());
			return username_s;
		}
	};
}