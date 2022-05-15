//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//
#ifndef _SIDK
#define SIDK

#include "../Config/Config.hpp"

namespace Core {
	class Sid {
	public:
		/*
		GetTokenInformation
		*/
		BOOL GetProcessSid(DWORD pid, PTOKEN_GROUPS ptokenGroup, LPSTR* sidStr)
		{
			HANDLE hProcess;
			if (pid != 0 && pid != 4) {
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				if (hProcess) {
					return GetProcessSid(hProcess, ptokenGroup, sidStr);
				}
				else{
					return FALSE;
				}
			}
			else {
				return FALSE;
			}

		}

		BOOL GetProcessSid(HANDLE hProcess, PTOKEN_GROUPS ptokenGroup, LPSTR* sidStr)
		{
			HANDLE hToken;
			DWORD ReturnLength = 0;
			// the second param access mask 
			// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
			if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
				if (!GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &ReturnLength) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
					if (GetTokenInformation(hToken, TokenLogonSid, ptokenGroup, ReturnLength, &ReturnLength)) {
						printf("GetTokenInformation TokenLogonSid length: %d\n", ReturnLength);
						if (ConvertSidToStringSidA(ptokenGroup->Groups[0].Sid, sidStr)) {
							return TRUE;
						}
						else
						{
							wprintError(L"ConvertSidToStringSid PSID ");
							return FALSE;
						}
					}

				}
				else {
					wprintError(L"GetTokenInformation TokenLogonSid ");
					return FALSE;
				}
			}
			else {
				wprintError(L"OpenProcessToken TOKEN_ALL_ACCESS ");
				return FALSE;
			}
		}

		/*
		https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
		difference enum value points to different structs
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
		*/
		BOOL GetCurrentSid(PTOKEN_GROUPS ptokenGroup,LPSTR* sidStr)
		{
			HANDLE hProcess = GetCurrentProcess();
			return GetProcessSid(hProcess, ptokenGroup, sidStr);
		};


		BOOL GetCurrentIntegrityLevel(DWORD pid,PTOKEN_MANDATORY_LABEL ptokenmandatoryLabel, LPSTR* sidStr)
		{
			HANDLE hProcess;
			if (pid != 0 && pid != 4) {
				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_VM_READ, FALSE, pid);
				if (hProcess) {
					return GetProcessIntegrityLevel(hProcess, ptokenmandatoryLabel, sidStr);
				}
				else {
					return FALSE;
				}
			}
			else {
				return FALSE;
			}
			
		}

		BOOL GetCurrentIntegrityLevel(PTOKEN_MANDATORY_LABEL ptokenmandatoryLabel, LPSTR* sidStr)
		{
			HANDLE hProcess = GetCurrentProcess();
			return GetProcessIntegrityLevel(hProcess, ptokenmandatoryLabel,sidStr);
		}
		/*
		GetTokenInformation    
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
		Token_Mandatory_Label
		*/
		BOOL GetProcessIntegrityLevel(HANDLE hProcess, PTOKEN_MANDATORY_LABEL ptokenmandatoryLabel, LPSTR* sidStr)
		{
			HANDLE hToken;
			DWORD ReturnLength = 0;
			if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
				if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &ReturnLength) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
					if (GetTokenInformation(hToken, TokenIntegrityLevel, ptokenmandatoryLabel, ReturnLength, &ReturnLength)) {
						printf("GetTokenInformation TokenIntegrityLevel length: %d\n", ReturnLength);
						if (ConvertSidToStringSidA(ptokenmandatoryLabel->Label.Sid, sidStr)) {
							return TRUE;
						}
						else{
							wprintError(L"ConvertSidToStringSid PSID ");
							return FALSE;
						}
					}

				}
				else {
					wprintError(L"GetTokenInformation TokenIntegrityLevel ");
					return FALSE;
				}
			}
			else {
				wprintError(L"OpenProcessToken TOKEN_ALL_ACCESS ");
				return FALSE;
			}
		}


		// https://github.com/uknowsec/getSystem/blob/master/getSystem/main.c
		// OwnerInformation

		BOOL IsUserAdmin(VOID)
			/*++
			Routine Description: This routine returns TRUE if the caller's
			process is a member of the Administrators local group. Caller is NOT
			expected to be impersonating anyone and is expected to be able to
			open its own process and process token.
			Arguments: None.
			Return Value:
			   TRUE - Caller has Administrators local group.
			   FALSE - Caller does not have Administrators local group. --
			*/
		{
			BOOL b;
			SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
			PSID AdministratorsGroup;
			b = AllocateAndInitializeSid(
				&NtAuthority,
				2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&AdministratorsGroup);
			if (b)
			{
				if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
				{
					b = FALSE;
				}
				FreeSid(AdministratorsGroup);
			}

			return(b);
		}
	};


}
#endif