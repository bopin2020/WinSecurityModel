//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//


#include "../Config/Config.hpp"
#include <Lmcons.h>
#include <ntstatus.h>


#pragma comment(lib,"Secur32.lib")

namespace Core {
	class Winlogon {
	public:
		Winlogon()
		{
			// MessageBox(0, 0, 0, 0);
		}

		BOOL WalkThroughLogonSession()
		{
			ULONG logonSessionCount;
			PLUID pluid;
			NTSTATUS status = LsaEnumerateLogonSessions(&logonSessionCount,&pluid);
			if (status != STATUS_SUCCESS)
			{
				printf("error code");
				return FALSE;
			}
			printf("logonSessionCount : %d\n", logonSessionCount);
			printf("%x", pluid);
			// LsaGetLogonSessionData function retrieves information about a specified logon session
			/*
			To retrieve information about a logon session,the caller must be the owner of the logon session or a local
			system administrator
			*/
			PSECURITY_LOGON_SESSION_DATA psec_logonSessionData;
			for (size_t i = 0; i < logonSessionCount; i++)
			{
				status = LsaGetLogonSessionData(pluid,&psec_logonSessionData);
				if (status != STATUS_SUCCESS)
				{
					printf("error code");
					return FALSE;
				}
				printf("Luid: %x\n",psec_logonSessionData->LogonId);
				printf("UserName: %ws\n",psec_logonSessionData->UserName.Buffer);
				printf("LogonDomain: %ws\n",psec_logonSessionData->LogonDomain.Buffer);
				printf("AuthenticationPackage: %ws\n",psec_logonSessionData->AuthenticationPackage.Buffer);
				// SECURITY_LOGON_TYPE Enum
				switch (psec_logonSessionData->LogonType)
				{
					// 2
				case Interactive:
					printf("LogonType: Interactive\n");
					break;
				case Network:
					printf("LogonType: Network\n");
					break;
				case Batch:
					printf("LogonType: Batch\n");
					break;
				case Service:
					printf("LogonType: Service\n");
					break;
				default:
					break;
				}
				printf("Session: %d\n", psec_logonSessionData->Session);
				LPSTR sidStr = (LPSTR)malloc(MAX_PATH);
				ZeroMemory(sidStr,MAX_PATH);
				if (ConvertSidToStringSidA(psec_logonSessionData->Sid, &sidStr))
				{
					printf("Session: %s\n", sidStr);
				}
				else
				{
					printf("Session: %s\n", sidStr);
				}

				PSID_NAME_USE sidType = 0;
				DWORD referenceDomain = 0;
				DWORD cchName = 0;
				if (LookupAccountSidA(NULL, psec_logonSessionData->Sid, NULL, &cchName, NULL,&referenceDomain, sidType))
				{
					printf("sidType %d\n", sidType);
				}
				else
				{
					printf("sidType %d\n", GetLastError());
				}

				printf("\n");
				pluid++;
			}
			return TRUE;
		}
	};
}