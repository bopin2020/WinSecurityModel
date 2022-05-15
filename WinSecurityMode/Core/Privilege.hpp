//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//

// Privilege and Account Privileges

#include "../Config/Config.hpp"
#include <NTSecAPI.h>
#include <ntstatus.h>

#define TARGET_SYSTEM_NAME L"bopinhost"

using namespace Core;
using namespace Config;

namespace Core {
	class AccountPriv {
	public:
        LSA_HANDLE GetPolicyHandle()
        {
            LSA_OBJECT_ATTRIBUTES ObjectAttributes;
            WCHAR SystemName[] = TARGET_SYSTEM_NAME;
            USHORT SystemNameLength;
            LSA_UNICODE_STRING lusSystemName;
            NTSTATUS ntsResult;
            LSA_HANDLE lsahPolicyHandle;

            // Object attributes are reserved, so initialize to zeros.
            ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

            //Initialize an LSA_UNICODE_STRING to the server name.
            SystemNameLength = wcslen(SystemName);
            lusSystemName.Buffer = SystemName;
            lusSystemName.Length = SystemNameLength * sizeof(WCHAR);
            lusSystemName.MaximumLength = (SystemNameLength + 1) * sizeof(WCHAR);

            // Get a handle to the Policy object.
            ntsResult = LsaOpenPolicy(
                NULL,    //Name of the target system. &lusSystemName
                &ObjectAttributes, //Object attributes.
                POLICY_LOOKUP_NAMES, //Desired access permissions.  POLICY_LOOKUP_NAMES POLICY_ALL_ACCESS
                &lsahPolicyHandle  //Receives the policy handle.
            );

            if (ntsResult != STATUS_SUCCESS)
            {
                // An error occurred. Display it as a win32 error code.
                wprintf(L"OpenPolicy returned %lu\n",
                    LsaNtStatusToWinError(ntsResult));
                return NULL;
            }
            return lsahPolicyHandle;
        }

        BOOL QueryAccountPriv()
        {
            // SID type
            SID_NAME_USE sid_type;
            NTSTATUS status;
            TOKEN_GROUPS tokenGroup = { 0 };
            LPSTR sidStr = (LPSTR)malloc(MAX_PATH);
            ZeroMemory(sidStr, MAX_PATH);
            Sid* sids = new Sid();
            if (sids->GetCurrentSid(&tokenGroup, &sidStr))
            {
                LSA_HANDLE lsaHandle = GetPolicyHandle();

                DWORD account_sid_len = 0;
                DWORD account_domain_name_len = 0;
                SID_NAME_USE account_sid_type;
                const WCHAR* account_name = L"james kernel";
                // LookupAccountName -> SID
                LookupAccountNameW(NULL, account_name, NULL, &account_sid_len, NULL, &account_domain_name_len, &account_sid_type);
                SID* account_sid = (SID*)malloc(account_sid_len);
                WCHAR* account_domain_name = (WCHAR*)malloc(account_domain_name_len * sizeof(WCHAR));
                if (!LookupAccountNameW(NULL, account_name, account_sid, &account_sid_len, account_domain_name, &account_domain_name_len, &account_sid_type)) {
                    free(account_sid);
                    free(account_domain_name);
                    DWORD err = GetLastError();
                    cout << err;
                    return 1;
                }
                LSA_UNICODE_STRING* granted_rights = (LSA_UNICODE_STRING*)malloc(MAX_PATH * 30);
                ULONG granted_rights_count = 0;
                LPSTR* string_sid = (LPSTR*)malloc(MAX_PATH);
                if (ConvertSidToStringSidA(account_sid, string_sid))
                {
                    printf("%s\n", *string_sid);
                }

                status = LsaEnumerateAccountRights(lsaHandle, account_sid, &granted_rights,&granted_rights_count);
                if(STATUS_SUCCESS != status)
                    Profile::ErrorMessage();
                ULONG errorCode = LsaNtStatusToWinError(status);
                cout << errorCode << endl;
                
                for (size_t i = 0; i < granted_rights_count; i++)
                {
                    wprintf(L"%s\n", granted_rights->Buffer);
                }
            }
            return TRUE;

        }


	};

	class Privilege {
        Privilege()
        {
            // usermode check the specified privileges
            //PrivilegeCheck();
            //LsaEnumerateAccountRights();
        }
	};
}
