//  https://github.com/bopin2020/WinSecurityModel
//  Let's go into Window Sight
//

#include "Config/Config.hpp"
#include "Core/Sid.hpp"
#include "Core/Token.hpp"
#include "Core/ACL.hpp"
#include "Core/Privilege.hpp"
#include "Core/Winlogon.hpp"



using namespace Config;
using namespace std;
using namespace Core;


int wmain(int argc, wchar_t* argv[])
{
#ifdef StartProfile
	Profile* profile = new Profile();
	cout << profile->nameA << endl;
	// convert char to void*   static_cast
	cout <<  static_cast<const void*>(profile->nameA) << endl;
	cout << profile->nameW << endl;
	cout <<  profile->nameW << endl;

	cout << Profile::StaticAddr << endl;
	cout << profile->ObjectAddr() << endl;
	cout << profile->FuncAddr << endl;
#endif

#ifdef GetTokenSid_IntegrityLevel
	TOKEN_GROUPS tokenGroup = { 0 };
	LPSTR sidStr = (LPSTR)malloc(MAX_PATH);
	ZeroMemory(sidStr, MAX_PATH);
	Sid* sid = new Sid();

	sid->GetProcessSid(6060,&tokenGroup, &sidStr);
	printf("%d\n", tokenGroup.GroupCount);
	printf("%s\n", sidStr);
	sid->GetCurrentSid(&tokenGroup,&sidStr);
	printf("%d\n", tokenGroup.GroupCount);
	printf("%s\n", sidStr);

	TOKEN_MANDATORY_LABEL token_manda_label = { 0 };
	sid->GetCurrentIntegrityLevel(6060,&token_manda_label, &sidStr);
	printf("%d\n", token_manda_label.Label.Attributes);
	printf("%s", sidStr);
	if (strcmp(sidStr, "S-1-16-12288") == 0)
	{
		printf("\t high level\n");
	}
	else if (strcmp(sidStr, "S-1-16") == 0)
	{
		printf("\t Untrusted level\n");
	}
	else if (strcmp(sidStr, "S-1-16-4096") == 0)
	{
		printf("\t low integrity level\n");
	}
	else if (strcmp(sidStr, "S-1-16-8192") == 0)
	{
		printf("\t medium integrity level\n");
	}
	else if (strcmp(sidStr, "S-1-16-16384") == 0)
	{
		printf("\t system integrity level\n");
	}
	else if (strcmp(sidStr, "S-1-16-20480") == 0)
	{
		printf("\t protected integrity level\n");
	}
#endif

#ifdef CheckIsAdmin
	Sid* sid = new Sid();
	cout << sid->IsUserAdmin() << endl;
#endif
	
	Token* token = new Token();
	cout << token->get_username() << endl;

	
	Acl* acl = new Acl();
	acl->GetFileSecuInfo("d:\\desktop\\vvv.ll");

// #define QueryPPL
#ifdef QueryPPL
	LPWSTR addr = (LPWSTR)malloc(MAX_PATH);
	Collection::ProcessGetProtectionLevelAsString(684,&addr);

	Collection::WalkThroughPPLProcesses();
#endif

#ifdef QueryPrivileges
	AccountPriv* accountpriv = new AccountPriv();
	accountpriv->QueryAccountPriv();
#endif

	Winlogon* winlogon = new Winlogon();
	winlogon->WalkThroughLogonSession();
}