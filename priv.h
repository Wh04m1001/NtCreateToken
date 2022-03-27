#pragma once
#define PRIVCOUNT 35
#define GROUPCOUNT 5
const wchar_t* privs[] = { L"SeCreateTokenPrivilege",L"SeAssignPrimaryTokenPrivilege",L"SeLockMemoryPrivilege",L"SeIncreaseQuotaPrivilege",L"SeMachineAccountPrivilege",L"SeTcbPrivilege",L"SeSecurityPrivilege",L"SeTakeOwnershipPrivilege",L"SeLoadDriverPrivilege",L"SeSystemProfilePrivilege",L"SeSystemtimePrivilege",L"SeProfileSingleProcessPrivilege",L"SeIncreaseBasePriorityPrivilege",L"SeCreatePagefilePrivilege",L"SeCreatePermanentPrivilege",L"SeBackupPrivilege",L"SeRestorePrivilege",L"SeShutdownPrivilege",L"SeDebugPrivilege",L"SeAuditPrivilege",L"SeSystemEnvironmentPrivilege",L"SeChangeNotifyPrivilege",L"SeRemoteShutdownPrivilege",L"SeUndockPrivilege",L"SeSyncAgentPrivilege",L"SeEnableDelegationPrivilege",L"SeManageVolumePrivilege",L"SeImpersonatePrivilege",L"SeCreateGlobalPrivilege",L"SeTrustedCredManAccessPrivilege",L"SeRelabelPrivilege",L"SeIncreaseWorkingSetPrivilege",L"SeTimeZonePrivilege",L"SeCreateSymbolicLinkPrivilege",L"SeDelegateSessionUserImpersonatePrivilege" };
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateToken)(OUT PHANDLE TokenHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES   ObjectAttributes, IN TOKEN_TYPE           TokenType, IN PLUID AuthenticationId, IN PLARGE_INTEGER       ExpirationTime, IN PTOKEN_USER          TokenUser, IN PTOKEN_GROUPS        TokenGroups, IN PTOKEN_PRIVILEGES    TokenPrivileges, IN PTOKEN_OWNER         TokenOwner, IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup, IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl, IN PTOKEN_SOURCE        TokenSource);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateLocallyUniqueId)(OUT PLUID LocallyUniqueId);
