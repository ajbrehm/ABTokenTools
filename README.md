# AccountRights

_AccountRights principal_

Shows the rights and privileges of a security principal (a user or group).

_AccountRights principal privilege_
_AccountRights principal right_

Grants a security principal a right or privilege.

_AccountRights principal privilege REMOVE_
_AccountRights principal right REMOVE_

Revokes a right or privilege for a security principal.

This works for all privileges and rights.

Rights are in the format "SeInteractiveLogonRight" and "SeDenyInteractiveLogonRight".
Privileges are in the format "SeShutdownPrivilege".
This also applies to other commands.

# AclEdit

_AclEdit type pathObject [sddl] [D|E]_

Sets a security descriptor in sddl format on an object at pathObject of the type type and optionally enables or disables inheritance.

Types are these:
0       SE_UNKNOWN_OBJECT_TYPE
1       SE_FILE_OBJECT
2       SE_SERVICE
3       SE_PRINTER
4       SE_REGISTRY_KEY
5       SE_LMSHARE
6       SE_KERNEL_OBJECT
7       SE_WINDOW_OBJECT
8       SE_DS_OBJECT
9       SE_DS_OBJECT_ALL
10      SE_PROVIDER_DEFINED_OBJECT
11      SE_WMIGUID_OBJECT
12      SE_REGISTRY_WOW64_32KEY
13      SE_REGISTRY_WOW64_64KEY

Currently supports setting DACLs and owners. Setting an owner might require the appropriate privilege.
Disable or enable inheritance with AclEdit type pathObject sddl D|E.
File, service, printer, registry, and share objects take UNC paths, DS_OBJECT takes X.500 format.

_AclEdit 1 "C:\"_

Shows the Security Descriptor of the root of drive C.


# CredManAccess

_CredManAccess type sTargetName sUserName [sPassword]_

Gets or sets the password for a user name and a target in Windows' credential manager. There is no particular reason to use this for anything.

Credential types are:
1 CRED_TYPE_GENERIC
2 CRED_TYPE_DOMAIN_PASSWORD
3 CRED_TYPE_DOMAIN_CERTIFICATE
4 CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
5 CRED_TYPE_GENERIC_CERTIFICATE5
6 CRED_TYPE_DOMAIN_EXTENDED


# CopyAsBackup

_CopyAsBackup "drive_letter:\directory\sourcefile" "drive_letter:\directory\targetfile"_

Copies a file sourcefile to file targetfile using backup privileges to ignore ACLs.


# DecryptLsaSecrets

_DecryptLsaSecrets pid SomeService_

Assuming pid is the PID of the Local Security Authority (lsass.exe), gets the password stored to start a service SomeService stored in HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. For some reason this fails if the service name contains an underscore (_) which most of them do.


# EnablePrivilege

_EnablePrivilege privilege_

Enables the user’s privilege given (if the user has it) and starts cmd with the privilege enabled.


# GetProcessOwner

_GetProcessOwner pid_

Often gets the privileges and owner of the process with pid pid.


# LookupAccountName

_LookupAccountName principal_

Gets the SID (security identifier) for a security principal.


# LookupAccountSid

_LookupAccountSid sid_

This does the same as LookupAccountName but vice versa, gets the user name for a SID.


# RunAsJob

_RunAsJob [/pid pid] [/image pathImage] [/processlimit processlimit] [/args ...]_

Starts a program pathImage or modifies the settings of a running process with pid pid to run inside a job with a process limit of processlimit (for example 1). Further arguments are passed to the program if started with RunAsJob.

This is a proof-of-concept and not of much practical use.


# S4ULogon

Logs a user on without a password and does nothing. To be honest, I have forgotten what this was good for other than a proof of concept…


# SessionForPId

_SessionForPId pid_

Returns the session for the PID pid in case someone wants it.


# TokenTest

_TokenTest upn_

Displays the privileges a user principal name would have if he logged on now. This is useful for testing effective privileges based on groups. It is a good counterpart to AccountRights above which shows the rights and privileges a security principal (user or group) has by itself.
