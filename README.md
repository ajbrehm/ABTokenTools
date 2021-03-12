# ABTokenTools
Simple utilities to manipulate Windows account security settings

AccountRights - displays or adds/removes rights and privileges from security principals (users and groups)
AccountsRights username - displays rights and privs
AccountsRights username SeBatchLogonRight - adds a right or priv
AccountsRights username SeBatchLogonRight REMOVE - removes a right or priv

CopyAsBackup - copies a file like a backup program would to make use of SeBackupPrvilege

GetProcessOwner - displays the process owner

LookupAccountName - displays a SID for a user name
LookupAccountSid - displays a user name for a SID

TokenTest - displays the privs of an access token

SessionForPid - displays the session for a process

DecryptLSASecrets - displays passwords stored by service control manager
DecryptLSASecrets <pid> <service name>
pid is the pid of lsass.exe, service name is the scm registry key for the service owned by administrators

S4ULogon - logs on as a service4you without password

None of these are superb. But they are so close to the APIs that the answers are unfiltered truth. That might be helpful.
