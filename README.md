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

TokenTest - displays the privs of an access token if the user has SeBatchLogonRight
NTokenTest - displays the privs of an access token regardless

SessionForPid - displays the session for a process

None of these are superb. But they are so close to the APIs that the answers are unfiltered truth. That might be helpful.
