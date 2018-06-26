/*
A Microsoft Windows Process Lockdown Tool using Job Objects

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsJobLock

Released under AGPL see LICENSE for more information
*/

#include "stdafx.h"
#include "XGetopt.h"
#include "Wtsapi32.h"

// Pre-processor macros
#define JOBNAME(name) (name? name : _T("unnamed"))
#define TF(expr) ((expr)? _T("True") : _T("False"))

// Miscellaneous constants
static const size_t PageSize = 1 << 12;
static const size_t WorkingSetSize_Minimum = PageSize * 20;
static const size_t WorkingSetSize_Maximum = ~1;

// Miscellaneous definitions
enum PrintSettings_enum {
	AttachToJob,
	CreateInJob,
};

// Global
BOOL bListProcesses = FALSE;
BOOL bCreateConsole = FALSE;
BOOL bIgnoreJobFailures = FALSE;
struct {
	BOOL dwProcessLimitQ;
	BOOL dwProcessTicksLimitQ;
	BOOL dwJobTicksLimitQ;
	BOOL dwMinimumWorkingSetSizeQ;
	BOOL dwMaximumWorkingSetSizeQ;

	DWORD dwProcessLimit;
	LARGE_INTEGER dwProcessTicksLimit;
	LARGE_INTEGER dwJobTicksLimit;
	SIZE_T dwMinimumWorkingSetSize;
	SIZE_T dwMaximumWorkingSetSize;
	BOOL  bKillProcOnJobClose;
	BOOL  bBreakAwayOK;
	BOOL  bSilentBreakAwayOK;
} Basic = { FALSE, FALSE, FALSE, FALSE, FALSE, 0, { 0 }, { 0 }, (SIZE_T)-1, (SIZE_T)-1, FALSE, FALSE, FALSE };
struct {
	BOOL dwJobMemoryQ;
	BOOL dwProcessMemoryQ;

	DWORD dwJobMemory;
	DWORD dwProcessMemory;
} Extended = { FALSE, FALSE, 0, 0 };
struct {
	BOOL  bUILimitDesktop;
	BOOL  bUILimitDispSettings;
	BOOL  bUILimitExitWindows;
	BOOL  bUILimitUserHandles;
	BOOL  bUILimitGlobalAtoms;
	BOOL  bUILimitReadClip;
	BOOL  bUILimitSystemParams;
	BOOL  bUILimitWriteClip;
} UI = { FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE };

//
// Function	: FindProcess
// Purpose	: Find a process by name
//
DWORD FindProcess(TCHAR *strName)
{
	DWORD dwCount = 0, dwRet;
	PWTS_PROCESS_INFO ppProcessInfo;

	if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppProcessInfo, &dwRet))
		return 0;
	
	for (dwCount = 0; dwCount < dwRet; dwCount++) {
		if (lstrcmp(ppProcessInfo[dwCount].pProcessName, strName) == 0) {
			 return ppProcessInfo[dwCount].ProcessId;
		}
	}

	return 0;
}

void
ListProcesses()
{
	DWORD dwCount, dwRet;
	PWTS_PROCESS_INFO ppProcessInfo;

	if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppProcessInfo, &dwRet))
		return;

	for(dwCount=0; dwCount<dwRet; dwCount++)
		_ftprintf(stdout, _T("[I] %s (%d) in session %d.\n"), ppProcessInfo[dwCount].pProcessName, ppProcessInfo[dwCount].ProcessId, ppProcessInfo[dwCount].SessionId);

	return;
}

//
// Function	: FindProcess
// Purpose	: Find as processes name by PID
//
BOOL FindProcessName(DWORD dwPID, TCHAR *strName)
{
	DWORD dwCount, dwRet;
	PWTS_PROCESS_INFO ppProcessInfo;

	if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppProcessInfo, &dwRet))
		return FALSE;

	for (dwCount = 0; dwCount < dwRet; dwCount++) {
		if(ppProcessInfo[dwCount].ProcessId== dwPID ){
			_tcscpy_s(strName, MAX_PATH, ppProcessInfo[dwCount].pProcessName);
			return TRUE;
		}
	}
	return FALSE;
}

BOOL
SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	// Copied and formatted from: https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/enabling-and-disabling-privileges-in-c--P
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
          return FALSE;

    return (GetLastError() == ERROR_NOT_ALL_ASSIGNED)? FALSE : TRUE;
}

BOOL
RequestNecessaryPrivileges(HANDLE hProcess)
{
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	if (!SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, TRUE))
		_ftprintf(stdout, _T("[!] Unable to set token privilege (%s) to process %d: error %d\n"), _T("SE_INCREASE_QUOTA_NAME"), GetProcessId(hProcess), GetLastError());

	if (!SetPrivilege(hToken, SE_INC_WORKING_SET_NAME, TRUE))
		_ftprintf(stdout, _T("[!] Unable to set token privilege (%s) to process %d: error %d\n"), _T("SE_INC_WORKING_SET_NAME"), GetProcessId(hProcess), GetLastError());

	CloseHandle(hToken);
	return TRUE;
}

BOOL
InitializeJobObject_BasicLimitInformation(struct _JOBOBJECT_BASIC_LIMIT_INFORMATION* jbli)
{
	BOOL result = FALSE;
	jbli->LimitFlags = 0;

	if (Basic.dwProcessLimitQ) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		jbli->ActiveProcessLimit = Basic.dwProcessLimit + 1;
		result = TRUE;
	}

	if (Basic.dwJobTicksLimitQ) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		jbli->PerJobUserTimeLimit = Basic.dwProcessTicksLimit;
		result = TRUE;
	}

	if (Basic.dwProcessTicksLimitQ) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		jbli->PerProcessUserTimeLimit = Basic.dwProcessTicksLimit;
		result = TRUE;
	}

	// FIXME: This probably needs the PROCESS_SET_QUOTA privilege
	if (Basic.dwMinimumWorkingSetSizeQ) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;

		if (Basic.dwMinimumWorkingSetSize < WorkingSetSize_Minimum) {
			_ftprintf(stdout, _T("[!] Requested Minimum Working Set Size (%d pages) is less than the minimum (%d pages). Using %d bytes instead.\n"), Basic.dwMinimumWorkingSetSize / PageSize, WorkingSetSize_Minimum / PageSize, WorkingSetSize_Minimum);
			jbli->MinimumWorkingSetSize = WorkingSetSize_Minimum;
		} else
			jbli->MinimumWorkingSetSize = Basic.dwMinimumWorkingSetSize;

		if (Basic.dwMaximumWorkingSetSize == -1)
			jbli->MaximumWorkingSetSize = WorkingSetSize_Maximum;
		result = TRUE;
	}

	// FIXME: This probably needs the PROCESS_SET_QUOTA privilege
	if (Basic.dwMaximumWorkingSetSizeQ) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
		if (Basic.dwMaximumWorkingSetSize < WorkingSetSize_Maximum)
			jbli->MaximumWorkingSetSize = Basic.dwMaximumWorkingSetSize;
		else {
			_ftprintf(stdout, _T("[!] Requested Maximum Working Set Size (%d pages) is larger than the maximum (%d pages). Using %d bytes instead.\n"), Basic.dwMaximumWorkingSetSize / PageSize, WorkingSetSize_Maximum / PageSize, WorkingSetSize_Maximum);
			jbli->MaximumWorkingSetSize = WorkingSetSize_Maximum;

		}
		if (Basic.dwMinimumWorkingSetSize == -1)
			jbli->MinimumWorkingSetSize = WorkingSetSize_Minimum;
		result = TRUE;
	}

	if (Basic.bKillProcOnJobClose) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		result = TRUE;
	}

	if (Basic.bBreakAwayOK) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
		result = TRUE;
	}

	if (Basic.bSilentBreakAwayOK) {
		jbli->LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
		result = TRUE;
	}

	return result;
}

BOOL
InitializeJobObject_ExtendedLimitInformation(struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION* jeli)
{
	BOOL result = FALSE;
	jeli->BasicLimitInformation.LimitFlags = 0;

	if (Extended.dwJobMemoryQ) {
		result = TRUE;
		jeli->BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
		jeli->JobMemoryLimit = Extended.dwJobMemory;
	}

	if (Extended.dwProcessMemoryQ) {
		result = TRUE;
		jeli->BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli->ProcessMemoryLimit = Extended.dwProcessMemory;
	}

	return result;
}

BOOL
InitializeJobObject_BasicUIRestrictions(struct _JOBOBJECT_BASIC_UI_RESTRICTIONS* jbur)
{
	BOOL result = FALSE;
	jbur->UIRestrictionsClass = 0;

	if (UI.bUILimitDesktop) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DESKTOP;
	}

	if (UI.bUILimitDispSettings) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
	}

	if (UI.bUILimitExitWindows) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
	}

	if (UI.bUILimitGlobalAtoms) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
	}

	if (UI.bUILimitUserHandles) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
	}

	if (UI.bUILimitReadClip) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
	}

	if (UI.bUILimitSystemParams) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
	}

	if (UI.bUILimitWriteClip) {
		result = TRUE;
		jbur->UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	}

	return result;
}

HANDLE
InitializeJobObject(TCHAR* jobName)
{
	HANDLE hJob = NULL;
	TCHAR strFinalName[MAX_PATH] = { 0 };

	struct jobLimits { BOOL basic : 1, extended : 1, ui : 1; };
	struct jobLimits jobRequired = { 0 };
	struct jobLimits jobSuccess = { TRUE, TRUE, TRUE };

	JOBOBJECT_BASIC_LIMIT_INFORMATION jblInfo = { 0 };
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jelInfo = { 0 };
	JOBOBJECT_BASIC_UI_RESTRICTIONS jbuiRestrictions = { 0 };

	jblInfo.LimitFlags = 0;
	jelInfo.BasicLimitInformation.LimitFlags = 0;
	jbuiRestrictions.UIRestrictionsClass = 0;

	// construct a job object using the name if specified
	hJob = CreateJobObject(NULL, jobName);

	_ftprintf(stdout, _T("[I] Final job name                - %s\n"), JOBNAME(jobName));

	// shit, we failed...
	if (hJob == NULL)
		goto fail;

	// populate the job-specific structures using globals initialized by getopt
	jobRequired.basic = InitializeJobObject_BasicLimitInformation(&jblInfo);
	jobRequired.extended = InitializeJobObject_ExtendedLimitInformation(&jelInfo);
	jobRequired.ui = InitializeJobObject_BasicUIRestrictions(&jbuiRestrictions);

	// Now we can set these structures to the job object
	if (jobRequired.basic && !SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &jblInfo, sizeof(jblInfo))) {
		_ftprintf(stdout, _T("[!] Couldn't set job basic limits to job %s (%#x): error %d\n"), JOBNAME(jobName), (unsigned int)hJob, GetLastError());
		jobSuccess.basic = FALSE;
	}
	else if (jobRequired.basic)
		_ftprintf(stdout, _T("[*] Applied job basic limits to job %s (%#x).\n"), JOBNAME(jobName), (unsigned int)hJob);

	if (jobRequired.extended && !SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jelInfo, sizeof(jelInfo))) {
		_ftprintf(stdout, _T("[!] Couldn't set job extended limits to job %s (%#x): error %d\n"), JOBNAME(jobName), (unsigned int)hJob, GetLastError());
		jobSuccess.extended = FALSE;
	}
	else if (jobRequired.extended)
		_ftprintf(stdout, _T("[*] Applied job extended limits to job %s (%#x).\n"), JOBNAME(jobName), (unsigned int)hJob);

	if (jobRequired.ui && !SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbuiRestrictions, sizeof(jbuiRestrictions))) {
		_ftprintf(stdout, _T("[!] Couldn't set job UI limits to job %s (%#x): error %d\n"), JOBNAME(jobName), (unsigned int)hJob, GetLastError());
		jobSuccess.ui = FALSE;
	}
	else if (jobRequired.ui)
		_ftprintf(stdout, _T("[*] Applied job UI limits to job %s (%#x).\n"), JOBNAME(jobName), (unsigned int)hJob);

	// Check if everything failed, and fail if so.
	if (!bIgnoreJobFailures && (!jobSuccess.basic && jobRequired.basic)) {
		_ftprintf(stdout, _T("[!] Unable to set required limits (%s) for job %s (%#x)!\n"), _T("basic"), JOBNAME(jobName), GetLastError());
		goto fail;
	}
	if (!bIgnoreJobFailures && (!jobSuccess.extended && jobRequired.extended)) {
		_ftprintf(stdout, _T("[!] Unable to set required limits (%s) for job %s (%#x)!\n"), _T("extended"), JOBNAME(jobName), GetLastError());
		goto fail;
	}
	if (!bIgnoreJobFailures && (!jobSuccess.ui && jobRequired.ui)) {
		_ftprintf(stdout, _T("[!] Unable to set required limits (%s) for job %s (%#x)!\n"), _T("ui"), JOBNAME(jobName), GetLastError());
		goto fail;
	}

	// Okay. We should be good to go.
	return hJob;

fail:
	if (hJob)
		CloseHandle(hJob);
	return NULL;
}

BOOL BuildAndDeploy(TCHAR* jobName, TCHAR* strProcess, HANDLE hProcess)
{
	DWORD err;
	HANDLE hJob;

	TCHAR strFinalName[MAX_PATH] = { 0 };

	// Risk of truncation in theory
	if(jobName != NULL){
		_tcscpy_s(strFinalName, MAX_PATH, _T("Local\\"));
		_tcscat_s(strFinalName, MAX_PATH, jobName);
	}

	// Request any required privileges
	if (!RequestNecessaryPrivileges(GetCurrentProcess())) {
		_ftprintf(stdout, _T("[!] Unable to request privileges to specify quotas: error %d\n"), GetLastError());
		return FALSE;
	}

	// Initialize a Job object using the arguments the user specified
	hJob = InitializeJobObject((jobName == NULL)? NULL : strFinalName);
	if (hJob == NULL) {
		err = GetLastError();
		if (err ==  ERROR_INVALID_HANDLE) {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a object name conflict!\n"), JOBNAME(jobName));
		} else if (err == ERROR_ALREADY_EXISTS) {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a job already existing with that name!\n"), JOBNAME(jobName));
		} else {
			_ftprintf(stdout, _T("[!] Couldn't create job %s: error %d\n"), JOBNAME(jobName), err);
		}
		return FALSE;
	}

	// Duplicate the handle into the target process
	if(!DuplicateHandle(GetCurrentProcess(),hJob,hProcess,NULL,JOB_OBJECT_QUERY,TRUE,NULL)){
		_ftprintf(stdout, _T("[!] Couldn't duplicate job handle into target process: error %d\n"), GetLastError());
		return FALSE;
	} else {
		_ftprintf(stdout, _T("[*] Duplicated handle of job (with restricted access) into target process!\n"));
	}

	// Now assign the process to the job object
	if(!AssignProcessToJobObject(hJob,hProcess)){
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) { // Windows 7 and Server 2008 R2 and below
			_ftprintf(stdout, _T("[!] Couldn't apply job object to %s as it looks like a job object has already been applied!\n"), strProcess);
			return FALSE;
		} else
			_ftprintf(stdout, _T("[!] Couldn't apply job object to %s: error %d\n"), strProcess, err);
	} else
		_ftprintf(stdout, _T("[*] Applied job object to process!\n"));

	return TRUE;
}

//
// Function	: PrintSettings
// Purpose	: Print the settings we will apply
//
void PrintSettings(enum PrintSettings_enum fmt)
{
	DWORD processLimit = Basic.dwProcessLimit;

	// figure out how the process limit should be outputted
	if (fmt == CreateInJob)
		processLimit = Basic.dwProcessLimit - 1;
	else if (fmt == AttachToJob)
		processLimit = Basic.dwProcessLimit;

	if (Basic.dwProcessLimitQ)
		_ftprintf(stdout, _T("[I] Process Limit                 - %s - %d+%d child%s\n"), TF(Basic.dwProcessLimitQ), 1, processLimit, (processLimit == 1)? _T("") : _T("ren"));
	else
		_ftprintf(stdout, _T("[I] Process Limit                 - %s - %d process%s\n"), TF(Basic.dwProcessLimitQ), processLimit, (processLimit == 1)? _T("") : _T("es"));

	// continue on with the rest of the configuration
	_ftprintf(stdout, _T("[I] Job Memory Limit              - %s - %d byte(s)\n"), TF(Extended.dwJobMemoryQ), Extended.dwJobMemory);
	_ftprintf(stdout, _T("[I] Process Memory Limit          - %s - %d byte(s)\n"), TF(Extended.dwProcessMemoryQ), Extended.dwProcessMemory);
	_ftprintf(stdout, _T("[I] Job Execution Time Limit      - %s - %lld second(s)\n"), TF(Basic.dwJobTicksLimitQ), Basic.dwJobTicksLimit.QuadPart);
	_ftprintf(stdout, _T("[I] Process Execution Time Limit  - %s - %lld second(s)\n"), TF(Basic.dwProcessTicksLimitQ), Basic.dwProcessTicksLimit.QuadPart);
	_ftprintf(stdout, _T("[I] Minimum Working Set Limit     - %s - %d byte(s)\n"), TF(Basic.dwMinimumWorkingSetSizeQ), Basic.dwMinimumWorkingSetSize);
	_ftprintf(stdout, _T("[I] Maximum Working Set Limit     - %s - %d byte(s)\n"), TF(Basic.dwMaximumWorkingSetSizeQ), Basic.dwMaximumWorkingSetSize);
	_ftprintf(stdout, _T("[I] Kill Process on Job Close     - %s\n"), TF(Basic.bKillProcOnJobClose == TRUE));
	_ftprintf(stdout, _T("[I] Break Away from Job OK        - %s\n"), TF(Basic.bBreakAwayOK == TRUE));
	_ftprintf(stdout, _T("[I] Silent Break Away from Job OK - %s\n"), TF(Basic.bSilentBreakAwayOK == TRUE));
	_ftprintf(stdout, _T("[I] Limit Desktop Operations      - %s\n"), TF(UI.bUILimitDesktop == TRUE));
	_ftprintf(stdout, _T("[I] Limit Display Changes         - %s\n"), TF(UI.bUILimitDispSettings == TRUE));
	_ftprintf(stdout, _T("[I] Limit Exit Windows            - %s\n"), TF(UI.bUILimitExitWindows == TRUE));
	_ftprintf(stdout, _T("[I] Limit Global Atoms            - %s\n"), TF(UI.bUILimitGlobalAtoms == TRUE));
	_ftprintf(stdout, _T("[I] Limit User Handles            - %s\n"), TF(UI.bUILimitUserHandles == TRUE));
	_ftprintf(stdout, _T("[I] Limit Reading of Clipboard    - %s\n"), TF(UI.bUILimitReadClip == TRUE));
	_ftprintf(stdout, _T("[I] Limit System Parameter Change - %s\n"), TF(UI.bUILimitSystemParams == TRUE));
	_ftprintf(stdout, _T("[I] Limit Writing to Clipboard    - %s\n"), TF(UI.bUILimitWriteClip == TRUE));
}

BOOL
AttachJobToPid(TCHAR* jobName, DWORD pid)
{
	HANDLE hProcess = NULL;
	TCHAR strProcName[MAX_PATH];

	if (!FindProcessName(pid, strProcName)) {
		_ftprintf(stdout,  _T("[!] Could not find the name of the process: pid %d\n"), pid);
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_DUP_HANDLE, false, pid);
	if(hProcess == NULL || hProcess == INVALID_HANDLE_VALUE){
		_ftprintf(stdout,  _T("[!] Could not open process %s (%d): error %d\n"), strProcName, pid, GetLastError());
		return FALSE;
	}
	_ftprintf(stdout, _T("[*] Successfully opened process %s (%d)!\n"), strProcName, pid);

	PrintSettings(AttachToJob);

	if (!BuildAndDeploy(jobName, strProcName, hProcess)) {
		_ftprintf(stdout, _T("[!] Failed to build and deploy job object to %s (%d)!\n"), strProcName, pid);
		return FALSE;
	}

	_ftprintf(stdout, _T("[*] Successfully built and deployed job object to %s (%d)!\n"), strProcName, pid);
	return TRUE;
}

TCHAR*
EscapedStringEmit(TCHAR* token, TCHAR* result, size_t maxlen)
{
	TCHAR ch[2] = { 0 };
	TCHAR* p;
	for (p = token; *p != _T('\0'); p++) {
		switch (*p) {
		case _T('"'):
			if (_tcscat_s(result, maxlen, _T("\\\"")))
				return p;
			break;
		case _T('\\'):
			if (_tcscat_s(result, maxlen, _T("\\\\")))
				return p;
			break;
		default:
			ch[0] = *p;
			if (_tcscat_s(result, maxlen, ch))
				return p;
		}
	}
	return p;
}

BOOL
ArgvToCommandLine(TCHAR** argv, TCHAR* result, size_t maxlen)
{
	const TCHAR IFS[] = _T(" ");
	int i;
	TCHAR* p;

	if (argv == NULL)
		goto fail;
	if (result == NULL)
		goto fail;

	for (i = 0; argv[i] != NULL; i++) {
		_tcscat_s(result, maxlen, _T("\""));
		p = EscapedStringEmit(argv[i], result, maxlen);
		if (*p != _T('\0'))
			goto fail;
		_tcscat_s(result, maxlen, _T("\""));
		_tcscat_s(result, maxlen, IFS);
	}

	return TRUE;
fail:
	return FALSE;
}

HANDLE
StartProcess(TCHAR* appname, TCHAR* cmdline)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOEX si;

	if (!appname || !cmdline)
		return NULL;

	si.StartupInfo.cb = sizeof(si.StartupInfo);
	si.StartupInfo.dwFlags = 0;
	si.StartupInfo.lpDesktop = NULL;
	si.StartupInfo.lpTitle = NULL;

	si.StartupInfo.lpReserved = NULL;
	si.StartupInfo.cbReserved2 = 0;
	si.StartupInfo.lpReserved2 = NULL;

	// FIXME: use STARTUPINFOEX to inherit just the job handle instead of inheriting all handles

	if (!CreateProcess(appname, cmdline, NULL, NULL, TRUE, (bCreateConsole? CREATE_NEW_CONSOLE : CREATE_NEW_PROCESS_GROUP), NULL, NULL, (LPSTARTUPINFOW)&si, &pi))
		return NULL;

	CloseHandle(pi.hThread);
	return pi.hProcess;
}

BOOL
CreateProcessInJob(TCHAR* jobName, TCHAR** argv)
{
	DWORD err;

	HANDLE hJob;
	TCHAR strFinalName[MAX_PATH] = { 0 };

	HANDLE hProcess = NULL;
	TCHAR cmdline[UNICODE_STRING_MAX_CHARS] = { 0 };

	// Risk of truncation in theory
	if(jobName != NULL){
		_tcscpy_s(strFinalName, MAX_PATH, _T("Local\\"));
		_tcscat_s(strFinalName, MAX_PATH, jobName);
	}

	// if a process limit was specified, then add 1 more process to it
	// since the current process is included in the count.
	if (Basic.dwProcessLimitQ)
		Basic.dwProcessLimit++;

	// output the settings
	PrintSettings(CreateInJob);

	// Request any required privileges
	if (!RequestNecessaryPrivileges(GetCurrentProcess())) {
		_ftprintf(stdout, _T("[!] Unable to request privileges to specify quotas: error %d\n"), GetLastError());
		goto fail;
	}

	// initialize a job object with the requested name
	hJob = InitializeJobObject((jobName == NULL) ? NULL : strFinalName);
	if (hJob == NULL) {
		err = GetLastError();
		if(err == ERROR_INVALID_HANDLE){
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a object name conflict!\n"), JOBNAME(jobName));
		} else if (err == ERROR_ALREADY_EXISTS){
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a job already existing with that name!\n"), JOBNAME(jobName));
		} else {
			_ftprintf(stdout, _T("[!] Couldn't create job %s: error %d\n"), JOBNAME(jobName), err);
		}
		goto fail;
	}

	// assign the job object to ourselves
	_ftprintf(stdout, _T("[I] Adding current process (%d) into job %s (%#x)\n"), GetCurrentProcessId(), JOBNAME(jobName), (unsigned int)hJob);
	if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) { // Windows 7 and Server 2008 R2 and below
			_ftprintf(stdout, _T("[!] Couldn't apply job object to self as it looks like a job object has already been applied!\n"));
		} else
			_ftprintf(stdout, _T("[!] Couldn't apply job object to self: error %d\n"), err);
		goto fail;
	}

	// construct the commandline for create process (ArgvToCommandLine)
	if (!ArgvToCommandLine(argv, cmdline, UNICODE_STRING_MAX_CHARS)) {
		_ftprintf(stdout, _T("[!] Unable to convert arguments into a regular commandline!\n"));
		goto fail;
	}

	_ftprintf(stdout, _T("[I] Starting process with command: %s\n"), cmdline);

	// now we can finally create the process
	hProcess = StartProcess(argv[0], cmdline);
	if (hProcess == NULL) {
		err = GetLastError();
		if (err = ERROR_FILE_NOT_FOUND) {
			_ftprintf(stdout, _T("[!] Unable to start process %s due to the file not being found!\n"), argv[0]);
		} else
			_ftprintf(stdout, _T("[!] Unable to start process %s: error %d\n"), argv[0], err);
		goto fail;
	}
	_ftprintf(stdout, _T("[!] Successfully started process %s: %d!\n"), argv[0], GetProcessId(hProcess));

	// wait until the process has actually started
	if (WaitForInputIdle(hProcess, INFINITE))
		goto fail;
	_ftprintf(stdout, _T("[!] Process %s (%d) is ready.\n"), argv[0], GetProcessId(hProcess));

	// we should be done and good to go
	CloseHandle(hProcess);
	return TRUE;

fail:
	if (hJob)
		CloseHandle(hJob);
	if (hProcess)
		CloseHandle(hProcess);
	return FALSE;
}

//
// Function	: PrintHelp
// Purpose	: Print the help out
//
void
PrintHelp(TCHAR *strExe)
{
	_ftprintf(stdout, _T("    i.e. %s [-h] -- [command]\n"), strExe);
	_ftprintf(stdout, _T("\n"));
	_ftprintf(stdout, _T(" General Settings / Options:\n"));
	_ftprintf(stdout, _T("    -g          - Get process list\n"));
	_ftprintf(stdout, _T("    -f          - Force application of job to process ignoring any failures\n"));
	_ftprintf(stdout, _T("    -c          - Create a new console when spawning the child process"));
	_ftprintf(stdout, _T("    -P <name>   - Process name to apply the job to\n"));
	_ftprintf(stdout, _T("    -p <PID>    - PID to apply the job to\n"));
	_ftprintf(stdout, _T("    -n <name>   - What the job will be called (optional)\n"));

	_ftprintf(stdout, _T(" Process Limits:\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	_ftprintf(stdout, _T("    -l <number> - Limit the number of process to this many\n"));

	_ftprintf(stdout, _T(" Memory:\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_MEMORY
	_ftprintf(stdout, _T("    -m <bytes>  - Limit the total memory in bytes for each process in the job\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_MEMORY
	_ftprintf(stdout, _T("    -M <bytes>  - Limit the total memory in bytes for the entire job\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_TIME
	_ftprintf(stdout, _T("    -t <ticks>   - Limit the execution time for each process in the job\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_TIME
	_ftprintf(stdout, _T("    -T <ticks>   - Limit the execution time for the entire job\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_WORKINGSET
	_ftprintf(stdout, _T("    -w <min-bytes> - Limit the minimum working set size\n"));
	_ftprintf(stdout, _T("    -W <max-bytes> - Limit the maximum working set size\n"));

	_ftprintf(stdout, _T(" Process Control (should be combined as a single parameter to -b):\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_ftprintf(stdout, _T("    -b k        - Kill all process when the job handle dies\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_BREAKAWAY_OK
	_ftprintf(stdout, _T("    -b b        - Allow child process to be created with CREATE_BREAKAWAY_FROM_JOB (weak security)\n"));
	// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
	_ftprintf(stdout, _T("    -b B        - Allow child process which aren't part of the job (weak security)\n"));

	_ftprintf(stdout, _T(" UI Security Controls (should be combined as a single parameter to -u):\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_DESKTOP
	_ftprintf(stdout, _T("    -u d        - Prevent processes within the job from switching or creating desktops\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
	_ftprintf(stdout, _T("    -u D        - Prevent processes within the job from calling the change display setting function\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_EXITWINDOWS
	_ftprintf(stdout, _T("    -u x        - Prevent processes within job from calling the exit Windows function\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_GLOBALATOMS
	_ftprintf(stdout, _T("    -u a        - Prevent processes within job from accessing global atoms\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_HANDLES
	_ftprintf(stdout, _T("    -u u        - Prevent processes within job from using user handles\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_READCLIPBOARD
	_ftprintf(stdout, _T("    -u c        - Prevent processes within job from reading the clipboard\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
	_ftprintf(stdout, _T("    -u s        - Prevent processes within job from changing system parameters\n"));
	// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_WRITECLIPBOARD
	_ftprintf(stdout, _T("    -u C        - Prevent processes within job from writing the clipboard\n"));

	// FIXME: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION

	// FIXME: JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION

	_ftprintf(stdout, _T("\n"));
}

//
// Function	: _tmain
// Purpose	: entry point
//
int _tmain(int argc, TCHAR* argv[])
{
	char  chOpt;

	// option settings
	DWORD dwPID = 0;
	TCHAR *strProcess = NULL; TCHAR *strName = NULL;

	// command to execute
	int argpos; TCHAR** cmdv;

	printf("[*] A Microsoft Windows Process Lockdown Tool using Job Objects - https://github.com/nccgroup/WindowsJobLock\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");
	printf("[*] -h for help \n");

	// Extract all the options
	argpos = 1;
	while ((chOpt = getopt(argc, argv, _T("gh fc P:p:l:m:M:n:t:T:w:W:u:b:"))) != EOF) {
		switch (chOpt) {
		case _T('g'):
			bListProcesses = TRUE;
			break;
		case _T('c'):
			bCreateConsole = TRUE;
			break;
		case _T('f'):
			bIgnoreJobFailures = TRUE;
			break;
		case _T('P'):
			strProcess = optarg; argpos++;
			break;
		case _T('p'):
			dwPID = _tstoi(optarg); argpos++;
			break;
		case _T('l'):
			Basic.dwProcessLimitQ = TRUE;
			Basic.dwProcessLimit = _tstoi(optarg); argpos++;
			break;
		case _T('M'):
			Extended.dwJobMemoryQ = TRUE;
			Extended.dwJobMemory = _tstoi(optarg); argpos++;
			break;
		case _T('m'):
			Extended.dwProcessMemoryQ = TRUE;
			Extended.dwProcessMemory = _tstoi(optarg); argpos++;
			break;
		case _T('T'):
			Basic.dwJobTicksLimitQ = TRUE;
			Basic.dwJobTicksLimit.QuadPart = _tstoi64(optarg); argpos++;
			break;
		case _T('t'):
			Basic.dwProcessTicksLimitQ = TRUE;
			Basic.dwProcessTicksLimit.QuadPart = _tstoi64(optarg); argpos++;
			break;
		case _T('w'):
			Basic.dwMinimumWorkingSetSizeQ = TRUE;
			Basic.dwMinimumWorkingSetSize = _tstoi(optarg); argpos++;
			break;
		case _T('W'):
			Basic.dwMaximumWorkingSetSizeQ = TRUE;
			Basic.dwMaximumWorkingSetSize = _tstoi(optarg); argpos++;
			break;
		case _T('n'):
			strName = optarg; argpos++;
			break;
		case  _T('b'):
			if (_tcsstr(optarg, _T("k")))
				Basic.bKillProcOnJobClose = TRUE;
			if (_tcsstr(optarg, _T("b")))
				Basic.bBreakAwayOK = TRUE;
			if (_tcsstr(optarg, _T("B")))
				Basic.bSilentBreakAwayOK = TRUE;
			argpos++;
			break;
		case _T('u'):
			if (_tcsstr(optarg, _T("d")))
				UI.bUILimitDesktop = TRUE;
			if (_tcsstr(optarg, _T("D")))
				UI.bUILimitDispSettings = TRUE;
			if (_tcsstr(optarg, _T("x")))
				UI.bUILimitExitWindows = TRUE;
			if (_tcsstr(optarg, _T("a")))
				UI.bUILimitGlobalAtoms = TRUE;
			if (_tcsstr(optarg, _T("u")))
				UI.bUILimitUserHandles = TRUE;
			if (_tcsstr(optarg, _T("c")))
				UI.bUILimitReadClip = TRUE;
			if (_tcsstr(optarg, _T("s")))
				UI.bUILimitSystemParams = TRUE;
			if (_tcsstr(optarg, _T("C")))
				UI.bUILimitWriteClip = TRUE;
			argpos++;
			break;
		case _T('h'):
			PrintHelp(argv[0]);
			return EXIT_SUCCESS;
		default:
			_ftprintf(stdout, _T("[!] No handler - %s\n"), argv[argpos]);
			break;
		}
		argpos++;
	}
	cmdv = &argv[argpos];

	// cmdv should be pointing to "--", but if it's not then seek to it.
	while (argpos < argc && _tcscmp(argv[argpos], _T("--")) != 0)
		argpos++;

	// if a "--" was found, then point cmdv at the arg following it
	if (argpos < argc && _tcscmp(argv[argpos], _T("--")) == 0)
		cmdv = &argv[argpos + 1];

	// List processe if requested by user
	if (bListProcesses) {
		ListProcesses();
		return EXIT_SUCCESS;
	}

	_ftprintf(stdout, _T("[*] Using current process id: pid %d.\n"), GetCurrentProcessId());
	
	// If the name was specified, then look for its pid.
	if (strProcess)
		dwPID = FindProcess(strProcess);

	if (dwPID)
		return AttachJobToPid(strName, dwPID)? EXIT_SUCCESS : EXIT_FAILURE;

	if (strProcess)
		_ftprintf(stdout, _T("[!] Could not find the process %s!\n"), strProcess);
	else {
		return CreateProcessInJob(strName, cmdv) ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	_ftprintf(stdout, _T("[!] You need to specify a PID or valid process name (use -g to list processes)!\n"));
	return EXIT_FAILURE;
}
