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
#define JOBNAME(name) (name? name : _T("None"))
#define TF(expr) ((expr)? _T("True") : _T("False"))

// Global
BOOL bListProcesses = FALSE;
DWORD dwProcessLimit = 0;
DWORD dwJobMemory = 0;
DWORD dwProcessMemory = 0;
LARGE_INTEGER dwProcessTicksLimit = { 0 };
LARGE_INTEGER dwJobTicksLimit = { 0 };
SIZE_T dwMinimumWorkingSetSize = -1;
SIZE_T dwMaximumWorkingSetSize = -1;
struct {
	BOOL  bKillProcOnJobClose;
	BOOL  bBreakAwayOK;
	BOOL  bSilentBreakAwayOK;
	BOOL  bUILimitDesktop;
	BOOL  bUILimitDispSettings;
	BOOL  bUILimitExitWindows;
	BOOL  bUILimitUserHandles;
	BOOL  bUILimitGlobalAtoms;
	BOOL  bUILimitReadClip;
	BOOL  bUILimitSystemParams;
	BOOL  bUILimitWriteClip;
} UI = { FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE };

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
		_ftprintf(stdout, _T("[I] %s (%d) in session %d\n"), ppProcessInfo[dwCount].pProcessName, ppProcessInfo[dwCount].ProcessId, ppProcessInfo[dwCount].SessionId);

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

HANDLE
InitializeJobObject(TCHAR* jobName)
{
	HANDLE hJob = NULL;
	TCHAR strFinalName[MAX_PATH] = { 0 };

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jelInfo = { 0 };
	JOBOBJECT_BASIC_UI_RESTRICTIONS jbuiRestrictions = { 0 };

	jelInfo.BasicLimitInformation.LimitFlags = 0;
	jbuiRestrictions.UIRestrictionsClass = 0;

	// construct a job object using the name if specified
	hJob = CreateJobObject(NULL, jobName);

	_ftprintf(stdout, _T("[I] Final job name                - %s\n"), JOBNAME(jobName));

	// shit, we failed...
	if (hJob == NULL)
		goto fail;

	// populate the job-specific structures using globals initialized by getopt
	if(dwProcessLimit){
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		jelInfo.BasicLimitInformation.ActiveProcessLimit = dwProcessLimit;
	}

	if(dwJobMemory){
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
		jelInfo.JobMemoryLimit = dwJobMemory;
	}
		
	if(dwProcessMemory){
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jelInfo.ProcessMemoryLimit = dwProcessMemory;
	}

	if (dwJobTicksLimit.QuadPart) {
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		jelInfo.BasicLimitInformation.PerJobUserTimeLimit = dwProcessTicksLimit;
	}

	if (dwProcessTicksLimit.QuadPart) {
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		jelInfo.BasicLimitInformation.PerProcessUserTimeLimit = dwProcessTicksLimit;
	}

	if (dwMinimumWorkingSetSize != -1) {
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
		jelInfo.BasicLimitInformation.MinimumWorkingSetSize = dwMinimumWorkingSetSize;
	}

	if (dwMaximumWorkingSetSize != -1) {
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
		jelInfo.BasicLimitInformation.MinimumWorkingSetSize = dwMinimumWorkingSetSize;
	}

	if(UI.bKillProcOnJobClose) jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	if(UI.bBreakAwayOK) jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
	if(UI.bSilentBreakAwayOK) jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
	if(UI.bUILimitDesktop)  jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DESKTOP;
	if(UI.bUILimitDispSettings) jbuiRestrictions.UIRestrictionsClass|= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
	if(UI.bUILimitExitWindows) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
	if(UI.bUILimitGlobalAtoms) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
	if(UI.bUILimitUserHandles) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
	if(UI.bUILimitReadClip) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
	if(UI.bUILimitSystemParams) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
	if(UI.bUILimitWriteClip) jbuiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

	// Now we can set these structures to the job object
	if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jelInfo, sizeof(jelInfo))) {
		_ftprintf(stdout, _T("[!] Couldn't set job extended limits to job object %s due to an error %d\n"), JOBNAME(jobName), GetLastError());
		goto fail;
	}
	_ftprintf(stdout, _T("[*] Applied job exended limits to job %s (%#x)\n"), JOBNAME(jobName), (unsigned int)hJob);

	if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbuiRestrictions, sizeof(jbuiRestrictions))) {
		_ftprintf(stdout, _T("[!] Couldn't set UI limits to job object %s due to an error %d\n"), JOBNAME(jobName), GetLastError());
		goto fail;
	}
	_ftprintf(stdout, _T("[*] Applied UI limits to job %s (%#x)\n"), JOBNAME(jobName), (unsigned int)hJob);

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

	// Initialize a Job object using the arguments the user specified
	hJob = InitializeJobObject((jobName == NULL)? NULL : strFinalName);
	if (hJob == NULL) {
		err = GetLastError();
		if (err ==  ERROR_INVALID_HANDLE) {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a object name conflict\n"), JOBNAME(jobName));
		} else if (err == ERROR_ALREADY_EXISTS) {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a job already existing with that name\n"), JOBNAME(jobName));
		} else {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to an unknown error %d\n"), JOBNAME(jobName), err);
		}
		return FALSE;
	}

	// Duplicate the handle into the target process
	if(!DuplicateHandle(GetCurrentProcess(),hJob,hProcess,NULL,JOB_OBJECT_QUERY,TRUE,NULL)){
		_ftprintf(stdout, _T("[!] Couldn't duplicate job handle into target process due to an error %d\n"), GetLastError());
		return FALSE;
	} else {
		_ftprintf(stdout, _T("[*] Duplicated handle of job (with restricted access) into target process!\n"));
	}

	// Now assign the process to the job object
	if(!AssignProcessToJobObject(hJob,hProcess)){
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) { // Windows 7 and Server 2008 R2 and below
			_ftprintf(stdout, _T("[!] Couldn't apply job object to %s Looks like a job object has already been applied\n"), strProcess);
			return FALSE;
		} else
			_ftprintf(stdout, _T("[!] Couldn't apply job object to %s due to an error %d\n"), strProcess, err);
	} else
		_ftprintf(stdout, _T("[*] Applied job object to process!\n"));

	return TRUE;
}

//
// Function	: PrintSettings
// Purpose	: Print the settings we will apply
//
void PrintSettings()
{
	_ftprintf(stdout, _T("[I] Process Limit                 - %s - %d\n"), TF(dwProcessLimit > 0), dwProcessLimit);
	_ftprintf(stdout, _T("[I] Job Memory Limit              - %s - %d\n"), TF(dwJobMemory > 0), dwJobMemory);
	_ftprintf(stdout, _T("[I] Process Memory Limit          - %s - %d\n"), TF(dwProcessMemory > 0), dwProcessMemory);
	_ftprintf(stdout, _T("[I] Job Execution Time Limit      - %s - %lld\n"), TF(dwJobTicksLimit.QuadPart > 0), dwJobTicksLimit.QuadPart);
	_ftprintf(stdout, _T("[I] Process Execution Time Limit  - %s - %lld\n"), TF(dwProcessTicksLimit.QuadPart > 0), dwProcessTicksLimit.QuadPart);
	_ftprintf(stdout, _T("[I] Minimum Working Set Limit     - %s - %d\n"), TF(dwMinimumWorkingSetSize > -1), dwMinimumWorkingSetSize);
	_ftprintf(stdout, _T("[I] Maximum Working Set Limti     - %s - %d\n"), TF(dwMaximumWorkingSetSize > -1), dwMaximumWorkingSetSize);
	_ftprintf(stdout, _T("[I] Kill Process on Job Close     - %s\n"), TF(UI.bKillProcOnJobClose == TRUE));
	_ftprintf(stdout, _T("[I] Break Away from Job OK        - %s\n"), TF(UI.bBreakAwayOK == TRUE));
	_ftprintf(stdout, _T("[I] Silent Break Away from Job OK - %s\n"), TF(UI.bSilentBreakAwayOK == TRUE));
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
		_ftprintf(stderr,  _T("[!] Could not find the name of the process for PID %d!\n"), pid);
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_DUP_HANDLE, false, pid);
	if(hProcess == NULL || hProcess == INVALID_HANDLE_VALUE){
		_ftprintf(stderr,  _T("[!] Could not open process %s (PID %d) - %d\n"), strProcName, pid, GetLastError());
		return FALSE;
	}
	_ftprintf(stdout, _T("[*] Opened process %s\n"), strProcName);

	PrintSettings();

	if (!BuildAndDeploy(jobName, strProcName, hProcess)) {
		_ftprintf(stderr, _T("[!] Failed to build and deploy job object to %s..\n"), strProcName);
	}

	_ftprintf(stdout, _T("[*] Successfully built and deployed job object to %s!\n"), strProcName);
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

	if (!CreateProcess(appname, cmdline, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP, NULL, NULL, (LPSTARTUPINFOW)&si, &pi))
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

	// output the settings
	PrintSettings();

	// initialize a job object with the requested name
	hJob = InitializeJobObject((jobName == NULL) ? NULL : strFinalName);
	if (hJob == NULL) {
		err = GetLastError();
		if(err == ERROR_INVALID_HANDLE){
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a object name conflict\n"), JOBNAME(jobName));
		} else if (err == ERROR_ALREADY_EXISTS){
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to a job already existing with that name\n"), JOBNAME(jobName));
		} else {
			_ftprintf(stdout, _T("[!] Couldn't create job %s due to an unknown error %d\n"), JOBNAME(jobName), err);
		}
		goto fail;
	}

	// assign the job object to ourselves
	_ftprintf(stdout, _T("[I] Joining current process (%d) into job %s (%#x)\n"), GetCurrentProcessId(), JOBNAME(jobName), (unsigned int)hJob);
	if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED) { // Windows 7 and Server 2008 R2 and below
			_ftprintf(stdout, _T("[!] Couldn't apply job object to ourselves Looks like a job object has already been applied\n"));
		} else
			_ftprintf(stdout, _T("[!] Couldn't apply job object to ourselves an error %d\n"), err);
		goto fail;
	}

	// construct the commandline for create process (ArgvToCommandLine)
	if (!ArgvToCommandLine(argv, cmdline, UNICODE_STRING_MAX_CHARS)) {
		_ftprintf(stdout, _T("[!] Unable to convert arguments into a regular commandline\n"));
		goto fail;
	}

	_ftprintf(stdout, _T("[I] Starting process with command: %s\n"), cmdline);

	// now we can finally create the process
	hProcess = StartProcess(argv[0], cmdline);
	if (hProcess == NULL) {
		err = GetLastError();
		if (err = ERROR_FILE_NOT_FOUND) {
			_ftprintf(stdout, _T("[!] Unable to start process %s due to the file not being found\n"), argv[0]);
		} else
			_ftprintf(stdout, _T("[!] Unable to start process %s due to an unknown error %d\n"), argv[0], err);
		goto fail;
	}
	_ftprintf(stdout, _T("[!] Successfully started process %s: %d\n"), argv[0], GetProcessId(hProcess));

	// wait until the process has actually started
	if (WaitForInputIdle(hProcess, INFINITE))
		goto fail;
	_ftprintf(stdout, _T("[!] Process %s (%d) is ready\n"), argv[0], GetProcessId(hProcess));

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
void PrintHelp(TCHAR *strExe){

        _ftprintf(stdout, _T("    i.e. %s [-h] -- [command]\n"), strExe);
		_ftprintf(stdout, _T("\n"));
		_ftprintf(stdout, _T(" General Settings / Options:\n"));
		_ftprintf(stdout, _T("    -g          - Get process list\n"));
		_ftprintf(stdout, _T("    -P <name>   - Process name to apply the job to\n"));
		_ftprintf(stdout, _T("    -p <PID>    - PID to apply the job to\n"));
        _ftprintf(stdout, _T("    -n <name>   - What the job will be called (optional)\n"));
		_ftprintf(stdout, _T(" Process Limits:\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        _ftprintf(stdout, _T("    -l <number> - Limit the number of process to this many\n"));
		_ftprintf(stdout, _T(" Memory:\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_MEMORY
        _ftprintf(stdout, _T("    -m <bytes>  - Limit the total memory in bytes for the entire job\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_MEMORY
		_ftprintf(stdout, _T("    -M <bytes>  - Limit the total memory in bytes for each process in the job\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_TIME
		_ftprintf(stdout, _T("    -t <ticks>   - Limit the execution time for the entire job by 100ns ticks\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_TIME
		_ftprintf(stdout, _T("    -T <ticks>   - Limit the execution time for each process in the job by 100ns ticks\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_WORKINGSET
		_ftprintf(stdout, _T("    -w <min-bytes> - Limit the minimum working set size\n"));
		_ftprintf(stdout, _T("    -W <max-bytes> - Limit the maximum working set size\n"));
		_ftprintf(stdout, _T(" Process Control:\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        _ftprintf(stdout, _T("    -k          - Kill all process when the job handle dies\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_BREAKAWAY_OK
		_ftprintf(stdout, _T("    -B          - Allow child process to be created with CREATE_BREAKAWAY_FROM_JOB (weak security)\n"));
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
		_ftprintf(stdout, _T("    -b          - Allow child process which aren't part of the job (weak security)\n"));
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
		// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
		// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
		// JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		// JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION

		_ftprintf(stdout, _T("\n"));
        ExitProcess(1);
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
	while ((chOpt = getopt(argc, argv, _T("hP:p:l:m:M:n:t:T:w:W:u:g"))) != EOF) {
		switch (chOpt) {
		case _T('g'):
			bListProcesses = TRUE;
			break;
		case _T('P'):
			strProcess = optarg; argpos++;
			break;
		case _T('p'):
			dwPID = _tstoi(optarg); argpos++;
			break;
		case _T('l'):
			dwProcessLimit = _tstoi(optarg); argpos++;
			break;
		case _T('m'):
			dwJobMemory = _tstoi(optarg); argpos++;
			break;
		case _T('M'):
			dwProcessMemory = _tstoi(optarg); argpos++;
			break;
		case _T('t'):
			dwJobTicksLimit.QuadPart = _tstoi64(optarg); argpos++;
			break;
		case _T('T'):
			dwProcessTicksLimit.QuadPart = _tstoi64(optarg); argpos++;
			break;
		case _T('w'):
			dwMinimumWorkingSetSize = _tstoi(optarg); argpos++;
			break;
		case _T('W'):
			dwMaximumWorkingSetSize = _tstoi(optarg); argpos++;
			break;
		case _T('n'):
			strName = optarg; argpos++;
			break;
		case _T('u'):
			if (_tcsstr(optarg, _T("k")))
				UI.bKillProcOnJobClose = TRUE;
			if (_tcsstr(optarg, _T("B")))
				UI.bBreakAwayOK = TRUE;
			if (_tcsstr(optarg, _T("b")))
				UI.bSilentBreakAwayOK = TRUE;
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
			return 0;
		default:
			_ftprintf(stderr, _T("[!] No handler - %s\n"), argv[argpos]);
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
		return 0;
	}
	
	// If the name was specified, then look for its pid.
	if (strProcess)
		dwPID = FindProcess(strProcess);

	if (dwPID)
		return AttachJobToPid(strName, dwPID)? 0 : -1;

	if (strProcess)
		_ftprintf(stderr, _T("[!] Could not find the process %s\n"), strProcess);
	else {
		if (dwProcessLimit)		// add 1 more process to what the user specified, since the current process counts as being part of the job.
			dwProcessLimit++;
		return CreateProcessInJob(strName, cmdv) ? 0 : -1;
	}
	_ftprintf(stderr, _T("[!] You need to specify a PID or valid process name (use -g to list processes)\n"));
	return -1;
}