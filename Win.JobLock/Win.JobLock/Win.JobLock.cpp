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

// Global
BOOL bListProcesses=FALSE;
HANDLE hProcess = NULL;
TCHAR *strProcess = NULL;
DWORD dwPID = 0;
TCHAR *strName = NULL;
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
	DWORD dwPIDArray[2048], dwCount = 0, dwRet;
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
		_ftprintf(stdout, L"[i] %s (%d) in session %d\n", ppProcessInfo[dwCount].pProcessName, ppProcessInfo[dwCount].ProcessId, ppProcessInfo[dwCount].SessionId);

	return;
}

//
// Function	: FindProcess
// Purpose	: Find as processes name by PID
//
BOOL FindProcessName(DWORD dwPID, TCHAR *strName)
{
	DWORD dwPIDArray[2048], dwCount = 0, dwRet;
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

	_ftprintf(stdout, L"[i] Final job name                - %s\n", (jobName == NULL)? L"NONAME" : jobName);

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

	if (dwMinimumWorkingSetSize) {
		jelInfo.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
		jelInfo.BasicLimitInformation.MinimumWorkingSetSize = dwMinimumWorkingSetSize;
	}

	if (dwMaximumWorkingSetSize) {
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
		_ftprintf(stdout,L"[!] Couldn't set job extended limits to job object %s due to an error %d\n",(jobName == NULL)? L"Unknown" : jobName, GetLastError());
		goto fail;
	}
	_ftprintf(stdout,L"[*] Applied job exended limits to job object\n");

	if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbuiRestrictions, sizeof(jbuiRestrictions))) {
		_ftprintf(stdout,L"[!] Couldn't set UI limits to job object %s due to an error %d\n",(jobName == NULL)? L"Unknown" : jobName, GetLastError());
		goto fail;
	}
	_ftprintf(stdout,L"[*] Applied UI limits to job object\n");

	return hJob;

fail:
	if (hJob)
		CloseHandle(hJob);
	return NULL;
}

BOOL BuildAndDeploy()
{
	HANDLE hJob;

	TCHAR strFinalName[MAX_PATH] = { 0 };

	// Risk of truncation in theory
	if(strName != NULL){
		_tcscpy_s(strFinalName,MAX_PATH,L"Local\\");
		_tcscat_s(strFinalName,MAX_PATH,strName);
	}

	// Initialize a Job object using the arguments the user specified
	hJob = InitializeJobObject((strName == NULL)? NULL : strFinalName);
	if(hJob == NULL){
		if(GetLastError() ==  ERROR_INVALID_HANDLE){
			_ftprintf(stdout,L"[!] Couldn't create job %s due to a object name conflict\n",strFinalName);
		} else if (GetLastError() ==ERROR_ALREADY_EXISTS){
			_ftprintf(stdout,L"[!] Couldn't create job %s due to a job already existing with that name\n",strFinalName);
		} else {
			_ftprintf(stdout,L"[!] Couldn't create job %s due to an unknown error %d\n",strFinalName, GetLastError());
		}
		return FALSE;
	}

	// Duplicate the handle into the target process
	if(!DuplicateHandle(GetCurrentProcess(),hJob,hProcess,NULL,JOB_OBJECT_QUERY,TRUE,NULL)){
		_ftprintf(stdout,L"[!] Couldn't duplicate job handle into target process due to an error %d\n",GetLastError());
		return FALSE;
	} else {
		_ftprintf(stdout,L"[*] Duplicated handle of job (with restricted access) into target process!\n");
	}

	// Now assign the process to the job object
	if(!AssignProcessToJobObject(hJob,hProcess)){
		// this is where I wanted to be lazy
		if(GetLastError() == ERROR_ACCESS_DENIED){ // Windows 7 and Server 2008 R2 and below
			_ftprintf(stdout,L"[!] Couldn't apply job object to %s Looks like a job object has already been applied\n", strProcess);
			return FALSE;
		} else {
			_ftprintf(stdout,L"[!] Couldn't apply job object to %s due to an error %d\n", strProcess, GetLastError());
		}
	} else {
		_ftprintf(stdout,L"[*] Applied job object to process!\n");
	}


	return TRUE;
}

//
// Function	: PrintSettings
// Purpose	: Print the settings we will apply
//
void PrintSettings()
{
	fprintf(stdout,"[i] Process Limit                 - %s - %d\n", dwProcessLimit > 0 ? "True " : "False", dwProcessLimit);
	fprintf(stdout,"[i] Job Memory Limit              - %s - %d\n", dwJobMemory > 0 ? "True " : "False", dwJobMemory);
	fprintf(stdout,"[i] Process Memory Limit          - %s - %d\n", dwProcessMemory > 0 ? "True " : "False", dwProcessMemory);
	fprintf(stdout,"[i] Job Execution Time Limit      - %s - %lld\n", dwJobTicksLimit.QuadPart > 0 ? "True " : "False", dwJobTicksLimit.QuadPart);
	fprintf(stdout,"[i] Process Execution Time Limit  - %s - %lld\n", dwProcessTicksLimit.QuadPart > 0 ? "True " : "False", dwProcessTicksLimit.QuadPart);
	fprintf(stdout,"[i] Minimum Working Set Limit     - %s - %d\n", dwMinimumWorkingSetSize > -1 ? "True " : "False", dwMinimumWorkingSetSize);
	fprintf(stdout,"[i] Maximum Working Set Limti     - %s - %d\n", dwMaximumWorkingSetSize > -1 ? "True " : "False", dwMaximumWorkingSetSize);
	fprintf(stdout,"[i] Kill Process on Job Close     - %s\n", UI.bKillProcOnJobClose == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Break Away from Job OK        - %s\n", UI.bBreakAwayOK == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Silent Break Away from Job OK - %s\n", UI.bSilentBreakAwayOK == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Desktop Operations      - %s\n", UI.bUILimitDesktop == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Display Changes         - %s\n", UI.bUILimitDispSettings == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Exit Windows            - %s\n", UI.bUILimitExitWindows == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Global Atoms            - %s\n", UI.bUILimitGlobalAtoms == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit User Handles            - %s\n", UI.bUILimitUserHandles == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Reading of Clipboard    - %s\n", UI.bUILimitReadClip == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit System Parameter Change - %s\n", UI.bUILimitSystemParams == TRUE ? "True ": "False");
	fprintf(stdout,"[i] Limit Writing to Clipboard    - %s\n", UI.bUILimitWriteClip == TRUE ? "True ": "False");
}

//
// Function	: PrintHelp
// Purpose	: Print the help out
//
void PrintHelp(TCHAR *strExe){

        _ftprintf(stdout,L"    i.e. %s [-h] \n",strExe);
		fprintf (stdout,"\n");
		fprintf (stdout," General Settings / Options:\n");
		fprintf (stdout,"    -g          - Get process list\n");
		fprintf (stdout,"    -P <name>   - Process name to apply the job to\n");
		fprintf (stdout,"    -p <PID>    - PID to apply the job to\n");
        fprintf (stdout,"    -n <name>   - What the job will be called (optional)\n");
		fprintf (stdout," Process Limits:\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        fprintf (stdout,"    -l <number> - Limit the number of process to this many\n");
		fprintf (stdout," Memory:\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_MEMORY
        fprintf (stdout,"    -m <bytes>  - Limit the total memory in bytes for the entire job\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_MEMORY
		fprintf (stdout,"    -M <bytes>  - Limit the total memory in bytes for each process in the job\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_JOB_TIME
		fprintf(stdout, "    -t <ticks>   - Limit the execution time for the entire job by 100ns ticks\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_PROCESS_TIME
		fprintf(stdout, "    -T <ticks>   - Limit the execution time for each process in the job by 100ns ticks\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_WORKINGSET
		fprintf(stdout, "    -w <min-bytes> - Limit the minimum working set size\n");
		fprintf(stdout, "    -W <max-bytes> - Limit the maximum working set size\n");
		fprintf (stdout," Process Control:\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        fprintf (stdout,"    -k          - Kill all process when the job handle dies\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_BREAKAWAY_OK
		fprintf (stdout,"    -B          - Allow child process to be created with CREATE_BREAKAWAY_FROM_JOB (weak security)\n");
		// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags - JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
		fprintf (stdout,"    -b          - Allow child process which aren't part of the job (weak security)\n");
		fprintf (stdout," UI Security Controls (should be combined as a single parameter to -u):\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_DESKTOP
        fprintf (stdout,"    -u d        - Prevent processes within the job from switching or creating desktops\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        fprintf (stdout,"    -u D        - Prevent processes within the job from calling the change display setting function\n");
        // JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_EXITWINDOWS
		fprintf (stdout,"    -u x        - Prevent processes within job from calling the exit Windows function\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_GLOBALATOMS
		fprintf (stdout,"    -u a        - Prevent processes within job from accessing global atoms\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_HANDLES
		fprintf (stdout,"    -u u        - Prevent processes within job from using user handles\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_READCLIPBOARD
		fprintf (stdout,"    -u c        - Prevent processes within job from reading the clipboard\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
		fprintf (stdout,"    -u s        - Prevent processes within job from changing system parameters\n");
		// JOBOBJECT_BASIC_UI_RESTRICTIONS - JOB_OBJECT_UILIMIT_WRITECLIPBOARD
		fprintf (stdout,"    -u C        - Prevent processes within job from writing the clipboard\n");
		// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
		// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
		// JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		// JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION


		fprintf (stdout,"\n");
        ExitProcess(1);
}


//
// Function	: _tmain
// Purpose	: entry point
//
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwPID = 0;
	char  chOpt;
	TCHAR strProcName[MAX_PATH];

	// variables pertaining to command to execute
	int argpos; _TCHAR** cmdv;

	printf("[*] A Microsoft Windows Process Lockdown Tool using Job Objects - https://github.com/nccgroup/WindowsJobLock\n");
	printf("[*] NCC Group Plc - http://www.nccgroup.com/ \n");
	printf("[*] -h for help \n");

	// Extract all the options
	argpos = 0;
	while ((chOpt = getopt(argc, argv, _T("hP:p:l:m:M:n:t:T:w:W:u:g"))) != EOF) {
		switch (chOpt) {
		case _T('g'):
			bListProcesses = TRUE;
			break;
		case _T('P'):
			strProcess = optarg;
			break;
		case _T('p'):
			dwPID = _tstoi(optarg);
			break;
		case _T('l'):
			dwProcessLimit = _tstoi(optarg);
			break;
		case _T('m'):
			dwJobMemory = _tstoi(optarg);
			break;
		case _T('M'):
			dwProcessMemory = _tstoi(optarg);
			break;
		case _T('t'):
			dwJobTicksLimit.QuadPart = _tstoi64(optarg);
			break;
		case _T('T'):
			dwProcessTicksLimit.QuadPart = _tstoi64(optarg);
			break;
		case _T('w'):
			dwMinimumWorkingSetSize = _tstoi(optarg);
			break;
		case _T('W'):
			dwMaximumWorkingSetSize = _tstoi(optarg);
			break;
		case _T('n'):
			strName = optarg;
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
			break;
		case _T('h'):
			PrintHelp(argv[0]);
			return 0;
		default:
			fwprintf(stderr, L"[!] No handler - %c\n", chOpt);
			break;
		}
		argpos++;
	}
	cmdv = &argv[argpos];

	// cmdv should be pointing to "--", but if it's not then seek to it.
	while (argpos < argc && _tcscmp(argv[argpos], _T("--")) != 0)
		argpos++;

	// if a "--" was found, then point cmdv at the arg following it
	if (argpos < argc)
		cmdv = &argv[argpos + 1];

	// continue doing what Ollie Whitehouse was doing...
	if(bListProcesses) {
		ListProcesses();
		return 0;
	}
	
	if(strProcess!=NULL){
		dwPID = FindProcess(strProcess);
	}

	if(dwPID == 0){
		if(strProcess != NULL) {
			_ftprintf(stderr,L"[!] Could not find the process %s\n",strProcess);
		} else {
			// XXX: Case to handle when a method doesn't exist
			_ftprintf(stderr,L"[!] You need to specify a PID or valid process name (use -g to list processes)\n");
		}
		return -1;
	}

	if(!FindProcessName(dwPID,strProcName)){
		_ftprintf(stderr,L"[!] Could not find the name of the process for PID %d!\n",dwPID);
		return -1;
	} else {
		// this is so I can be lazy later
		strProcess = strProcName;
	}

	hProcess = OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE|PROCESS_DUP_HANDLE,false,dwPID);
	if(hProcess == NULL || hProcess == INVALID_HANDLE_VALUE){
		_ftprintf(stderr,L"[!] Could not open process %s (PID %d) - %d\n",strProcName,dwPID,GetLastError());
		return -1;
	} else {
		_ftprintf(stdout,L"[*] Opened process %s\n",strProcName);
	}

	PrintSettings();
	if(!BuildAndDeploy()){
		_ftprintf(stderr,L"[!] Failed to build and deploy job object to %s..\n",strProcName);
		return -1;
	} else {
		_ftprintf(stdout,L"[*] Successfully built and deployed job object to %s!\n",strProcName);
	}

	return 0;
}

