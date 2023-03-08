#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include "resource.h"
#include "..\CVHide\CVHideDrv.h"
#include "../CVHide/Ioctl.h"

HINSTANCE hInst;

static void PopulateHideInfo(HWND hwndDlg, HIDE_INFO& hideInfo)
{
	hideInfo.HookNtQueryObject = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYOBJECT) ? TRUE : FALSE;
	hideInfo.HookNtQueryInformationProcess = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYINFORMATIONPROCESS) ? TRUE : FALSE;
	hideInfo.HookNtQuerySystemInformation = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYSYSTEMINFORMATION) ? TRUE : FALSE;
	hideInfo.HookNtQueryInformationJobObject = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYINFORMATIONJOBOBJECT) ? TRUE : FALSE;
	hideInfo.HookNtQueryInformationThread = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYINFORMATIONTHREAD) ? TRUE : FALSE;
	hideInfo.HookNtSetInformationThread = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTSETINFORMATIONTHREAD) ? TRUE : FALSE;
	hideInfo.HookNtSetInformationProcess = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTSETINFORMATIONPROCESS) ? TRUE : FALSE;
	hideInfo.HookNtSetContextThread = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTSETCONTEXTTHREAD) ? TRUE : FALSE;
	hideInfo.HookNtGetContextThread = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTGETCONTEXTTHREAD) ? TRUE : FALSE;
	hideInfo.HookNtClose = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCLOSE) ? TRUE : FALSE;
	hideInfo.HookNtYieldExecution = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTYIELDEXECUTION) ? TRUE : FALSE;
	hideInfo.HookNtCreateThreadEx = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCREATETHREADEX) ? TRUE : FALSE;
	hideInfo.HookNtCreateFile = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCREATEFILE) ? TRUE : FALSE;
	hideInfo.HookNtContinue = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCONTINUE) ? TRUE : FALSE;
	hideInfo.HookNtCreateProcessEx = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCREATEPROCESSEX) ? TRUE : FALSE;
	hideInfo.HookNtCreateUserProcess = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTCREATEUSERPROCESS) ? TRUE : FALSE;
	hideInfo.HookNtGetNextProcess = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTGETNEXTPROCESS) ? TRUE : FALSE;
	hideInfo.HookNtOpenProcess = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTOPENPROCESS) ? TRUE : FALSE;
	hideInfo.HookNtOpenThread = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTOPENTHREAD) ? TRUE : FALSE;
	hideInfo.HookNtSystemDebugControl = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTSYSTEMDEBUGCONTROL) ? TRUE : FALSE;
	hideInfo.HookNtUserFindWindowEx = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTUSERFINDWINDOWEX) ? TRUE : FALSE;
	hideInfo.HookNtUserBuildHwndList = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTUSERBUILDHWNDLIST) ? TRUE : FALSE;
	hideInfo.HookNtUserQueryWindow = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTUSERQUERYWINDOW) ? TRUE : FALSE;
	hideInfo.HookNtUserGetForegroundWindow = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTUSERGETFOREGROUNDWINDOW) ? TRUE : FALSE;
	hideInfo.HookNtQuerySystemTime = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYSYSTEMTIME) ? TRUE : FALSE;
	hideInfo.HookNtQueryPerformanceCounter = IsDlgButtonChecked(hwndDlg, IDC_CHK_NTQUERYPERFORMANCECOUNTER) ? TRUE : FALSE;
	hideInfo.HookKiDispatchException = IsDlgButtonChecked(hwndDlg, IDC_CHK_KIEXCEPTIONDISPATCH) ? TRUE : FALSE;
	hideInfo.HookKuserSharedData = IsDlgButtonChecked(hwndDlg, IDC_CHK_KIUSERSHAREDDATA) ? TRUE : FALSE;
	hideInfo.ClearPebNtGlobalFlag = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARPEBNTGLOBALFLAG) ? TRUE : FALSE;
	hideInfo.ClearPebBeingDebugged = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARPEBNTGLOBALFLAG) ? TRUE : FALSE;
	hideInfo.ClearHeapFlags = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARHEAPFLAGS) ? TRUE : FALSE;
	hideInfo.ClearKuserSharedData = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARKUSERSHAREDDATA) ? TRUE : FALSE;
	hideInfo.ClearHideFromDebuggerFlag = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARHIDEFROMDEBUGGERFLAG) ? TRUE : FALSE;
	hideInfo.ClearBypassProcessFreeze = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARBYPASSPROCESSFREEZEFLAG) ? TRUE : FALSE;
	hideInfo.ClearProcessBreakOnTerminationFlag = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARPROCESSBREAKONTERMINATIONFLAG) ? TRUE : FALSE;
	hideInfo.ClearThreadBreakOnTerminationFlag = IsDlgButtonChecked(hwndDlg, IDC_CHK_CLEARTHREADBREAKONTERMINATIONFLAG) ? TRUE : FALSE;
	hideInfo.SaveProcessHandleTracing = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVEPROCESSHANDLETRACING) ? TRUE : FALSE;
	hideInfo.SaveProcessDebugFlags = IsDlgButtonChecked(hwndDlg, IDC_CHK_SAVEPROCESSDEBUGFLAGS) ? TRUE : FALSE;
}

CVHideDrv drv;
HIDE_INFO HideInfo;
static void CVHideCall(HWND hwndDlg)
{
	BOOL hDevice = drv.CreateHandleToDriver();
	if (!hDevice)
	{
		MessageBoxA(hwndDlg, "Could not open CVHide handle...", "Driver loaded?", MB_ICONERROR);
		return;
	}
	HideInfo.Pid = (ULONG)GetDlgItemInt(hwndDlg, IDC_EDT_PID, 0, FALSE);
	PopulateHideInfo(hwndDlg, HideInfo);
	drv.SetTargetPid(HideInfo.Pid);
	BOOLEAN res = drv.CallDriver(IOCTL_ADD_HIDER_ENTRY);
	if (!res) {
		MessageBoxA(hwndDlg, "Couldn't add entry in the driver", "Wrong PID?", MB_ICONERROR);
		return;
	}
	res = drv.Hide(HideInfo);
	if (res) {
		MessageBoxA(hwndDlg, "Hidden!", "Done", MB_ICONINFORMATION);
	}
	else {
		MessageBoxA(hwndDlg, "Error...", "Unknown cause", MB_ICONERROR);
	}
	return;
}

static void CheckAll(HWND hwndDlg) {
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYOBJECT, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONPROCESS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYSYSTEMINFORMATION, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONJOBOBJECT, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONTHREAD, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETINFORMATIONTHREAD, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETINFORMATIONPROCESS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETCONTEXTTHREAD, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTGETCONTEXTTHREAD, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCLOSE, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTYIELDEXECUTION, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATETHREADEX, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEFILE, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCONTINUE, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEPROCESSEX, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEUSERPROCESS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTGETNEXTPROCESS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTOPENPROCESS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTOPENTHREAD, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSYSTEMDEBUGCONTROL, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERFINDWINDOWEX, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERBUILDHWNDLIST, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERQUERYWINDOW, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERGETFOREGROUNDWINDOW, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYSYSTEMTIME, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYPERFORMANCECOUNTER, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_KIEXCEPTIONDISPATCH, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_KIUSERSHAREDDATA, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARPEBNTGLOBALFLAG, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARHEAPFLAGS, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARKUSERSHAREDDATA, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARHIDEFROMDEBUGGERFLAG, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARBYPASSPROCESSFREEZEFLAG, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARPROCESSBREAKONTERMINATIONFLAG, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARTHREADBREAKONTERMINATIONFLAG, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_SAVEPROCESSHANDLETRACING, 1);
	CheckDlgButton(hwndDlg, IDC_CHK_SAVEPROCESSDEBUGFLAGS, 1);
}

static void UncheckAll(HWND hwndDlg) {
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYOBJECT, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONPROCESS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYSYSTEMINFORMATION, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONJOBOBJECT, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYINFORMATIONTHREAD, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETINFORMATIONTHREAD, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETINFORMATIONPROCESS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSETCONTEXTTHREAD, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTGETCONTEXTTHREAD, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCLOSE, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTYIELDEXECUTION, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATETHREADEX, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEFILE, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCONTINUE, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEPROCESSEX, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTCREATEUSERPROCESS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTGETNEXTPROCESS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTOPENPROCESS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTOPENTHREAD, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTSYSTEMDEBUGCONTROL, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERFINDWINDOWEX, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERBUILDHWNDLIST, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERQUERYWINDOW, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTUSERGETFOREGROUNDWINDOW, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYSYSTEMTIME, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_NTQUERYPERFORMANCECOUNTER, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_KIEXCEPTIONDISPATCH, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_KIUSERSHAREDDATA, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARPEBNTGLOBALFLAG, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARHEAPFLAGS, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARKUSERSHAREDDATA, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARHIDEFROMDEBUGGERFLAG, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARBYPASSPROCESSFREEZEFLAG, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARPROCESSBREAKONTERMINATIONFLAG, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_CLEARTHREADBREAKONTERMINATIONFLAG, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_SAVEPROCESSHANDLETRACING, 0);
	CheckDlgButton(hwndDlg, IDC_CHK_SAVEPROCESSDEBUGFLAGS, 0);
}

static BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
	}
	return TRUE;

	case WM_CLOSE:
	{
		EndDialog(hwndDlg, 0);
	}
	return TRUE;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BTN_HIDE:
		{
			CVHideCall(hwndDlg);
			return TRUE;
		}
		case IDC_BTN_UNHIDE:
		{
			//CVHideCall(hwndDlg); TODO fix unhide
			return TRUE;
		}

		case IDC_BTN_UNHIDEALL:
		{
			//CVHideCall(hwndDlg); TODO fix unhide
			return TRUE;
		}

		case IDC_BTN_CHECKALL:
		{
			CheckAll(hwndDlg);
			return TRUE;
		}

		case IDC_BTN_UNCHECKALL:
		{
			UncheckAll(hwndDlg);
			return TRUE;
		}
		}
	}
	return TRUE;
	}
	return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	hInst = hInstance;
	InitCommonControls();
	return (int)DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}
