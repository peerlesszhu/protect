// protect.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <Winternl.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "anti_debug.h"
#include "MD5.h"
/*
User32.dll		EnumWindows
				GetWindowThreadProcessId
	
Kernel32.dll	OpenProcess 
				ReadProcessMemory 
				WriteProcessMemory
*/

//返回真则目标API被HOOK
BOOL IsFuncHooked(LPCTSTR* ModuleNameList, LPCSTR* FunctionNameList, int count)
{
	for (int index = 0; index < count; index++)
	{
		PVOID pFunction = GetProcAddress(GetModuleHandle(ModuleNameList[index]), FunctionNameList[index]);

		if (!pFunction)return FALSE;

		DWORD OldProtect = 0;
		VirtualProtect(pFunction, 6, PAGE_EXECUTE_READWRITE, &OldProtect);

		UCHAR chas = *(UCHAR *)((ULONG)pFunction + 5);

		if (((*(UCHAR *)pFunction == 0x68) && (*(UCHAR *)((ULONG)pFunction + 5) == 0xC3)) || (*(UCHAR *)pFunction == 0xEB) || (*(UCHAR *)pFunction == 0xEA))
		{
			VirtualProtect(pFunction, 6, OldProtect, &OldProtect);
			return TRUE;
		}
		else
		{
			VirtualProtect(pFunction, 6, OldProtect, &OldProtect);
			return FALSE;
		}
	}
	return FALSE;
}

DWORD GetParentProcessID(DWORD dwProcessID)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (pe.th32ProcessID == dwProcessID) {
			CloseHandle(hSnapshot);
			return pe.th32ParentProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

//返回真则父进程匹配成功
BOOL MatchParentProcess(LPCTSTR ParentProcessName)
{
	DWORD dwPID = GetCurrentProcessId();
	DWORD dwParentProcessID = GetParentProcessID(dwPID);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (pe.th32ProcessID == dwParentProcessID && _tcsicmp(pe.szExeFile,ParentProcessName)==0 ) {	
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}
	CloseHandle(hSnapshot);
	return FALSE;	
}

//返回真则检测到目标进程名
BOOL ProcessCheck(LPCTSTR* ProcessNameList,int count)
{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (INVALID_HANDLE_VALUE == hSnapshot) {
			return NULL;
		}
		PROCESSENTRY32 pe = { sizeof(pe) };
		for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
			for (int index = 0; index < count; index++){
				if (_tcsicmp(pe.szExeFile, ProcessNameList[index]) == 0) {
					CloseHandle(hSnapshot);
					return TRUE;
				}
			}
		}
		CloseHandle(hSnapshot);
		return FALSE;
}


//{
//	DWORD dwPID = GetCurrentProcessId();
//	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
//	MODULEENTRY32 me32;
//	// Take a snapshot of all modules in the specified process.
//	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
//	if (hModuleSnap == INVALID_HANDLE_VALUE)
//	{
//		return(FALSE);
//	}
//	// Set the size of the structure before using it.
//	me32.dwSize = sizeof(MODULEENTRY32);
//
//	// Retrieve information about the first module,
//	// and exit if unsuccessful
//	if (!Module32First(hModuleSnap, &me32))
//	{
//		CloseHandle(hModuleSnap);    // Must clean up the
//									 //   snapshot object!
//		return(FALSE);
//	}
//
//	// Now walk the module list of the process,
//	// and display information about each module
//	do
//	{
//		for (int index = 0; index < count; index++)
//		{
//			if (_tcsicmp(me32.szModule, ModuleNameList[index]) == 0)
//			{
//				CloseHandle(hModuleSnap);
//				return(TRUE);
//			}
//		}
//
//	} while (Module32Next(hModuleSnap, &me32));
//
//	CloseHandle(hModuleSnap);
//	return FALSE;
//}


DWORD WINAPI DemoMain(LPVOID param)
{
	 LPCTSTR ModuleNameList[ ] = { _T("User32.dll"), _T("User32.dll"), _T("Kernel32.dll"), _T("Kernel32.dll"), _T("Kernel32.dll") };
	 LPCSTR FunctionNameList[] = { "EnumWindows", "GetWindowThreadProcessId", "OpenProcess", "ReadProcessMemory", "WriteProcessMemory" };
	 LPCSTR dat_md5 = "0274025690AE46C4E3CC32A395C29F5F";
	 char md5_buf[256] = { 0 };
	do
	{
		if (Ring3AntiDebug()) break;
		if (IsFuncHooked(ModuleNameList, FunctionNameList, 5)) break;
		if (!MatchParentProcess(_T("GameOfMir_合击登录器.exe"))) break;
		getFileMD5("Client.dat", md5_buf);
		if (stricmp(md5_buf, dat_md5)!=0) break;

		Sleep(1000);
	} while (true);
	ExitProcess(0);
	return 0;
}