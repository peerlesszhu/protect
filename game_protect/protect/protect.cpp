// protect.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <Winternl.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <WinNT.h>
#include "anti_debug.h"
#include "MD5.h"
#include "CRC32.h"
#include "protect.h"
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

		//DWORD OldProtect = 0;
		//VirtualProtect(pFunction, 6, PAGE_EXECUTE_READWRITE, &OldProtect);

		UCHAR chas = *(UCHAR *)((ULONG)pFunction + 5);

		if (((*(UCHAR *)pFunction == 0x68) && (*(UCHAR *)((ULONG)pFunction + 5) == 0xC3)) || (*(UCHAR *)pFunction == 0xEB) || (*(UCHAR *)pFunction == 0xEA))
		{
			//VirtualProtect(pFunction, 6, OldProtect, &OldProtect);
			return TRUE;
		}
		else
		{
			//VirtualProtect(pFunction, 6, OldProtect, &OldProtect);
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
BOOL ListProcessModules(LPCTSTR * ModuleNameList, int count)
{
	return 0;
}
//返回真表示Client.dat代码段被修改
BOOL CheckCodeCRC()
{
	HANDLE hProcessBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hProcessBase;;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hProcessBase + pDosHeader->e_lfanew);
	DWORD dwCodeBase = pNtHeader->OptionalHeader.BaseOfCode;
	DWORD dwCodeSize = pNtHeader->OptionalHeader.SizeOfCode;
	PUCHAR pCodeAddr = (PUCHAR)((DWORD)hProcessBase + dwCodeBase);
	unsigned int crc = 0xffffffff;
	unsigned int retCRC = crc32(crc, pCodeAddr, dwCodeSize);
	if (retCRC != 2427338296 && retCRC !=1701433134 )
	{
		return TRUE;
	}
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
	 BYTE user32[ ] = { 0x55,0x00,0x73,0x00,0x65,0x00,0x72,0x00,0x33,0x00,0x32,0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C,0,0 };
	 BYTE kernel32[ ] = { 0x4B,0x00,0x65,0x00,0x72,0x00,0x6E,0x00,0x65,0x00,0x6C,0x00,0x33,0x00,0x32,0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C,0,0 };
	 BYTE enumwindows[ ] = { 0x45,0x6E,0x75,0x6D,0x57,0x69,0x6E,0x64,0x6F,0x77,0x73,0 };
	 BYTE getwindowthreadprocessid [ ] = { 0x47,0x65,0x74,0x57,0x69,0x6E,0x64,0x6F,0x77,0x54,0x68,0x72,0x65,0x61,0x64,0x50,0x72,0x6F,0x63,0x65,0x73,0x73,0x49,0x64,0 };
	 BYTE openprocess[ ] = { 0x4F,0x70,0x65,0x6E,0x50,0x72,0x6F,0x63,0x65,0x73,0x73,0 };
	 BYTE readprocessmemory[ ] = { 0x52,0x65,0x61,0x64,0x50,0x72,0x6F,0x63,0x65,0x73,0x73,0x4D,0x65,0x6D,0x6F,0x72,0x79,0 };
	 BYTE writeprocessmemory[ ] = { 0x57,0x72,0x69,0x74,0x65,0x50,0x72,0x6F,0x63,0x65,0x73,0x73,0x4D,0x65,0x6D,0x6F,0x72,0x79,0 };
	 LPCTSTR ModuleNameList[ ] = { (LPCTSTR)user32, (LPCTSTR)user32 ,(LPCTSTR)kernel32,(LPCTSTR)kernel32,(LPCTSTR)kernel32 };
	 LPCSTR FunctionNameList[] = { (LPCSTR)enumwindows, (LPCSTR)getwindowthreadprocessid, (LPCSTR)openprocess, (LPCSTR)readprocessmemory, (LPCSTR)writeprocessmemory };
	 const char dat_md5[ ] = { 0x30,0x32,0x37,0x34,0x30,0x32,0x35,0x36,0x39,0x30,0x41,0x45,0x34,0x36,0x43,0x34,0x45,0x33,0x43,0x43,0x33,0x32,0x41,0x33,0x39,0x35,0x43,0x32,0x39,0x46,0x35,0x46,0 };
	 BYTE gamename[ ] = { 0x47,0x00,0x61,0x00,0x6D,0x00,0x65,0x00,0x4F,0x00,0x66,0x00,0x4D,0x00,0x69,0x00,0x72,0x00,0x5F,0x00,0x08,0x54,0xFB,0x51,0x7B,0x76,0x55,0x5F,0x68,0x56,0x2E,0x00,0x65,0x00,0x78,0x00,0x65,0,0 };
	 BYTE datname[ ] = { 0x43,0x6C,0x69,0x65,0x6E,0x74,0x2E,0x64,0x61,0x74,0 };
	 char md5_buf[256] = { 0 };
	 init_crc_table();
	 BYTE exitprocess[ ] = { 0x45,0x78,0x69,0x74,0x50,0x72,0x6F,0x63,0x65,0x73,0x73,0 };
	EXITPROCESS lpExitProcess = (EXITPROCESS)GetProcAddress(LoadLibrary((LPCTSTR)kernel32), (LPCSTR)exitprocess);
	do
	{
		if (Ring3AntiDebug()) break;
		if (IsFuncHooked(ModuleNameList, FunctionNameList, 5)) break;
		if (!MatchParentProcess((LPCTSTR)gamename)) break;
		getFileMD5((LPCSTR)datname, md5_buf);
		if (stricmp(md5_buf, dat_md5)!=0) break;
		if (CheckCodeCRC()) break;
		Sleep(1000);
	} while (true);
	lpExitProcess(0);
	
	return 0;
}