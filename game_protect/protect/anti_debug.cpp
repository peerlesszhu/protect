#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "anti_debug.h"
#pragma comment(lib,"Psapi.lib")
BOOL LookUpPreocessDebuger()
{
	BOOL ret = FALSE;
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize=sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	BOOL bMore=Process32First(hProcessSnap,&pe32);
	while (bMore)
	{
			if (!_tcsicmp(pe32.szExeFile,_T("ollyice.exe")))
			{
				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, _T("ollydbg.exe")))
			{

				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, _T("idaq.exe")))
			{

				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, _T("peid.exe")))
			{

				ret = TRUE;
				break;
			}
			bMore=Process32Next(hProcessSnap,&pe32);
	}
	CloseHandle(hProcessSnap);
	return ret;
}



BOOL CheckDebugWindows()
{
	if(FindWindow(_T("OLLYDBG"),NULL))
	{

		return TRUE;
	}
	if(FindWindow(_T("WinDbg结构分类"),NULL))
	{

		return TRUE;
	}
	return FALSE;
}


BOOL LookUpTEBdebuger()
{
	int result=0;
	__asm
	{
		mov eax,fs:[0x30]
		movzx eax,byte ptr ds:[eax+0x02]
		mov result,eax
	}
	if (result)
	{

		return TRUE;
	}
	return FALSE;
}

BOOL checkHeapFlags()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x18]
		cmp DWORD ptr [eax+0x0c],2		
		jne findDebug	
	}
	return FALSE;
findDebug:

	return TRUE;
}
BOOL checkForceFlags()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x18]
		cmp  DWORD ptr [eax+0x10],0
		jne findDebug
	}
	return FALSE;
findDebug:

	return TRUE;
}

BOOL CheckNtGlobalFlag()
{
	__asm
	{
		mov eax,fs:[0x30]
		cmp DWORD ptr [eax+0x68],0
		jne findDebug	
	}
	return FALSE;
findDebug:

	return TRUE;
}


BOOL CheckSEH()
{
	__asm
	{
			push exception_handler
			push dword ptr fs:[0]
			mov fs:[0],esp
			int 3		
		
	}

	return TRUE;
	deal:
	__asm
	{
		pop dword ptr fs:[0]
		add esp,4
	}
	return FALSE;
exception_handler:
	__asm{
		mov eax,[esp+0x0c]
		mov DWORD ptr [eax+0xb8],offset deal
		xor eax,eax                    //因为这句话又白白浪费我好几天
		retn
	}
}

BOOL Ring3AntiDebug()
{
	if (LookUpPreocessDebuger() || 
		CheckDebugWindows() || 
		LookUpTEBdebuger() || 	
		CheckNtGlobalFlag() || 
		CheckSEH())
	{
		return TRUE;
	}
	return FALSE;
}
