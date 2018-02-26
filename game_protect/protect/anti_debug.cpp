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
	BYTE ollyice[]= { 0x6F,0x00,0x6C,0x00,0x6C,0x00,0x79,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x2E,0x00,0x65,0x00,0x78,0x00,0x65,0,0 };
	BYTE ollydbg[]	= { 0x6F,0x00,0x6C,0x00,0x6C,0x00,0x79,0x00,0x64,0x00,0x62,0x00,0x67,0x00,0x2E,0x00,0x65,0x00,0x78,0x00,0x65,0,0 };
	BYTE idaq[]= { 0x69,0x00,0x64,0x00,0x61,0x00,0x71,0x00,0x2E,0x00,0x65,0x00,0x78,0x00,0x65,0,0 };
	BYTE peid[] = { 0x70,0x00,0x65,0x00,0x69,0x00,0x64,0x00,0x2E,0x00,0x65,0x00,0x78,0x00,0x65,0,0 };
	while (bMore)
	{
			if (!_tcsicmp(pe32.szExeFile, (LPCTSTR)ollyice))
			{
				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, (LPCTSTR)"ollydbg.exe"))
			{

				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, (LPCTSTR)"idaq.exe"))
			{

				ret = TRUE;
				break;
			}
			if (!_tcsicmp(pe32.szExeFile, (LPCTSTR)"peid.exe"))
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
	BYTE ollydbg[ ]= { 0x4F,0x00,0x4C,0x00,0x4C,0x00,0x59,0x00,0x44,0x00,0x42,0x00,0x47,0,0 };
	BYTE windbg[ ]= { 0x57,0x00,0x69,0x00,0x6E,0x00,0x44,0x00,0x62,0x00,0x67,0x00,0xD3,0x7E,0x84,0x67,0x06,0x52,0x7B,0x7C,0,0 };
	if(FindWindow((LPCTSTR)ollydbg,NULL))
	{
		return TRUE;
	}
	if(FindWindow((LPCTSTR)windbg,NULL))
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
