#pragma once
#include <Windows.h>
BOOL IsFuncHooked(LPCTSTR* ModuleNameList, LPCSTR* FunctionNameList,int count);
BOOL MatchParentProcess(LPCTSTR ParentProcessName);
DWORD GetParentProcessID(DWORD dwProcessID);
BOOL ProcessCheck(LPCTSTR* ProcessNameList,int count);
BOOL ListProcessModules(LPCTSTR* ModuleNameList, int count);

DWORD WINAPI DemoMain(LPVOID);