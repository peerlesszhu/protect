#pragma once
#include <Windows.h>
BOOL LookUpPreocessDebuger();
BOOL CheckDebugWindows();
BOOL LookUpTEBdebuger();
BOOL checkHeapFlags();
BOOL checkForceFlags();
BOOL CheckNtGlobalFlag();
BOOL CheckSEH();

BOOL Ring3AntiDebug();