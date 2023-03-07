#pragma once
#include <ntifs.h>
#include "HookHelper.h"

namespace SSDT 
{
	BOOLEAN FindCodeCaves();

	BOOLEAN HookWin32kSyscall(CONST CHAR* SyscallName, SHORT SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction);

	BOOLEAN UnhookNtSyscall(PHOOK &hook);
	BOOLEAN UnhookWin32kSyscall(CONST CHAR* SyscallName);

	BOOLEAN HookNtSyscall(ULONG SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunc, PHOOK &hook);

	BOOLEAN GetSsdt();

	PVOID GetWin32KFunctionAddress(CONST CHAR* SyscallName, SHORT SyscallIndex);

	extern ULONG64 KernelCodeCaves[200];
	extern UCHAR KernelAlignIndex;
}