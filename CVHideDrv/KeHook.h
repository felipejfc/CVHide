#pragma once
#pragma once
#include "Utils.h"

class _KeHook {
public:
	PVOID Create(PCHAR _Name, PVOID _NTFunction, PVOID _Function);
	VOID  Remove(PCHAR _Name);
	VOID  RemoveAll();
	typedef struct _KeEntry {
		PVOID Trampoline;
		PVOID NTFunction;
		PVOID Function;
		ULONG Size;
		PCHAR Name;
	} KeEntry, * PKeEntry;

private:
	ULONG  HookCount = 0;

	BOOL IsFunctionHooked(PVOID _NTFunction);
	ULONG FindHookLength(PVOID _NTFunction, ULONG _ShellCodeLength);
};
