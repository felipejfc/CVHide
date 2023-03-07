#pragma warning( disable : 4201)
#include <ntifs.h>
#include "Utils.h"
#include "Log.h"
#include "GlobalData.h"
#include "Ntapi.h"
#include "HookHelper.h"
#include "ssdt.h"
#include "KeHook.h"

typedef struct _SSDT
{
	LONG* ServiceTable;
	PVOID CounterTable;
	ULONG64 SyscallsNumber;
	PVOID ArgumentTable;
}_SSDT, *_PSSDT;

_PSSDT NtTable;
_PSSDT Win32kTable;
_KeHook KeHook;

ULONG64 Win32kCodeCaves[200] = { 0 };

extern HYPER_HIDE_GLOBAL_DATA g_CVHide;

namespace SSDT 
{
	ULONG64 KernelCodeCaves[200] = { 0 };
	UCHAR KernelAlignIndex = 0;
	UCHAR Win32kAlignIndex = 0;
	BOOLEAN GetSsdt()
	{
		PVOID KernelTextSectionBase = 0;
		ULONG64 KernelTextSectionSize = 0;

		if (GetSectionData("ntoskrnl.exe", ".text", KernelTextSectionSize, KernelTextSectionBase) == FALSE)
			return FALSE;

		CONST CHAR* Pattern = "\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\xF7";
		CONST CHAR* Mask = "xxx????xxx????x";

		ULONG64 KeServiceDescriptorTableShadowAddress = (ULONG64)FindSignature(KernelTextSectionBase, KernelTextSectionSize, Pattern, Mask);
		if (KeServiceDescriptorTableShadowAddress == NULL)
			return FALSE;

		NtTable = (_PSSDT)((*(ULONG*)(KeServiceDescriptorTableShadowAddress + 10)) + KeServiceDescriptorTableShadowAddress + 14);
		Win32kTable = NtTable + 1;

		LogInfo("Found SSDT at 0x%X", NtTable->ServiceTable);
		LogInfo("Found Win32kTable at 0x%X", Win32kTable->ServiceTable);

		return TRUE;
	}

	PVOID GetWin32KFunctionAddress(CONST CHAR* SyscallName, SHORT SyscallIndex)
	{
		KAPC_STATE State;
		PVOID AddressOfTargetFunction = 0;

		PEPROCESS CsrssProcess = GetCsrssProcess();
		KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

		if (g_CVHide.CurrentWindowsBuildNumber > WINDOWS_8_1)
		{
			ULONG64 ImageSize;
			PVOID ImageBaseAddress = 0;

			if (GetProcessInfo("win32kfull.sys", ImageSize, ImageBaseAddress) == TRUE) {}
				AddressOfTargetFunction = GetExportedFunctionAddress(NULL, ImageBaseAddress, SyscallName);
		}
		else
		{
			AddressOfTargetFunction = (PVOID)((ULONG64)Win32kTable->ServiceTable + (Win32kTable->ServiceTable[SyscallIndex] >> 4));
		}

		KeUnstackDetachProcess(&State);

		return AddressOfTargetFunction;
	}

	BOOLEAN HookWin32kSyscall(CONST CHAR* SyscallName, SHORT SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction)
	{
		KAPC_STATE State;

		PEPROCESS CsrssProcess = GetCsrssProcess();
		KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

		PVOID AddressOfTargetFunction = GetWin32KFunctionAddress(SyscallName, SyscallIndex);
		if (!AddressOfTargetFunction) {
			LogError("Coudln't find address of function %s", SyscallName);
			return false;
		}

		// TODO Add x86 support
		*OriginFunction = KeHook.Create((PCHAR)SyscallName, AddressOfTargetFunction, NewFunctionAddress);

		LogDebug("%s Original 0x%llX NewFunctionAddr 0x%llX OriginFunc 0x%llX", SyscallName, AddressOfTargetFunction, NewFunctionAddress, *OriginFunction);

		KeUnstackDetachProcess(&State);
		return true;
	}

	BOOLEAN UnhookWin32kSyscall(CONST CHAR* SyscallName)
	{

		KAPC_STATE State;
		PEPROCESS CsrssProcess = GetCsrssProcess();
		KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

		KeHook.Remove((PCHAR) SyscallName);

		KeUnstackDetachProcess(&State);
		return true;
	}

	// You can get SyscallIndex on https://j00ru.vexillium.org/syscalls/nt/64/ for 64 bit system nt syscalls
	// And https://j00ru.vexillium.org/syscalls/win32k/64/ for 64 bit system win32k syscalls
	BOOLEAN HookNtSyscall(ULONG SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunc, PHOOK &hook)
	{
		if (SyscallIndex > NtTable->SyscallsNumber)
		{
			LogError("There is no such syscall");
			return FALSE;
		}

		PVOID AddressOfTargetFunction = (PVOID)((ULONG64)NtTable->ServiceTable + (NtTable->ServiceTable[SyscallIndex] >> 4));
		PVOID CodeCave = (PVOID)KernelCodeCaves[KernelAlignIndex++];

		hook = (PHOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));
		hook->addr = (ULONG_PTR)CodeCave;
#ifdef _WIN64
		hook->hook.mov = 0xB848;
#else
		hook->hook.mov = 0xB8;
#endif
		hook->hook.addr = (ULONG_PTR)NewFunctionAddress;
		hook->hook.push = 0x50;
		hook->hook.ret = 0xc3;
		hook->SSDTold = NtTable->ServiceTable[SyscallIndex];
		hook->SSDTindex = SyscallIndex;
		
		RtlCopyMemory(&hook->orig, CodeCave, sizeof(HOOKOPCODES));
		if (!NT_SUCCESS(RtlSuperCopyMemory(CodeCave, &hook->hook, sizeof(HOOKOPCODES))))
		{
			RtlFreeMemory(hook);
			return FALSE;
		}

		LONG newValue = (LONG)((ULONG_PTR)CodeCave - (ULONG_PTR)NtTable->ServiceTable);
		newValue = (newValue << 4) | NtTable->ServiceTable[SyscallIndex] & 0xF;
		hook->SSDTnew = newValue;

		*OriginFunc = AddressOfTargetFunction;
		
		if (!NT_SUCCESS(RtlSuperCopyMemory(&NtTable->ServiceTable[SyscallIndex], &newValue, sizeof(newValue)))) {
			RtlFreeMemory(hook);
			return FALSE;
		}

		return TRUE;
	}

	BOOLEAN UnhookNtSyscall(PHOOK &hook)
	{
		RtlSuperCopyMemory(&NtTable->ServiceTable[hook->SSDTindex], &hook->SSDTold, sizeof(hook->SSDTold));
		if (NT_SUCCESS(RtlSuperCopyMemory((PVOID)hook->addr, hook->orig, sizeof(HOOKOPCODES))))
		{
			RtlFreeMemory(hook);
			return true;
		}
		return false;
	}

	BOOLEAN FindCodeCaves()
	{
		KAPC_STATE State;
		ULONG64 KernelTextSectionSize;
		PVOID KernelTextSectionBase;
		PVOID Win32kBaseTextSectionBase;
		ULONG64 Win32kTextSectionSize;

		if (GetSectionData("ntoskrnl.exe", ".text", KernelTextSectionSize, KernelTextSectionBase) == FALSE || !KernelTextSectionSize || !KernelTextSectionBase)
		{
			LogError("Couldn't get ntoskrnl .text section data");
			return FALSE;
		}

		PEPROCESS CsrssProcess = GetCsrssProcess();
		KeStackAttachProcess((PRKPROCESS)CsrssProcess, &State);

		if (g_CVHide.CurrentWindowsBuildNumber > WINDOWS_8_1)
		{
			if (GetSectionData("win32kfull.sys", ".text", Win32kTextSectionSize, Win32kBaseTextSectionBase) == FALSE)
			{
				LogError("Couldn't get win32k .text section data");
				return FALSE;
			}
		}

		else
		{
			if (GetSectionData("win32k.sys", ".text", Win32kTextSectionSize, Win32kBaseTextSectionBase) == FALSE)
			{
				LogError("Couldn't get win32k .text section data");
				return FALSE;
			}
		}

		ULONG64 Win32kCodeCaveIndex = 0;
		ULONG64 Win32kCodeCaveSize = 0;

		for (ULONG64 MemoryLocation = (ULONG64)Win32kBaseTextSectionBase; MemoryLocation < Win32kTextSectionSize + (ULONG64)Win32kBaseTextSectionBase, Win32kCodeCaveIndex < 200; MemoryLocation++)
		{
			*(UCHAR*)MemoryLocation == 0xCC || *(UCHAR*)MemoryLocation == 0x90 ? Win32kCodeCaveSize++ : Win32kCodeCaveSize = 0;

			if (Win32kCodeCaveSize == 15)
			{
				// Ignore if at page boundary
				if (PAGE_ALIGN(MemoryLocation) != PAGE_ALIGN(MemoryLocation - 13))
					continue;

				Win32kCodeCaves[Win32kCodeCaveIndex] = MemoryLocation - 13;
				Win32kCodeCaveIndex++;
			}
		}

		KeUnstackDetachProcess(&State);

		ULONG64 KernelCodeCaveIndex = 0;
		ULONG64 KernelCodeCaveSize = 0;

		for (ULONG64 MemoryLocation = (ULONG64)KernelTextSectionBase; MemoryLocation < KernelTextSectionSize + (ULONG64)KernelTextSectionBase, KernelCodeCaveIndex < 200; MemoryLocation++)
		{
			*(UCHAR*)MemoryLocation == 0xCC || *(UCHAR*)MemoryLocation == 0x90 ? KernelCodeCaveSize++ : KernelCodeCaveSize = 0;

			if (KernelCodeCaveSize == 15)
			{
				// Ignore if at page boundary
				if (PAGE_ALIGN(MemoryLocation) != PAGE_ALIGN(MemoryLocation - 13))
					continue;

				KernelCodeCaves[KernelCodeCaveIndex] = MemoryLocation - 13;
				KernelCodeCaveIndex++;
			}
		}

		return TRUE;
	}
}