#pragma warning(disable : 4267 4201)

#include <ntifs.h>
#include "Utils.h"
#include "HookHelper.h"
#include "GlobalData.h"
#include "Log.h"
#include <intrin.h>

extern HYPER_HIDE_GLOBAL_DATA g_CVHide;

extern HANDLE(NTAPI* OriginalNtUserQueryWindow)(HANDLE hWnd, WINDOWINFOCLASS WindowInfo);

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo)
{
	//
	// First process is always system so there won't be a case when forbidden process is first
	//
	PSYSTEM_PROCESS_INFO PrevProcessInfo = NULL;

	while (PrevProcessInfo != ProcessInfo)
	{
		ULONG Offset = ProcessInfo->NextEntryOffset;

		if (Hider::IsProcessNameBad(&ProcessInfo->ImageName) == TRUE)
		{
			if (ProcessInfo->NextEntryOffset == NULL)
				PrevProcessInfo->NextEntryOffset = NULL;

			else
				PrevProcessInfo->NextEntryOffset += ProcessInfo->NextEntryOffset;
				
			RtlSecureZeroMemory(ProcessInfo, sizeof(SYSTEM_PROCESS_INFO) + ProcessInfo->NumberOfThreads * sizeof(SYSTEM_THREAD_INFORMATION) - sizeof(SYSTEM_THREAD_INFORMATION));
		}

		else
		{
			PrevProcessInfo = ProcessInfo;
		}

		ProcessInfo = (PSYSTEM_PROCESS_INFO)((UCHAR*)ProcessInfo + Offset);
	}
}

BOOLEAN IsWindowBad(HANDLE hWnd)
{
	PEPROCESS WindProcess = PidToProcess(OriginalNtUserQueryWindow(hWnd, WindowProcess));
	if (WindProcess == IoGetCurrentProcess())
		return FALSE;

	UNICODE_STRING WindowProcessName = PsQueryFullProcessImageName(WindProcess);

	return Hider::IsProcessNameBad(&WindowProcessName);
}

SHORT GetSyscallNumber(PVOID FunctionAddress)
{
	return *(SHORT*)((ULONG64)FunctionAddress + 4);
}

BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 22>& SyscallsToFind)
{
	UNICODE_STRING knownDlls{};
	RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\ntdll.dll)");

	OBJECT_ATTRIBUTES objAttributes{};
	InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE section{};
	if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
		return false;

	PVOID ntdllBase{};
	size_t ntdllSize{};
	LARGE_INTEGER sectionOffset{};
	if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &ntdllBase, 0, 0, &sectionOffset, &ntdllSize, ViewShare, 0, PAGE_READONLY)))
	{
		ZwClose(section);
		return false;
	}

	auto status = true;
	for (auto& syscallInfo : SyscallsToFind)
	{
		if (syscallInfo.SyscallName == "NtQuerySystemTime")
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, "NtAccessCheckByTypeAndAuditAlarm");
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress) + 1;
		}
		else
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, syscallInfo.SyscallName.data());
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress);
		}

		LogDebug("Syscall %s is equal: 0x%X", syscallInfo.SyscallName.data(), syscallInfo.SyscallNumber);
	}

	ZwClose(section);
	ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);

	return status;
}

VOID GetWin32kSyscallNumbersPreRedstone(std::array<SyscallInfo, 5>& SyscallsToFind)
{
	SyscallsToFind[0].SyscallName = "NtUserBuildHwndList";
	SyscallsToFind[1].SyscallName = "NtUserFindWindowEx";
	SyscallsToFind[2].SyscallName = "NtUserQueryWindow";
	SyscallsToFind[3].SyscallName = "NtUserGetForegroundWindow";
	SyscallsToFind[4].SyscallName = "NtUserGetThreadState";

	if (g_CVHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2 || g_CVHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		SyscallsToFind[0].SyscallNumber = 0x70;
		SyscallsToFind[1].SyscallNumber = 0x1f;
		SyscallsToFind[2].SyscallNumber = 0x13;
		SyscallsToFind[3].SyscallNumber = 0x3f;
		SyscallsToFind[4].SyscallNumber = 0x3;
	}
	else if (g_CVHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		SyscallsToFind[0].SyscallNumber = 0x6f;
		SyscallsToFind[1].SyscallNumber = 0x1e;
		SyscallsToFind[2].SyscallNumber = 0x12;
		SyscallsToFind[3].SyscallNumber = 0x3e;
		SyscallsToFind[4].SyscallNumber = 0x2;
	}
	else if (g_CVHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		SyscallsToFind[0].SyscallNumber = 0x6e;
		SyscallsToFind[1].SyscallNumber = 0x1d;
		SyscallsToFind[2].SyscallNumber = 0x11;
		SyscallsToFind[3].SyscallNumber = 0x3d;
		SyscallsToFind[4].SyscallNumber = 0x1;
	}
	else if (g_CVHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_CVHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		SyscallsToFind[0].SyscallNumber = 0x6e;
		SyscallsToFind[1].SyscallNumber = 0x1c;
		SyscallsToFind[2].SyscallNumber = 0x10;
		SyscallsToFind[3].SyscallNumber = 0x3c;
		SyscallsToFind[4].SyscallNumber = 0x0;
	}
}

BOOLEAN GetWin32kSyscallNumbers(std::array<SyscallInfo, 5>& SyscallsToFind)
{
	if (g_CVHide.CurrentWindowsBuildNumber >= WINDOWS_10_VERSION_REDSTONE1)
	{
		UNICODE_STRING knownDlls{};
		RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\win32u.dll)");

		OBJECT_ATTRIBUTES objAttributes{};
		InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		HANDLE section{};
		if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
			return false;

		PVOID win32uBase{};
		size_t win32uSize{};
		LARGE_INTEGER sectionOffset{};
		if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &win32uBase, 0, 0, &sectionOffset, &win32uSize, ViewShare, 0, PAGE_READONLY)))
		{
			ZwClose(section);
			return false;
		}

		auto status = true;
		for (auto& syscallInfo : SyscallsToFind)
		{
			const auto functionAddress = GetExportedFunctionAddress(0, win32uBase, syscallInfo.SyscallName.data());
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress) - 0x1000;
			LogDebug("Syscall %s is equal: 0x%X", syscallInfo.SyscallName.data(), syscallInfo.SyscallNumber);
		}

		ZwClose(section);
		ZwUnmapViewOfSection(ZwCurrentProcess(), win32uBase);

		return status;
	}
	else
	{
		GetWin32kSyscallNumbersPreRedstone(SyscallsToFind);
		return true;
	}
}

#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

ULONG RtlNextRandom(ULONG Min, ULONG Max) // [Min,Max)
{
	if (RandomSeed == RANDOM_SEED_INIT)  // One-time seed initialisation. It doesn't have to be good, just not the same every time
		RandomSeed = static_cast<ULONG>(__rdtsc());

	// NB: In user mode, the correct scale for RtlUniform/RtlRandom/RtlRandomEx is different on Win 10+:
	// Scale = (RtlNtMajorVersion() >= 10 ? MAXUINT32 : MAXINT32) / (Max - Min);
	// The KM versions seem to have been unaffected by this change, at least up until RS3.
	// If this ever starts returning values >= Max, try the above scale instead
	const ULONG Scale = static_cast<ULONG>(MAXINT32) / (Max - Min);
	return RtlRandomEx(&RandomSeed) / Scale + Min;
}

ULONG GetPoolTag()
{
	constexpr ULONG PoolTags[] =
	{
		' prI', // Allocated IRP packets
		'+prI', // I/O verifier allocated IRP packets
		'eliF', // File objects
		'atuM', // Mutant objects
		'sFtN', // ntfs.sys!StrucSup.c
		'ameS', // Semaphore objects
		'RwtE', // Etw KM RegEntry
		'nevE', // Event objects
		' daV', // Mm virtual address descriptors
		'sdaV', // Mm virtual address descriptors (short)
		'aCmM', // Mm control areas for mapped files
		'  oI', // I/O manager
		'tiaW', // WaitCompletion Packets
		'eSmM', // Mm secured VAD allocation
		'CPLA', // ALPC port objects
		'GwtE', // ETW GUID
		' ldM', // Memory Descriptor Lists
		'erhT', // Thread objects
		'cScC', // Cache Manager Shared Cache Map
		'KgxD', // Vista display driver support
	};

	constexpr ULONG NumPoolTags = ARRAYSIZE(PoolTags);
	const ULONG Index = RtlNextRandom(0, NumPoolTags);
	NT_ASSERT(Index <= NumPoolTags - 1);
	return PoolTags[Index];
}

void* RtlAllocateWin32Memory(bool InZeroMemory, SIZE_T InSize)
{
	void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, GetPoolTag());

	if (InZeroMemory && (Result != NULL))
		RtlZeroMemory(Result, InSize);

	// create an MDL for the allocated memory
	PMDL pMdl = IoAllocateMdl(Result, (ULONG)InSize, FALSE, FALSE, NULL);

	if (pMdl == NULL)
	{
		// failed to create the MDL, free the allocated memory and return NULL
		ExFreePool(Result);
		return NULL;
	}

	// lock the MDL in memory and map the memory into user mode address space
	MmProbeAndLockPages(pMdl, KernelMode, IoWriteAccess);
	void* pUserModeMemory = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);

	return pUserModeMemory;
}

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
	void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, GetPoolTag());
	if (InZeroMemory && (Result != NULL))
		RtlZeroMemory(Result, InSize);
	return Result;
}

void RtlFreeMemory(void* InPointer)
{
	ExFreePool(InPointer);
}

NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length)
{
	const KIRQL Irql = KeRaiseIrqlToDpcLevel();

	PMDL Mdl = IoAllocateMdl(Destination, Length, 0, 0, nullptr);
	if (Mdl == nullptr)
	{
		KeLowerIrql(Irql);
		return STATUS_NO_MEMORY;
	}

	MmBuildMdlForNonPagedPool(Mdl);

	// Hack: prevent bugcheck from Driver Verifier and possible future versions of Windows
#pragma prefast(push)
#pragma prefast(disable:__WARNING_MODIFYING_MDL, "Trust me I'm a scientist")
	const CSHORT OriginalMdlFlags = Mdl->MdlFlags;
	Mdl->MdlFlags |= MDL_PAGES_LOCKED;
	Mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

	// Map pages and do the copy
	const PVOID Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, nullptr, FALSE, HighPagePriority);
	if (Mapped == nullptr)
	{
		Mdl->MdlFlags = OriginalMdlFlags;
		IoFreeMdl(Mdl);
		KeLowerIrql(Irql);
		return STATUS_NONE_MAPPED;
	}

	RtlCopyMemory(Mapped, Source, Length);

	MmUnmapLockedPages(Mapped, Mdl);
	Mdl->MdlFlags = OriginalMdlFlags;
#pragma prefast(pop)
	IoFreeMdl(Mdl);
	KeLowerIrql(Irql);

	return STATUS_SUCCESS;
}

NTSTATUS SuperCleanMemory(PVOID Dest, BYTE Val, ULONG Length) {
	PMDL mdl = IoAllocateMdl(Dest, Length, 0, 0, 0);
	if (!mdl) return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(mdl);
	PBYTE Mapped = (PBYTE)MmMapLockedPages(mdl, KernelMode);
	if (!Mapped) {
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	memset(Mapped, Val, Length);
	KeLowerIrql(kirql);

	MmUnmapLockedPages(Mapped, mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}

#ifdef _WIN64
PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize)
{
	unsigned char* Code = (unsigned char*)CodeStart;

	for (unsigned int i = 0, j = 0; i < CodeSize; i++)
	{
		if (Code[i] == 0x90 || Code[i] == 0xCC)  //NOP or INT3
			j++;
		else
			j = 0;
		if (j == CaveSize)
			return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
	}
	return 0;
}
#endif //_WIN64

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

static ZWQUERYSYSTEMINFORMATION ZwQSI = 0;

#pragma warning(disable:4459)
#pragma warning(disable:4200)
PVOID GetKernelBase(PULONG pImageSize)
{

	if (!ZwQSI)
	{
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
		ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
		if (!ZwQSI) {
			LogError("[CVHide] Failed to find ZwQuerySystemInformation address\r\n");
			return NULL;
		}
	}

	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	NTSTATUS status = ZwQSI(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		LogError("[CVHide] ZwQuerySystemInformation (1) failed...\r\n");
		return NULL;
	}

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize * 2, GetPoolTag());

	if (!pSystemInfoBuffer)
	{
		LogError("[CVHide] ExAllocatePool failed...\r\n");
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = ZwQSI(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
		if (pImageSize)
			*pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
	}
	else
		LogError("[CVHide] ZwQuerySystemInformation (2) failed...\r\n");

	ExFreePool(pSystemInfoBuffer);

	return pModuleBase;
}
