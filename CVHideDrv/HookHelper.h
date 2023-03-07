#pragma once
#include <ntifs.h>
#include <array>
#include <string>
#include "Ntstructs.h"

#pragma pack(push,1)
struct HOOKOPCODES
{
#ifdef _WIN64
    unsigned short int mov;
#else
    unsigned char mov;
#endif
    ULONG_PTR addr;
    unsigned char push;
    unsigned char ret;
};
#pragma pack(pop)

typedef struct HOOKSTRUCT
{
    ULONG_PTR addr;
    HOOKOPCODES hook;
    unsigned char orig[sizeof(HOOKOPCODES)];
    //SSDT extension
    ULONG SSDTindex;
    LONG SSDTold;
    LONG SSDTnew;
}HOOK, *PHOOK;

struct SyscallInfo
{
	SHORT SyscallNumber;
	std::string_view SyscallName;
	PVOID HookFunctionAddress;
	PVOID* OriginalFunctionAddress;
    PHOOK* Hook;
};

BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 22>& SyscallsToFind);

BOOLEAN GetWin32kSyscallNumbers(std::array<SyscallInfo, 5>& SyscallsToFind);

BOOLEAN IsWindowBad(HANDLE hWnd);

VOID FilterProcesses(PSYSTEM_PROCESS_INFO ProcessInfo);

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize);
void* RtlAllocateWin32Memory(bool InZeroMemory, SIZE_T InSize);
void RtlFreeMemory(void* InPointer);
NTSTATUS SuperCleanMemory(PVOID Dest, BYTE Val, ULONG Length);
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length);
PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize);
PVOID GetKernelBase(PULONG pImageSize = NULL);
