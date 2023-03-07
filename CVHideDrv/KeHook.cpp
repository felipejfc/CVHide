#include "KeHook.h"
#include "HookHelper.h"
#include "Log.h"

_KeHook::KeEntry Hooks[100];

PVOID _KeHook::Create(PCHAR _Name, PVOID _NTFunction, PVOID _Function) {
	BYTE ShellCode[] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // JMP + RIP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Absolute Address
	};

	// Check if NT Function is hooked.
	if (IsFunctionHooked(_NTFunction)) {
		LogInfo("[KeHook] [%s] Function Already Hooked", _Name);
		return 0;
	}

	// Find length needed on NTFunction
	ULONG HookLength = FindHookLength(_NTFunction, sizeof(ShellCode));

	// Create Trampoline
	PVOID Trampoline = (PVOID)RtlAllocateMemory(true, HookLength + sizeof(ShellCode));
	if (!Trampoline) {
		LogInfo("[KeHook] [%s] Failed Allocating Trampoline", _Name);
		return 0;
	}

	// Copy NT Bytes On Trampoline
	if (!NT_SUCCESS(RtlSuperCopyMemory(Trampoline, _NTFunction, HookLength))) {
		LogInfo("[KeHook] [%s] Failed Copying NT Bytes", _Name);
		RtlFreeMemory(Trampoline);
		return 0;
	}

	// Write JMP On Trampoline
	*(ULONG_PTR*)&ShellCode[6] = (ULONG64)_NTFunction + HookLength;
	if (!NT_SUCCESS(RtlSuperCopyMemory((PVOID)((ULONG64)Trampoline + HookLength), &ShellCode[0], sizeof(ShellCode)))) {
		LogInfo("[KeHook] [%s] Failed Writing JMP On Trampoline", _Name);
		RtlFreeMemory(Trampoline);
		return 0;
	}

	// Write JMP On NTFunction
	*(ULONG_PTR*)&ShellCode[6] = (ULONG64)_Function;
	if (!NT_SUCCESS(RtlSuperCopyMemory(_NTFunction, &ShellCode[0], sizeof(ShellCode)))) {
		LogInfo("[KeHook] [%s] Failed Writing JMP On NTFunction", _Name);
		RtlFreeMemory(Trampoline);
		return 0;
	}

	// NOP Left Over Bytes On NTFunction [Not Critical]
	if (sizeof(ShellCode) > HookLength) {
		if (!NT_SUCCESS(SuperCleanMemory((PVOID)((ULONG_PTR)_NTFunction + sizeof(ShellCode)), 0x90, HookLength - sizeof(ShellCode)))) {
			LogInfo("[KeHook] [%s] Failed NOP Left Over Bytes On NTFunction", _Name);
		}
	}

	// Log
	LogInfo("[KeHook] [%s] Hook Placed", _Name);

	KeEntry Entry;
	Entry.Name = _Name;
	Entry.Trampoline = Trampoline;
	Entry.NTFunction = _NTFunction;
	Entry.Function = _Function;
	Entry.Size = HookLength;
	Hooks[HookCount++] = Entry;

	return Trampoline;
}

VOID _KeHook::Remove(PCHAR _Name) {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name || strcmp(_Name, Hooks[i].Name) != 0)
			continue;

		// Copy NT BytesFrom Trampoline Onto NTFunction
		if (!NT_SUCCESS(RtlSuperCopyMemory(Hooks[i].NTFunction, Hooks[i].Trampoline, Hooks[i].Size))) {
			LogInfo("[KeHook] [%ws] Failed Restoring NT Bytes", Hooks[i].Name);
			break;
		}

		// Release Trampoline
		RtlFreeMemory(Hooks[i].Trampoline);

		// Log
		LogInfo("[KeHook] [%s] Removed Hook", Hooks[i].Name);

		// Clean
		RtlSecureZeroMemory(&Hooks[i], sizeof(KeEntry));

		break;
	}
}

VOID _KeHook::RemoveAll() {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name)
			continue;

		Remove(Hooks[i].Name);
	}
}

BOOL _KeHook::IsFunctionHooked(PVOID _NTFunction) {
	for (SIZE_T i = 0; i < HookCount; i++) {
		if (!Hooks[i].Name || Hooks[i].NTFunction != _NTFunction) continue;
		return TRUE;
		break;
	}
	return FALSE;
}

ULONG _KeHook::FindHookLength(PVOID _NTFunction, ULONG _ShellCodeLength) {
	ULONG Length = _ShellCodeLength;
	while (true) {
		if (*(BYTE*)((ULONG_PTR)_NTFunction + Length) == 0x45) break; // MOV
		if (*(BYTE*)((ULONG_PTR)_NTFunction + Length) == 0x48) break; // MOV
		if (*(BYTE*)((ULONG_PTR)_NTFunction + Length) == 0x4C) break; // MOV
		if (*(BYTE*)((ULONG_PTR)_NTFunction + Length) == 0xC3) break; // RTRN
		Length++;
	};
	return Length;
}

