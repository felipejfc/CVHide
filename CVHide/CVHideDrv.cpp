#include <Windows.h>
#include "CVHideDrv.h"
#include "Ioctl.h"

CVHideDrv::CVHideDrv()
{
}

CVHideDrv::~CVHideDrv() 
{
    SetHyperVisorVisibility(TRUE);
	if (this->DriverHandle != 0 && this->DriverHandle != INVALID_HANDLE_VALUE)
		CloseHandle(this->DriverHandle);
}

BOOLEAN CVHideDrv::CreateHandleToDriver() 
{
	this->DriverHandle = CreateFileA("\\\\.\\CVHideDrv", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (this->DriverHandle == INVALID_HANDLE_VALUE)
		return FALSE;
	return TRUE;
}

BOOLEAN CVHideDrv::CallDriver(size_t Ioctl)
{
    if (this->Pid == 0)
        return FALSE;

    DWORD BytesReturned = 0;
    return DeviceIoControl
    (
        this->DriverHandle,
        Ioctl,
        &Pid, sizeof(UINT32),
        0, 0,
        &BytesReturned, NULL
    );
}

void CVHideDrv::SetHyperVisorVisibility(BOOLEAN Value)
{
    DWORD BytesReturned = 0;
    DeviceIoControl
    (
        this->DriverHandle,
        IOCTL_SET_HYPERVISOR_VISIBILITY,
        &Value, sizeof(BOOLEAN),
        0, 0,
        &BytesReturned, NULL
    );
}

BOOLEAN CVHideDrv::Hide(HIDE_INFO& HideInfo)
{
    if (this->Pid == NULL)
        return FALSE;

    DWORD BytesReturned = 0;
    HideInfo.Pid = Pid;

    return DeviceIoControl
    (
        this->DriverHandle,
        IOCTL_HIDE_FROM_SYSCALL,
        &HideInfo, sizeof(HIDE_INFO),
        0, 0,
        &BytesReturned, NULL
    );
}

HANDLE CVHideDrv::GetDriverHandleValue() 
{
    return this->DriverHandle;
}

void CVHideDrv::SetTargetPid(UINT32 Pid)
{
    this->Pid = Pid;
}