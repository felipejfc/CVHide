#pragma warning( disable : 4201)
#include <ntifs.h>
#include "Ioctl.h"
#include "Hider.h"
#include "Utils.h"
#include "GlobalData.h"
#include "Peb.h"

extern HYPER_HIDE_GLOBAL_DATA g_CVHide;

NTSTATUS DrvIOCTLDispatcher(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;

	switch (Stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_ADD_HIDER_ENTRY:
		{
			ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
			if (Hider::CreateEntry(IoGetCurrentProcess(), PidToProcess(*Pid)) == FALSE)
				Status = STATUS_UNSUCCESSFUL;
			else
				g_CVHide.NumberOfActiveDebuggers++;
			break;
		}

		case IOCTL_REMOVE_HIDER_ENTRY:
		{
			ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
			if (Hider::RemoveEntry(PidToProcess(*Pid)) == FALSE)
				Status = STATUS_UNSUCCESSFUL;
			else
				g_CVHide.NumberOfActiveDebuggers--;
			break;
		}

		case IOCTL_HIDE_FROM_SYSCALL:
		{
			PHIDE_INFO HideInfo = (PHIDE_INFO)Irp->AssociatedIrp.SystemBuffer;

			if (Hider::Hide(HideInfo) == FALSE)
				Status = STATUS_UNSUCCESSFUL;
			break;
		}

		case IOCTL_CLEAR_PEB_DEBUGGER_FLAG:
		{
			ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

			if (SetPebDeuggerFlag(PidToProcess(*Pid),FALSE) == FALSE)
				Status = STATUS_UNSUCCESSFUL;
			break;
		}

		case IOCTL_SET_PEB_DEBUGGER_FLAG:
		{
			ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

			if (SetPebDeuggerFlag(PidToProcess(*Pid), TRUE) == FALSE)
				Status = STATUS_UNSUCCESSFUL;
			break;
		}

	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}