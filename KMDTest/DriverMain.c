#include <ntddk.h>

typedef struct {
	PDEVICE_OBJECT pdo;
	UNICODE_STRING symLink;
} DeviceExtension, *PDeviceExtension;

VOID unload(_In_ PDRIVER_OBJECT DO);

NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING RegPath);

NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING RegPath) {
	NTSTATUS nts;
	PDEVICE_OBJECT pdo;
	PDeviceExtension pde;
	UNICODE_STRING devName;
	UNICODE_STRING symLink;

#if DBG
	DbgPrint(">>MDR: DriverEntry");
	DbgPrint(">>MDR: RegPath: %ws", RegPath->Buffer);
#endif

	RtlInitUnicodeString(&devName, L"\\Device\\MDR");

	driverObject->DriverUnload = unload;
	driverObject->MajorFunction[IRP_MJ_CREATE] = NULL;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = NULL;
	driverObject->MajorFunction[IRP_MJ_READ] = NULL;
	driverObject->MajorFunction[IRP_MJ_WRITE] = NULL;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NULL;

	nts = IoCreateDevice(driverObject, sizeof(DeviceExtension), &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pdo);

	if (!NT_SUCCESS(nts)) {
		return nts;
	}

	pde = (PDeviceExtension)pdo->DeviceExtension;
	pde->pdo = pdo;

	RtlInitUnicodeString(&symLink, L"\\DosDevices\\MDR");

	nts = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(nts)) {
		IoDeleteDevice(pdo);
		return nts;
	}
	pde->symLink = symLink;

	return nts;
}

VOID unload(PDRIVER_OBJECT DO)
{
	PDEVICE_OBJECT pdo;
	UNICODE_STRING* ustr;
	PDeviceExtension pde;
	int t;

#if DBG
	DbgPrint(">>MDR: DriverUnload");
#endif // DBG

	pdo = DO->DeviceObject;

	for (t = 0; pdo != NULL; t++) {
		pde = (PDeviceExtension)pdo->DeviceExtension;
		ustr = &(pde->symLink);

		pdo = pdo->NextDevice;
#if DBG
		DbgPrint(">>MDR: Deleted Device (%d): pointer to PDO = %X.", t, pde->pdo);
		DbgPrint(">>MDR: Deleted symlink = %ws.", ustr->Buffer);
#endif // DBG

		IoDeleteSymbolicLink(ustr);
		IoDeleteDevice(pde->pdo);

	}

	return;
}
