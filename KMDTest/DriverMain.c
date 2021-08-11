#include <ntddk.h>
#include <ntimage.h>

//typedef int DWORD;
//typedef DWORD* PDWORD;
//typedef unsigned char BYTE;
//typedef BYTE* PBYTE;

typedef struct {
	PDEVICE_OBJECT pdo;
	UNICODE_STRING symLink;
} DeviceExtension, *PDeviceExtension;

//typedef struct _SYSTEM_SERVICE_TABLE {
//	PDWORD ServiceTable;
//	PDWORD CounterTable;
//	ULONG ServiceLimit;
//	PBYTE ArgumentTable;
//} SYSTEM_SERVICE_TABLE,
//*PSYSTEM_SERVICE_TABLE,
//**PPSYSTEM_SERVICE_TABLE;
//
//typedef struct _SERVICE_DESCRIPTOR_TABLE {
//	SYSTEM_SERVICE_TABLE ntoskrnl;  // SST для ntoskrnl.exe
//	SYSTEM_SERVICE_TABLE win32k;    // SST для win32k.sys
//	SYSTEM_SERVICE_TABLE table3;    // не используется
//	SYSTEM_SERVICE_TABLE table4;    // не используется
//} SERVICE_DESCRIPTOR_TABLE,
//*PSERVICE_DESCRIPTOR_TABLE,
//**PPSERVICE_DESCRIPTOR_TABLE;
//
//extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD unload;

void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

//VOID unload(_In_ PDRIVER_OBJECT DO);

NTSTATUS NTAPI DriverEntry(IN PDRIVER_OBJECT driverObject, IN PUNICODE_STRING RegPath) {
	NTSTATUS nts = STATUS_SUCCESS;
	PDEVICE_OBJECT pdo;
	PDeviceExtension pde;
	UNICODE_STRING devName;
	UNICODE_STRING symLink;

	DbgPrint(">>MDR: Hello");
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
	
	RtlInitUnicodeString(&symLink, L"\\Global??\\MDR");
	
	nts = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(nts)) {
		IoDeleteDevice(pdo);
#if DBG
		DbgPrint(">>MDR: IoCreateSymbolicLink error");
#endif // DBG
		return nts;
	}
	pde->symLink = symLink;

	nts = PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	if (!NT_SUCCESS(nts)) {
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(pdo);
#if DBG
		DbgPrint(">>MDR: PsSetLoadImageNotifyRoutine error");
#endif // DBG
		return nts;
	}

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

	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
}

void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	IMAGE_DOS_HEADER* idh = NULL;
	IMAGE_NT_HEADERS32* nt32 = NULL;
	//IMAGE_NT_HEADERS64* nt64 = NULL;
	IMAGE_EXPORT_DIRECTORY* IED = NULL;
	char* cb = NULL;
	int* ib = NULL;
	int t;
	SIZE_T imageLength;
	//PUNICODE_STRING str;
	//PIMAGE_INFO_EX ex_image;

	if (ProcessId == NULL) {
		return;
	}

	if (FullImageName == NULL) {
		return;
	}

	if (ImageInfo == NULL) {
		return;
	}

#if DBG
	DbgPrint(">>MDR: watch %ws", FullImageName->Buffer);
#endif // DBG

	idh = (IMAGE_DOS_HEADER*)ImageInfo->ImageBase;
	imageLength = ImageInfo->ImageSize;
	
	if (ImageInfo->ExtendedInfoPresent) {
	
	}
	
	nt32 = (IMAGE_NT_HEADERS32*)(idh->e_lfanew + (LONG)ImageInfo->ImageBase);

	if (nt32 == NULL) {
#if DBG
		DbgPrint(">>MDR: e_lfanew == NULL!");
#endif // DBG
		return;
	}
	
	if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		//nt64 = (IMAGE_NT_HEADERS64*)idh->e_lfanew;
		nt32 = NULL;
	}
	
	if (nt32 != NULL) {
		IED = (IMAGE_EXPORT_DIRECTORY*)nt32->OptionalHeader.DataDirectory[0].VirtualAddress;
		if (IED == NULL) {
#if DBG
			DbgPrint(">>MDR: no export func");
#endif // DBG
			return;
		}
		IED = (IMAGE_EXPORT_DIRECTORY*)((LONG)IED + (LONG)idh);
	}
	//else if (nt64 != NULL) {
	//	IED = (IMAGE_EXPORT_DIRECTORY*)nt64->OptionalHeader.DataDirectory[0].VirtualAddress;
	//}
	else {
		DbgPrint(">>MDR: load image error");
		return;
	}

	ib = (int*)(IED->AddressOfNames + (LONG)idh);
	for (t = 0; t < (int)IED->NumberOfNames; t++) {
		cb = (char*)((LONG)ib[t] + (LONG)idh);
		DbgPrint(">>MDR: №%d export func name from %ws: %s", t, FullImageName->Buffer, cb);
	}
	//DbgPrint(">>MDR: 1st export func name from %ws: %s", FullImageName->Buffer, cb);

}
