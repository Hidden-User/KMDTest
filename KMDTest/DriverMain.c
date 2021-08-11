#include <ntddk.h>
#include <ntimage.h>

typedef int DWORD;
typedef DWORD* PDWORD;
typedef unsigned char BYTE;
typedef BYTE* PBYTE;

typedef struct {
	PDEVICE_OBJECT pdo;
	UNICODE_STRING symLink;
} DeviceExtension, *PDeviceExtension;

typedef struct _SYSTEM_SERVICE_TABLE {
	PDWORD ServiceTable;
	PDWORD CounterTable;
	ULONG ServiceLimit;
	PBYTE ArgumentTable;
} SYSTEM_SERVICE_TABLE,
*PSYSTEM_SERVICE_TABLE,
**PPSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	SYSTEM_SERVICE_TABLE ntoskrnl;  // SST для ntoskrnl.exe
	SYSTEM_SERVICE_TABLE win32k;    // SST для win32k.sys
	SYSTEM_SERVICE_TABLE table3;    // не используется
	SYSTEM_SERVICE_TABLE table4;    // не используется
} SERVICE_DESCRIPTOR_TABLE,
*PSERVICE_DESCRIPTOR_TABLE,
**PPSERVICE_DESCRIPTOR_TABLE;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;

extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

extern PUSHORT NtBuildNumber;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD unload;

#ifdef INTERCEPTION

#pragma pack (push, 1)

typedef struct _far_jmp {
	BYTE  PushOp;
	PVOID PushArg;
	BYTE  RetOp;
} far_jmp, *pfar_jmp;


typedef struct _OldCode {
	USHORT One;
	ULONG  TWO;
} OldCode, *POldCode;

#pragma pack (pop)

const char message[] = "Your PC was HACKED!";
OldCode OpPrcOld;
far_jmp fjmp;
ULONG NtQueryProcId;
ULONG CR0Reg;

PVOID oldNtQuerySystemInformation;

NTSTATUS newNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
#endif // INTERCEPTION


void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

//VOID unload(_In_ PDRIVER_OBJECT DO);

NTSTATUS NTAPI DriverEntry(IN PDRIVER_OBJECT driverObject, IN PUNICODE_STRING RegPath) {
	NTSTATUS nts = STATUS_SUCCESS;
	PDEVICE_OBJECT pdo;
	PDeviceExtension pde;
	UNICODE_STRING devName;
	UNICODE_STRING symLink;
#ifdef INTERCEPTION
	POldCode func;
	pfar_jmp fnjp;
#endif // INTERCEPTION

	DbgPrint(">>MDR: DriverEntry");
	DbgPrint(">>MDR: RegPath: %ws", RegPath->Buffer);

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

		DbgPrint(">>MDR: IoCreateSymbolicLink error");

		return nts;
	}
	pde->symLink = symLink;

#ifndef INTERCEPTION
	nts = PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	if (!NT_SUCCESS(nts)) {
		IoDeleteSymbolicLink(&symLink);
		IoDeleteDevice(pdo);
		DEBUG(">>MDR: PsSetLoadImageNotifyRoutine error");
		return nts;
	}
#else
	switch (*NtBuildNumber)
	{
	default:
		NtQueryProcId = 0x0105;
		break;
	}

	fjmp.PushOp = 0x68;
	fjmp.PushArg = (PVOID)newNtQuerySystemInformation;
	fjmp.RetOp = 0xC3;

	__asm {
		cli
		mov EAX, CR0
		mov CR0Reg, EAX
		and EAX, 0xFFFEFFFF
		mov CR0, EAX
	}
	
	oldNtQuerySystemInformation = (PVOID)KeServiceDescriptorTable->ntoskrnl.ServiceTable[NtQueryProcId];
	func = (POldCode)oldNtQuerySystemInformation;
	OpPrcOld.One = func->One;
	OpPrcOld.TWO = func->TWO;

	fnjp = (pfar_jmp)oldNtQuerySystemInformation;

	fnjp->PushOp = fjmp.PushOp;
	fnjp->PushArg = fjmp.PushArg;
	fnjp->RetOp = fjmp.RetOp;

	__asm {
		mov EAX, CR0Reg
		mov CR0, EAX
		sti
	}

#endif // INTERCEPTION

	return nts;
}

VOID unload(PDRIVER_OBJECT DO)
{
	PDEVICE_OBJECT pdo;
	UNICODE_STRING* ustr;
	PDeviceExtension pde;
#ifdef INTERCEPTION
	POldCode poc = (POldCode)oldNtQuerySystemInformation;
#endif // INTERCEPTION

	int t;

	DbgPrint(">>MDR: DriverUnload");

	pdo = DO->DeviceObject;

	for (t = 0; pdo != NULL; t++) {
		pde = (PDeviceExtension)pdo->DeviceExtension;
		ustr = &(pde->symLink);

		pdo = pdo->NextDevice;

		DbgPrint(">>MDR: Deleted Device (%d): pointer to PDO = %X.", t, pde->pdo);
		DbgPrint(">>MDR: Deleted symlink = %ws.", ustr->Buffer);

		IoDeleteSymbolicLink(ustr);
		IoDeleteDevice(pde->pdo);

	}

#ifndef INTERCEPTION
	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
#else
	__asm {
		cli
		mov EAX, CR0
		mov CR0Reg, EAX
		and EAX, 0xFFFEFFFF
		mov CR0, EAX
	}

	poc->One = OpPrcOld.One;
	poc->TWO = OpPrcOld.TWO;

	__asm {
		mov EAX, CR0Reg
		mov CR0, EAX
		sti
	}

#endif // !INTERCEPTION

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

	DbgPrint(">>MDR: watch %ws", FullImageName->Buffer);

	idh = (IMAGE_DOS_HEADER*)ImageInfo->ImageBase;
	imageLength = ImageInfo->ImageSize;
	
	if (ImageInfo->ExtendedInfoPresent) {
	
	}
	
	nt32 = (IMAGE_NT_HEADERS32*)(idh->e_lfanew + (LONG)ImageInfo->ImageBase);

	if (nt32 == NULL) {
		DbgPrint(">>MDR: e_lfanew == NULL!");
		return;
	}
	
	if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		//nt64 = (IMAGE_NT_HEADERS64*)idh->e_lfanew;
		nt32 = NULL;
	}
	
	if (nt32 != NULL) {
		IED = (IMAGE_EXPORT_DIRECTORY*)nt32->OptionalHeader.DataDirectory[0].VirtualAddress;
		if (IED == NULL) {
			DbgPrint(">>MDR: no export func");
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

NTSTATUS newNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	__asm {
		mov EAX, SystemInformation
		mov EAX, SystemInformationLength
		mov EAX, ReturnLength
		mov EAX, SystemInformationClass
		sub EAX, 0x05
		//jz __Continue
		cli
		mov EAX, CR0
		mov CR0Reg, EAX
		and EAX, 0xFFFEFFFF
		mov CR0, EAX
		lea EAX, OpPrcOld
		mov EBX, oldNtQuerySystemInformation
		mov AX, [EAX]
		mov [EBX], AX
		lea EAX, OpPrcOld
		mov EAX, [EAX + 2]
		mov [EBX + 2], EAX
		xor EBX, EBX
		mov EAX, CR0Reg
		mov CR0, EAX
		sti
		int 3
		push SystemInformationClass
		push SystemInformation
		push SystemInformationLength
		push ReturnLength
		jmp oldNtQuerySystemInformation
		pop EBX
		pop EBX
		pop EBX
		pop EBX
		xor EBX, EBX
		//call oldNtQuerySystemInformation
		int 3
		push EAX
		cli
		mov EAX, CR0
		mov CR0Reg, EAX
		and EAX, 0xFFFEFFFF
		mov CR0, EAX
		lea EAX, fjmp
		lea EBX, [oldNtQuerySystemInformation]
		mov AL, [EAX]
		mov [EBX], AL
		lea EAX, fjmp
		mov EAX, [EAX + 1]
		mov [EBX + 1], EAX
		lea EAX, fjmp
		mov AL, [EAX + 5]
		mov [EBX + 5], AL
		xor EBX, EBX
		mov EAX, CR0Reg
		mov CR0, EAX
		sti
		pop EAX
		ret
	}
//__Continue:
	return STATUS_SUCCESS;
}
