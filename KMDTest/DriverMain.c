#include <ntifs.h>
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

const wchar_t message[] = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const wchar_t system[] = L"System";
const unsigned sysLen = 12u;
const char origProlog[] = { 0x8b, 0xff, 0x55, 0x8b, 0xec };
OldCode OpPrcOld;
far_jmp fjmp;
ULONG NtQueryProcId;
ULONG CR0Reg;

PVOID origNtQuerySystemInformation;

NTSTATUS newNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS _interceptor(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

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
	//char* interceptor;
	char* orig;
	int t, i;
	//char c;
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

	/*interceptor = (char*)_interceptor;
	t = 0;

	c = 0x90;

	while (interceptor[t] != c) {
		t++;
	}

	i = 0;

	while (interceptor[t] == c)
	{
		t++;
		i++;
	}

	if (i == 10) {
		interceptor = &(interceptor[t - i]);
	}
	else {
		return STATUS_BAD_DATA;
	}*/

	orig = (char*)KeServiceDescriptorTable->ntoskrnl.ServiceTable[NtQueryProcId];

	for (t = 0, i = 0;; t++) {
		if (orig[t] == origProlog[i]) {
			for (; i < sizeof(origProlog); i++, t++) {
				if (orig[t] != origProlog[i]) {
					return STATUS_BAD_DATA;
				}
			}
			orig = &(orig[t - i]);
			origNtQuerySystemInformation = (PVOID)((ULONG)orig + 5ul);
			break;
		}
	}

	__asm {
		cli
		mov EAX, CR0
		mov CR0Reg, EAX
		and EAX, 0xFFFEFFFF
		mov CR0, EAX
	}

	/*
		mov EAX, orig
		mov EAX, [EAX]
		mov [EBX], EAX
		mov EAX, orig
		mov byte ptr[EAX], 0xe9
		mov ECX, EBX
		sub ECX, EAX
		add ECX, 5
		mov AL, [EAX + 4]
		mov [EBX + 4], AL

		pop EBX
	*/

	//interceptor[0] = orig[0];
	//
	//((LONG*)&(interceptor[1]))[0] = ((LONG*)&(orig[1]))[0];

	orig[0] = 0xe9;
	*((ULONG*)&(orig[1])) = (ULONG)newNtQuerySystemInformation - (ULONG)KeServiceDescriptorTable->ntoskrnl.ServiceTable[NtQueryProcId] - 5ul;

	//*((ULONG*)&interceptor) += 5ul;
	//interceptor[0] = 0xe9;
	//*((ULONG*)&interceptor) += 1ul;
	//((ULONG*)interceptor)[0] = (ULONG)KeServiceDescriptorTable->ntoskrnl.ServiceTable[NtQueryProcId] - (ULONG)newNtQuerySystemInformation - 0x11;

	__asm {
		mov EAX, CR0Reg
		mov CR0, EAX
		sti
		int 3
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
	char* origFunc;
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

	origFunc = (char*)origNtQuerySystemInformation;

	for (t = 0; t < sizeof(origProlog); t++) {
		origFunc[t] = origProlog[t];
	}

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

__declspec(naked)
NTSTATUS _interceptor(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	__asm {
		mov EAX, SystemInformationClass
		mov EAX, SystemInformation
		mov EAX, SystemInformationLength
		mov EAX, ReturnLength
		mov EDI, EDI
		push EBP
		mov EBP, ESP
		jmp origNtQuerySystemInformation
	}
}

NTSTATUS newNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS result;
	NTSTATUS inRes;
	PVOID inBuff;
	SYSTEM_PROCESS_INFORMATION* spi;
	SIZE_T len;
	ULONG length;
	int i;
	
	result = _interceptor(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (ReturnLength == NULL) {
		return result;
	}

	if (result != 0) {
		return result;
	}
	
	if (SystemInformationClass == 0x05) {
		length = 0;
		spi = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
		while (length < SystemInformationLength)
		{
			if (spi->ImageName.Length == sysLen) {
				if (memcmp(spi->ImageName.Buffer, system, sysLen) == 0) {
					if (spi->ImageName.MaximumLength > sizeof(message)) {
						for (i = 0; i < 15; i++) {
							spi->ImageName.Buffer[i] = message[i];
						}
						spi->ImageName.Length = sizeof(message) - 2u;
					}
					else {
						inBuff = NULL;
						len = sizeof(message);
						inRes = ZwAllocateVirtualMemory(ZwCurrentProcess(), &inBuff, (ULONG_PTR)NULL, &len, MEM_COMMIT, PAGE_READWRITE);
						if (inRes == STATUS_SUCCESS) {
							spi->ImageName.Buffer = (PWCH)inBuff;
							spi->ImageName.MaximumLength = (USHORT)len;
							spi->ImageName.Length = sizeof(message) - 2u;
							memcpy(spi->ImageName.Buffer, message, sizeof(message));
						}
					}
				}
			}
			//if (spi->ImageName.MaximumLength >= sizeof(message)) {
			//	for (i = 0; i < 7; i++) {
			//		spi->ImageName.Buffer[i] = message[i];
			//	}
			//	spi->ImageName.Length = 12u;
			//}
			if (spi->NextEntryOffset == 0) {
				break;
			}
			length += spi->NextEntryOffset;
			*((ULONG*)&spi) += spi->NextEntryOffset;
		}
	}

	//if (SystemInformationClass == 0x05) {
	//	length = 0;
	//	spi = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;
	//	while (length < SystemInformationLength)
	//	{
	//		if (spi->ImageName.Length < spi->ImageName.MaximumLength) {
	//			spi->ImageName.Buffer[spi->ImageName.Length++] = L'*';
	//			spi->ImageName.Buffer[spi->ImageName.Length] = L'\n';
	//		}
	//		if (spi->NextEntryOffset == 0) {
	//			break;
	//		}
	//		length += spi->NextEntryOffset;
	//		*((ULONG*)&spi) += spi->NextEntryOffset;
	//	}
	//}
	
	return result;
}
