#include <Windows.h>
#include <iostream>

// Define necessary structures and types

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

hidden struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
	PUNICODE_STRING ImageName;
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

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;



<MAIN>
{

    DWORD targetProcessId = 0x9c0;
    CLIENT_ID clientId = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    clientId.UniqueProcess = targetProcessId;
    clientId.UniqueThread = NULL;
    HANDLE hProcess = NULL;
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES); 
	PVOID BaseAddress = NULL;
	ULONG_PTR ZeroBits = NULL;
	ULONG NumberOfBytesWritten = 0;
	SIZE_T RegionSize = 0x1000;
	DWORD rtn = NULL;
	DWORD imageName = NULL;
    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientId);

	rtn = NtAllocateVirtualMemory(hProcess, &BaseAddress, ZeroBits, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
	imageName = (SYSTEM_PROCESS_INFORMATION)rtn->ImageName->Length;
	PVOID Buffer = "Hello, World!";
	ULONG NumberOfBytesToWrite = sizeof(Buffer);
	NtWriteVirtualMemory(hProcess, BaseAddress, Buffer, NumberOfBytesToWrite, &NumberOfBytesWritten);


}
