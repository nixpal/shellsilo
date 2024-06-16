#include <Windows.h>
#include <iostream>

// Define necessary structures and types

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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

    DWORD targetProcessId = 5244;

    CLIENT_ID clientId = NULL;

	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    clientId.UniqueProcess = targetProcessId;
    clientId.UniqueThread = NULL;

    HANDLE hProcess = NULL;
    NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientId);
	PVOID remoteBuffer = NULL;
    SIZE_T bufferSize = 4096; 
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES)
	PVOID mystr = "Hello, World!";
	ULONG numOfBytesWritten = 0;
	
    NtAllocateVirtualMemory(hProcess, &remoteBuffer, 0, &bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(hProcess, remoteBuffer, dataToWrite, 13, &numOfBytesWritten);
}
