#include <Windows.h>
#include <stdio.h>

// Define NTDLL function prototypes
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

<MAIN> 
{
	HANDLE test;
    HANDLE processHandle = GetCurrentProcess();
	PVOID remoteAddress = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	CLIENT_ID ClientId;
	ClientId.UniqueProcess = 8888;
	NTSTATUS status;
	HANDLE hProcess = NULL;
	DWORD DesiredAccess = PROCESS_ALL_ACCESS;
	DWORD allocationSize = 1024;
	status = NtOpenProcess(
			&hProcess,
			DesiredAccess,
			&ObjectAttributes,
			&ClientId
			);

	status = NtAllocateVirtualMemory(hProcess, 
			&remoteAddress,
			0, 
			&allocationSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

    return 0;
}
