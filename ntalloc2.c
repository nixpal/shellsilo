#include <Windows.h>
#include <iostream>

// Define necessary structures and types







<MAIN>
{

	PVOID BaseAddress = NULL;
	ULONG NumberOfBytesWritten = 0;
	SIZE_T RegionSize = 0x2000;
	DWORD ZeroBits = 0;
	HANDLE hProcess = GetCurrentProcess();
	NtAllocateVirtualMemory(hProcess, &BaseAddress, ZeroBits, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	PVOID buffer = "Hello";	
	ULONG NumberOfBytesToWrite = sizeof(buffer);
	NtWriteVirtualMemory(hProcess, BaseAddress, buffer, NumberOfBytesToWrite, &NumberOfBytesWritten);
	
	}

}
