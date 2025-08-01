
type_map = {
    "0x1": "byte",
    "0x2": "word",
    "0x4": "dword",
    "0x8": "qword"
}


dataTypes = {
    "PWSTR":0x8,
    "PVOID":0x4,
    "PWCHAR":0x4,
    "PSIZE_T":0x4,
    "HANDLE":0x8,
    "SIZE_T":0x8,
    "UCHAR":0x1,
    "USHORT":0x2,
    "BYTE":0x1,
    "ULONG":0x4,
    "ULONG_PTR":0x8,
    "SIZE_T":0x4,
    "NTSTATUS":0x4,
    "DWORD":0x4,
    "KPRIORITY":0x4,
    "LARGE_INTEGER":0x8,
    "ULONGLONG":0x8,
    
    "ACCESS_MASK":0x4}

dataTypes_x86 = {
    "PWSTR": 0x4,
    "PVOID": 0x4,
    "PWCHAR": 0x4,
    "PSIZE_T": 0x4,
    "HANDLE": 0x4,
    "SIZE_T": 0x4,
    "UCHAR": 0x1,
    "USHORT": 0x2,
    "BYTE": 0x1,
    "ULONG": 0x4,
    "ULONG_PTR": 0x4,
    "NTSTATUS": 0x4,
    "DWORD": 0x4,
    "KPRIORITY": 0x4,
    "LARGE_INTEGER": 0x8,
    "ULONGLONG": 0x8,
    "ACCESS_MASK": 0x4
}

specialVars = {
    "GetCurrentProcess()":-1,
    "MEM_COMMIT":hex(0x1000),
    "MEM_RESERVE":hex(0x2000),
    "MEM_RELEASE":hex(0x8000),
    "PAGE_EXECUTE_READWRITE":hex(0x40),
    "PAGE_READWRITE":hex(0x4),
    "PAGE_READONLY":hex(0x2),
    "PROCESS_ALL_ACCESS":hex(0x1fffff),
    "THREAD_ALL_ACCESS":hex(0x001FFFFF),
    "False":hex(0x0),
    "True":hex(0x1),
    "NTSTATUS":"NULL",
    "NULL":hex(0x0)}

