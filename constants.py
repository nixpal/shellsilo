

dataTypes = {
    "PWSTR":0x4,
    "PVOID":0x4,
    "PWCHAR":0x4,
    "PSIZE_T":0x4,
    "HANDLE":0x4,
    "SIZE_T":0x4,
    "UCHAR":0x1,
    "USHORT":0x2,
    "BYTE":0x1,
    "ULONG":0x4,
    "ULONG_PTR":0x4,
    "SIZE_T":0x4,
    "NTSTATUS":0x4,
    "DWORD":0x4,
    "KPRIORITY":0x4,
    "ACCESS_MASK":0x4}

specialVars = {"GetCurrentProcess()":hex(0xffffffff),
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


sysCalls = {"NtAllocateVirtualMemory":{"10":["0018"],
                                       "11":["0018"]
                                       },
            "NtQuerySystemInformation":{"10":["0036"],
                                        "11":["0167" ,"0169", "016c", "016c", "016d"]
                                        },
            "NtOpenProcess":{"10":["0026"],
                             "11":["0029"]
                             },
            "NtWriteVirtualMemory":{"10":["003A"],
                                    "11":["0030"]
                                    },
            "NtCreateThreadEx":{"10":["00b3","00b4","00b6","00b9","00ba","00bb","00bc","00bd","00bd","00c1","00c1","00c1","00c2","00c2"],
                                "11":["00c5","00c6","00c7","00c7","00c8"]
                }
        }
