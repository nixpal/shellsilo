🐚 ShellSilo Manual

A guide to ShellSilo's custom C-like syntax for generating syscall shellcode.

📌 Table of Contents

🔁 Control Flow

If Statement

While Loop

🏗 Struct Definitions

🔧 Main Function

🔣 Variable Definitions

📝 Variable Assignment

📦 Structure Instances

🧱 Struct Member Assignment

📞 Function Calls

📥 Returned Structures

🔍 Accessing Returned Values

🔠 Unicode String Initialization

🧵 String Variable Assignment

🔐 Special Constants and Functions

🔁 Control Flow

✅ If Statement

if (var1 == <var2/string/int/hex>) {
    do something
    break;
}

The right-hand side of the condition must be a variable, string, integer, or hex value.

♾ While Loop

while(TRUE) {
    if (var1 == <var2/string/int/hex>) {
        do something
        break;
    }
}

Only infinite while(TRUE) loops are currently supported.

if conditions are only valid inside while(TRUE) loops.

🏗 Struct Definitions

typedef struct <structure_name> {
    type member1;
    type member2;
    ...
} <struct_alias>, *<optional_pointer>;

Example 1:

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

Example 2:

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

🔧 Main Function

<MAIN> {
    line 1;
    line 2;
    ...
}

Use <MAIN> instead of int main()

🔣 Variable Definitions

<type> <variable_name> = <var | NULL | int | string | constant>;

Example:

PVOID remoteAddress = NULL;
DWORD DesiredAccess = PROCESS_ALL_ACCESS;
DWORD ProcInfo = 0x5;

📝 Variable Assignment

BaseAddress = 0;
BaseAddress += 1;
BaseAddress -= 1;
mystring = "Hello world";

📦 Structure Instances

UNICODE_STRING NtImagePath;
CLIENT_ID clientId = NULL;

🧱 Struct Member Assignment

clientId.UniqueThread = NULL;
ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

📞 Function Calls

FunctionName(param1, param2, param3);
FunctionName(
    param1,
    param2,
    param3
);

Example:

NtAllocateVirtualMemory(hProcess, &BaseAddress, ZeroBits, &RegionSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

📥 Returned Structures

hidden struct _SYSTEM_PROCESS_INFORMATION {
    type member1;
    type member2;
};

Use hidden struct for returned structures from syscall functions.

🔍 Accessing Returned Values

var = (STRUCT_NAME)returned_ptr->Member->NestedMember;

Example:

imageName = (SYSTEM_PROCESS_INFORMATION)newBaseAddress->ImageName->Buffer;

🔠 Unicode String Initialization

InitUnicodeStr(<variable>, "string");

Example:

InitUnicodeStr(processName, "C:\\Windows\\System32\\calc.exe");

🧵 String Variable Assignment

PVOID var = "Hello world!";

🔐 Special Constants and Functions

✅ Functions

sizeof(...);

Get size of a structure or string.

🏷 Constants

MEM_COMMIT

MEM_RESERVE

MEM_RELEASE

PAGE_EXECUTE_READWRITE

PAGE_READWRITE

PAGE_READONLY

PROCESS_ALL_ACCESS

THREAD_ALL_ACCESS

False, True

NTSTATUS

NULL

🛠️ ShellSilo is evolving — future versions will expand support for more control flow constructs and struct/array operations.
