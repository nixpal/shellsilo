# Tool Documentation

## Control Structures

### If Statement

```C
if (var1 == <var2/string/int/hex>) {
    // Code to execute
    break;
}
```


Notes:

    Right side must be a variable, string, integer, or hex value

    Currently only works inside infinite loops

Infinite While Loop

```C
while(TRUE) {
    if (<condition>) {
        // Code to execute
        break;
    }
}
```
Notes:

    Only infinite loops (while(TRUE)) are supported

    if statements must be nested inside loops (for now)

Data Structures
Defining Structs


```C
typedef struct <structure_name> {
    <type> member1;
    <type> member2;
} <struct_alias>, *<optional_pointer>;
```
Example 1: Unicode String


```C
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```


Example 2: Object Attributes
```C
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
```
Main Function


```c
<MAIN> {
    // Code lines
    line1;
    line2;
}
```
Note: Starts with \<MAIN\> instead of C-style int main()
Variables
Definition & Assignment
```C
<type> <name> = <value>;  // e.g., NULL, string, hex, int
```
Examples:
```C

PVOID remoteAddress = NULL;
DWORD DesiredAccess = PROCESS_ALL_ACCESS;
DWORD ProcInfo = 0x5;
mystring = "Hello World";
```
Notes:

    Types must match those in constants.py

    Custom types can be added to constants.py with correct sizes

Struct Member Access
```C

<struct_instance>.<member> = <value>;
```
Examples:
```C

clientId.UniqueThread = NULL;
ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
```
Functions
Calling Functions

Single-line:
```C
<function>(param1, param2);
```
Multi-line:
```C

<function>(
    param1,
    param2
);
```
Example:
```C
NtAllocateVirtualMemory(
    hProcess,
    &BaseAddress,
    ZeroBits,
    &RegionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```
Returned Structures
Definition
```C

hidden struct <name> {
    <members>;
} <alias>;
```


Example:
```C

hidden struct _SYSTEM_PROCESS_INFORMATION {
    ULONG Offset;
    PVOID ImageName;
} SYSTEM_PROCESS_INFORMATION;
```


Accessing Nested Members
```C

<var> = (<struct_type>)<pointer>->member->nested_member;
```
Example:
```C

imageName = (SYSTEM_PROCESS_INFORMATION)newBaseAddress->ImageName->Buffer;

Strings
Unicode Initialization
```

```C
InitUnicodeStr(<variable>, "<string>");
```
Examples:
```C
InitUnicodeStr(processName, "chrome.exe");
InitUnicodeStr(path, "C:\\Windows\\system32");
```
String Assignment
```C
PVOID <var> = "<string>";
```


Example:
```C

PVOID buffer = "Hello World";
```
Special Constants & Functions
sizeof()

Gets size of a variable/type

Examples:
```c
ULONG size = sizeof(OBJECT_ATTRIBUTES);
ULONG strSize = sizeof("example");
```
Constants
```
MEM_COMMIT      
MEM_RESERVE      
MEM_RELEASE
PAGE_READWRITE  
PAGE_READONLY    
PROCESS_ALL_ACCESS
THREAD_ALL_ACCESS
True            
False            
NTSTATUS
NULL
```
