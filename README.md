ShellSilo is a state-of-the-art tool translates C syntax into syscall assembly and its corresponding shellcode. It streamlines the process of constructing and utilizing structures, assigning variables, and making system calls. With this tool, integrating strings into your shellcode and initializing Unicode strings has never been easier.

ShellSilo supports the following:

* Reading and parsing structures
* Structres instances
* Structres member assignments
* Infinite while loop
* If statements
* Variables definition and assignments
* Function calls
* Initializing unicode string
* Some C constants such as MEM_COMMIT and MEM_RESERVE


### Practical Example:
The most practical template of the files provided is the ntwrt.c file.
### What's happening in the ntwrt.c file ?
* The code starts by looping through two syscall apis NtAllocateVirtualMemory, and NtQuerySystemInformation to find a specific running process that you will define in the code. Change the name of the process in the code from "CrypTool.exe" to whatever process you want, Example: Calculator.exe (Windows 10). The process nam you change will automatically be initialzed as unicode string using ShellSilo's buildin function InitUnicodeStr, do you don't need to worry about that part.
* The next step is to allocate enough memory in that process using NtOpenProcess followed by NtAllocateVirtualMemory
* Next is to copy the buffer on line 110 which is "h" works as a place holder, to the remote process. this is a place holder, after you generate the assembly change this line with your actual payload buffer line, please refer to my Defcon example 
https://github.com/nixpal/ProcInjectSyscall/blob/main/shellcode.c#L222
* Finally, the code will create a new thread of that copied buffer using NtCreateThreadEx.

![Alt text](https://github.com/nixpal/shellsilo/blob/main/images/main.png)

![Alt text](https://github.com/nixpal/shellsilo/blob/main/images/output_sample.png)

![Alt text](https://github.com/nixpal/shellsilo/blob/main/images/help.png)

![Alt text](https://github.com/nixpal/shellsilo/blob/main/images/shellcode.png)
