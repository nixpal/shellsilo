#!/usr/bin/python3 
import re
import string
import random
import json
import sys
from constants import dataTypes, dataTypes_x86, specialVars, type_map
from keystone import *
import readline
import csv
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, BarColumn, TimeRemainingColumn
from rich.panel import Panel
import time
import threading
import subprocess
import os

console = Console()

rst="\033[0;0m"
red = "\033[38;5;9m"
by="\033[38;5;3m"
y = "\033[1;33m"
b="\033[38;5;27m"
p="\033[1;33;35m"
c="\033[38;5;6m"
w="\033[38;5;7m"
o="\033[38;5;202m"
lb="\033[38;5;117m"
g="\033[38;5;2m"
checkMark = u'\u2705'
crossMark = u'\u2715'

pure_red = "\033[0;31m"
dgr = "\033[0;32m"
orange = "\033[0;33m"
dark_blue = "\033[0;34m"
bright_purple = "\033[0;35m"
dark_cyan = "\033[0;36m"
dulw = "\033[0;37m"
publk = "\033[0;30m"
bright_red = "\033[0;91m"
light_green = "\033[0;92m"
yellow = "\033[0;93m"
yellow = "\033[1;33m"
bright_blue = "\033[0;94m"
magenta = "\033[0;95m"
light_cyan = "\033[0;96m"
brblk = "\033[0;90m"
bright_white = "\033[0;97m"
cyan_back = "\033[0;46m"
purple_back = "\033[0;45m"
white_back = "\033[0;47m"
blue_back = "\033[0;44m"
orange_back = "\033[0;43m"
green_back = "\033[0;42m"
pink_back = "\033[0;41m"
grey_back = "\033[0;40m"
grey = '\033[38;4;236m'
bold = "\033[1m"
underline = "\033[4m"
italic = "\033[3m"
darken = "\033[2m"
invisible = '\033[08m'
reverse_colour = '\033[07m'
grey = "\x1b[90m"

structs = []
hiddenstructs = []
mainVars = []
ebpVars = []
mainStructs = []
finalAssembly = []
allLoops = [None]
loopDetected = [False]
breakDetected = [False]
ifDetected = [False]
breakData = [None]
win10Checked = True 
win11Checked = False
x64 = False
nasm = True 
masm = False
dataSection = False
generateBinaryFile = False
funcCalls = {}
syscallsAndApiNum = {}
assemblyAndComments = []

def run_with_progress(operationType=None, taskArg=None):
    result = []
    exception = []
    try:
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        ) as progress: 
            task = progress.add_task("Processing", total=100)
            def readFileWithProgress():
                try:
                    res = taskArg.readFile() 
                    if res:
                        result.append("Operation successful")
                    else:
                        exception.append("Operation failed")
                except Exception as e:
                    exception.append(e)
                    raise
            def run_command(command):
                try:
                    cmdResult = subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                    result.append("Operation successful")
                    #if cmdResult.stdout:
                        #print("Output:", cmdResult.stdout)
                except subprocess.CalledProcessError as e:
                    print(f"failed!")
                    print("Error:", e.stderr)
                    exception.append("Operation failed")
                    raise

            if operationType and operationType == "readfile":
                thread = threading.Thread(target=readFileWithProgress)
                thread.start()
            elif operationType and operationType == "run":
                thread = threading.Thread(target=run_command(taskArg))
                thread.start()
            
            while thread.is_alive():
                progress.update(task, advance=1)
                time.sleep(0.05)
                
                if progress.tasks[0].percentage > 95:
                    progress.update(task, advance=0.1)
            
            thread.join()
            progress.update(task, completed=100)  # Force 100% at end
        
        # Result display
        if exception:
            console.print(f"[red]✗ Error: {exception[0]}[/red]")
            return False
        else:
            console.print(f"[green]✓ {result[0]}[/green]")
            return True
    except Exception as e:
        raise

class ContextCompleter:
    def __init__(self):
        self.commands = ['generate', 'load', 'help', 'exit', 'quit', 'set', 'enable']
        self.command_args = {
            'generate': ['assembly', 'shellcode', 'binary'],
            'enable':['data'],
            'set':['arch', 'assembler'],
            'arch':['x64', 'x86'],
            'assembler':['nasm', 'masm']
        }   
    
    def complete(self, text, state):
        line_org = readline.get_line_buffer()
        tokens = re.split(r'(\s+)', line_org)
        line = [token for token in tokens if token]
        #line = readline.get_line_buffer().split()
        #print("Length: ", len(line), line, "text: ", text)
        if len(line) == 0:
            possible_commands = [cmd for cmd in self.commands if cmd.startswith(text)]
            if state < len(possible_commands):
                return possible_commands[state]

        if len(line) == 1:
            options = [cmd for cmd in self.commands if cmd.startswith(text)]
            if state < len(options):
                return options[state]

        if len(line) > 1:
            if line[-1] == " ":
                command = line[-2] 
                options = [arg for arg in self.command_args[command] if arg.startswith(text)]
                if state < len(options):
                    return options[state]
            else:
                command = line[-1]
                if command in self.command_args:
                    options = [arg for arg in self.command_args[command] if arg.startswith(text)]
                    if state < len(options):
                        return options[state]
                else:
                    line = line[:-2]
                    command = line[-1]
                    options = [arg for arg in self.command_args[command] if arg.startswith(text)]
                    if state < len(options):
                        return options[state]

        return None

class Structs:
    def __init__(self):
        self.Lines = []
        self.Name = ''
        self.Pointer = ''
        
        self.totalSize = 0
        self.Members = []

class Vars:
    def __init__(self):
        self.Name = ''
        self.Type = ''
        self.Value = ''
        self.instance = ''
        self.unicode = ''
        self.assignedTo = ''
        self.assigned = False
        self.Size = 0
        self.Length = 0

class Asm:
    def __init__(self):
        self.stackStart = 0x4 
        self.stackSize = 0x2000
        self.assembly = ""
        self.masm = ""
        self.nasm = ""
        self.dotData = ""
        self.shellcode = ""
        self.registers = {
                "RAX":None,
                "RBX":None,
                "RCX":None,
                "RDX":None,
                "RSI":None,
                "RDI":None,
                "RBP":None,
                "RSP":None,
                "R8":None,
                "R9":None,
                "R10":None,
                "R11":None,
                "R12":None,
                "R13":None,
                "R14":None,
                "R15":None
                }

class whileLoop:
    def __init__(self):
        self.loopStart = None 
        self.loopEnd = None 

        
class Reader:
    def __init__(self, file):
        self.file = file 
    asmObj = Asm()
    
    def addUnicodeStr(self, ptrName, structName, structVal):
        unicodeVal = structVal["u"]
        return self.pushAscii(unicodeVal)

    def assemblerDataSection(self):
        asm = "global _start\n"
        asm += "section .text\n"
        asm += "_start:\n"
        if nasm:
            ds = "section .data\n"
        elif masm:
            ds = ".data\n"
        ds += self.asmObj.dotData
        ds += asm
        return ds

    def testShellcode(self, assembly):
        assembly_lines = assembly.strip().split('\n')
        for i, line in enumerate(assembly_lines):
            try:
                if x64:
                    ks = Ks(KS_ARCH_X86, KS_MODE_64)
                else:
                    ks = Ks(KS_ARCH_X86, KS_MODE_32)
                encoding, count = ks.asm(line)
                if not encoding:
                    print(f"Didn't like this instruction: {y}{line}{rst}")
            except Exception as e:
                print(f"Error on line {i + 1}: {line}")
                print(f"Error message: {e}")


    def asm2Shellcode(self, assembly):
        #self.testShellcode(assembly)
        allText = ""
        allText += f"\t\t  {y}**********************\n"
        allText += f"\t\t  *****{o} Shellcode{y} ******\n"
        allText += f"\t\t  {y}**********************{rst}\n\n"
        if x64:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
        else:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        try:
            if not dataSection:
                encoding, _ = ks.asm(assembly)
                opcode_hex = "".join(f"\\x{byte:02x}" for byte in encoding)
                bytes_per_line = 16 
                allText += '\n'.join(opcode_hex[i:i + bytes_per_line * 4] for i in range(0, len(opcode_hex), bytes_per_line * 4))
                allText += '\n'
        except KsError as e:
            print(f"[!] Shellcode generation failed")
        except Exception as e:
            print(f"[!] Shellcode generation failed")

        return allText

    def findEbpVar(self, value):
        for ebp in ebpVars:
            if value in ebp:
                return ebp 
        return False

    def sizeOf(self, data):
        found = re.search(r'sizeof\(("?[^"]+"?)\)', data)
        if found:
            extracted = found.group(1)
            foundVal = self.getValueType(extracted)
            if foundVal == "int":
                return hex(4)
            elif foundVal == "string":
                return hex(len(extracted.replace('"', '')))
            elif foundVal == "variable" and extracted == "int":
                return hex(4)
            elif foundVal == "variable" and extracted == "char":
                return hex(1)
            elif foundVal == "variable" and (extracted != "int" or extracted != "char"):
                varVal = self.getVarValue(extracted)
                if varVal:
                    if "\\x" in varVal:
                        try:
                            varVal = varVal.replace("\\x", "").replace('"', '')
                            raw_bytes = bytes.fromhex(varVal)
                            return hex(len(raw_bytes))
                        except Exception as e:
                            print(e)
                    return hex(len(varVal.replace('"', '')))
                else:
                    print(f"{red}Error: variable {extracted} doesn't exist.{rst}")
                    print(f"{w}Error on: {data}{rst}")
                    sys.exit()
            else: return None


    def rawBytesFormat(self, bytes_list, label=None, bytes_per_line=10):
        try:
            if not bytes_list:
                return ""
            hex_parts = []
            for b in bytes_list:
                hex_parts.append(f"0{b:02x}h")  # MASM: 0AAh
            
            chunks = [hex_parts[i:i+bytes_per_line] 
                  for i in range(0, len(hex_parts), bytes_per_line)]
            asm_lines = []
            for i, chunk in enumerate(chunks):
                if i == 0:
                    asm_lines.append(f"{label} db {', '.join(chunk)}")
                else:
                    asm_lines.append(f"        db {', '.join(chunk)}")
            
            if len(bytes_list) > 20:
                asm_lines.insert(0, f"; {len(bytes_list)} bytes")
            asm = "\n".join(asm_lines) 
            return asm
        except Exception as e:
            raise
            return None

    def newVarAssm(self, Type, name, value, size):
        varEbpDict = self.findEbpVar(name)
        varEbpVal = None
        assignedEbpVal = None
        if varEbpDict:
            varEbpVal = varEbpDict[name]
        else:
            if Type == "newVarAdd" or Type == "newVarSub":
                print(f"{red}Error: could not find var {name}, did you forget to define it ?{rst}")
                sys.exit()

        currentStack = self.asmObj.stackStart
        allTypes = dataTypes if x64 else dataTypes_x86
        resVal = self.getValueType(value)
        asm = ""
        string = None
        rawbytes = None
        bytes_list = []
        if resVal == "int":
            value = hex(int(value))
        elif resVal == "hex":
            value = hex(int(value, 16))
        elif resVal == "string":
            pushedStr = self.pushString(value)
            string = pushedStr
            asm += pushedStr
        elif resVal == "sizeof":
            value = self.sizeOf(value)
        elif resVal == "raw":
            try:
                rawbytes = True
                hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', value)
                for seq in hex_bytes:
                    bytes_list.append(int(seq, 16))
                dotDataBytes = self.rawBytesFormat(bytes_list, name, 10)
                self.asmObj.dotData = f"{dotDataBytes}\n" 
            except Exception as e:
                raise

        else:
            rtnDict = self.findEbpVar(value)
            if rtnDict:
                assignedEbpVal = rtnDict[value] 
        if value in specialVars:
            value = specialVars[value]
        for var in mainVars:
            if name == var.Name:
                size = var.Size
                dType = type_map.get(hex(int(size)))
                #if size == 4:
                #    dType = "dword"
                #elif size == 2:
                #    dType = "word"
                #elif size == 1:
                #    dType == "byte"
                #else:
                #    print(f"Not found: {size}{var.Name}")
                if x64:
                    size = 8
                    dType = "qword"
                if string:
                    if x64:
                        dType = "qword"
                        assmLine = f"  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], rbx"
                    else:
                        assmLine = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], ebx"
                    asm += "{:60s};{}={}".format(assmLine,lb+name,value+rst)
                elif rawbytes:
                    if x64:
                        dType = "qword"
                        if masm:
                            if dataSection:
                                assmLine = f"  lea rax, {name}\n"
                                assmLine += f"  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], rax"
                            else:
                                assmLine = f";;;  lea rax, {name}\n"
                                assmLine += f";;;  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], rax"
                        elif nasm:
                            if dataSection:
                                assmLine = f"  lea rax, [rel {name}]\n"
                                assmLine += f"  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], rax"
                            else:
                                assmLine = f";;;  lea rax, [rel {name}]\n"
                                assmLine += f";;;  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], rax"
                        else:
                            print("[!] Error: Assembler not set")
                            sys.exit()

                    else:
                        if dataSection:
                            assmLine = f" lea eax, {name}\n"
                            assmLine += f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], eax"
                        else:
                            assmLine = f";;;  lea eax, {name}\n"
                            assmLine += f";;;  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], eax"


                    asm += "{:87s};{}".format(assmLine,lb+name+rst)
                else:
                    if Type == "newVarAdd" and varEbpVal:
                        if assignedEbpVal:
                            if x64:
                                dType = "qword"
                                assmLine = f"  mov rbx, qword ptr[{assignedEbpVal}]"
                                asm += "{:47s};{}\n".format(assmLine,lb+name+rst)
                                assmLine = f"  add {y+dType+rst} ptr[{varEbpVal}], rbx"
                            else:
                                assmLine = f"  mov ebx, dword ptr[{assignedEbpVal}]"
                                asm += "{:47s};{}\n".format(assmLine,lb+name+rst)
                                assmLine = f"  add {y+dType+rst} ptr[{varEbpVal}], ebx"
                            asm += "{:60s}".format(assmLine)
                        else:
                            assmLine = f"  add {y+dType+rst} ptr[{varEbpVal}], {value}"
                            asm += "{:60s};{}".format(assmLine,lb+name+rst)
                    elif Type == "newVarSub" and varEbpVal:
                        if assignedEbpVal:
                            if x64:
                                dType = "qword"
                                assmLine = f"  mov rbx, qword ptr[{assignedEbpVal}]"
                                asm += "{:47s};{}\n".format(assmLine, lb+name+rst)
                                assmLine = f"  sub {y+dType+rst} ptr[{varEbpVal}], rbx"
                            else:
                                assmLine = f"  mov ebx, dword ptr[{assignedEbpVal}]"
                                asm += "{:47s};{}\n".format(assmLine, lb+name+rst)
                                assmLine = f"  sub {y+dType+rst} ptr[{varEbpVal}], ebx"
                            asm += "{:60s}".format(assmLine)
                        else:
                            assmLine = f"  sub {y+dType+rst} ptr[{varEbpVal}], {value}"
                            asm += "{:60s};{}".format(assmLine,lb+name+rst)
                    else:
                        if varEbpVal: # if the assigned var (left side) exists already
                            if assignedEbpVal: # if the right side is a variable
                                if x64:
                                    dType = "qword"
                                    assmLine = f"  mov rbx, qword ptr[{assignedEbpVal}]"
                                    asm += "{:60s}\n".format(assmLine)
                                    assmLine = f"  mov {y+dType+rst} ptr[{varEbpVal}], rbx"
                                else:
                                    assmLine = f"  mov ebx, dword ptr[{assignedEbpVal}]"
                                    asm += "{:60s}\n".format(assmLine)
                                    assmLine = f"  mov {y+dType+rst} ptr[{varEbpVal}], ebx"
                                asm += "{:60s};{}\n".format(assmLine,lb+name+rst)
                            else:
                                assmLine = f"  mov {y+dType+rst} ptr[{varEbpVal}], {value}"
                                asm += "{:60s};{}".format(assmLine,lb+name+rst)
                        else:
                            if x64:
                                ## assigning a value to a variable
                                assmLine = f"  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], {value}"
                            else:
                                assmLine = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], {value}"
                            asm += "{:60s};{}".format(assmLine,lb+name+rst)
                
                if varEbpVal:
                    assignedEbp = f"{varEbpVal}"
                else:
                    if x64:
                        assignedEbp = f"rbp-{hex(currentStack)}"
                    else:
                        assignedEbp = f"ebp-{hex(currentStack)}"
                self.asmObj.stackStart += size
                ebpDict = {var.Name:assignedEbp,
                           "value":value,
                           "type":dType}
                ebpVars.append(ebpDict)
                return(asm)

    def invokeSysCall(self):
        asm = ""
        if x64:
            asm += f"  mov r10, rcx\n"
            asm += f"  mov rax, rdi ; assume syscall number in rdi\n"
            asm += f"  call {lb}invokeSysCall{rst}\n"
        else:
            asm += f"  mov eax, ecx ; assume syscall number in ecx\n"
            asm += f"  call {lb}invokeSysCall{rst}\n"
        return asm


    def getApiNumFromFile(self, funcName):
        asm = ""
        apiNumFromFile = readSysCalls(funcName, False, True)
        if x64:
            asm += f"  mov rdi, {apiNumFromFile}\n"
        else:
            asm += f"  mov edi, {apiNumFromFile}\n"
        asm += f"  call {lb}GetSysModelNumber{rst}\n"
        return asm

    def x64ParamAsm(self, idx, param):
        asm = ""
        ## Assigning values to rcx, rdx, r8, r9
        try:
            param = str(param)
            x64Mov = param.replace("dword", "qword")
            if idx == 0:
                asm += f"  mov rcx, {x64Mov}"
            elif idx == 1:
                asm += f"  mov rdx, {x64Mov}"
            elif idx == 2:
                asm += f"  mov r8, {x64Mov}"
            elif idx == 3:
                asm += f"  mov r9, {x64Mov}"
            else:
                asm += f"  push {x64Mov}"
        except Exception as e:
            raise
        return asm


    def funcCallAssmHandler(self, stackAdjust, asm, funcName, assignedTo):
        try:
            apiNum = readSysCalls(funcName, False, True)
            if apiNum:
                syscallsAndApiNum.update({funcName:apiNum})
            else:
                print(f"Error: couldn't find api num from syscalls file")
            asm += self.getApiNumFromFile(funcName)
            asm += self.invokeSysCall()
            if assignedTo:
                for var in mainVars:
                    if var.Name == assignedTo:
                        if var.Value:
                            for ebp in ebpVars:
                                if var.Name in ebp:
                                    ebpVal = ebp[var.Name]
                                    if x64:
                                        prepAsm = f"  mov {lb}qword{rst} ptr[{ebpVal}], rax"
                                    else:
                                        prepAsm = f"  mov {lb}dword{rst} ptr[{ebpVal}], eax"
                                    asm += "{:64s};{} {}\n".format(prepAsm,lb+"save return value in",o+var.Name+rst)
                        else:
                            currentStack = self.asmObj.stackStart
                            if x64:
                                prepAsm = f"  mov {y}qword{rst} ptr[rbp-{hex(currentStack)}], rax"
                            else:
                                prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(currentStack)}], eax"
                            asm += "{:64s};{} {}\n".format(prepAsm,lb+"save return value in",o+var.Name+rst)
                            if x64:
                                assignedEbp = f"rbp-{hex(currentStack)}"
                                var.Value = "RAX"
                                ebpDict = {var.Name:assignedEbp,
                                    "value":"RAX",
                                    "type":"dword"}
                            else:
                                assignedEbp = f"ebp-{hex(currentStack)}"
                                var.Value = "EAX"
                                ebpDict = {var.Name:assignedEbp,
                                    "value":"EAX",
                                    "type":"dword"}
                            if x64:
                                self.asmObj.stackStart += 0x8
                            else:
                                self.asmObj.stackStart += 0x4
            if x64:
                asm += f"  add rsp, {hex(stackAdjust+32)}\n"
            else:
                asm += f"  add esp, {hex(stackAdjust)}\n"
        except Exception as e:
            raise
        return(asm)

    def get_parameter_order(self, params):
        if x64:
            register_params = params[:4]
            stack_params = params[4:][::-1]  # Reverse only params 5+
            return register_params + stack_params
        else:
            # x86 (32-bit): ALL params are pushed in reverse order
            return params

    def funcCallAssmX86(self, params, funcName, assignedTo):
        params = self.get_parameter_order(params)
        asm = ""
        eaxAssm = ""
        stackAdjust = 0
        numberOfParams = len(params)
        RCX = None
        RDX = None
        R8 = None
        R9 = None
        try:
            for func in mainVars:
                if func.Name == funcName:
                    for idx, param in enumerate(params if x64 else reversed(params)):
                        stackAdjust += 4
                        if param[0] != "&":
                            paramType = self.getValueType(param)
                            if paramType == "variable":
                                ebp = self.findEbpVar(param)
                                if ebp:
                                    ebpOff = ebp[param]
                                    ebpVal = ebp["value"]
                                    if len(ebpVal) > 10 and "\\x" in ebpVal:
                                        raw_bytes = ebpVal.encode('latin-1') if isinstance(ebpVal, str) else ebpVal
                                        trim_bytes = raw_bytes[:10]
                                        hex_str = ''.join([f'\\x{byte:02x}' for byte in trim_bytes])
                                        hex_str += "# ...truncated"
                                        ebpVal = hex_str
                                        
                                    ebpType = ebp["type"]
                                    reg = f"{y+ebpType+rst} ptr[{ebpOff}]"
                                    if x64:
                                        prepAsm = self.x64ParamAsm(idx, reg)
                                    else:
                                        prepAsm = f"  push {y+ebpType+rst} ptr[{ebpOff}]"
                                        #asm += "{:60s};{}:{}\n".format(prepAsm,lb+param,o+ebpVal+rst)
                                    asm += "{:60s};{}:{}\n".format(prepAsm,lb+param,o+ebpVal+rst)
                                else:
                                    if param in specialVars:
                                        newParam = specialVars[param]
                                        reg = f"{newParam}"
                                        if x64:
                                            prepAsm = self.x64ParamAsm(idx, newParam)
                                        else:
                                            prepAsm = f"  push {newParam}"
                                        asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                                    else:
                                        newParam = self.reservedType(param)
                                        if newParam != param:
                                            newParam = hex(newParam)
                                            if x64:
                                                prepAsm = self.x64ParamAsm(idx,newParam)
                                            else:
                                                prepAsm = f"  push {newParam}"
                                            asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                                        else:
                                            print(f"{red}Error: parameter {param} did not match any variable{rst}")
                                            sys.exit()

                            elif paramType == "string":
                                isString = re.findall('"(.*)"', param)
                                if isString:
                                    pushStr = isString[0]
                                    strAsm = self.pushString(pushStr)
                                    asm += strAsm
                            elif paramType == "int":
                                paramVal = hex(int(param))
                                if x64:
                                    prepAsm = self.x64ParamAsm(idx, paramVal)
                                else:
                                    prepAsm = f"  push {paramVal}"
                                asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                            elif paramType == "hex":
                                v = hex(int(param, 16))
                                if x64:
                                    prepAsm = self.x64ParamAsm(idx, v)
                                else:
                                    prepAsm = f"  push {v}"
                                asm += "{:44s};{}\n".format(prepAsm,lb+param+rst)
                            elif paramType == "sizeof":
                                foundSizeOf, rtnVal = self.isSizeOf(param)
                                if foundSizeOf:
                                    if self.isStruct(rtnVal):
                                        paramVal = self.getStructSize(rtnVal)
                                        if x64:
                                            prepAsm = self.x64ParamAsm(idx, paramVal)
                                        else:
                                            prepAsm = f"  push {paramVal}"
                                        asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                                    else:
                                        paramVal = self.sizeOf(param)
                                        if x64:
                                            prepAsm = self.x64ParamAsm(idx, paramVal)
                                        else:
                                            prepAsm = f"  push {paramVal}"
                                        asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                            else:
                                if param in specialVars:
                                    paramVal = specialVars[param]
                                    if x64:
                                        prepAsm = self.x64ParamAsm(idx, paramVal)
                                    else:
                                        prepAsm = f"  push {paramVal}"
                                    asm += "{:44s};{}\n".format(prepAsm,lb+param+rst)

                        else:
                            newParam = param.replace("&", "")
                            ebp = self.findEbpVar(newParam)
                            if ebp:
                                ebpOff = ebp[newParam]
                                ebpVal = ebp["value"]
                                ebpType = ebp["type"]
                                if x64:
                                    prepAsm = f"  lea rbx, {y+'qword'+rst} ptr[{ebpOff}]"
                                else:
                                    prepAsm = f"  lea ebx, {y+'dword'+rst} ptr[{ebpOff}]"
                                asm += "{:60s};{}:{}\n".format(prepAsm,lb+param,o+ebpVal+rst)
                                if x64:
                                    prepAsm = self.x64ParamAsm(idx, "rbx")
                                    asm += "{:60s}\n".format(prepAsm)
                                else:
                                    asm += f"  push ebx\n"
                    break
        except Exception as e:
            raise
        if x64:
            asm += " sub rsp, 0x20\n"
        return self.funcCallAssmHandler(stackAdjust, asm, funcName, assignedTo)

        

    def funcCallAssm(self, funcName, params, assignedTo):
        asm = ""
        try:
            if funcName not in funcCalls:
                asm += f"\n{lb+funcName+rst}:\n"
                funcCalls.update({funcName:0})
            else:
                funcCallNum = funcCalls[funcName]
                NewfuncName = f"{funcName}{funcCallNum+1}"
                funcCalls.update({NewfuncName:funcCallNum+1})
                asm += f"\n{lb+NewfuncName+rst}:\n"
            result = self.funcCallAssmX86(params, funcName, assignedTo)
            asm += result
        except Exception as e:
            raise
        return asm


    def structPtrAsm(self,ptr):
        currentStack = self.asmObj.stackStart
        asm = ""
        ptrOffset = 0
        pointerName = ""
        for s in structs:
            if s.Pointer == ptr:
                pointerName = s.Name
                if x64:
                    ptrOffset = f"rbp-{hex(currentStack)}"
                else:
                    ptrOffset = f"ebp-{hex(currentStack)}"
                ebpDict = {s.Pointer:ptrOffset,
                           "value":"0x0",
                           "type":"struct",
                           "members":[]}
                members = s.Members
                 
                for mem in members:
                    for key, value in mem.items():
                        dType = type_map.get(hex(int(key)) if "0x" not in key else key)
                        #if key == "0x4":
                        #    dType = "dword"
                        #elif key == "0x2":
                        #    dType = "word"
                        #elif key == "0x1":
                        #    dType = "byte"
                        #elif key == "0x8":
                        #    dType = "qword"
                        ebpDict["members"].append({value:hex(currentStack)})
                        if x64:
                            prepAsm = f"  mov {y+dType+rst} ptr[rbp-{hex(currentStack)}], 0x0"
                        else:
                            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], 0x0"
                        asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
                        if x64:
                            ptrOffset = f"rbp-{hex(currentStack)}"
                        else:
                            ptrOffset = f"ebp-{hex(currentStack)}"
                        currentStack += int(key, 16)
                ebpVars.append(ebpDict)
        self.asmObj.stackStart = currentStack
        return asm,ptrOffset,pointerName 

    
    def checkStructPtr(self, st):
        members = st.Members
        for mem in members:
            for key, value in mem.items():
                if "->" in value:
                    structPtr = value.split("->")[1]
                    return True,structPtr
        return False,None

    def genStructAssembly(self, members, var, offset=None, ptrName=None):
        v = var
        asm = ""
        finalAsm = ""
        if v.instance != "":
            v.Name = v.instance
        if x64:
            currStackPtr = f"rbp-{hex(self.asmObj.stackStart)}"
        else:
            currStackPtr = f"ebp-{hex(self.asmObj.stackStart)}"
        ebpDict = {v.Name:currStackPtr,
                   "value":"0x0",
                   "type":"struct",
                   "members":[]}
        tmpStackPtr = 0
        try:
            for mem in members:
                for key, value in mem.items():
                    possibleArr = re.search(r'\[(\d+)\]', value)
                    if possibleArr:
                        ArrSize = possibleArr.group(1)
                        key = hex(int(key, 16) * int(ArrSize))
                    currentStack = self.asmObj.stackStart
                    if key == "0x4":
                        dType = "dword"
                    elif key == "0x2":
                        dType = "word"
                    elif key == "0x1":
                        dType = "byte"
                    elif key == "0x8":
                        dType = "qword"
                    else:
                        print(f"[!] Unknwon type")
                    ebpDict["members"].append({value:hex(currentStack)})
                    if x64:
                        tmpStackPtr = f"rbp-{hex(currentStack)}"
                    else:
                        tmpStackPtr = f"ebp-{hex(currentStack)}"
                    if "->" in value:
                        isInitialized = v.Value.replace(" ", "")
                        if "0" in isInitialized or "{0}" in isInitialized:
                            if x64:
                                prepAsm = f"  mov {y}dword{rst} ptr[rbp-{hex(self.asmObj.stackStart)}], 0x0"
                            else:
                                prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                        else:
                            if x64:
                                prepAsm = f"  lea rbx, {y}qword{rst} ptr[{offset}]"
                                asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                                prepAsm = f"  mov {y}qword{rst} ptr[rbp-{hex(self.asmObj.stackStart)}], rbx"
                            else:
                                prepAsm = f"  lea ebx, {y}dword{rst} ptr[{offset}]"
                                asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                                prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(self.asmObj.stackStart)}], ebx"
                            #asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                            asm += "{:60s}\n".format(prepAsm)
                        self.asmObj.stackStart += int(key, 16)
                    else:
                        if "0" in v.Value or "null" in v.Value.lower():
                            if x64:
                                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{hex(self.asmObj.stackStart)}], 0x0"
                            else:
                                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
                            self.asmObj.stackStart += int(key, 16)
                        elif v.Value == "":
                            if x64:
                                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{hex(self.asmObj.stackStart)}], 0x0"
                            else:
                                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
                            self.asmObj.stackStart += int(key, 16)
        except Exception as e:
            raise
        ebpDict[v.Name] = tmpStackPtr 
        ebpVars.append(ebpDict)
        finalAsm += asm
        return finalAsm

    def structAssm(self, name, value):
        asm = ""
        finalAsm = ""
        structOffset = None
        for var in mainVars:
            if var.Name == name:
                for m in structs:
                    if m.Name == name:
                        isPtrExist,ptrName = self.checkStructPtr(m)
                        if isPtrExist:
                            rtnAsm,structOffset,ptrName = self.structPtrAsm(ptrName)
                            finalAsm += rtnAsm
                        if structOffset:
                            tmpAsm = self.genStructAssembly(m.Members, var,structOffset,ptrName)
                            finalAsm += tmpAsm

                        else:
                            tmpAsm = self.genStructAssembly(m.Members, var)
                            finalAsm += tmpAsm
        return finalAsm



    def findStructMember(self, structInstance, structMember):
        for m in ebpVars:
            sName = list(m.keys())[0]
            if m["type"] == "struct" and sName == structInstance:
                allMembers = m["members"]
                for mem in allMembers:
                    for key, value in mem.items():
                        if key == structMember:
                            offset = value
                            return offset


    def findStructMemType(self, stMember):
        for st in structs:
            for m in st.Members:
                for key, value in m.items():
                    if value == stMember:
                        return key
    def isUnicode(self, varName):
        for v in mainVars:
            if v.Name == varName and v.Type == "unicode":
                return True

    def getVarValue(self, varName):
        for v in mainVars:
            if (v.Name == varName) and v.Type != "structInstance":
                return v.Value
            elif (v.Name == varName) and v.Type == "structInstance":
                if self.isUnicode(varName):
                    offset = self.findStructMember(varName, "Buffer")
                    if x64:
                        result = f"rbp-{offset}"
                    else:
                        result = f"ebp-{offset}"
                    return result
                return self.getEbpValue(varName)        
            
    def getEbpValue(self, varName):
        for v in ebpVars:
            vName, ebpValue = next(iter(v.items()))
            vValue = v["value"]
            if varName == vName:
                return ebpValue

    def getValueType(self, value):
        try:
            int(value)
            return "int"
        except Exception as e:
            try:
                int(value, 16)
                return "hex"
            except:
                if "sizeof" in value:
                    foundSizeOf = re.search(r'sizeof\(("?[^"]+"?)\)', value) 
                    if foundSizeOf:
                        return "sizeof"
                if '"' in value:
                    try:
                        hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', value)
                        if hex_bytes:
                            return "raw"
                        return "string"
                    except Exception as c:
                        raise
                elif "u:" in value:
                    return "unicode"
                else:
                    return "variable"

    def getStructSize(self, structName):
        size = 0
        for st in structs:
            if st.Name == structName: 
                for i in st.Members:
                    for k in i:
                        size += int(k, 16)
        return(hex(size))

    def isStruct(self, value):
        for st in structs:
            if st.Name == value:
                return True


    def isSizeOf(self, value):
        foundSizeOf = re.search(r'sizeof\(("?[^"]+"?)\)',value)
        if foundSizeOf:
            return True,foundSizeOf.group(1)
        return False, False
    
    def structMember(self, name, value):
        stName = name.split(".")[0]
        stMember = name.split(".")[1]
        asm = ""
        memberOffset = self.findStructMember(stName, stMember)
        memberSize = self.findStructMemType(stMember)
        foundSizeOf, rtnVal = self.isSizeOf(value)
        if foundSizeOf:
            if self.isStruct(rtnVal):
                value = self.getStructSize(rtnVal)
            else:
                value = self.sizeOf(value)

        if not memberSize:
            return

        dType = type_map.get(hex(int(memberSize)) if "0x" not in memberSize else memberSize)
        #if memberSize == "0x4":
        #    dType = "dword"
        #elif memberSize == "0x2":
        #    dType = "word"
        #elif memberSize == "0x1":
        #    dType = "byte"
        
        if value == "NULL":
            value = 0
        vType = self.getValueType(value)

        if vType == "int":
            varValue = int(value)
            if x64:
                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{memberOffset}], {hex(int(varValue))}"
            else:
                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], {hex(int(varValue))}"
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(varValue)+rst)
        elif vType == "hex":
            if x64:
                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{memberOffset}], {value}"
            else:
                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], {value}"
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(value)+rst)
        elif vType == "string":
            pushedStr = self.pushString(value)
            if x64:
                dType = "qword"
                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{memberOffset}], rbx"
            else:
                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], ebx"
            asm += pushedStr
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(value)+rst)
        elif vType == "variable":
            isVariable = value
            varValue = self.getVarValue(isVariable)
            varType = self.getValueType(varValue)
            varEbpVal = self.getEbpValue(isVariable)
            if x64:
                prepAsm = f"  mov rbx, qword ptr[{varEbpVal}]"
                asm += "{:47s};{}\n".format(prepAsm, lb+isVariable+rst)
                prepAsm = f"  mov qword ptr[rbp-{memberOffset}], rbx"
            else:
                prepAsm = f"  mov ebx, dword ptr[{varEbpVal}]"
                asm += "{:47s};{}\n".format(prepAsm, lb+isVariable+rst)
                prepAsm = f"  mov dword ptr[ebp-{memberOffset}], ebx"
            asm += "{:47s};{}<=>{}\n".format(prepAsm, lb+stMember+rst, lb+isVariable+rst)
        elif vType == "unicode":
            extractVal = value.split("u:")[1]
            hexVal = self.toHex(extractVal)
            uniVal = self.toUnicode(hexVal)
            pushedStr = self.pushAscii(uniVal)
            if x64:
                dType = "qword"
                prepAsm = f"  mov {y+dType+rst} ptr[rbp-{memberOffset}], rbx"
            else:
                prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], ebx"
            asm += pushedStr
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(value)+rst)
            
        return asm  

    def toAssembly(self, Type, name, value, size=None, assignedTo=None):
        if Type == "newVar" or Type == "newVarAdd" or Type == "newVarSub":
            return self.newVarAssm(Type,name,value,size)
        elif Type == "funcCall":
            return self.funcCallAssm(name, value,assignedTo)            
        elif Type == "newstruct":
            return self.structAssm(name, value)
        elif Type == "structMember":
            return self.structMember(name,value)    

    def getFunctionParams(self, line, lines):
        funcName = re.findall('([a-zA-Z0-9]*)\(', line)
        currentPos = lines.index(line)
        params = []
        for newline in lines[currentPos:]:
            firstParam = re.findall('\(([a-zA-Z0-9&_|]+),', newline)
            lastParam = re.findall('([a-zA-Z0-9&_|]+)\)', newline)
            if firstParam:
                parsed = firstParam[0]
                params.append(parsed)
            elif lastParam:
                parsed = lastParam[0]
                params.append(parsed)
                break
            else:
                if newline.strip() == ");":
                    break
                parsed = newline.replace(",", "").strip()
                params.append(parsed)

        if funcName and params:
            return funcName, params
        else:
            return None,None

    def isExist(self, varName):
        for var in mainVars:
            if varName == var.Name and not var.assigned:
                return True,False
            elif varName == var.Name and var.assigned:
                return True,True
        return False,False

    def reservedType(self, varVal):
        res = 0
        if "MEM_COMMIT" in varVal or "MEM_RESERVE" in varVal:
            varVal = varVal.replace("MEM_COMMIT", str(specialVars["MEM_COMMIT"]))
            varVal = varVal.replace("MEM_RESERVE", str(specialVars["MEM_RESERVE"]))
            if "|" in varVal:
                varVal = varVal.replace("|", "+")
                operands = varVal.split("+")
                for op in operands:
                    res += int(op, 16)
            else:
                res += int(varVal, 16)
            varVal = res 

        elif "PAGE_READWRITE" in varVal or "PAGE_EXECUTE_READWRITE" in varVal or "PAGE_READONLY" in varVal:
            varVal = varVal.replace("PAGE_EXECUTE_READWRITE", str(specialVars["PAGE_EXECUTE_READWRITE"]))
            varVal = varVal.replace("PAGE_READONLY", str(specialVars["PAGE_READONLY"]))
            varVal = varVal.replace("PAGE_READWRITE", str(specialVars["PAGE_READWRITE"]))
            res += int(varVal, 16)
            varVal = res 
        elif "MEM_RELEASE" in varVal:
            varVal = varVal.replace("MEM_RELEASE", str(specialVars["MEM_RELEASE"]))
            res += int(varVal, 16)
            varVal = res

        return varVal

    def getStartofLoop(self, line, lines, index):
        for i in range(index, -1, -1):
            if "while(" in lines[i]:
                return i

    def checkType(self, lineNum, lines, line, varObj):
        line = line.replace(";", "")
        sName = line.split(" ")[0]
        if re.search("while\(.*\)", line):
            if not loopDetected[0]:
                return True,None,"start","while",None,None

        if "}" in line and not ifDetected[0]:
            if loopDetected[0] and not breakDetected[0]:
                start_index = lineNum 
                end_index = self.getStartofLoop(line, lines, lineNum)
                loopData = lines[end_index:start_index+1]
                loopDataStr = '\n'.join(i for i in loopData)
                print(f"{w}Warning, no break detected\n{rst}{red}{loopDataStr}{rst}")
                return True,None,"end","while",None,None
            elif loopDetected[0] and breakDetected[0]:
                return True,None,"end","while",None,None
        if "break" in line:
            return True,None,None,"break",None,None

        if re.search("if\s+\(.*\).*", line):
            ifData = re.search("if\s+\((.*)\).*", line)
            return True,None,ifData.group(1),"if", None,None

        if "}" in line and ifDetected[0]:
            return True,None,"end","if",None,None
        for s in structs:
            if sName == s.Name:
                sValue = line.split(" ")[1]
                if "=" in line:
                    assigned = re.findall('.*=(.*)', line)
                    if assigned:
                        assignedVal = assigned[0].strip().replace(";", "")
                        varObj.Name = sName 
                        varObj.Value = assignedVal
                        varObj.Type = "structInstance"
                        varObj.unicode = sName
                        varObj.assigned = True
                        varObj.instance = sValue
                        #mainVars.append(varObj)
                    else:
                        print(f"[!] Syntax Error on {line}")
                else:
                    varObj.Name = sName
                    varObj.Type = "structInstance"
                    varObj.assigned = False 
                    varObj.Value = ""
                    varObj.unicode = sName
                    varObj.instance = sValue
                return True,sName,sValue,"struct",None,True

            elif sName == s.Pointer:
                sValue = line.split(" ")[1]
                return True,sName,sValue,"structPtr",None,False

        if "InitUnicodeStr" in line:
            return True,'',line,"unicode",None,False

        allData = dataTypes if x64 else dataTypes_x86
        if sName in allData:    #check if handle, pvoid, ulong..etc
            size = allData[sName]
            if "=" in line and "+=" not in line:
                lineData = ''.join(line.split(" ")[1:])
                varName = lineData.split("=")[0]
                varVal = lineData.split("=")[1]
                varVal = self.reservedType(varVal)
                return True,varName,varVal,"variable",size,True
            elif "+=" in line:
                lineData = ''.join(line.split(" ")[1:])
                varName = lineData.split("+=")[0]
                varVal = lineData.split("+=")[1]
                varVal = self.reservedType(varVal)
                return True,varName,varVal,"varAdd",size,True
            elif "-=" in line:
                lineData = ''.join(line.split(" ")[1:])
                varName = lineData.split("-=")[0]
                varVal = lineData.split("-=")[1]
                varVal = self.reservedType(varVal)
                return True,varName,varVal,"varSub",size,True

            else:
                varName = line.split(" ")[1]
                return True,varName,None,"variable",size,False
        else:
            params = None
            isFunction = re.findall('[a-zA-Z0-9]*\((.*)\)', line)
            if isFunction and "=" not in line:  # Check if the line is a function E.g func(param1, param2)
                params = isFunction[0].replace(" ", "").split(",")
                funcName = re.findall('([a-zA-Z0-9]*)\(', line)
                if funcName:
                    funcName = funcName[0]
                    if "=" not in line:
                        varObj.assignedTo = False
                        return True,funcName,params,"functionCall",None,None
                    elif "=" in line:
                        assignedVar = line.replace(" ", "").split("=")[0]
                        varObj.assignedTo = assignedVar
                        return True,funcName,params,"functionCall",None,None
            else:
                if "(" in line and ")" not in line: # check if multiline function call
                    if re.findall('[a-zA-Z0-9]*\(',line):
                        funcName, params = self.getFunctionParams(line, lines)
                        if funcName and params:
                            funcName = funcName[0]
                            if "=" in line:
                                assignedVar = line.replace(" ", "").split("=")[0]
                                varObj.assignedTo = assignedVar
                            return True,funcName,params,"functionCall",None,None
                elif re.findall('[a-zA-Z0-9]+\((.*)\)', line) and "sizeof" not in line:
                    funcName = re.findall('([a-zA-Z0-9]+)\(', line)
                    params = isFunction[0].replace(" ", "").split(",")
                    if funcName:
                        funcName = funcName[0]
                        if "=" in line and "sizeof" not in funcName:
                            assignedVar = line.replace(" ", "").split("=")[0]
                            varObj.assignedTo = assignedVar
                            return True,funcName,params,"functionCall",None,None

                else:
                    if "=" in line and "+=" not in line and "-=" not in line:
                        lineData = ''.join(line.split(" ")).replace(";", "")
                        varName = lineData.split("=")[0]
                        varVal = lineData.split("=")[1]
                        varVal = self.reservedType(varVal)
                        if "." in varName:
                            return True,varName,varVal,"structMember",None,True
                        elif "->" in varVal:
                            hiddenStruct = re.match('(\w+)\s*=\s*\((\w+)\)(\w+)->(\w+)$', line)
                            hiddenStructNested = re.match('(\w+)\s*=\s*\((\w+)\)(\w+)->(\w+)->(\w+)', line)
                            if hiddenStruct:
                                assignedVar = hiddenStruct.group(1)
                                hiddenStructName = hiddenStruct.group(2)
                                hiddenVarName = hiddenStruct.group(3)
                                hiddenStructMember = hiddenStruct.group(4)
                                hiddenStructData = {"type":"regular",
                                                    "assignedVar":assignedVar,
                                                    "structName":hiddenStructName,
                                                    "structMemberName":hiddenStructMember,
                                                    "hiddenVarName":hiddenVarName}

                                return True,assignedVar,hiddenStructData,"hiddenStruct",None,True
                            elif hiddenStructNested:
                                assignedVar = hiddenStructNested.group(1)
                                hiddenStructName = hiddenStructNested.group(2)
                                hiddenVarName = hiddenStructNested.group(3)
                                hiddenStructMember = hiddenStructNested.group(4)
                                hiddenStructNestedMember = hiddenStructNested.group(5) 
                                hiddenStructData = {"type":"nested",
                                                    "assignedVar":assignedVar,
                                                    "structName":hiddenStructName,
                                                    "structMemberName":hiddenStructMember,
                                                    "hiddenVarName":hiddenVarName,
                                                    "hiddenNestedMember":hiddenStructNestedMember}
                                return True,assignedVar,hiddenStructData,"hiddenStruct",None,True


                        return True,varName,varVal,"variable",None,True
                    elif "+=" in line:
                        lineData = ''.join(line.split(" ")).replace(";", "")
                        varName = lineData.split("+=")[0]
                        varVal = lineData.split("+=")[1]
                        varVal = self.reservedType(varVal)
                        return True,varName,varVal,"varAdd",None,True
                    elif "-=" in line:
                        lineData = ''.join(line.split(" ")).replace(";", "")
                        varName = lineData.split("-=")[0]
                        varVal = lineData.split("-=")[1]
                        varVal = self.reservedType(varVal)
                        return True,varName,varVal,"varSub",None,True

        return False,None,None,None,None,None

    def pushNull(self):
        if x64:
            tmp = "\n  xor rbx, rbx\n"
            tmp += "  push rbx\n"
        else:
            tmp = "\n  xor ebx, ebx\n"
            tmp += "  push ebx\n"
        return tmp

    def pushString(self, str2push):
        varStr = str2push.replace('"', '')
        i = len(varStr)

        pushList = []
        while (i >= 0):
            if (i - 4 < 0):
                tmp = varStr[:i]
                pushList.append(tmp)
            else:

                tmp = varStr[i-4:i]
                pushList.append(tmp)
            i -= 4

        asmCode2 = self.pushNull()

        Flag = True  
        for word in pushList:
            data = word[::-1]
            wordLen = len(data)
            if wordLen == 4:
                wordHex = "".join("{:02x}".format(ord(c)) for c in data)
                prepAsm = f"  push 0x{wordHex}"
                asmLine = {"instr":prepAsm, "comment":data}
                asmCode2 += "{:47s};{}\n".format(prepAsm,lb+data+rst)

            elif wordLen == 2:
                wordHex = "".join("{:02x}".format(ord(c)) for c in data)
                prepAsm = f"  mov bx, 0x{wordHex}\n"
                prepAsm += "  push bx"
                asmLine = {"instr":prepAsm, "comment":data}
                asmCode2 += "{:64s};{}\n".format(prepAsm,lb+data+rst)

            elif wordLen == 1 or wordLen == 3:
                Flag = False
                wordHex = "".join("{:02x}".format(ord(c)) for c in data)
                tmp = wordHex + "00"

                letters = string.ascii_lowercase
                randStr = (''.join(random.choice(letters) for i in range(4)))
                randStr = "".join("{:02x}".format(ord(c)) for c in randStr)
              
                randStr2Int = int(randStr, 16)
                wordHex2Int = int(tmp, 16)
                Xored = randStr2Int ^ wordHex2Int
                Xored = hex(Xored).replace("0x", "")
              
                tmpAsm = '  mov ebx, 0x{}'.format(Xored)
                tmpAsm = "{:47s};{}\n".format(tmpAsm, lb+data+rst)
                tmpAsm += '  xor ebx, 0x{}\n'.format(randStr)
                if(wordLen == 1):
                    tmpAsm += '  push bx\n'
                else:
                    if x64:
                        tmpAsm += '  push rbx\n'
                    else:
                        tmpAsm += '  push ebx\n'
                if x64: 
                    tmpAsm += "  mov rbx, rsp\n"
                    tmpAsm += '  inc rbx\n'
                else:
                    tmpAsm += "  mov ebx, esp\n"
                    tmpAsm += '  inc ebx\n'
                
                asmCode2 += tmpAsm
        if Flag:
            if x64:
                prepAsm = "  push rsp"
                asmCode2 += "{:47s};{}\n".format(prepAsm,lb + str2push+rst)
                prepAsm = "  pop rbx\n"
                asmCode2 += "  pop rbx\n"
            else:
                prepAsm = "  push esp"
                asmCode2 += "{:47s};{}\n".format(prepAsm,lb + str2push+rst)
                prepAsm = "  pop ebx\n"
                asmCode2 += "  pop ebx\n"
        return asmCode2

    def pushAsciiX64(self, asciiArr):
        bytes_per_chunk = 8  # 4 UTF-16 chars = 8 bytes
        total_len = len(asciiArr)
        chunks = []
        i = 0
        while i < total_len:
            end = min(i + bytes_per_chunk, total_len)
            chunk = asciiArr[i:end]
            while len(chunk) < bytes_per_chunk:
                chunk.append('00')
            chunks.append(chunk)
            i += bytes_per_chunk
        
        asm = ""
        total_size = len(chunks) * bytes_per_chunk
        asm += f"  sub rsp, 0x{total_size:02x}\n"
        
        for idx, chunk in enumerate(chunks):
            hex_str = ''.join(chunk)
            bytes_le = bytes.fromhex(hex_str)
            little_endian = ''.join(f"{b:02x}" for b in reversed(bytes_le))
            offset = f"+{idx * bytes_per_chunk}" if idx != 0 else ""
            asm += f"  mov rax, 0x{little_endian}\n"
            asm += f"  mov qword ptr[rsp{offset}], rax\n"
        
        asm += "  mov rbx, rsp\n"
        return asm


    def pushAscii(self, asciiArr):
        if x64:
            return self.pushAsciiX64(asciiArr)
        length = len(asciiArr)
        i = 0
        newData = []
        asm = ""
        while(i < length):
            if(i+4) > length:
                tmp = ''.join(asciiArr[i:])
                newData.append(f"{tmp}")
            else:
                tmp = ''.join(asciiArr[i:i+4])
                newData.append(f"{tmp}")
            i+=4
        newData.reverse()
        numberOfPushes = 0
        for group in newData:
            numberOfPushes += 1
            newHex = ""
            for byte in reversed(bytes.fromhex(group)):
                b = format(byte, '02x')
                newHex += b
            asm += f"  push 0x{newHex}\n"
        if x64:
            asm += "  mov rbx, rsp\n"
            asm += f"  add rsp, {hex(numberOfPushes*4)}\n"
        else:
            asm += "  mov ebx, esp\n"
            asm += f"  add esp, {hex(numberOfPushes*4)}\n"
        return asm 

    def initUnicode(self, ptrName, unicode, length, line):
        asm = ""
        data = {
            "u":unicode,
            "len":length
        }
        found = False
        for vr in mainVars:
            if vr.Type == "structInstance":
                #for st in structs:
                if ptrName == vr.Name:
                    asm += self.structMember(f"{vr.Name}.Buffer", f"u:{unicode}")
                    asm += self.structMember(f"{vr.Name}.Length", f"{length}")
                    found = True
                    break
        if found:
            return asm
        else:
            print(f"{red}Error: could not match structure name{rst}")
            print(f"{w}Error line: {line}{rst}")
            sys.exit()

    def reAssign(self, rName, rValue):
        for var in mainVars:
            if var.Name == rName:
                var.Value = rValue

    def removeAsmComments(self, asm):
        #ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        cleaned_lines = []
        for line in asm.split('\n'):
            line = ansi_escape.sub('', line)
            line = re.sub(r';.*$', '', line).strip()
            if line:  # Keep non-empty lines
                cleaned_lines.append(line)
        #line = re.sub(r';.*$', '', line).strip()
        return '\n'.join(cleaned_lines)
        #return ansi_escape.sub('', asm)

    def genRandStr(self, length):
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for _ in range(length))

    def parseWhileLoop(self, loopType,line, lines):
        loopObj = whileLoop()
        LoopStartAt = lines.index(line)
        asm = ""
        if loopType == "start":
            loopStr = self.genRandStr(3)
            loopStart = f"loopStart_{loopStr}"
            loopObj.loopStart = f"loopStart_{loopStr}"
            loopStr = self.genRandStr(3)
            loopObj.loopEnd = f"loopEnd_{loopStr}"
            allLoops[0] = loopObj
            asm += f"{lb}{loopStart}:{rst}\n"
        elif loopType == "end":
            loopData = allLoops[0]
            loopStart = loopData.loopStart
            loopEnd = loopData.loopEnd
            asm += f"  jmp {lb}{loopStart}{rst}\n"
            asm += f"{lb}{loopEnd}{rst}:\n"
        else:
            print(f"{red}Error: could not parse while loop{rst}")
            print(f"{w}Error line: {line}{rst}")
            sys.exit()
        return asm

    def recvBreak(self, op, jmpTo):
        asm = ""
        asm += f"  {op} {lb}{jmpTo}{rst}\n"
        return asm

    def hiddenStructAsm(self, varName, offset, hiddenVarName, size):
        asm = ""
        srcVarEbp = None 
        destVarEbp = None
        data_types = {"0x8":"qword","0x4":"dword", "0x2":"word", "0x2":"byte"}
        register_type = {"0x4":"ebx", "0x8":"rbx"}
        for ebp in ebpVars:
            vName, ebpVal = next(iter(ebp.items()))
            if vName == hiddenVarName:
                srcVarEbp = ebpVal
            elif vName == varName:
                destVarEbp = ebpVal
        if srcVarEbp and destVarEbp:
            if x64:
                prepAsm = f"  mov rbx, qword ptr[{srcVarEbp}]"
            else:
                prepAsm = f"  mov ebx, dword ptr[{srcVarEbp}]"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Get address of "+hiddenVarName+rst)

            dType = data_types.get(size)
            if not dType:
                print("couldn't find for ", size, hiddenVarName, varName, offset)

            register = register_type.get(size)
            if offset == 0:
                if x64:
                    prepAsm = f"  mov {register}, {dType} ptr[rbx]"
                else:
                    prepAsm = f"  mov ebx, dword ptr[ebx]"
            else:
                if x64:
                    prepAsm = f"  mov {register}, {dType} ptr[rbx+{hex(offset)}]"
                else:
                    prepAsm = f"  mov ebx, dword ptr[ebx+{hex(offset)}]"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Access offset " + str(hex(offset)) + " in " +hiddenVarName+rst)
            if x64:
                prepAsm = f"  mov qword ptr[{destVarEbp}], rbx"
            else:
                prepAsm = f"  mov dword ptr[{destVarEbp}], ebx"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Copy value to " +varName+rst)
        return asm

    def findHiddenStruct(self, structName):
        for hs in hiddenstructs:
            if hs.Name == structName:
                return hs.Members
        return False

    def findSizeByDataType(self):
        pass
    def findNestedMemberSize(self, data, nestedMember):
        totalSize = 0
        found = False
        offset = 0
        size = 0
        iteration = 0
        for count,field in enumerate(data):
            for size_str, name in field.items():
                size = int(size_str, 16)
                if x64:
                    #alignment = min(size, 8) if size <= 8 else 8
                    pad = (size - (offset % size)) % size
                    offset += pad
                    #if offset % alignment != 0:
                    #    print(f"[*] Offset {offset} not aligned, alignment {alignment}")
                    #    pad = alignment - (offset % alignment)
                    #    print(f"Aligning offset {offset} , padding {pad}")
                    #    offset += pad
                if name == nestedMember:
                    if count == 0:                                                                                         
                        offset = 0                                                                                         
                    return True, offset, size                                                                              
                offset += size 
        return False, offset, size  

    def hiddenStruct(self, varName, structData):
        hiddenType = structData["type"]
        structName = structData["structName"]
        structMember = structData["structMemberName"]
        hiddenVarName = structData["hiddenVarName"]
        offset = 0
        found = False
        foundSize = 0
        members = self.findHiddenStruct(structName)
        if not members:
            print(f"{red}Error: could not find struct name structName {rst}")
            sys.exit()
        sizeAndName = [(key, value) for memberDict in members for key, value in memberDict.items()]
        sizeAndNameDict = [{key :value} for memberDict in members for key, value in memberDict.items()]
        if hiddenType == "regular":
            found, recvSize, memberSize = self.findNestedMemberSize(sizeAndNameDict, structMember)
            if found:
                if memberSize < 1:
                    print(f"[!] Error: invalid member size")
                    sys.exit()
                #foundSize = f"{hex(recvSize)}"
                offset += recvSize
                memberSize = f"0x{memberSize}"
            else:
                print(f"[!] Error: couldn't find member size")
                sys.exit()
            #offset1 = 0
            #for size1, name1 in sizeAndName:
            #    if structMember == name1:
            #        found1 = True
            #        foundSize1 = size1
            #        offset1 += int(size1, 16)
            #        break
            #    offset1 += int(size1, 16)
            #print(offset1, foundSize1 , offset, foundSize) 
            #input("Result------------")


        elif hiddenType == "nested":
            nestedMember = structData["hiddenNestedMember"]
            for size, name in sizeAndName:
                if type(name) == dict:
                    memberNameAndPtr = [i for i in name][0]
                    memberName = memberNameAndPtr.split("->")[0]
                    if memberName == structMember:
                        found, recvSize, memberSize = self.findNestedMemberSize(name[memberNameAndPtr], nestedMember)
                        offset += recvSize
                        memberSize = f"{hex(memberSize)}"
                        if found:
                            break
                else:
                    offset += int(size, 16)

        if not found:
            print(f"{red}Error: could not find member {structMember}, are you sure it's not nested member ? {rst}")
            sys.exit()
        asm = self.hiddenStructAsm(varName, offset, hiddenVarName, memberSize)
        return asm
         

    def ifStatement(self, data, line):
        operator = re.search("(==)|(!=)|(>=)|(<=)|(>)|(<)", data)
        data = data.replace(" ", "")
        ifDetected[0] = True
        if operator:
            op = operator.group()
            if op == "==":
                asmOp = "je"
            elif op == "!=":
                asmOp = "jne"
            elif op == ">=":
                asmOp = "jge"
            elif op == "<=":
                asmOp = "jle"
            elif op == ">":
                asmOp = "jg"
            elif op == "<":
                asmOp = "jl"
            left = data.split(op)[0]
            right = data.split(op)[1]
            return asmOp,left,right
        else:
            print(f"{red}Error: could not read if statement operator{rst}")
            print(f"{w}Error line: {line}{rst}")
            sys.exit()

    def ifStatementAsm(self, op, left, right, lType, rType, line, name):
        asm = ""
        leftEbp = self.findEbpVar(left)
        leftEbpValue = leftEbp[left]
        loopData = allLoops[0]
        loopEnd = loopData.loopEnd
        if loopDetected[0]:
            if rType != "string":
                breakData[0] = {op:loopEnd}
            elif rType == "string":
                breakData[0] = {"jecxz":loopEnd}
        if rType == "int":
            if x64:
                asm += f"  mov rax, qword ptr[{leftEbpValue}]\n"
                asm += f"  cmp rax, {hex(int(right))}\n"
            else:
                asm += f"  mov eax, dword ptr[{leftEbpValue}]\n"
                asm += f"  cmp eax, {hex(int(right))}\n"
        elif rType == "hex":
            if x64:
                asm += f"  mov rax, qword ptr[{leftEbpValue}]\n"
                asm += f" cmp rax, {right}"
            else:
                asm += f"  mov eax, dword ptr[{leftEbpValue}]\n"
                asm += f" cmp eax, {right}"
        elif rType == "string":
            if x64:
                asm += f"  mov rdi, dword ptr[{leftEbpValue}]\n"
            else:
                asm += f"  mov edi, dword ptr[{leftEbpValue}]\n"
            rtnStringVal = self.pushString(right)
            asm += rtnStringVal
            strLen = self.sizeOf(f"sizeof({right})")
            if x64:
                asm += f"  mov rsi, rbx\n"
                asm += f"  mov rcx, {strLen}\n"
            else:
                asm += f"  mov esi, ebx\n"
                asm += f"  mov ecx, {strLen}\n"
            asm += "  cld\n"
            asm += "  repe cmpsb\n"
        elif rType == "variable":
            for v in mainVars:
                if v.Name == name:
                    if any(reg in right for reg in ("ebp", "rbp")) and v.Type == "unicode":
                        if x64:
                            asm += f"  mov rdi, qword ptr[{leftEbpValue}]\n"
                            asm += f"  mov rsi, qword ptr[{right}]\n"
                            asm += f"  mov rcx, {hex(v.Length)}\n"
                        else:
                            asm += f"  mov edi, dword ptr[{leftEbpValue}]\n"
                            asm += f"  mov esi, dword ptr[{right}]\n"
                            asm += f"  mov ecx, {hex(v.Length)}\n"
                        asm += "  cld\n"
                        asm += "  repe cmpsb\n"
        else:
            print(f"{red}Error: could not evaluate right side of if statement{rst}")
            print(f"{w}Error line: {line}{rst}")
            sys.exit()
        return asm

    def sysCallAsm(self):
        asm = ""
        asm += f"{lb}invokeSysCall{rst}:\n"
        if x64:
            asm += f"  syscall\n"
        else:
            asm += f"  call {y}dword{rst} ptr fs:[0xc0]\n"
        asm += f"  ret\n"
        asm += f"{lb}Begin{rst}:\n"
        return asm

    def checkSyscallNumAsm(self, modelNum):
        asm = ""
        for api, val in syscallsAndApiNum.items():
            if x64:
                asm += f"  cmp rdi, {val}\n"
            else:
                asm += f"  cmp edi, {val}\n"
            syscallNum = readSysCalls(api, modelNum, False)
            if x64:
                asm += f"  mov rbx, {syscallNum}\n"
                asm += f"  cmovz rdi, rbx\n"
            else:
                asm += f"  mov ebx, {syscallNum}\n"
                asm += f"  cmovz ecx, ebx\n"
        asm += "  ret\n"
        return asm

    def GetSyscallNumber(self):
        asm = ""
        asm += f"jmp {lb}Begin{rst}\n"
        asm += f"{lb}m_10240:{rst}\n"
        asm += self.checkSyscallNumAsm("10240")
        asm += f"{lb}m_10586:{rst}\n"
        asm += self.checkSyscallNumAsm("10586")
        asm += f"{lb}m_14393:{rst}\n"
        asm += self.checkSyscallNumAsm("14393")
        asm += f"{lb}m_15063:{rst}\n"
        asm += self.checkSyscallNumAsm("15063")
        asm += f"{lb}m_16299:{rst}\n"
        asm += self.checkSyscallNumAsm("16299")
        asm += f"{lb}m_17134:{rst}\n"
        asm += self.checkSyscallNumAsm("17134")
        asm += f"{lb}m_17763:{rst}\n"
        asm += self.checkSyscallNumAsm("17763")
        asm += f"{lb}m_18362:{rst}\n"
        asm += self.checkSyscallNumAsm("18362")
        asm += f"{lb}m_18363:{rst}\n"
        asm += self.checkSyscallNumAsm("18363")
        asm += f"{lb}m_19041:{rst}\n"
        asm += self.checkSyscallNumAsm("19041")
        asm += f"{lb}m_19042:{rst}\n"
        asm += self.checkSyscallNumAsm("19042")
        asm += f"{lb}m_19043:{rst}\n"
        asm += self.checkSyscallNumAsm("19043")
        asm += f"{lb}m_19044:{rst}\n"
        asm += self.checkSyscallNumAsm("19044")
        asm += f"{lb}m_19045:{rst}\n"
        asm += self.checkSyscallNumAsm("19045")
        asm += f"{lb}m_22000:{rst}\n"
        asm += self.checkSyscallNumAsm("22000")
        asm += f"{lb}m_20348:{rst}\n"
        asm += self.checkSyscallNumAsm("20348")
        asm += f"{lb}m_22621:{rst}\n"
        asm += self.checkSyscallNumAsm("22621")
        asm += f"{lb}m_22631:{rst}\n"
        asm += self.checkSyscallNumAsm("22631")
        asm += f"{lb}m_25398:{rst}\n"
        asm += self.checkSyscallNumAsm("25398")
        asm += f"{lb}m_26100:{rst}\n"
        asm += self.checkSyscallNumAsm("26100")

        return asm

    def GetModelNumber(self):
        asm = ""
        asm += f"""{lb}GetSysModelNumber{rst}:
"""
        if x64:
            asm += """  mov rax, gs:[0x60]
  mov rax, [rax+0x120]
  and rax, 0xffff
"""     
        else:
            asm += f"""  mov edx, fs:[0x30]
  mov eax, [edx+0xAC]
  and eax, 0xFFFF
  """
        asm += """ cmp eax, 10240
  je m_10240
  cmp eax, 10586
  je m_10586
  cmp eax, 14393
  je m_14393
  cmp eax, 15063
  je m_15063
  cmp eax, 16299
  je m_16299
  cmp eax, 17134
  je m_17134
  cmp eax, 17763
  je m_17763
  cmp eax, 18362
  je m_18362
  cmp eax, 18363
  je m_18363
  cmp eax, 19041
  je m_19041
  cmp eax, 19042
  je m_19042
  cmp eax, 19043
  je m_19043
  cmp eax, 19044
  je m_19044
  cmp eax, 19045
  je m_19045
  cmp eax, 22000
  je m_22000
  cmp eax, 20348
  je m_20348
  cmp eax, 22621
  je m_22621
  cmp eax, 22631
  je m_22631
  cmp eax, 25398
  je m_25398
  cmp eax, 26100
  je m_26100
  ret
"""
        return asm

    def stackSpace(self):
        if x64:
            asm = "push rbp\n"
            asm += "mov rbp, rsp\n"
            asm += "sub rsp, 0x500\n"
        else:
            asm = "push ebp\n"
            asm += "mov ebp, esp\n"
            asm += "sub esp, 0x500\n"
        return asm
    
    def stackEnd(self):
        if x64:
            asm = "leave\n"
            asm += "ret\n"
        else:
            asm = "leave\n"
            asm += "ret\n"
        return asm
    
    def ignoreRawBytes(self, asm):
        assemblyOnly = '\n'.join(
        line for line in asm.split('\n') if not line.strip().startswith(';;;'))
        return assemblyOnly
    def convertToMasmHex(self, assembly):
        lines = assembly.split('\n')
        converted_lines = []
        for line in lines:
            converted_line = re.sub(
            r'0x([0-9a-fA-F]+)',
            lambda m: f"0{m.group(1)}h" if m.group(1)[0].upper() in 'ABCDEF' else f"{m.group(1)}h",
            line
        )
            #converted_line = re.sub(r'0x([0-9a-fA-F]+)', lambda m: f"{m.group(1)}h", line)
            converted_lines.append(converted_line)
        return '\n'.join(converted_lines)
    
    def formatAssemblyAndComments(self, code):
        asm = ""
        instrAndComments = []
        for line in code.split("\n"):                                                                                     
            line = line.replace(lb, "").replace(y, "").replace(o, "").replace(rst, "") 
            try:
                instr, comment = [part for part in (line.split(";", 1) + [""])[:2]]
                instrAndComments.append({"instruction":instr, "comment":comment})
            except Exception as e:
                raise
        longest_instruction_len = max(len(line["instruction"]) for line in instrAndComments) + len(o) + len(rst)
        for line in instrAndComments:
            try:
                instruction = line["instruction"]
                comment = line["comment"]
                is_label = re.search(r".*:$", instruction)
                padded_line = instruction.ljust(longest_instruction_len)
                colored_instr = (f"{lb}{instruction}{rst}" if is_label 
                           else f"{w}{instruction}{rst}")
                colored_instr = colored_instr.ljust(longest_instruction_len)
                if comment:
                    comment = re.sub(
                        r'(:\s*)(.*)',  # Capture group 1: colon + spaces, group 2: everything after
                        lambda m: f"{m.group(1)}{g}{m.group(2)}{rst}",
                        comment,
                        count=1  # Only replace first occurrence
                    )
                    colored_instr += f"  ; {o}{comment}{rst}"
                asm += f"{colored_instr}\n"
            except Exception as e:
                raise
        return asm

    def parseMain(self, lines):
        finalAssm = ""
        self.asmObj.assembly = ""
        try:
            for index, line in enumerate(lines):
                varObj = Vars()
                isValid,rName,rValue,rType,rSize,isAssigned = self.checkType(index, lines, line, varObj)
                if isValid:
                    if rType == "struct" or rType == "structPtr":
                        mainVars.append(varObj)
                        asm = self.toAssembly("newstruct",rName, rValue, rSize)
                        finalAssm += f"{asm}"
                    elif rType == "while" and rValue == "start":
                        asm = self.parseWhileLoop("start", line, lines)
                        finalAssm += asm
                        loopDetected[0] = True
                    elif rType == "while" and rValue == "end":
                        asm = self.parseWhileLoop("end", line, lines)
                        finalAssm += asm
                        loopDetected[0] = False
                    elif rType == "hiddenStruct":
                        asm = self.hiddenStruct(rName, rValue)
                        finalAssm += asm
                    elif rType == "if" and rValue != "end":
                        op,left,right = self.ifStatement(rValue, line)
                        leftType = self.getValueType(left)
                        if leftType == "variable":
                            leftValue = self.getVarValue(left)
                        elif leftType == "int" or leftType == "string":
                            print(f"Error: {line}\nLeft side cannot be a string or integer")
                            sys.exit()
                        rightType = self.getValueType(right)
                        if rightType == "variable":
                            rightValue = self.getVarValue(right)
                            rightType = self.getValueType(rightValue)
                        else:
                            rightValue = right
                        finalAssm += self.ifStatementAsm(op, left, rightValue, leftType, rightType, line, right)
                    elif rType == "if" and rValue == "end":
                        ifDetected[0] = False
                    elif rType == "break":
                        if loopDetected[0]:
                            #loopDetected[0] = False
                            if breakData[0] is not None:
                                for op, jmpTo in breakData[0].items():
                                    finalAssm += self.recvBreak(op, jmpTo)
                            else:
                                print(f"{red}Error: loop and break detected, but break data not found")
                                print(f"{w}Error line: {line}{rst}")
                                sys.exit()
                            breakDetected[0] = True
                    elif rType == "unicode":
                        ptr, inStr = self.extractString(rValue)
                        
                        if ptr and inStr:
                            hexStr = self.toHex(inStr)
                            unicodeStr = self.toUnicode(hexStr)
                            varObj.Name = ptr 
                            varObj.Type = rType
                            varObj.Value = inStr
                            ucodeLen = len(unicodeStr)
                            varObj.Length = ucodeLen 
                            mainVars.append(varObj)
                            finalAssm += self.initUnicode(ptr, inStr, ucodeLen, line)
                    elif rType == "variable" or rType == "varAdd" or rType == "varSub":
                        varObj.Name = rName 
                        varObj.Type = rType 
                        varObj.Value = rValue
                        varObj.assigned = isAssigned
                        varObj.Size = rSize
                        exist, assigned = self.isExist(rName)
                        if not exist and isAssigned and rSize:
                            mainVars.append(varObj)
                        if not exist and not isAssigned:
                            mainVars.append(varObj)
                        if exist and not isAssigned and not rValue:
                            print(f"[!] {red}Error{rst} Line: {lb+line+rst}")
                            print(f"[!] {red}Error:{rst} cannot redefine variable {lb+rName+rst}")
                            return
                        if not exist and isAssigned and not rSize:
                            print(f"[!] {red}Error{rst} Line: {lb+line+rst}")
                            print(f"[!] {red}Error:{rst} Variable {lb+rName+rst} is not defined")
                            return
                        if exist and isAssigned and rValue:
                            self.reAssign(rName, rValue)
                        if rValue:
                            if rType == "varAdd":
                                assm = self.toAssembly("newVarAdd", rName,rValue,rSize)
                            elif rType == "varSub":
                                assm = self.toAssembly("newVarSub", rName,rValue,rSize)
                            else:
                                assm = self.toAssembly("newVar", rName,rValue,rSize)
                            finalAssm += f"{assm}\n"
                            currentStack = self.asmObj.stackStart

                    elif rType == "functionCall":
                        varObj.Name = rName 
                        varObj.Type = rType 
                        varObj.Value = rValue
                        mainVars.append(varObj)
                        assm = self.toAssembly("funcCall", rName,rValue,"None",varObj.assignedTo)
                        finalAssm += f"{assm}\n"
                    elif rType == "structMember":
                        varObj.Name = rName 
                        varObj.Type = rType 
                        varObj.Value = rValue
                        mainVars.append(varObj)
                        assm = self.toAssembly("structMember",rName,rValue,"None",varObj.assignedTo)
                        finalAssm += assm
            #print(f"{self.asmObj.dotData}")
        except Exception as e:
            raise
        self.asmObj.assembly += self.stackSpace()
        self.asmObj.assembly += self.GetSyscallNumber()
        self.asmObj.assembly += self.GetModelNumber()
        self.asmObj.assembly += self.sysCallAsm()
        self.asmObj.assembly += finalAssm
        self.asmObj.assembly += self.stackEnd()
        if nasm:
            if dataSection:
                self.asmObj.nasm += self.assemblerDataSection()
            self.asmObj.nasm += self.asmObj.assembly
            nasmAsmTemp = self.asmObj.nasm
            nasmAsmTemp = self.ignoreRawBytes(nasmAsmTemp)
            self.asmObj.nasm = nasmAsmTemp.replace("ptr", "")
            self.asmObj.nasm = self.formatAssemblyAndComments(self.asmObj.nasm)
            noCommentAsm = self.removeAsmComments(self.asmObj.nasm)
            shellcode = self.asm2Shellcode(noCommentAsm)
            self.asmObj.shellcode = shellcode
            
        elif masm:
            if dataSection:
                self.asmObj.nasm += self.assemblerDataSection()
            self.asmObj.masm += self.ignoreRawBytes(self.asmObj.assembly)
            self.asmObj.masm = self.formatAssemblyAndComments(self.asmObj.masm)
            noCommentAsm = self.removeAsmComments(self.asmObj.masm)
            shellcode = self.asm2Shellcode(noCommentAsm)
            self.asmObj.shellcode = shellcode
        finalAssembly.append(self.asmObj)
        noCommentAsm = self.removeAsmComments(self.asmObj.assembly)
        #shellcode = self.asm2Shellcode(noCommentAsm)
        #self.asmObj.shellcode = shellcode

    def readMain(self,lines):
        code = None
        try:
            mainLines = [k.replace("\n", "").strip() for k in lines]
            mainLines = list(filter(None, mainLines)) 
            if mainLines[1] == "{" and mainLines[-1] == "}":
                code = mainLines[2:-1]
            else:
                for num, line in reversed(list(enumerate(mainLines))):
                    if line == "}":
                        code = mainLines[2:num]
                        break
        except Exception as e:
            raise
        if code:
            self.parseMain(code)

    def hiddenStructFound(self, struct, structObj, structName, structPtr):
        constTypes = {
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
            "ACCESS_MASK":0x4,
            "LARGE_INTEGER":0x8}

        struct = struct[1:-1]
        types = dataTypes if x64 else dataTypes_x86
        try:
            for stLine in struct:
                memSize = 0
                stLine = stLine.lstrip()
                dType = stLine.strip().split(" ")[0]
                if dType in types:
                    memberName = stLine.strip().split(" ")[-1]
                    memberName = memberName.replace(";", "")
                    possibleArr = re.search(r'\[(\d+)\]', memberName)
                    if possibleArr:
                        arrSize = possibleArr.group(1)
                        memSize += (types[dType] * int(arrSize))
                    else:
                        memSize += types[dType]
                    memDict = {hex(memSize):memberName}
                    structObj.Members.append(memDict)
                else:
                    for st in structs:
                        if st.Name in dType:
                            totalStructSize = 0
                            hexSizes = [list(item.keys())[0] for item in st.Members]
                            decimalSizes =  [int(size, 16) for size in hexSizes]
                            totalStructSize += sum(decimalSizes)
                            dName = stLine.split(" ")[1]
                            dName = dName.strip().replace("\n", "").replace(";","")
                            memDict = {hex(totalStructSize):{dName+"->"+st.Name:st.Members[::-1]}}
                            structObj.Members.append(memDict)
        except Exception as e:
            raise

    def structFound(self,struct, structObj, structName, structPtr):
        struct = struct[1:-1]
        types = dataTypes if x64 else dataTypes_x86
        size = 0
        structRev = struct[::-1]
        try:
            for stLine in structRev:
                currentStackPtr = self.asmObj.stackStart
                stLine = stLine.lstrip()
                dType = stLine.split(" ")[0]
                if dType in types:
                    memberName = stLine.split(" ")[-1].strip()
                    memberName = memberName.replace(";", "")
                    possibleArr = re.search(r'\[(\d+)\]', memberName)
                    if possibleArr:
                        arrSize = possibleArr.group(1)
                        size += (types[dType] * int(arrSize))
                    else:
                        size += types[dType]
                    memDict = {hex(types[dType]):memberName}
                    structObj.Members.append(memDict)
                else:
                    for st in structs:
                        if st.Name in dType:
                            dName = stLine.split(" ")[1]
                            dName = dName.strip().replace("\n", "").replace(";","")
                            ptrLoc = st.Members[0]
                            ptrHex = [x for x in ptrLoc][0]
                            memDict = {hex(4):dName+"->"+dType}
                            structObj.Members.append(memDict)
        except Exception as e:
            raise
        structObj.totalSize = size


    def toUnicode(self, Arr):
        newArr = []
        for i in Arr:
            newArr.append(i)
            newArr.append('00')
        return newArr
         
    def getStructData(self, chunk):
        for count, value in enumerate(chunk):
            if "," in value and "*" in value:
                return(chunk[:count+1])
            elif "}" in value and ";" in value:
                return (chunk[:count+1])
        
    def getStructNameAndPointer(self, chunk):
        line = chunk[-1]
        name = re.findall('[a-zA-Z0-9_]+,', line)
        ptr = re.findall('[a-zA-Z0-9_]+;', line)
        if ptr and not name:
            return(ptr[0][:-1], "")

        elif name and ptr:
            return(name[0][:-1], ptr[0][:-1])
    
    def toHex(self, Arr):
        converted = []
        try:
            for char in Arr:
                ordDec = ord(str(char))
                Hex = f'{ordDec:x}'
                converted.append(Hex)
            return converted
        except Exception as e:
            raise

    def extractString(self, line):
        getString = re.search('InitUnicodeStr\((.*),\s*(.*)\)', line)
        if getString:
            inStr = getString.group(2).replace('"',"")
            structPtr = getString.group(1)
            return structPtr,inStr
        else:
            print(f"{red}Error: cannot extract unicode string{rst}")
            print(f"Error line: {line}")
            sys.exit()

    def debug(self, text, Type):
        dbg = "[{}] {}".format(o + "*" + rst, g + "DEBUG" + rst)
        print("{} {} {}".format(dbg, c + text+ rst, red + Type + rst))

    def parser(self, lines):
        try:
            for count, line in enumerate(lines): 
                if "typedef" in line and "struct" in line:
                    self.structObj = Structs()
                    structData = self.getStructData(lines[count:])
                    structName, structPtr = self.getStructNameAndPointer(structData)
                    self.structObj.Name = structName
                    self.structObj.Pointer = structPtr 
                    self.structObj.Lines = structData 
                    structs.append(self.structObj)
                    self.structFound(self.structObj.Lines, self.structObj, structName, structPtr)
                    continue
                elif "hidden" in line and "struct" in line:
                    self.structObj = Structs()
                    structData = self.getStructData(lines[count:])
                    structName, structPtr = self.getStructNameAndPointer(structData)
                    self.structObj.Name = structName
                    self.structObj.Pointer = structPtr 
                    self.structObj.Lines = structData 
                    hiddenstructs.append(self.structObj)
                    self.hiddenStructFound(self.structObj.Lines, self.structObj, structName, structPtr)
                elif "<MAIN>" in line:
                    self.readMain(lines[count:])
            return True
        except Exception as e:
            raise
            return False

    def readFile(self):
        allLines = []
        with open(self.file, "r") as content:
            for line in content:
                allLines.append(line)

        return self.parser(allLines)


def show_help():
    table = Table(title="\nAvailable Commands", 
                 show_header=True, 
                 header_style="bold magenta",
                 box=box.ROUNDED,
                 border_style="dim blue")
    
    table.add_column("Command", style="cyan", width=30)
    table.add_column("Description", style="green")

    # Configuration Group
    table.add_row("  set arch <x64|x86>", "Switch between 32/64-bit modes")
    table.add_row("  set assembler <masm|nasm>", "Select assembler syntax")
    table.add_row("  generate shellcode", "Output raw bytes")
    table.add_row("  generate assembly", "Output assembly instructions")
    table.add_row("  generate binary", "Output nasm generated binary")
    table.add_row("  enable data", "Enable .data section. Important if using third party shellcode")
    table.add_row("  load <filename>", "Load custom C file")
    table.add_row("  help", "Print this help menu")
    console.print(table)


def help():
    allText = ""
    allText += "\n"
    allText += f"\t  {y}******************\n"
    allText += f"\t  ******{o} Help{y} ******\n"
    allText += f"\t  {y}******************{rst}"

    T = f"""
 {w}
 load  [filepath]       Load and read c file from given path 
 print assembly         Translate c code to assembly
 print shellcode        Convert assembly to shellcode
 exit                   Exit the program                        
 {rst}

    """
    print(allText)
    print(T)


def readSysCalls(syscall_name, model_number=None, find_api_num=None):
    csv_file = "syscallslist.csv"
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        headers = next(reader)
        try:
            for row in reader:
                api_num = row[0]
                ntApiName = row[1]
                if ntApiName == syscall_name:  # Check System call column
                    if find_api_num:
                        return hex(int(api_num))  # Return the line number
                    else:
                        col_index = headers.index(model_number)
                        return row[col_index]  # Return the syscall number in hex
        except Exception as e:
            raise
            return None  # Model number not found
    
    return None  # Syscall not found


def readSysCalls2(syscall_name, model_number=None, find_api_num=None):
    try:
        file_path = "syscallslist.txt"
        data_dict = {}
        apis_and_nums = {}
        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter='\t')
            header = next(reader)
            for row in reader:
                service_name = row[1]
                service_id = row[0]
                api_num_dict = {service_name:service_id}
                apis_and_nums.update(api_num_dict)
                values = row[2:]  # Values start from index 2 onward
                data_dict[service_name] = {}
                for i, value in enumerate(values):
                    column_number = header[i+2]  # +2 to skip # and ServiceName columns
                    if value.strip():
                        data_dict[service_name][column_number] = value
                    else:
                        data_dict[service_name][column_number] = None
        if not find_api_num:
            if syscall_name in data_dict and model_number in data_dict[syscall_name]:
                value = data_dict[syscall_name][model_number]
                return hex(int(value, 16))
            else:
                return None
        else:
            api_num = apis_and_nums[syscall_name]
            return hex(int(api_num))
    except Exception as e:
        raise


def getAssemblerCmd():
    nasm_command = [
    "nasm",
    "-f", "win64",
    "-o", "main.obj",
    "main.asm"
    ]
    return nasm_command

def generateBinary(rawAssembly):
    writeAsmToFile(rawAssembly)
    assemblyCmd = getAssemblerCmd()
    binFileName = input(f"{c}[*]{rst} Enter file name: ")
    if not binFileName.lower().endswith(".exe"):
        binFileName += ".exe"
    compileCmd = getCompilerCmd(binFileName)
    console.print("[bold cyan]Assembling...[/bold cyan]")
    run_with_progress("run", assemblyCmd)
    console.print("[bold cyan]Compiling...[/bold cyan]")
    if run_with_progress("run", compileCmd):
        output_path = os.path.join("bin", binFileName)
        print(f"File saved to {g}{output_path}{rst}")

def getCompilerCmd(outputFileName):
    os.makedirs("bin", exist_ok=True)
    full_output_path = os.path.join("bin", outputFileName)
    mingw_command = [
    "x86_64-w64-mingw32-gcc",
    "-o", full_output_path,
    "main.obj",
    "-lkernel32",
    "-mconsole",
    "-nostartfiles"
    ]
    return mingw_command

def writeAsmToFile(asmCode):
    nasm_syntax = """
global _start
section .text
_start:
    """
    try:
        with open("main.asm", "w") as f:
            #f.write(nasm_syntax)
            f.write(asmCode)
        return True
    except:
        return False

def cli():
    completer = ContextCompleter()
    readline.set_completer(completer.complete)
    system_name = platform.system()
    global x64
    global masm 
    global nasm
    global dataSection
    if system_name == "Darwin":
        readline.parse_and_bind('bind ^I rl_complete')
    elif system_name == "Linux":    
        readline.parse_and_bind('tab: complete')
    readerObject = None
    while True:
        try:
            fullCmd = input(f"{brblk}S{o}I{y}L{o}O{brblk}>{rst} ")
            if not fullCmd.strip():
                continue
            else:
                cmdLine = fullCmd.split(" ")
                numArgs = len(cmdLine)
                if numArgs == 2:
                    cmd = cmdLine[0]
                    if cmd.lower() == "load":
                        filePath = cmdLine[1]
                        try:
                            console.print("[bold cyan]Loading file...[/bold cyan]")
                            r = Reader(filePath)
                            readerObject = r
                            run_with_progress("readfile", r)
                        except Exception as e:
                            print(f"{w}{e}{rst}")
                    elif cmd.lower() == "generate":
                        cType = cmdLine[1]
                        if cType == "assembly":
                            if masm:
                                if len(Reader.asmObj.masm) < 1:
                                    print(f"{y}[!]{rst} {c}Please load a file first")
                                else:
                                    print("\n")
                                    print(Reader.asmObj.masm)
                            elif nasm:
                                if len(Reader.asmObj.nasm) < 1:
                                    print(f"{y}[!]{rst} {c}Please load a file first")
                                else:
                                    print("\n")
                                    print(Reader.asmObj.nasm)
                            else:
                                print("\n")
                                print(Reader.asmObj.assembly)

                        elif cType == "shellcode":
                            print("\n")
                            print(Reader.asmObj.shellcode)
                        elif cType == "binary":
                            if len(Reader.asmObj.nasm) < 1:
                                print(f"{y}[!]{rst} {c}Please load a file first")
                            else:
                                if nasm:
                                    rawAssembly = readerObject.removeAsmComments(Reader.asmObj.nasm)
                                    generateBinary(rawAssembly)
                                else:
                                    print(f"{y}[!]{rst} {c}Sorry, only NASM works for binary generation.")
                                    
                        else:
                            print(f"{red}[!]{rst} Invalid command")
                    elif cmd.lower() == "enable" and cmdLine[1] == "data":
                        if dataSection:
                            print(f"{c}[*]{rst} Data section already enabled")
                        else:
                            dataSection = True
                            print(f"{c}[*]{rst} Data section enabled")

                    else:
                        print(f"{red}[!]{rst} Invalid command")
                        continue
                elif numArgs == 3:
                    cmd = cmdLine[0]
                    if cmd.lower() in "set":
                        cType = cmdLine[1]
                        if cType in "arch":
                            arch = cmdLine[2]
                            if arch == "x64":
                                x64 = True
                                print(f"{c}[*]{rst} Arch set to {g}x64{rst}")
                            elif arch == "x86":
                                print(f"{c}[*]{rst} Arch set to {g}x86{rst}")
                            else:
                                print(f"{red}[!]{rst} Invalid arch, defaulting to {g}x86{rst}")
                        elif cType in "assembler":
                            flavor = cmdLine[2]
                            if flavor == "masm":
                                if masm:
                                    nasm = False
                                    print(f"{c}[*]{rst} Assembler already set to {g}MASM{rst}")
                                else:
                                    masm = True
                                    nasm = False
                                    print(f"{c}[*]{rst} Assembler set to {g}MASM{rst}")
                            elif flavor == "nasm":
                                if nasm:
                                    masm = False
                                    print(f"{c}[*]{rst} Assembler already set to {g}NASM{rst}")
                                else:
                                    nasm = True
                                    masm = False
                                    print(f"{c}[*]{rst} Assembler set to {g}NASM{rst}")
                            else:
                                print(f"{red}[!]{rst} Invalid Assembler, type help for more options")

                elif numArgs == 1:
                    if fullCmd in ["exit", "quit"]:
                        print(f"{w}Exiting..{rst}")
                        break
                    elif fullCmd == "help":
                        show_help()
                    else:
                        print(f"{red}[!]{rst} Invalid command")
                else:
                    print(f"{red}[!]{rst} Invalid command")

        except KeyboardInterrupt:
            print(f"\n[!] Closing..")
            break
        except Exception as e:
            raise


def banner2():
    
    T = """
[bold cyan] ███████╗██╗  ██╗███████╗██╗     ██╗     ███████╗██╗██╗      ██████╗ 
 ██╔════╝██║  ██║██╔════╝██║     ██║     ██╔════╝██║██║     ██╔═══██╗
 ███████╗███████║█████╗  ██║     ██║     ███████╗██║██║     ██║   ██║
 ╚════██║██╔══██║██╔══╝  ██║     ██║     ╚════██║██║██║     ██║   ██║
 ███████║██║  ██║███████╗███████╗███████╗███████║██║███████╗╚██████╔╝
 ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚══════╝ ╚═════╝ [/bold cyan][bold yellow]
    ╔══════════════════════[white] SHELLSILO [/]══════════════════════╗
    ║  [bold cyan]0x48 0x89 0xFE[/bold cyan] [bold red]0x0F 0x05[/bold red] │ [dim]v1.0[/dim] │ [white]Tarek Ahmed ☢️[/]      ║
    ╚═══════════════════════════════════════════════════════╝[/bold yellow]"""
    console.print(T, end="")
def banner():

    T = f"""
                        {y}@@@@@@@@@
                    @@@@@@@@@@@@@@@@@
                  @@@@@@@@@@@@@@@@@@@@@@@
                 @@@{brblk}:::{y}@@@@@@@@@@@@@{brblk}:::{y}@@@
               @@@@{brblk}:::::{y}@@@@@@@@@@@{brblk}:::::{y}@@@@
              @@@{brblk}::::::::{y}@@@@@@@@@{brblk}::::::::{y}@@@
             @@@{brblk}::::::::::{y}@@@@@@@{brblk}::::::::::{y}@@@
             @@@{brblk}:{o}PUSH RAX{brblk}::{y}@@@@@{brblk}::{o}PUSH RBX{brblk}:{y}@@@
             @@{brblk}:::::::::::{y}@{brblk}:::::{y}@{brblk}:::::::::::{y}@@
            @@@{brblk}::::::::::{y}@@{brblk}:::::{y}@@{brblk}::::::::::{y}@@@
             @@@@@@@@@@@@@@{brblk}:::::{y}@@@@@@@@@@@@@@
             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
             @@@@@@@@@@@@@{brblk}:::::::{y}@@@@@@@@@@@@@
              @@@@@@@@@@@{brblk}:::::::::{y}@@@@@@@@@@@
               @@@@@@@@@{brblk}:::::::::::{y}@@@@@@@@@
                 @@@@@@{brblk}:::{o}SYSCALL{brblk}:::{y}@@@@@@
                  @@@@@{brblk}:::::::::::::{y}@@@@@
                     @@@@@@@@@@@@@@@@@
                        @@@@@@@@@
"""
    print(T)

def main():
    banner2()
    banner()
    cli()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
