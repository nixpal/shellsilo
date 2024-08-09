#!/usr/bin/python3 
import re
import string
import random
import json
import sys
from constants import dataTypes, specialVars,sysCalls
from keystone import *
import readline
import csv

rst="\033[0;0m"
red = "\033[38;5;9m"
by="\033[38;5;3m"
y="\033[38;5;11m"
y = "\033[1;33m"
b="\033[38;5;27m"
p="\033[1;33;35m"
c="\033[38;5;6m"
w="\033[38;5;7m"
o="\033[38;5;202m"
lb="\033[38;5;117m"
g="\033[38;5;2m"

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
ks = Ks(KS_ARCH_X86, KS_MODE_32)
win10Checked = True 
win11Checked = False
funcCalls = {}
syscallsAndApiNum = {}
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
        self.shellcode = ""

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

    def Asm2Opcode(self, assembly):
        allText = ""
        allText += f"\t\t  {y}**********************\n"
        allText += f"\t\t  *****{o} Shellcode{y} ******\n"
        allText += f"\t\t  {y}**********************{rst}\n\n"
        try:
            encoding, _ = ks.asm(assembly)
            opcode_hex = "".join(f"\\x{byte:02x}" for byte in encoding)
            bytes_per_line = 16 
            allText += '\n'.join(opcode_hex[i:i + bytes_per_line * 4] for i in range(0, len(opcode_hex), bytes_per_line * 4))
            allText += '\n'
        except KsError as e:
            print(f"Assembly failed: {e}")
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
                    return hex(len(varVal.replace('"', '')))
                else:
                    print(f"{red}Error: variable {extracted} doesn't exist.{rst}")
                    print(f"{w}Error on: {data}{rst}")
                    sys.exit()
            else: return None




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
        allTypes = dataTypes
        resVal = self.getValueType(value)
        asm = ""
        string = None
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
        else:
            rtnDict = self.findEbpVar(value)
            if rtnDict:
                assignedEbpVal = rtnDict[value] 
        if value in specialVars:
            value = specialVars[value]
        for var in mainVars:
            if name == var.Name:
                size = var.Size
                if size == 4:
                    dType = "dword"
                elif size == 2:
                    dType = "word"
                elif size == 1:
                    dType == "byte"

                if string:
                    assmLine = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], ebx"
                    asm += "{:60s};{}={}".format(assmLine,lb+name,value+rst)
                else:
                    if Type == "newVarAdd" and varEbpVal:
                        if assignedEbpVal:
                            assmLine = f"  mov ebx, dword ptr[{assignedEbpVal}]"
                            asm += "{:47s};{}\n".format(assmLine,lb+name+rst)
                            assmLine = f"  add {y+dType+rst} ptr[{varEbpVal}], ebx"
                            asm += "{:60s}".format(assmLine)
                        else:
                            assmLine = f"  add {y+dType+rst} ptr[{varEbpVal}], {value}"
                            asm += "{:60s};{}".format(assmLine,lb+name+rst)
                    elif Type == "newVarSub" and varEbpVal:
                        if assignedEbpVal:
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
                                assmLine = f"  mov ebx, dword ptr[{assignedEbpVal}]"
                                asm += "{:60s}\n".format(assmLine)
                                assmLine = f"  mov {y+dType+rst} ptr[{varEbpVal}], ebx"
                                asm += "{:60s};{}\n".format(assmLine,lb+name+rst)
                            else:
                                assmLine = f"  mov {y+dType+rst} ptr[{varEbpVal}], {value}"
                                asm += "{:60s};{}".format(assmLine,lb+name+rst)
                        else:
                            assmLine = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], {value}"
                            asm += "{:60s};{}".format(assmLine,lb+name+rst)
                
                if varEbpVal:
                    assignedEbp = f"{varEbpVal}"
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
        asm += f"  mov eax, ecx ; assume syscall number in ecx\n"
        asm += f"  call {lb}invokeSysCall{rst}\n"
        return asm

    def invokeSysCallOld(self, funcName):
        asm = ""
        asm += "  mov edi, esp\n"
        asm += "  sub esp, 0x50\n"
        numOfPushes = 0
        listOfSysCalls = sysCalls
        if not win10Checked and not win11Checked:
            print(f"{red}Error: you need at least one operating system to be checked for syscalls.{rst}")
            print(f"{w}Currently you have both win10 and win11 unchecked.{rst}")
            sys.exit()
        if funcName[-1].isdigit():
            NewfuncName = funcName[:-1]
        else:
            NewfuncName = funcName
        if NewfuncName in listOfSysCalls:
            sysCallsNums = listOfSysCalls[funcName]
            win10List = [x for x in sysCallsNums["10"]]
            win10List.append("ffff")
            win10List.reverse()
            win11List = [x for x in sysCallsNums["11"]]
            win11List.append("ffff")
            win11List.reverse()
            if win10Checked:
                for i in range(0, len(win10List) - 1, 2):
                    spair = win10List[i:i+2]
                    pushPair = ''.join(spair)
                    asm += f"  push 0x{pushPair}\n"
                    numOfPushes += 1
                if len(win10List) % 2 == 1:
                    asm += f"  push 0x{win10List[-1]}\n"
                    numOfPushes += 1
            if win11Checked:
                for i in range(0, len(win11List) - 1, 2):
                    spair = win11List[i:i+2]
                    pushPair = ''.join(spair)
                    asm += f"  push 0x{pushPair}\n"
                if len(win11List) % 2 == 1:
                    asm += f"  push 0x{win11List[-1]}\n"
                    numOfPushes += 1

            #sysCallNum = listOfNames[funcName]
            #asm += f"  mov eax, {hex(sysCallNum)}\n"
            asm += "  mov esi, esp\n"
            asm += "  mov esp, edi\n"
            asm += f"  call {lb}invokeSysCall{rst}\n"
            #asm += f"  add esp, {hex(numOfPushes*4)}\n"
        else:
            print(f"{red}Error: could not find api {funcName} in the constants file{rst}")
            sys.exit()
        return asm,numOfPushes



    def getApiNumFromFile(self, funcName):
        print("getApiNumFromFile")
        asm = ""
        apiNumFromFile = readSysCalls(funcName, False, True)
        asm += f"  mov edi, {apiNumFromFile}\n"
        asm += f"  call {lb}GetSysModelNumber{rst}\n"
        return asm

    def funcCallAssm(self, funcName, params, assignedTo):
        asm = ""
        if funcName not in funcCalls:
            asm += f"\n{lb+funcName+rst}:\n"
            funcCalls.update({funcName:0})
        else:
            funcCallNum = funcCalls[funcName]
            NewfuncName = f"{funcName}{funcCallNum+1}"
            funcCalls.update({NewfuncName:funcCallNum+1})
            asm += f"\n{lb+NewfuncName+rst}:\n"
        eaxAssm = ""
        stackAdjust = 0
        for func in mainVars:
            if func.Name == funcName:
                for param in reversed(params):
                    stackAdjust += 4
                    if param[0] != "&":
                        paramType = self.getValueType(param)
                        if paramType == "variable":
                            ebp = self.findEbpVar(param)
                            if ebp:
                                ebpOff = ebp[param]
                                ebpVal = ebp["value"]
                                ebpType = ebp["type"]
                                prepAsm = f"  push {y+ebpType+rst} ptr[{ebpOff}]"
                                asm += "{:60s};{}:{}\n".format(prepAsm,lb+param,o+ebpVal+rst)
                            else:
                                if param in specialVars:
                                    newParam = specialVars[param]
                                    prepAsm = f"  push {newParam}"
                                    asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                                else:
                                    newParam = self.reservedType(param)
                                    if newParam != param:
                                        newParam = hex(newParam)
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
                            prepAsm = f"  push {paramVal}"
                            asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                        elif paramType == "hex":
                            v = hex(int(param, 16))
                            prepAsm = f"  push {v}"
                            asm += "{:44s};{}\n".format(prepAsm,lb+param+rst)
                        elif paramType == "sizeof":
                            foundSizeOf, rtnVal = self.isSizeOf(param)
                            if foundSizeOf:
                                if self.isStruct(rtnVal):
                                    paramVal = self.getStructSize(rtnVal)
                                    prepAsm = f"  push {paramVal}"
                                    asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                                else:
                                    paramVal = self.sizeOf(param)
                                    prepAsm = f"  push {paramVal}"
                                    asm += "{:47s};{}\n".format(prepAsm,lb+param+rst)
                        else:
                            if param in specialVars:
                                paramVal = specialVars[param]
                                prepAsm = f"  push {paramVal}"
                                asm += "{:44s};{}\n".format(prepAsm,lb+param+rst)

                    else:
                        newParam = param.replace("&", "")
                        ebp = self.findEbpVar(newParam)
                        if ebp:
                            ebpOff = ebp[newParam]
                            ebpVal = ebp["value"]
                            ebpType = ebp["type"]
                            prepAsm = f"  lea ebx, {y+'dword'+rst} ptr[{ebpOff}]"
                            asm += "{:60s};{}:{}\n".format(prepAsm,lb+param,o+ebpVal+rst)
                            asm += f"  push ebx\n"
                break

        #rtnAsm, numOfPushes = self.invokeSysCall((funcName))
        #asm += self.GetModelNumber(funcName) 
        #asm += rtnAsm
        #asm += self.invokeSysCall(funcName)
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
                                prepAsm = f"  mov {lb}dword{rst} ptr[{ebpVal}], eax"
                                asm += "{:64s};{} {}\n".format(prepAsm,lb+"save return value in",o+var.Name+rst)
                    else:
                        currentStack = self.asmObj.stackStart
                        prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(currentStack)}], eax"
                        asm += "{:64s};{} {}\n".format(prepAsm,lb+"save return value in",o+var.Name+rst)
                        assignedEbp = f"ebp-{hex(currentStack)}"
                        var.Value = "EAX"
                        self.asmObj.stackStart += 0x4
                        ebpDict = {var.Name:assignedEbp,
                           "value":"EAX",
                           "type":"dword"}
        #asm += f"  add esp, {hex(stackAdjust+(numOfPushes*4))}"
        #asm += "\n"
        return(asm)


    def structPtrAsm(self,ptr):
        currentStack = self.asmObj.stackStart
        asm = ""
        ptrOffset = 0
        pointerName = ""
        for s in structs:
            if s.Pointer == ptr:
                pointerName = s.Name
                ptrOffset = f"ebp-{hex(currentStack)}"
                ebpDict = {s.Pointer:ptrOffset,
                           "value":"0x0",
                           "type":"struct",
                           "members":[]}
                members = s.Members
                 
                for mem in members:
                    for key, value in mem.items():
                        if key == "0x4":
                            dType = "dword"
                        elif key == "0x2":
                            dType = "word"
                        elif key == "0x1":
                            dType = "byte"
                        ebpDict["members"].append({value:hex(currentStack)})
                        prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(currentStack)}], 0x0"
                        asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
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
                    ebpDict["members"].append({value:hex(currentStack)})
                    tmpStackPtr = f"ebp-{hex(currentStack)}"
                    if "->" in value:
                        isInitialized = v.Value.replace(" ", "")
                        if "0" in isInitialized or "{0}" in isInitialized:
                            prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                        else:
                            prepAsm = f"  lea ebx, {y}dword{rst} ptr[{offset}]"
                            asm += "{:60s};{}\n".format(prepAsm, lb+"ptr:"+ptrName+rst)
                            prepAsm = f"  mov {y}dword{rst} ptr[ebp-{hex(self.asmObj.stackStart)}], ebx"
                            asm += "{:60s}\n".format(prepAsm)
                        self.asmObj.stackStart += int(key, 16)
                    else:
                        if "0" in v.Value or "null" in v.Value.lower():
                            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
                            self.asmObj.stackStart += int(key, 16)
                        elif v.Value == "":
                            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{hex(self.asmObj.stackStart)}], 0x0"
                            asm += "{:60s};{}\n".format(prepAsm, lb+value+rst)
                            self.asmObj.stackStart += int(key, 16)
        except Exception as e:
            print("genStructAssembly -> ", e)
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
                    return "string"
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
        if memberSize == "0x4":
            dType = "dword"
        elif memberSize == "0x2":
            dType = "word"
        elif memberSize == "0x1":
            dType = "byte"
        
        if value == "NULL":
            value = 0
        vType = self.getValueType(value)

        if vType == "int":
            varValue = int(value)
            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], {hex(int(varValue))}"
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(varValue)+rst)
        elif vType == "hex":
            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], {value}"
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(value)+rst)
        elif vType == "string":
            pushedStr = self.pushString(value)
            prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], ebx"
            asm += pushedStr
            asm += "{:60s};{}={}\n".format(prepAsm, lb+stMember+rst, lb+str(value)+rst)
        elif vType == "variable":
            isVariable = value
            varValue = self.getVarValue(isVariable)
            varType = self.getValueType(varValue)
            varEbpVal = self.getEbpValue(isVariable)
            #if varType == "hex":
                #varValue = int(varValue, 16)


            prepAsm = f"  mov ebx, dword ptr[{varEbpVal}]"
            asm += "{:47s};{}\n".format(prepAsm, lb+isVariable+rst)
            prepAsm = f"  mov dword ptr[ebp-{memberOffset}], ebx"
            asm += "{:47s};{}<=>{}\n".format(prepAsm, lb+stMember+rst, lb+isVariable+rst)
            #prepAsm = f"  mov {y+dType+rst} ptr[ebp-{memberOffset}], {hex(int(varValue))}"
            #asm += "{:60s};{}<=>{}\n".format(prepAsm, lb+stMember+rst, lb+isVariable+rst)
        elif vType == "unicode":
            extractVal = value.split("u:")[1]
            hexVal = self.toHex(extractVal)
            uniVal = self.toUnicode(hexVal)
            pushedStr = self.pushAscii(uniVal)
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
        #varObj = Vars()
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
                    #mainVars.append(varObj)
                return True,sName,sValue,"struct",None,True

            elif sName == s.Pointer:
                sValue = line.split(" ")[1]
                return True,sName,sValue,"structPtr",None,False

        if "InitUnicodeStr" in line:
            return True,'',line,"unicode",None,False

        allData = dataTypes
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
        # print("Length: ", wordLen)
            if wordLen == 4:
                wordHex = "".join("{:02x}".format(ord(c)) for c in data)
                prepAsm = f"  push 0x{wordHex}"
                asmCode2 += "{:47s};{}\n".format(prepAsm,lb+data+rst)
          

            elif wordLen == 2:
                wordHex = "".join("{:02x}".format(ord(c)) for c in data)
                prepAsm = f"  mov bx, 0x{wordHex}\n"
                prepAsm += "  push bx"
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
              # print("Xoring ", randStr2Int, wordHex2Int)
                Xored = randStr2Int ^ wordHex2Int
                Xored = hex(Xored).replace("0x", "")
              
                tmpAsm = '  mov ebx, 0x{}'.format(Xored)
                tmpAsm = "{:47s};{}\n".format(tmpAsm, lb+data+rst)
                tmpAsm += '  xor ebx, 0x{}\n'.format(randStr)
                if(wordLen == 1):
                    tmpAsm += '  push bx\n'
                else:
                    tmpAsm += '  push ebx\n'
              
                tmpAsm += "  mov ebx, esp\n"
                tmpAsm += '  inc ebx\n'

                asmCode2 += tmpAsm
          # print("Final code from function", asmCode)
        if Flag:
            prepAsm = "  push esp"
            asmCode2 += "{:47s};{}\n".format(prepAsm,lb + str2push+rst)
            asmCode2 += "  pop ebx\n"
        return asmCode2


    def pushAscii(self, asciiArr):
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
        for group in newData:
            newHex = ""
            for byte in reversed(bytes.fromhex(group)):
                b = format(byte, '02x')
                newHex += b
            asm += f"  push 0x{newHex}\n"
        asm += "  mov ebx, esp\n"
        return asm 


    def initUnicode(self, ptrName, unicode, length, line):
        asm = ""
        data = {
            "u":unicode,
            "len":length
        }
        # Length is the unicode string length
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
        asmNoComment = ""
        for i in asm.split("\n"):
            i = i.strip()
            i = i.replace(lb, "")
            i = i.replace(y, "")
            i = i.replace(o, "")
            i = i.replace(rst, "")
            commentFound = re.findall('(.*);', i)
            if commentFound:
                asmNoComment += commentFound[0] + "\n"
            else:
                asmNoComment += i + "\n"
        return asmNoComment
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

    def hiddenStructAsm(self, varName, offset, hiddenVarName):
        asm = ""
        srcVarEbp = None 
        destVarEbp = None
        for ebp in ebpVars:
            vName, ebpVal = next(iter(ebp.items()))
            if vName == hiddenVarName:
                srcVarEbp = ebpVal
            elif vName == varName:
                destVarEbp = ebpVal
        if srcVarEbp and destVarEbp:
            prepAsm = f"  mov ebx, dword ptr[{srcVarEbp}]"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Get address of "+hiddenVarName+rst)
            if offset == 0:
                prepAsm = f"  mov ebx, dword ptr[ebx]"
            else:
                prepAsm = f"  mov ebx, dword ptr[ebx+{hex(offset)}]"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Access offset " + str(hex(offset)) + " in " +hiddenVarName+rst)
            prepAsm = f"  mov dword ptr[{destVarEbp}], ebx"
            asm += "{:47s};{}\n".format(prepAsm, lb+"Copy value to " +varName+rst)
        return asm

    def findHiddenStruct(self, structName):
        for hs in hiddenstructs:
            if hs.Name == structName:
                return hs.Members
        return False

    def findNestedMemberSize(self, data, nestedMember):
        totalSize = 0
        found = False
        combinedDict = {}
        for x in data:
            for key, val in x.items():
                newdict = {val:key}
                combinedDict.update(newdict)
        for elem, size in combinedDict.items():
            if nestedMember == elem:
                found = True
                break
            totalSize += int(size, 16)
        return found, totalSize

    def hiddenStruct(self, varName, structData):
        hiddenType = structData["type"]
        structName = structData["structName"]
        structMember = structData["structMemberName"]
        hiddenVarName = structData["hiddenVarName"]
        offset = 0
        found = False
        members = self.findHiddenStruct(structName)
        if not members:
            print(f"{red}Error: could not find struct name structName {rst}")
            sys.exit()
        sizeAndName = [(key, value) for memberDict in members for key, value in memberDict.items()]
        if hiddenType == "regular":
            for size, name in sizeAndName:
                if structMember == name:
                    found = True
                    break
                offset += int(size, 16)

        elif hiddenType == "nested":
            nestedMember = structData["hiddenNestedMember"]
            for size, name in sizeAndName:
                if type(name) == dict:
                    memberNameAndPtr = [i for i in name][0]
                    memberName = memberNameAndPtr.split("->")[0]
                    if memberName == structMember:
                        found, recvSize = self.findNestedMemberSize(name[memberNameAndPtr], nestedMember)
                        offset += recvSize
                        if found:
                            break
                else:
                    offset += int(size, 16)

        if not found:
            print(f"{red}Error: could not find member {structMember}, are you sure it's not nested member ? {rst}")
            sys.exit()
        asm = self.hiddenStructAsm(varName, offset, hiddenVarName)
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
            asm += f"  mov eax, dword ptr[{leftEbpValue}]\n"
            asm += f"  cmp eax, {hex(int(right))}\n"
        elif rType == "hex":
            asm += f"  mov eax, dword ptr[{leftEbpValue}]\n"
            asm += f" cmp eax, {right}"
        elif rType == "string":
            asm += f"  mov edi, dword ptr[{leftEbpValue}]\n"
            rtnStringVal = self.pushString(right)
            asm += rtnStringVal
            strLen = self.sizeOf(f"sizeof({right})")
            asm += f"  mov esi, ebx\n"
            asm += f"  mov ecx, {strLen}\n"
            asm += "  cld\n"
            asm += "  repe cmpsb\n"
        elif rType == "variable":
            for v in mainVars:
                if v.Name == name:
                    if "ebp" in right and v.Type == "unicode":
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
    
    
    def sysCallAsm_old(self):
        asm = ""
        asm += f"{lb}invokeSysCall{rst}:\n"
        asm += f"  xor ecx, ecx\n"
        asm += f"  mov cx, word ptr[esi]\n"
        asm += f"  add esi, 2\n"
        asm += f"  cmp cx, 0xffff\n"
        asm += f"  je AttackEnd\n"
        asm += f"  xor eax, eax\n"
        asm += f"  mov eax, ecx\n"
        asm += f"  call {y}dword{rst} ptr fs:[0xc0]\n"
        asm += f"  test eax, eax\n"
        asm += f"  jne invokeSysCall\n"
        asm += f"  AttackEnd:\n"
        asm += f"  ret\n"
        asm += f"{lb}Begin{rst}:\n"
        return asm

    def sysCallAsm(self):
        asm = ""
        asm += f"{lb}invokeSysCall{rst}:\n"
        asm += f"  call {y}dword{rst} ptr fs:[0xc0]\n"
        asm += f"  ret\n"
        asm += f"{lb}Begin{rst}:\n"
        return asm

    def checkSyscallNumAsm(self, modelNum):
        print("checkSyscallNumAsm", modelNum)
        asm = ""
        for api, val in syscallsAndApiNum.items():
            asm += f"  cmp edi, {val}\n"
            syscallNum = readSysCalls(api, modelNum, False)
            print(f"syscall: {syscallNum}")
            asm += f"  mov ebx, {syscallNum}\n"
            asm += f"  cmovz ecx, ebx\n"
        asm += "  ret\n"
        return asm

    def GetSyscallNumber(self):
        print("GetSyscallNumber")
        asm = ""
        asm += f"jmp {lb}Begin{rst}\n"
        asm += f"{lb}m_19_all:{rst}\n"
        asm += self.checkSyscallNumAsm("19041")
        asm += f"{lb}m_10061:{rst}\n"
        asm += self.checkSyscallNumAsm("10061")
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
        asm += f"{lb}m_20348:{rst}\n"
        asm += self.checkSyscallNumAsm("20348")
        asm += f"{lb}m_22000:{rst}\n"
        asm += self.checkSyscallNumAsm("22000")
        asm += f"{lb}m_22621:{rst}\n"
        asm += self.checkSyscallNumAsm("22621")
        asm += f"{lb}m_22631:{rst}\n"
        asm += self.checkSyscallNumAsm("22631")
        asm += f"{lb}m_26120:{rst}\n"
        asm += self.checkSyscallNumAsm("26120")
        asm += f"{lb}m_26212:{rst}\n"
        asm += self.checkSyscallNumAsm("26212")
        asm += f"{lb}m_26227:{rst}\n"
        asm += self.checkSyscallNumAsm("26227")

        return asm


    def GetModelNumber(self):
        print("GetModelNumber")
        asm = ""
        asm += f"""
{lb}GetSysModelNumber{rst}:
  mov edx, fs:[0x30]
  mov eax, [edx+0xAC]
  and eax, 0xFFFF
  cmp ah, 0x4A	; 19041, 19042...
  je m_19_all
  cmp eax, 10061
  je m_10061
  cmp eax, 10240
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
  cmp eax, 20348
  je m_20348
  cmp eax, 22000
  je m_22000
  cmp eax, 22621
  je m_22621
  cmp eax, 22631
  je m_22631
  cmp eax, 26120
  je m_26120
  cmp eax, 26212
  je m_26212
  cmp eax, 26227
  je m_26227
  ret
"""
        return asm

    def stackSpace(self):
        asm = "sub esp, 0x2000\n"
        return asm
    
    def stackEnd(self):
        asm = "add esp, 0x2000\n"
        return asm

    def parseMain(self, lines):
        finalAssm = ""
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
        self.asmObj.assembly += self.stackSpace()
        self.asmObj.assembly += self.GetSyscallNumber()
        self.asmObj.assembly += self.GetModelNumber()
        self.asmObj.assembly += self.sysCallAsm()
        self.asmObj.assembly += finalAssm
        self.asmObj.assembly += self.stackEnd()
        finalAssembly.append(self.asmObj)
        noCommentAsm = self.removeAsmComments(self.asmObj.assembly)
        shellcode = self.Asm2Opcode(noCommentAsm)
        self.asmObj.shellcode = shellcode

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
            print("Error: readMain ->", e)
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
        types = constTypes
        #structRev = struct[::-1]
        try:
            for stLine in struct:
                size = 0
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
                    memDict = {hex(size):memberName}
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
            print(e)

    def structFound(self,struct, structObj, structName, structPtr):
        struct = struct[1:-1]
        types = dataTypes
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
            print(e)
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
        #name = re.findall('[a-zA-Z0-9_]+,', line)[0][:-1]
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
            print("Error:", e)

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

    def readFile(self):
        allLines = []
        with open(self.file, "r") as content:
            for line in content:
                allLines.append(line)
        self.parser(allLines)

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
    file_path = "syscallslist.txt"
    data_dict = {}
    apis_and_nums = {}
    mod_19 = [19042, 19043, 19044, 19045]
    if model_number in mod_19:
        model_number = 19041
    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter='\t')
        header = next(reader)
        for row in reader:
            service_name = row[1]
            service_id = row[0]
            api_num_dict = {service_name:service_id}
            apis_and_nums.update(api_num_dict)
            values = row[2:]  # Values start from index 2 onward
        
        # Create a nested dictionary to store values for each service
            data_dict[service_name] = {}
        
        # Populate the nested dictionary with values based on column headers
            for i, value in enumerate(values):
                column_number = header[i+2]  # +2 to skip # and ServiceName columns
                if value.strip():
                    data_dict[service_name][column_number] = int(value)
                else:
                    data_dict[service_name][column_number] = None
    if not find_api_num:
        if syscall_name in data_dict and model_number in data_dict[syscall_name]:
            value = data_dict[syscall_name][model_number]
            return hex(value)
            #print(f"Value for '{syscall_name}' at number '{model_number}': {value}")
        else:
            return None
    else:
        api_num = apis_and_nums[syscall_name]
        return hex(int(api_num))
def cli():
    global win10Checked
    global win11Checked
    checkMark = u'\u2713'
    crossMark = u'\u2715'
    while True:
        try:
            c = input(f"{brblk}S{o}I{y}L{o}O{brblk}>{rst} ")
            if c == "":
                continue
            else:
                cmdLine = c.split(" ")
                numArgs = len(cmdLine)
                if numArgs == 2:
                    cmd = cmdLine[0]
                    if cmd.lower() in "load":
                        filePath = cmdLine[1]
                        try:
                            r = Reader(filePath)
                            r.readFile()
                            print(f"{w}File loaded.{rst}")
                            
                        except Exception as e:
                            print(f"{w}{e}{rst}")
                    elif cmd.lower() in "print":
                        cType = cmdLine[1]
                        if cType in "assembly":
                            print("\n")
                            print(Reader.asmObj.assembly)
                        elif cType in "shellcode":
                            print("\n")
                            print(Reader.asmObj.shellcode)
                        else:
                            print(f"{w}Invalid command{rst}")
                    elif cmd.lower() == "set":
                        if cmdLine[1] == "win10":
                            if not win10Checked:
                                win10Checked = True
                                print(f"{w}Windows 10 syscalls [{g}{checkMark}{w}]")
                            else:
                                win10Checked = False
                                print(f"{w}Windows 10 syscalls [{red}{crossMark}{w}]")

                        if cmdLine[1] == "win11":
                            if not win11Checked:
                                win11Checked = True
                                print(f"{w}Windows 11 syscalls [{g}{checkMark}{w}]")
                            else:
                                win11Checked = False 
                                print(f"{w}Windows 11 syscalls [{red}{crossMark}{w}]")

                    else:
                        print(f"{w}Invalid command{rst}")
                        continue
                elif numArgs == 1:
                    if c == "quit" or c == "exit":
                        print(f"{w}Exiting..{rst}")
                        break
                    elif c == "help":
                        help()
                    else:
                        print(f"{w}Invalid command")
                else:
                    print(f"{w}Invalid command")

        except KeyboardInterrupt:
            print(f"\n[!] Closing..")
            break

def banner():
    T = f"""
      {brblk}____  _   _ _____ _     _       {brblk}____ ___ _     ___  
     {y}/ ___|| | | | ____| |   | |     {o}/ ___|_ _| |   / _ \ 
     {y}\___ \| |_| |  _| | |   | |     {o}\___ \| || |  | | | |
      {y}___) |  _  | |___| |___| |___   {o}___) | || |__| |_| |
     {y}|____/|_| |_|_____|_____|_____| {o}|____/___|_____\___/ 
                                                          
                         {y}.@@@@@@@.                         
                   .=@@#:::::::::::#@@=                    
                 .@@:::::::::::::::::::@@.                 
               =@:::#*:::::::::::::::*#:::@=               
              @-::{brblk}@@@@@{y}:::::::::::::%{brblk}@@@@{y}::-@              
            .@::#{brblk}@@@@@@@{y}-::::::::::{brblk}@@@@@@@{y}%::@.            
            @::{brblk}@@@@@@@@@@{y}:::::::::{brblk}@@@@@@@@@@{y}::@.           
           @::{brblk}@@@@@@@@@@@@:::::::{brblk}@@@@@@@@@@@@{y}::@.          
          @@::{brblk}@@{o}PUSH EAX{brblk}@@@{y}:::::{brblk}@@@{o}PUSH EBX{brblk}@@{y}::@@          
          @::{brblk}@@@@@@@@@@@@{y}::{brblk}@@@@@{y}::{brblk}@@@@@@@@@@@@{y}::@          
          @::{brblk}@@@@@@@@@@@{y}::{brblk}@@@@@@@{y}::{brblk}@@@@@@@@@@@{y}::@          
          @:::::::::::::::{brblk}@@@@@@@{y}:::::::::::::::@          
          @::::::::::::::::{brblk}@@@@@{y}::::::::::::::::@          
          @@:::::::::::::::::::::::::::::::::::@@          
           @::::::::::::::{brblk}@@@@@@@{y}::::::::::::::@.          
            @::::::::::::{brblk}@@@@@@@@@{y}::::::::::::@            
            .@::::::::::{brblk}@@@@@@@@@@@{y}-:::::::::@.            
             .@-::::::-{brblk}@{o}@{brblk}@@@@@@@@@{o}@{brblk}@{y}=::::::-@              
               =@::::*{brblk}@@@{o}:SYSCALL:{brblk}@@@{y}*:::-@+               
                 .@@::::{brblk}@@@@@@@@@@@{y}::::@@.                 
                    =@@#:::::::::::#@@+                    
                         .@@@@@@@.
                         {rst}
                                                           
"""
    print(T)

def main():
    banner()
    #print(readSysCalls("NtAllocateVirtualMemory", False, True))

    cli()

if __name__ == "__main__":
    main()
