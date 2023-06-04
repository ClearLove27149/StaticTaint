#asm elf or pe
import pefile
from capstone import *
from xprint import *
from taintDataType import *
#CPUState = {}

def getaddr(insn, operand, CPUState):
    if operand.mem.base != 0 and operand.mem.index != 0:
        base_reg = insn.reg_name(operand.mem.base)
        index_reg = insn.reg_name(operand.mem.index)
        return operand.mem.scale * CPUState[index_reg] + CPUState[base_reg] + operand.mem.disp
    if operand.mem.base != 0 and operand.mem.index == 0:
        base_reg = insn.reg_name(operand.mem.base)
        return CPUState[base_reg] + operand.mem.disp
    if operand.mem.base == 0 and operand.mem.index != 0:
        index_reg = insn.reg_name(operand.mem.index)
        return operand.mem.scale * CPUState[index_reg] + operand.mem.disp
    if operand.mem.base == 0 and operand.mem.index == 0:
        return operand.mem.disp

def disassemble(file_path):
    pe = pefile.PE(file_path)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)

    code_dump = code_section.get_data()

    #code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
    code_addr = code_section.VirtualAddress
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for i in md.disasm(code_dump, code_addr):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    #insn_set = {}

    #for insn in md.disasm(code_dump, code_addr):
        
    #    print_insn_detail(CS_MODE_64, insn)
        #insn_set[insn.address] = insn
    #return insn_set

    #with open(filename, 'r') as f:

def readCPUState(filename):
    pass

disassemble(r"C:\Users\26685\source\repos\test\x64\Release\test.exe")
#pprint.pprint(insn_set)