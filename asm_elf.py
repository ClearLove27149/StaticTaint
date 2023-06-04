# asm_elf
from elftools.elf.elffile import ELFFile
from capstone import *
from taintDataType import *

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
	with open(file_path, 'rb') as f:
		elf = ELFFile(f)

		code = elf.get_section_by_name('.text')
		ops = code.data()
		addr = code['sh_addr']

		md = Cs(CS_ARCH_X86, CS_MODE_64)
		md.detail = True
		#for i in md.disasm(ops, addr):
		#print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

		insn_set = {}

		for insn in md.disasm(ops, addr):
			insn_set[insn.address] = insn
		return insn_set

def readCPUState(filename, base_addr):
	with open(filename, 'r')as f:
		lines = f.readlines()
		CPUState = []
		for line in lines:
			line = line.lstrip()
			if line.startswith("0x"):
				cur_cpu = {}
				addr = int(line.split(':')[0], base=16) - base_addr
				cur_cpu["addr"] = addr
				continue
			if line == "":
				CPUState.append(cur_cpu)
				continue
			line = line.split("=")
			cur_cpu[line[0]] = int(line[1], base=16)
			#print(line)
			reg64_index = normal_regs.index(line[0])
			reg64_value = int(line[1], base=16)
			#extend 32, 16bit reg
			reg32_value = reg64_index & 0x00000000FFFFFFFF
			cur_cpu[normal_regs_d[reg64_index]] = reg32_value
			reg16_value = reg32_value & 0x0000FFFF
			cur_cpu[normal_regs_w[reg64_index]] = reg16_value
			reg8_value = reg16_value & 0x00FF
			cur_cpu[normal_regs_b[reg64_index]] = reg8_value
			#push ah,bg,ch,dh
			if reg64_index < 4:
				cur_cpu[normal_regs_h[reg64_index]] = reg16_value & 0xFF00

			

	return CPUState
