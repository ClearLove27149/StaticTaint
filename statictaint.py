#statictaint
from taintDataType import *
from taintRules import *
from asm_elf import *
from capstone.x86_const import *
from capstone import *

elfname = "read"
cpufilename = "result2.txt"
#define taint source

#taint rules
insn_set = disassemble(elfname)

#pprint.pprint(insn_set)
#CPUState = readCPUState(filename)

#test
#CPUState = [{"addr":0x102b,"rcx":1,"rcx":1}]
CPUState = readCPUState(cpufilename, base_addr = 0x000056060446f000)
#define taint source
#taint_source = {"type":"REG", "tag":"FF","value":"rcx"}
taint_source = {"type":"MEM", "tag":"FF", "value":0x00007fff558b72c4, "start_insn_addr":0x769}
taint_leak = {"type":"MEM", "value":0x00007fff558b72ce}

#add taint sorce
#if taint_source["type"] == "REG":
#	taint_regs_init()
#	taint_regs_append(taint_source["value"], taint_source["tag"])
#if taint_source["type"] == "MEM":
#	taint_mems_append(taint_source["value"], taint_source["tag"])


flag = 0
taint_regs_init()
for item in CPUState:
	if item["addr"] == taint_source["start_insn_addr"]:
		if taint_source["type"] == "REG":
			
			taint_regs_append(taint_source["value"], taint_source["tag"])
		if taint_source["type"] == "MEM":
			taint_mems_append(taint_source["value"], taint_source["tag"])
		print("define taint source :")
		print(taint_regs)
		print(taint_mems)
		print("\n")
	# taint_leak is current?
	if taint_leak["type"] == "MEM":
		if taint_leak["value"] in taint_mems.keys():
			flag = 1
			#print("taint leak is current, analysis complete")
			#print(taint_regs)
			#print(taint_mems)
			break
	addr = item["addr"]
	cpu = item
	#print(addr)
	insn = insn_set[addr]
	print(insn.address)
	print(insn)
	#print(insn.address)
	if insn.mnemonic == "mov":
		#operand_count = len(insn.operands)
		op0 = insn.operands[0]   #dst op
		#print("op0 : ")
		#print(insn.reg_name(op0.reg))
		op1 = insn.operands[1]   #src_op
		#print("op1 : ")
		#print(insn.reg_name(op1.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_mov_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_mov_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_mov_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))

	if insn.mnemonic == "add":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_add_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_add_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_add_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))

	if insn.mnemonic == "sub":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_sub_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_sub_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_sub_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))

	if insn.mnemonic == "lea":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_lea_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))

	if insn.mnemonic == "movsx":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op

		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_movsx_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_movsx_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))

	if insn.mnemonic == "movzx":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op

		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_movzx_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_movzx_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))
	if insn.mnemonic == "add":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_add_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_add_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_add_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))
	if insn.mnemonic == "or":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_or_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_or_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_or_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))
	if insn.mnemonic == "xor":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_xor_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_REG and op0.type == X86_OP_MEM:
			propagate_xor_rm(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_xor_mr(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))
	if insn.mnemonic == "div" or insn.mnemonic == "idiv":
		op0 = insn.operands[0]

		if op0.type == X86_OP_REG:
			propagate_div_reg(insn.reg_name(op0.reg))
		if op0.type == X86_OP_MEM:
			propagate_div_mem(getaddr(insn, op0, cpu))

	if insn.mnemonic == "mul" or insn.mnemonic == "imul":
		op0 = insn.operands[0]

		if op0.type == X86_OP_REG:
			propagate_mul_reg(insn.reg_name(op0.reg))
		if op0.type == X86_OP_MEM:
			propagate_mul_mem(getaddr(insn, op0, cpu))

	if insn.mnemonic == "stos":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op

		propagate_stos(insn.reg_name(op1.reg), getaddr(insn, op0, cpu))

	if insn.mnemonic == "push":
		op0 = insn.operands[0]
		if op0.type == X86_OP_REG:
			propagate_push_reg(insn.reg_name(op0.reg))
		if op0.type == X86_OP_MEM:
			propagate_push_mem(getaddr(insn, op0, cpu))

	if insn.mnemonic == "pop":
		op0 = insn.operands[0]
		if op0.type == X86_OP_REG:
			propagate_pop_reg("rsp", insn.reg_name(op0.reg))
		if op0.type == X86_OP_MEM:
			propagate_pop_mem("rsp", getaddr(insn, op0, cpu))

	if insn.mnemonic == "xchg":
		op0 = insn.operands[0]   #dst op
		op1 = insn.operands[1]   #src_op
		
		if op1.type == X86_OP_REG and op0.type == X86_OP_REG:
			propagate_xchg_rr(insn.reg_name(op1.reg), insn.reg_name(op0.reg))
		if op1.type == X86_OP_MEM and op0.type == X86_OP_REG:
			propagate_xchg_mr_rm(getaddr(insn, op1, cpu), insn.reg_name(op0.reg))


if flag == 0:
	print("taint analysis complete, can not find taint leak")
	print(taint_regs)
	print(taint_mems)
else:
	print("taint leak is current, analysis complete")
	print(taint_regs)
	print(taint_mems)