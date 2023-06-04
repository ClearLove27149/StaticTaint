#taint rules
from taintDataType import *
#mov；
def propagate_mov_ir(reg):
	pass
def propagate_mov_im(addr):
	pass
def propagate_mov_rr(reg_src, reg_dst):
	overwrite_reg2reg(reg_src, reg_dst)
def propagate_mov_rm(reg, addr):
	overwrite_reg2mem(reg, addr)

def propagate_mov_mr(addr, reg):
	overwrite_mem2reg(addr, reg)

#add
def propagate_add_ir(reg):
	pass

def propagate_add_im(addr):
	pass
def propagate_add_rr(reg_src, reg_dst):
	merge_reg2reg(reg_src, reg_dst)
def propagate_add_mr(addr, reg):
	merge_mem2reg(addr, reg)
def propagate_add_rm(reg, addr):
	merge_reg2mem(reg, addr)

#sub
def propagate_sub_ir(reg):
	pass
def propagate_sub_im(addr):
	pass
def propagate_sub_rr(reg_src, reg_dst):
	merge_reg2reg(reg_src, reg_dst)
def propagate_sub_mr(addr, reg):
	merge_mem2reg(addr, reg)
def propagate_sub_rm(reg, addr):
	merge_reg2mem(reg, addr)

#lea
def propagate_lea_mr(addr, reg):
	overwrite_mem2reg(addr, reg)

#movsx
def propagate_movsx_mr(addr, reg):
	overwrite_mem2reg(addr, reg)

def propagate_movsx_rr(reg_src, reg_dst):
	overwrite_reg2reg(reg_src, reg_dst)

#movzx
def propagate_movzx_rr(reg_src, reg_dst):
	overwrite_reg2reg(reg_src, reg_dst)
def propagate_movzx_mr(addr, reg):
	overwrite_mem2reg(addr, reg)

#add
def propagate_add_ir(reg):
	pass
def propagate_add_im(reg):
	pass
def propagate_add_rr(reg_src, reg_dst):
	merge_reg2reg(reg_src, reg_dst)
def propagate_add_mr(addr, reg):
	merge_mem2reg(addr, reg)
def propagate_add_rm(reg, addr):
	merge_reg2mem(reg, addr)

#or
def propagate_or_ir(reg):
	pass
def propagate_or_ir_im(reg):
	pass
def propagate_or_rr(reg_src, reg_dst):
	merge_reg2reg(reg_src, reg_dst)
def propagate_or_mr(addr, reg):
	merge_mem2reg(addr, reg)
def propagate_or_rm(reg, addr):
	merge_reg2mem(reg, addr)
#xor
def propagate_xor_ir(reg):
	pass
def propagate_xor_im(reg):
	pass
def propagate_xor_rr(reg_src, reg_dst):
	merge_reg2reg(reg_src, reg_dst)
def propagate_xor_mr(addr, reg):
	merge_mem2reg(addr, reg)
def propagate_xor_rm(reg, addr):
	merge_reg2mem(reg, addr)

#div, idiv
def propagate_div_reg(reg):
	merge_reg2reg(reg, "rax")
	merge_reg2reg(reg, "rdx")

def propagate_div_mem(addr):
	merge_mem2reg(addr, "rax")
	merge_mem2reg(addr, "rdx")

#mul, imul
def propagate_mul_reg(reg):
	merge_reg2reg(reg, "rax")
	merge_reg2reg(reg, "rdx")

def propagate_mul_mem(addr):
	merge_mem2reg(addr, "rax")
	merge_mem2reg(addr, "rdx")

#stos
def propagate_stos(reg, addr):
	overwrite_reg2mem(reg, addr)

#push
def propagate_push_imm():
	pass
def propagate_push_reg(reg_src, reg_dst="rsp"):
	overwrite_reg2reg(reg_src, reg_dst)
def propagate_push_mem(addr, reg="rsp"):
	overwrite_mem2reg(addr, reg)

#pop,reg_src="rsp"
def propagate_pop_reg(reg_src, reg_dst):
	overwrite_reg2reg(reg_src, reg_dst)
def propagate_pop_mem(reg, addr):
	overwrite_reg2mem(reg, addr)

#xchg
def propagate_xchg_rr(reg_src, reg_dst):
	exchange_reg2reg(reg_src, reg_dst)

def propagate_xchg_mr_rm(addr,reg):
	exchange_reg2mem(reg, addr)

#cmp
#nothing
