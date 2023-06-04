# taint data type
#taint_data = {"taint_tag":-1, "taint_count":0}


normal_regs = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]
normal_regs_d = ["eax", "ebx", "ecx", "edx", "esp", "ebp", "esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"]
normal_regs_w = ["ax", "bx", "cx", "dx", "sp", "bp", "si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"]
normal_regs_b = ["al", "bl", "cl", "dl", "spl", "bpl", "sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"]
normal_regs_h = ["ah", "bh", "ch", "dh"]
taint_regs = {}
taint_mems = {}

def reg_normal(reg):
	if reg in normal_regs_b:
		return normal_regs[normal_regs_b.index(reg)]

	elif reg in normal_regs_d:
		return normal_regs[normal_regs_d.index(reg)]

	elif reg in normal_regs_w:
		return normal_regs[normal_regs_w.index(reg)]
	
	elif reg in normal_regs_h:
		return normal_regs[normal_regs_h.index(reg)]
	else:
		return reg


def taint_regs_init():
	for reg in normal_regs:
		#taint_list1 --> eax....
		#taint_reg = {"taint_list1":[], "taint_list2":[]}
		taint_regs[reg] = []


def taint_regs_append(reg, taint_tag):
	reg = reg_normal(reg)
	value = taint_regs[reg]
	for ii in value:
		if ii["taint_tag"] == taint_tag:
			ii["taint_count"] = ii["taint_count"] + 1
			return
	taint_regs[reg].append({"taint_tag":taint_tag, "taint_count":1})

def taint_regs_pop(reg, taint_tag):
	reg = reg_normal(reg)
	value = taint_regs[reg]
	for ii in value:
		if ii["taint_tag"] == taint_tag:
			ii["taint_count"] = ii["taint_count"] - 1
			if ii["taint_count"] == 0:
				value.pop(ii)
			break

def taint_regs_clean(reg):
	reg = reg_normal(reg)
	taint_regs[reg] = []	


def taint_mems_init():
	pass

def taint_mems_append(addr, taint_tag):
	for key,value in taint_mems.items():
		if key == addr:
			for ii in value:
				if ii["taint_tag"] == taint_tag:
					ii["taint_count"] = ii["taint_count"] + 1
					return
			
			value.append({"taint_tag":taint_tag, "taint_count":1})
			return

		
	taint_mems[addr] = [{"taint_tag":taint_tag, "taint_count":1}]

def taint_mems_pop(addr, taint_tag):
	for key,value in taint_mems.items():
		if key == addr:
			for ii in value:
				if ii["taint_tag"] == taint_tag:
					ii["taint_count"] = ii["taint_count"] - 1
					if ii["taint_count"] == 0:
						value.pop(ii)

						if value == []:
							taint_mems.pop(key)
					break
			break

def taint_mems_clean(addr):
	if addr in taint_mems.keys():
		taint_mems.pop(addr)


# merge, exchange, overwrite
# merge
def merge_reg2reg(reg_src, reg_dst):
	reg_src = reg_normal(reg_src)
	reg_dst = reg_normal(reg_dst)
	taint_regs[reg_dst].extend(taint_regs[reg_src])


def merge_reg2mem(reg, addr):
	reg = reg_normal(reg)
	if taint_regs[reg] == []:
		return
	if addr not in taint_mems.keys():
		taint_mems[addr] = taint_regs[reg]
	else:
		taint_mems[addr].extend(taint_regs[reg])


def merge_mem2reg(addr, reg):
	reg = reg_normal(reg)
	if addr not in taint_mems.keys():
		return
	taint_regs[reg].extend(taint_mems[addr])

def merge_mem2mem(addr_src, addr_dst):
	if addr_src not in taint_mems.keys():
		return
	if addr_dst not in taint_mems.keys():
		taint_mems[addr_dst] = taint_mems[addr_src]
	else:
		taint_mems[addr_dst].extend(taint_mems[addr_src])

#overwrite
def overwrite_mem2mem(addr_src, addr_dst):
	if addr_dst not in taint_mems.keys():
		if addr_src not in taint_mems.keys():
			return
		else:
			taint_mems[addr_dst] = taint_mems[addr_src]
	else:
		if addr_src not in taint_mems.keys():
			taint_mems.pop(addr_dst)
		else:
			taint_mems[addr_dst] = taint_mems[addr_src]

def overwrite_reg2mem(reg, addr):
	reg = reg_normal(reg)
	if addr not in taint_mems.keys():
		if taint_regs[reg] == []:
			return
		else:
			taint_mems[addr] = taint_regs[reg]
	else:
		if taint_regs[reg] == []:
			taint_mems.pop(addr)
		else:
			taint_mems[addr] = taint_regs[reg]

def overwrite_reg2reg(reg_src, reg_dst):
	#print(reg_src)
	reg_src = reg_normal(reg_src)
	reg_dst = reg_normal(reg_dst)
	taint_regs[reg_dst] = taint_regs[reg_src]

def overwrite_mem2reg(addr, reg):
	reg = reg_normal(reg)
	if addr not in taint_mems.keys():
		return
	else:
		taint_regs[reg] = taint_mems[addr]

#exchange
def exchange_reg2reg(reg_src, reg_dst):
	reg_src = reg_normal(reg_src)
	reg_dst = reg_normal(reg_dst)
	taint_regs[reg_src], taint_regs[reg_dst] = taint_regs[reg_dst], taint_regs[reg_src]

def exchange_reg2mem(reg, addr):
	reg = reg_normal(reg)
	if addr not in taint_mems.keys():
		if taint_regs[reg] == []:
			return
		else:
			taint_mems[addr] = taint_regs[reg]
			taint_regs[reg] = []
	else:
		if taint_regs[reg] == []:
			taint_regs[reg] = taint_mems[addr]
			taint_mems.pop(addr)
		else:
			taint_mems[addr], taint_regs[reg] = taint_regs[reg], taint_mems[addr]

def exchange_mem2mem(addr_src, addr_dst):
	if addr_src not in taint_mems.keys():
		if addr_dst not in taint_mems.keys():
			return
		else:
			taint_mems[addr_src] = taint_mems[addr_dst]
			taint_mems.pop(addr_dst)
	else:
		if addr_dst not in taint_mems.keys():
			taint_mems[addr_dst] = taint_mems[addr_src]
			taint_mems.pop(addr_src)
		else:
			taint_mems[addr_src], taint_mems[addr_dst] = taint_mems[addr_dst], taint_mems[addr_src]

def exchange_mem2reg(addr, reg):
	reg = reg_normal(reg)
	if addr not in taint_mems.keys():
		if taint_regs[reg] == []:
			return
		else:
			taint_mems[addr] = taint_regs[reg]
			taint_regs[reg] = []
	else:
		if taint_regs[reg] == []:
			taint_regs[reg] = taint_mems[addr]
			taint_mems.pop(addr)
		else:
			taint_mems[addr], taint_regs[reg] = taint_regs[reg], taint_mems[addr]