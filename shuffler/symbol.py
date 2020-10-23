from capstone import *

from .ir.branch import BranchIR
from .ir.cond_branch import CondBranchIR
from .ir.it_block import ITBlockIR
from .ir.ldr import LoadLiteralIR
from .ir.literal import *
from .ir.nop import NopIR
from .ir.ret import ReturnIR
from .ir.table_branch import *
from .ir.indirect_branch import *
from .ir.pop import *


class Symbol:
    UINT32_MAX = 0xFFFFFFFF
    reloc = None

    def __init__(self, address, size, code, name=None):
        self.__address = address
        self.__size = size
        self.__code = code
        self.__literal_pool_base = self.UINT32_MAX
        self.__literal_pool_limit = self.UINT32_MAX
        self.__name = name
        self.__branch_targets = set()
        self.__jmp_tbl_br = -1
        self.__jmp_tbl_bv = -1  # jump table base address
        self.__jmp_tbl_il = 0  # jump table item length

        self.__md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
        self.__md.detail = True

        self.__md.skipdata_callback = lambda b, s, o, u: 4
        self.__md.skipdata = True

        if len(code) != size:
            print(len(code))
            print(size)

        assert (len(code) == size)

    @property
    def address(self):
        return self.__address

    @property
    def size(self):
        return self.__size

    @property
    def name(self):
        return self.__name

    @property
    def code(self):
        return self.__code

    def __handle_jump_table(self, base, item_length):
        jmp_tbl = self.__code[base:]
        limit = self.UINT32_MAX
        pos = 0
        ir = BranchTableIR(base)
        ir.entry_size = item_length

        while base + pos < limit and base + pos not in self.__branch_targets:
            value = int.from_bytes(jmp_tbl[pos:pos + item_length], byteorder='little')
            if item_length == 4:
                offset = value - self.__address
            else:
                offset = base + (value << 1)
            if offset in range(0, self.__size):
                item = TableBranchEntryIR(base, item_length)
                item.ref_addr = offset
                # if item_length == 4:
                #     print("value: %08x, offset: %s" % (value, hex(offset)))
                #     print("pos: %s, limit: %s" % (hex(base + pos), hex(limit)))
                if offset > base:
                    limit = min(offset, limit)
                ir.append_child(item)
                pos += item_length
            else:
                break

        return pos, ir

    def __handle_literal_pool(self, base):
        literal_pool = self.__code[base:]
        pos = 0
        ir = BlockIR(base)

        lp_limit = self.__literal_pool_limit - self.__address + 1
        while base + pos < lp_limit:
            item = LiteralIR(pos)
            item.value = int.from_bytes(literal_pool[pos:pos + 4], byteorder='little')
            ir.append_child(item)
            addr = self.__address + base + pos - 1
            if addr in self.reloc:
                # need to be relocated
                setattr(item, "reloc", self.reloc[addr])
            pos += 4

        self.__literal_pool_base = self.__literal_pool_limit = self.UINT32_MAX

        return pos, ir

    def __inst_analyze(self, bufp, inst):
        pos = inst.size

        if inst.id == ARM_INS_ADR:
            # instruction "ADD Rd, PC, #<const> (ADR Rd, <label>)"
            pc = ((inst.address - 1) + 4)
            self.__jmp_tbl_br = inst.operands[0].value.reg
            self.__jmp_tbl_bv = pc + inst.operands[1].value.imm
            ir = IR(bufp, inst.bytes)
            # print(hex(inst.address - 1))
            # print(hex(self.__jmp_tbl_bv))

        elif inst.id == ARM_INS_LDR:
            """
            LDR PC, [Rt, Rn, lsl #2] --> handle jump table
            LDR PC, [SP, #offset] --> handle function return
            LDR Rd, [PC, #offset] --> handle literal pool
            """
            if inst.operands[0].value.reg == ARM_REG_PC:
                if inst.operands[1].value.mem.base == ARM_REG_SP:
                    # TODO: handle function return
                    ir = ReturnIR(bufp)
                else:
                    if self.__jmp_tbl_br == inst.operands[1].value.mem.base and \
                            inst.operands[1].value.mem.index != 0:
                        self.__jmp_tbl_il = 4
                    ir = IR(bufp, inst.bytes)
            else:
                if inst.operands[1].value.mem.base == ARM_REG_PC:
                    # handle literal pool
                    pc = ((inst.address - 1) + 4) & ~3
                    literal_address = pc + inst.operands[1].value.mem.disp
                    if self.__literal_pool_base == self.UINT32_MAX:
                        self.__literal_pool_base = literal_address
                    else:
                        self.__literal_pool_base = min(self.__literal_pool_base, literal_address)

                    if self.__literal_pool_limit == self.UINT32_MAX:
                        self.__literal_pool_limit = self.__literal_pool_base + 4
                    else:
                        self.__literal_pool_limit = max(self.__literal_pool_limit, literal_address + 4)

                    ir = LoadLiteralIR(bufp)
                    ir.len = inst.size
                    ir.reg = ArmReg(inst.operands[0].value.reg)
                    ir.ref_addr = literal_address - self.address + 1
                else:
                    ir = IR(bufp, inst.bytes)

        elif inst.id in (ARM_INS_TBB, ARM_INS_TBH) and inst.operands[0].value.mem.base == ARM_REG_PC:
            # handle jump table
            ir = TableBranchIR(bufp, code=inst.bytes)
            self.__jmp_tbl_br = ARM_REG_PC
            # self.__jmp_tbl_bv = ((inst.address - 1) + 4) & ~3
            self.__jmp_tbl_bv = ((inst.address - 1) + 4)
            if inst.id == ARM_INS_TBB:
                ir.entry_size = self.__jmp_tbl_il = 1
            else:
                ir.entry_size = self.__jmp_tbl_il = 2

        elif inst.id in (ARM_INS_B, ARM_INS_BL):
            ir = BranchIR(bufp)
            ir.len = inst.size
            ir.link = inst.id == ARM_INS_BL
            if inst.operands[0].imm in range(self.__address, self.__address + self.__size):
                self.__branch_targets.add(inst.operands[0].imm - self.__address)
                ir.ref_addr = inst.operands[0].imm - self.__address
            else:
                ir.ref_addr = inst.operands[0].imm - 1

        elif inst.id in (ARM_INS_BX, ARM_INS_BLX):
            ir = IndirectBranchIR(bufp)
            ir.link = inst.id == ARM_INS_BLX
            ir.reg = inst.operands[0].value.reg

        elif inst.id in (ARM_INS_CBNZ, ARM_INS_CBZ):
            self.__branch_targets.add(inst.operands[1].imm - self.__address)
            ir = CondBranchIR(bufp)
            ir.reg = ArmReg(inst.operands[0].value.reg)
            ir.ref_addr = inst.operands[1].imm - self.__address
            ir.zero_flag = inst.id == ARM_INS_CBZ

        elif inst.id == ARM_INS_IT:
            ir = ITBlockIR(bufp)
            ir.first_cond = get_cond_id(inst.op_str)

        elif inst.id == ARM_INS_NOP:
            # ignore NOP instruction
            ir = NopIR(bufp, inst.size == 4)

        elif inst.id == ARM_INS_POP and inst.operands[-1].value.reg == ARM_REG_PC:
            ir = PopIR(bufp)
            ir.reg_list = {o.value.reg for o in inst.operands}

        else:
            ir = IR(bufp, inst.bytes)

        if inst.mnemonic == '.byte':
            print("0x%x:\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
        else:
            ir.cond = inst.cc

        return pos, ir

    def disasm(self):
        if hasattr(self, "type") and self.type != "STT_FUNC":
            raise SymbolDisassembleError

        bufp = 0
        while bufp < self.__size:
            buffer = self.__code[bufp:]
            # extract instructions and inline data
            address = self.__address + bufp
            it_block = None
            for inst in self.__md.disasm(buffer, address):
                if inst.address - 1 == self.__jmp_tbl_bv:
                    pos, ir = self.__handle_jump_table(bufp, self.__jmp_tbl_il)
                    self.__jmp_tbl_br = -1
                    self.__jmp_tbl_bv = -1
                    self.__jmp_tbl_il = 0
                    bufp += pos
                    yield ir
                    break

                if inst.address - 1 == self.__literal_pool_base:
                    pos, ir = self.__handle_literal_pool(bufp)
                    bufp += pos
                    yield ir
                    break

                pos, ir = self.__inst_analyze(bufp, inst)
                bufp += pos

                if not it_block:
                    if isinstance(ir, ITBlockIR):
                        it_block = {"capacity": len(inst.mnemonic) - 1, "ir": ir}
                    else:
                        yield ir
                else:
                    if it_block["capacity"] > 0:
                        ir.cond = inst.cc
                        it_block["ir"].append_child(ir)
                        it_block["capacity"] -= 1
                        if it_block["capacity"] == 0:
                            yield it_block["ir"]
                            it_block = None


class SymbolDisassembleError(Exception):
    pass
