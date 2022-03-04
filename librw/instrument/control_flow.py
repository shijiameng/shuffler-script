from librw.ir.arm_reg import ArmReg
from librw.ir.block import BlockIR
from librw.ir.firmware import FirmwareIR
from librw.ir.function import FunctionIR
from librw.ir.indirect_branch import IndirectBranchIR
from librw.ir.ir import IR
from librw.ir.it_block import ITBlockIR
from librw.ir.ldr import LoadLiteralIR
from librw.ir.literal import LiteralIR

from capstone.arm import *


def indirect_branch_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("indirect_branch_veneer", 0)

    fn.append_child(IR(0, "push {r0}"))  # push {r0}
    fn.append_child(IR(0, "mov r0, #0xFF"))  # mov r0, #0xFF
    fn.append_child(IR(0, "eors r0, r12, lsr #24"))  # eors r0, r12, lsr #24
    fn.append_child(IR(0, "pop {r0}"))  # pop {r0}

    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_EQ
    ir = IndirectBranchIR(ARM_REG_R12)
    ir.cond = ARM_CC_EQ
    it_block.append_child(ir)

    fn.append_child(it_block)
    fn.append_child(IR(0, "tst r12, #0x10000000"))  # tst r12, #0x10000000
    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_NE

    literal_pool = BlockIR(0)
    literal_pool.append_child(LiteralIR(0, value=cmse_fn["call_address_dispatch"]))  # indirect_call_dispatch
    literal_pool.append_child(LiteralIR(0, value=cmse_fn["return_address_dispatch"]))  # return_dispatch

    ir = LoadLiteralIR(0)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir.cond = ARM_CC_NE
    ir.ref = literal_pool.child_at(0)

    it_block.append_child(ir)

    ir = LoadLiteralIR(0)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir.cond = ARM_CC_EQ
    ir.ref = literal_pool.child_at(1)

    fn.append_child(it_block)
    fn.append_child(ir)
    fn.append_child(literal_pool)
    fw.insert_child(src, fn, pos='after')
    stretched_size = fn.layout_refresh()
    fw.stretch(fn, stretched_size)
    setattr(fw, "indirect_branch_veneer", fn)
    return fn.len


def indirect_call_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("indirect_call_veneer", 0)
    ir = LoadLiteralIR(0, parent=fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=cmse_fn["call_address_dispatch"]))
    ir.ref = ir2
    fn.append_child(ir)
    fn.append_child(ir2)
    fw.insert_child(src, fn, pos='after')
    stretched_size = fn.layout_refresh()
    fw.stretch(fn, stretched_size)
    setattr(fw, "indirect_call_veneer", fn)
    return fn.len


def return_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("return_veneer", 0)

    fn.append_child(IR(code="ldr lr, [sp], #4"))
    fn.append_child(IR(code="mov r12, lr, lsr #24"))
    fn.append_child(IR(code="cmp r12, #0xFF"))

    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_EQ
    ir = IndirectBranchIR(ARM_REG_LR)
    ir.cond = ARM_CC_EQ
    it_block.append_child(ir)
    ir = LoadLiteralIR(0, parent=fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=cmse_fn["return_address_dispatch"]))
    ir.ref = ir2
    fn.append_child(it_block)
    fn.append_child(ir)
    fn.append_child(ir2)

    fw.insert_child(src, fn, pos='after')

    stretched_size = fn.layout_refresh()
    fw.stretch(fn, stretched_size)
    setattr(fw, "return_veneer", fn)

    return fn.len