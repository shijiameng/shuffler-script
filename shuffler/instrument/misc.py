from shuffler.ir.arm_reg import ArmReg
from shuffler.ir.block import BlockIR
from shuffler.ir.firmware import FirmwareIR
from shuffler.ir.function import FunctionIR
from shuffler.ir.ldr import LoadLiteralIR
from shuffler.ir.literal import LiteralIR

from capstone.arm import *

def wfi_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("wfi_veneer", 0)
    ir = LoadLiteralIR(0, parent=fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=cmse_fn["enter_low_power_mode"]))
    ir.ref = ir2
    fn.append_child(ir)
    fn.append_child(ir2)
    fw.insert_child(src, fn, pos='after')
    stretched_size = fn.layout_refresh()
    fw.stretch(fn, stretched_size)
    setattr(fw, "wfi_veneer", fn)

    return fn.len