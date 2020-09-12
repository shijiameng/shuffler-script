from capstone.arm import *

_REG_STR = {
    ARM_REG_R0: "r0",
    ARM_REG_R1: "r1",
    ARM_REG_R2: "r2",
    ARM_REG_R3: "r3",
    ARM_REG_R4: "r4",
    ARM_REG_R5: "r5",
    ARM_REG_R6: "r6",
    ARM_REG_R7: "r7",
    ARM_REG_R8: "r8",
    ARM_REG_R9: "r9",
    ARM_REG_R10: "r10",
    ARM_REG_R11: "r11",
    ARM_REG_R12: "r12",
    ARM_REG_SP: "sp",
    ARM_REG_LR: "lr",
    ARM_REG_PC: "pc"
}

_COND_STR = {
    ARM_CC_EQ: "eq",
    ARM_CC_NE: "ne",
    ARM_CC_HS: "cs",
    ARM_CC_LO: "cc",
    ARM_CC_MI: "mi",
    ARM_CC_PL: "pl",
    ARM_CC_VS: "vl",
    ARM_CC_VC: "vc",
    ARM_CC_HI: "hi",
    ARM_CC_LS: "ls",
    ARM_CC_GE: "ge",
    ARM_CC_LT: "lt",
    ARM_CC_GT: "gt",
    ARM_CC_LE: "le",
    ARM_CC_AL: "",
}

_COND_ID = {
    "eq": ARM_CC_EQ,
    "ne": ARM_CC_NE,
    "hs": ARM_CC_HS,
    "cs": ARM_CC_HS,
    "lo": ARM_CC_LO,
    "cc": ARM_CC_LO,
    "mi": ARM_CC_MI,
    "pl": ARM_CC_PL,
    "vl": ARM_CC_VS,
    "vc": ARM_CC_VC,
    "hi": ARM_CC_HI,
    "ls": ARM_CC_LS,
    "ge": ARM_CC_GE,
    "lt": ARM_CC_LT,
    "gt": ARM_CC_GT,
    "le": ARM_CC_LE,
    "": ARM_CC_AL
}


def get_register_name(r_id):
    return _REG_STR[r_id]


def get_cond_name(c_id):
    return _COND_STR[c_id]


def get_cond_id(c_str):
    return _COND_ID[c_str]


def tohex(val, nbits):
    return (val + (1 << nbits)) % (1 << nbits)
