from .ref import *
from .arm_reg import *


class LiteralIR(IR):
    def __init__(self, offset, value=0xFFFFFFFF, parent=None):
        super().__init__(offset, None, parent)
        self._code = bytearray(value.to_bytes(4, byteorder='little'))

    @property
    def value(self):
        return int.from_bytes(self._code, 'little')

    @value.setter
    def value(self, v):
        assert isinstance(v, int)
        self._code = bytearray(v.to_bytes(4, byteorder='little'))

    def __str__(self):
        if not hasattr(self, "reloc"):
            return "%s: %08x .word 0x%08x" % (hex(self.addr), self.value, self.value)
        else:
            return "%s: %08x .word 0x%08x (RELOC: %s)" % (hex(self.addr), self.value, self.value, self.reloc["type"])