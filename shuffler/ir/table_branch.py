from .block import BlockIR
from .ir import IR
from .ref import RefIR
from .utils import tohex


class TableBranchIR(IR):
    def __init__(self, offset, code, parent=None):
        super().__init__(offset, code, parent)
        self.__entry_size = 1

    def __repr__(self):
        return ("%s: Table Branch Byte (TBB)" if self.__entry_size == 1 else "%s: Table Branch Halfword (TBH)") \
               % hex(self.addr)

    def __str__(self):
        if len(self.code) > 0:
            return "%s (%s)" % (super().__str__(), self.__repr__())
        else:
            return self.__repr__()

    @property
    def entry_size(self):
        return self.__entry_size

    @entry_size.setter
    def entry_size(self, v):
        assert isinstance(v, int)
        assert v in (1, 2)
        self.__entry_size = v

    @property
    def len(self):
        return 4


class BranchTableIR(BlockIR):
    entry_size = 4


class TableBranchEntryIR(RefIR):
    def __init__(self, offset, length=4, parent=None):
        super().__init__(offset, parent)
        self._len = length

    def __repr__(self):
        if self._len == 1:
            return "%s: jump to %s (.byte 0x%02x)" % (hex(self.addr), hex(self.ref_addr), self.value)
        elif self._len == 2:
            return "%s: jump to %s (.short 0x%04x)" % (hex(self.addr), hex(self.ref_addr), self.value)
        else:
            return "%s: jump to %s (.word 0x%08x)" % (hex(self.addr), hex(self.ref_addr), self.value)

    def __str__(self):
        return self.__repr__()

    @property
    def len(self):
        return self._len

    @len.setter
    def len(self, v):
        assert isinstance(v, int)
        self._len = v

    @property
    def value(self):
        if self.len != 4:
            return tohex(self.__calc_disp(), 32) >> 1
        else:
            return self.parent.addr + self.__calc_disp() + 1

    def __calc_disp(self):
        return self.ref.addr - self.parent.addr

    def reachable(self):
        disp = tohex(self.__calc_disp(), 32)
        if self.len == 1:
            return (disp >> 1) <= 0xff
        elif self.len == 2:
            return (disp >> 1) <= 0xffff
        else:
            return True

    def asm(self):
        if self.reachable():
            disp = self.__calc_disp()
            if self.len != 4:
                target = disp >> 1
            else:
                target = self.parent.addr + disp + 1
            self._code = bytearray(target.to_bytes(self.len, byteorder='little'))
        else:
            raise ValueError("Out of range")

