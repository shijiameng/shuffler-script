from keystone import KsError

from .block import *
from .utils import *


class ITBlockIR(BlockIR):
    MAX_CAPACITY = 4

    def __init__(self, offset, parent=None):
        super().__init__(offset, init_pos=2, parent=parent)
        self.__first_cond = ARM_CC_EQ
        self._len = 2

    def __repr__(self):
        irstr = "%s: IT Block (first condition: %s)\n" % (hex(self.addr), get_cond_name(self.first_cond))
        return irstr + super().__repr__()

    def __str__(self):
        if len(self._code) > 0:
            return super().__str__()
        else:
            return self.__repr__()
        # irstr = "%s: IT Block (first condition: %s)" % (hex(self.addr), get_cond_name(self.first_cond))
        # for i in self.child_iter():
        #     irstr += "\n%s %s" % (i, get_cond_name(i.cond))
        # return irstr

    @property
    def first_cond(self):
        return self.__first_cond

    @first_cond.setter
    def first_cond(self, c):
        assert c in range(ARM_CC_EQ, ARM_CC_AL + 1)
        self.__first_cond = c

    def insert_child(self, src_ir, new_ir, pos='before'):
        assert pos.lower() in ('before', 'after', 'replace')

        if self.size < self.MAX_CAPACITY:
            super().insert_child(src_ir, new_ir, pos)
            if super().child_index(new_ir) == 0:
                assert new_ir.cond == self.first_cond
        else:
            raise ITBlockFull

    def append_child(self, ir):
        if self.size < self.MAX_CAPACITY:
            if self.size == 0:
                assert ir.cond == self.first_cond
            super().append_child(ir)
        else:
            raise ITBlockFull

    def layout_refresh(self):
        self._pos = 2
        self._len = 2
        super().layout_refresh()

    def split(self, where):
        assert where < len(self._child)
        it_block = ITBlockIR(0)
        it_block.first_cond = self._child[where].cond
        for i in self._child[where:]:
            it_block.append_child(i)
            self._len -= i.len
        self._child = list(filter(lambda x: self._child.index(x) < where, self._child))
        return it_block

    def asm(self):
        # step 1: Assemble the IT instruction
        # step 2: Assemble each instruction in the block
        super().asm()

        asmcode = list('i')
        for i in self.child_iter():
            # i.asm()
            # self._code += i.code
            asmcode += 't' if i.cond == self.__first_cond else 'e'

        asmcode += ' ' + get_cond_name(self.__first_cond)
        code, count = IR._ks.asm(''.join(asmcode))
        # self._code = bytearray(code) + self._code
        self._code = bytearray(code)


class ITBlockFull(BlockInsertError):
    pass


class ITBlockInvalidCond(BlockInsertError):
    pass


class ITBlockInsertError(BlockInsertError):
    pass
