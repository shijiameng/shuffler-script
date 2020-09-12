from .block import *
from .it_block import *
from .nop import *
from .ref import RefIR, RefError
from .table_branch import BranchTableIR


class FunctionIR(BlockIR):
    def __init__(self, name, offset, parent=None):
        super().__init__(offset, init_pos=0, parent=parent)
        self.__name = name
        self.__ir_map = dict()
        self.isr = False

    def __str__(self):
        return "%s @ %s (size: %s)" % (self.__name, hex(self.addr), hex(self.len))

    @property
    def name(self):
        return self.__name

    def __update_ir_map(self):
        self.__ir_map.clear()
        for i in self._child:
            if not isinstance(i, BlockIR):
                self.__ir_map[i.offset] = i
            else:
                for j in i.child_iter():
                    self.__ir_map[j.offset] = j

    def layout_refresh(self):
        children = self._child
        finished = False
        while not finished:
            # remove all NOP IR
            children = list(filter(lambda x: not isinstance(x, NopIR) and not hasattr(x, "void"), children))
            where_nop = list()
            self._pos = 0
            # assign offset for each instruction
            for i in children:
                i.offset = self._pos
                if isinstance(i, BlockIR) and not isinstance(i, ITBlockIR) and not isinstance(i, BranchTableIR) and \
                        i.addr % 4 != 0:
                    # Align literal pool to 4 bytes
                    where_nop.append((children.index(i), self._pos))
                    self._pos += 2
                    i.offset = self._pos
                self._pos += i.len

            # insert NOP instructions to adjust the layout
            for idx, offset in where_nop:
                # children.insert(idx, NopIR(offset, parent=self))
                children.append(NopIR(offset, parent=self))

            children.sort(key=lambda x: x.offset)

            # check ref instructions is reachable
            ref_ir = list(filter(lambda x: isinstance(x, RefIR), children))
            if len(ref_ir) > 0:
                for i in ref_ir:
                    if not i.reachable():
                        i.len += 2
                        break
                    if i is ref_ir[-1]:
                        finished = True
            else:
                finished = True

        self._child = children
        self._len = self._pos
        self.__update_ir_map()

    def append_child(self, ir):
        super().append_child(ir)
        self.__ir_map[ir.offset] = ir
        if isinstance(ir, BlockIR):
            for i in ir.child_iter():
                self.__ir_map[ir.offset + i.offset] = i
        for k in self.__ir_map:
            i = self.__ir_map[k]
            if isinstance(i, RefIR) and not i.ref and i.ref_addr in self.__ir_map:
                i.ref = self.__ir_map[i.ref_addr]

    def insert_child(self, src_ir, new_ir, pos='before'):
        super().insert_child(src_ir, new_ir, pos)
        self.__update_ir_map()

    def get_ir(self, offset):
        return self.__ir_map[offset]
