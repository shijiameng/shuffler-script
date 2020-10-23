from .block import BlockIR
from .branch import BranchIR
from .function import FunctionIR, NopIR
from .ir import IR


class FirmwareIR(BlockIR):
    def __init__(self, name, offset=0):
        super().__init__(offset)
        self.__name = name
        self.fn_map = dict()

    @property
    def name(self):
        return self.__name

    @property
    def parent(self):
        return None

    def append_child(self, fn: IR, align=2):
        assert align in (2, 4)

        # if fn.name == "vRestoreContextOfFirstTask":
        #     print("======")
        #     print(hex(self.addr + self._pos))
        # if align == 4 and (self.addr + self._pos) % 4 != 0:
        #     super().append_child(NopIR(0))
        #
        # if fn.name == "vRestoreContextOfFirstTask":
        #     print("======")
        #     print(hex(self.addr + self._pos))

        super().append_child(fn)

        # if fn.name == "vRestoreContextOfFirstTask":
        #     print("======!!!")
        #     print(hex(fn.addr))

    def commit(self):
        fn = filter(lambda x: isinstance(x, FunctionIR), self._child)
        for i in fn:
            for ir in i.child_iter():
                if isinstance(ir, BranchIR) and not ir.ref:
                    if ir.ref_addr in self.fn_map:
                        ir.ref = self.fn_map[ir.ref_addr]["ir"]
                    else:
                        for k in self.fn_map:
                            if k < ir.ref_addr <= k + self.fn_map[k]["ir"].len:
                                ir.ref = self.fn_map[k]["ir"].get_ir(ir.ref_addr - k)
                        if not ir.ref:
                            print(ir)
                        assert ir.ref

    def verify(self):
        pos = 0
        for i in self._child:
            if hasattr(i, "verify"):
                i.verify()

            if i.offset != pos:
                print("%s, offset is incorrect!")
                assert 1 == 0
            else:
                pos += i.len

    def output_to_stream(self, ir, stream):
        if not hasattr(ir, "child_iter"):
            stream.write(ir.code)
            return len(ir.code)
        else:
            for i in ir.child_iter():
                return self.output_to_stream(i, stream)

    def save_as_file(self, path):
        with open(path, "wb") as stream:
            stream.write(self.code)
