from .ir import IR


class ObjectIR(IR):
    def __init__(self, name, code, offset=0, parent=None):
        super().__init__(offset, code, parent)
        self._name = name
        if len(self._code) % 2 != 0:
            print("%s: %d" % (name, len(self._code)))
            self._code += b'\xff'

    def __str__(self):
        return "%s @ %s (size: %s)" % (self.name, hex(self.addr), self.len)

    @property
    def name(self):
        return self._name

    @property
    def code(self):
        return super().code

    @code.setter
    def code(self, v):
        self._code = bytearray(v)
