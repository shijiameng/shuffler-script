import getopt
import sys

from capstone.arm import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import RelocationSection

from shuffler.ir.arm_reg import ArmReg
from shuffler.ir.block import BlockIR
from shuffler.ir.branch import BranchIR
from shuffler.ir.firmware import FirmwareIR
from shuffler.ir.function import FunctionIR
from shuffler.ir.indirect_branch import IndirectBranchIR
from shuffler.ir.ir import IR
from shuffler.ir.it_block import ITBlockIR
from shuffler.ir.ldr import LoadLiteralIR
from shuffler.ir.literal import LiteralIR
from shuffler.ir.object import ObjectIR
from shuffler.ir.pop import PopIR
from shuffler.ir.ret import ReturnIR
from shuffler.ir.ret_encode import LoadReturnOffsetIR, LoadCallerIndexIR, LoadFuncPtrIR
from shuffler.ir.retrieve import RetrieveIR
from shuffler.ir.vector import VectorIR
from shuffler.symbol import Symbol


def export_fn_pointers(elf, text_range):
    reloc_table = elf.get_section_by_name(".rel.text")
    if not isinstance(reloc_table, RelocationSection):
        raise Exception("No relocation table found")

    fn_ptrs = dict()

    symbols = elf.get_section(reloc_table["sh_link"])
    for i in reloc_table.iter_relocations():
        symbol = symbols.get_symbol(i["r_info_sym"])
        r_type = i["r_info_type"]
        r_offset = i["r_offset"]
        if r_type == ENUM_RELOC_TYPE_ARM["R_ARM_ABS32"] and symbol["st_value"] in text_range:
            fn_ptrs[r_offset] = dict(offset=symbol["st_value"], type=symbol["st_info"]["type"])
            if symbol["st_info"]["type"] == 'STT_FUNC':
                fn_ptrs[r_offset]["offset"] -= 1

    return fn_ptrs


def export_fn_symbols(elf):
    symtab = elf.get_section_by_name(".symtab")
    if not symtab:
        raise Exception("No symbol table found")

    strtab = elf.get_section_by_name(".strtab")
    if not strtab:
        raise Exception("No string table found")

    text = elf.get_section_by_name(".text")
    if not text:
        raise Exception("No text section found")

    code = text.data()
    text_base = text['sh_addr']
    text_range = range(text_base, text_base + len(code))

    fn_symbols = list()
    addresses = set()

    setattr(Symbol, "reloc", export_fn_pointers(elf, text_range))
    raw_symbols = list()

    # Extract all functions
    for s in symtab.iter_symbols():
        if s['st_value'] in text_range and s['st_value'] not in addresses:
            if s['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'):
                if strtab.get_string(s['st_name']) in ('__bhs_ldivmod1', '__aeabi_memcpy4'):
                    continue
                addresses.add(s['st_value'])
                raw_symbols.append(s)
            elif s['st_info']['type'] == 'STT_NOTYPE' and s['st_info']['bind'] == 'STB_GLOBAL' and \
                    not (s.name[-6:] == '_start' or s.name[-4:] == '_end'):
                raw_symbols.append(s)
            else:
                pass

    raw_symbols.sort(key=lambda x: x['st_value'])

    prev_symbol = None
    gap_cnt = 0
    for i in range(len(raw_symbols)):
        s = raw_symbols[i]
        st_value = s['st_value']
        st_size = s['st_size']

        if prev_symbol and s['st_info']['type'] == 'STT_OBJECT' and prev_symbol['st_info']['type'] == 'STT_OBJECT':
            if st_value - prev_symbol['st_value'] != prev_symbol['st_size']:
                gap_size = st_value - prev_symbol['st_value'] - prev_symbol['st_size']
                gap_addr = prev_symbol['st_value'] + prev_symbol['st_size']
                start = gap_addr - text_base
                end = start + gap_size
                fn_code = code[start:end]
                sym = Symbol(gap_addr, gap_size, fn_code, "gap%d" % gap_cnt)
                setattr(sym, "type", "STT_OBJECT")
                fn_symbols.append(sym)
                gap_cnt += 1

        if s.name != '__aeabi_memcpy':
            if st_size == 0 and i < len(raw_symbols) - 1:
                st_size = raw_symbols[i + 1]['st_value'] - st_value
                if raw_symbols[i + 1]['st_info']['type'] == 'STT_FUNC':
                    st_size -= 1
        else:
            st_size = 52

        start = st_value - text_base
        if s['st_info']['type'] == 'STT_FUNC':
            start -= 1

        end = start + st_size
        fn_code = code[start:end]

        if s['st_info']['type'] == 'STT_NOTYPE':
            st_type = 'STT_OBJECT'
        else:
            st_type = s['st_info']['type']

        sym = Symbol(st_value, st_size, fn_code, strtab.get_string(s['st_name']))
        setattr(sym, "type", st_type)
        fn_symbols.append(sym)
        prev_symbol = s

        if i == len(raw_symbols) - 1:
            if len(code[end:]) > 0:
                st_value = end + text_base
                st_size = len(code[end:])
                fn_code = code[end:]
                sym = Symbol(st_value, st_size, fn_code, "gap%d" % gap_cnt)
                sym.type = 'STT_OBJECT'
                fn_symbols.append(sym)

    return fn_symbols


def symbol_translate(s, fw: FirmwareIR):
    if s.type == "STT_FUNC":
        ir = FunctionIR(s.name, 0, fw)
        for i in s.disasm():
            ir.append_child(i)
        if s.address in fw.vector.vector:
            ir.isr = True
    else:
        if s.address == fw.addr:
            # handle vector table
            ir = VectorIR(s.code)
            setattr(fw, "vector", ir)
        else:
            ir = ObjectIR(s.name, code=s.code)
        # handle relocation
        offset = 0
        while len(s.code) - offset >= 4:
            addr = s.address + offset
            if addr in Symbol.reloc:
                if not hasattr(ir, "reloc_map"):
                    setattr(ir, "reloc_map", dict())
                ir.reloc_map[offset] = Symbol.reloc[addr]
            offset += 4

    return ir


def do_instrument(src_ir, new_ir, pos='before'):
    if isinstance(src_ir.parent, ITBlockIR):
        new_ir.cond = src_ir.cond
        it_block = src_ir.parent
        if pos != 'replace':
            if it_block.size < 4:
                if src_ir.cond == it_block.first_cond:
                    it_block.insert_child(src_ir, new_ir, pos=pos)
                else:
                    it_block.insert_child(src_ir, new_ir, cond='e', pos=pos)
            else:
                new_it_block = it_block.split(it_block.child_index(src_ir))
                new_it_block.insert_child(src_ir, new_ir, pos=pos)
                assert isinstance(it_block.parent, FunctionIR)
                it_block.parent.insert_child(it_block, new_it_block, pos='after')
        else:
            it_block.insert_child(src_ir, new_ir, pos='replace')
    else:
        assert isinstance(src_ir.parent, FunctionIR)
        src_ir.parent.insert_child(src_ir, new_ir, pos=pos)


def reference_handoff(dst_ir, src_ir):
    if hasattr(src_ir, "ref_by"):
        for i in src_ir.ref_by:
            i.ref = dst_ir
        delattr(src_ir, "ref_by")


def fn_instrument(fn: FunctionIR, fw: FirmwareIR):
    need_instrument = lambda x: isinstance(x, BranchIR) and x.link and isinstance(x.ref, FunctionIR) or \
                                isinstance(x, IndirectBranchIR) and (x.link or str(x.reg) == "lr") or \
                                isinstance(x, PopIR) or isinstance(x, ReturnIR)
    ipoint = list()
    for i in fn.child_iter():
        if isinstance(i, BlockIR):
            for j in i.child_iter():
                if need_instrument(j):
                    ipoint.append(j)
        else:
            if need_instrument(i):
                ipoint.append(i)

    if len(ipoint) > 0:
        for i in ipoint:
            if isinstance(i, BranchIR):
                i.link = False
                ir = LoadReturnOffsetIR(parent=fn)
                reference_handoff(ir, i)
                do_instrument(i, ir)
                do_instrument(i, LoadCallerIndexIR(fw.child_index(fn), parent=fn))
            elif isinstance(i, IndirectBranchIR):
                if i.link:
                    ir = LoadFuncPtrIR(i.reg, parent=fn)
                    reference_handoff(ir, i)
                    do_instrument(i, ir)
                    do_instrument(i, LoadReturnOffsetIR(parent=fn))
                    do_instrument(i, LoadCallerIndexIR(fw.child_index(fn), parent=fn))
                    ir = BranchIR(i.offset, parent=fn)
                    ir.len = 4
                    ir.ref = fw.indirect_call_veneer
                    do_instrument(i, ir, pos='replace')
                elif str(i.reg) == 'lr' and not fn.isr:
                    ir = BranchIR(i.offset, parent=fn)
                    ir.len = 4
                    ir.ref = fw.return_veneer
                    reference_handoff(ir, i)
                    do_instrument(i, ir, pos='replace')
                else:
                    pass
            elif (isinstance(i, PopIR) or isinstance(i, ReturnIR)) and not fn.isr:
                ir1 = RetrieveIR(i.offset, parent=fn)
                if isinstance(i, PopIR):
                    i.remove_reg(ARM_REG_PC)
                    do_instrument(i, ir1, pos='after')
                else:
                    reference_handoff(ir1, i)
                    do_instrument(i, ir1, pos='replace')
                ir2 = BranchIR(ir1.offset, parent=fn)
                ir2.len = 4
                ir2.ref = fw.return_veneer
                do_instrument(ir1, ir2, pos='after')
            else:
                pass
        # fn.layout_refresh()

    return fn


def indirect_call_veneer_instrument(fw: FirmwareIR):
    fn = FunctionIR("indirect_call_veneer", 0)
    ir = LoadLiteralIR(0, fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=0x1001fe01))
    ir.ref = ir2
    fn.append_child(ir)
    fn.append_child(ir2)
    fn.layout_refresh()
    fw.append_child(fn)
    return fn


def return_veneer_instrument(fw: FirmwareIR):
    fn = FunctionIR("return_veneer", 0)
    fn.append_child(IR(0, bytearray(b"\x4d\xf8\x04\xcd")))  # push {r12}
    fn.append_child(IR(0, bytearray(b"\xce\xf3\x07\x6c")))  # ubfx r12, lr, #24, #8
    fn.append_child(IR(0, bytearray(b"\xbc\xf1\xff\x0f")))  # cmp r12, #0xff
    lp_block = BlockIR(0)
    lp_block.append_child(LiteralIR(0, value=0x1001fe29))
    it_block = ITBlockIR(0)  # itt ne
    it_block.first_cond = ARM_CC_NE
    pop = IR(0, bytearray(b"\x5d\xf8\x04\xcb"))
    pop.cond = ARM_CC_NE
    it_block.append_child(pop)  # popne {r12}
    ldr = LoadLiteralIR(0)  # ldrne pc, [pc, #xx]
    ldr.reg = ArmReg(ARM_REG_PC)
    ldr.ref = lp_block
    ldr.len = 4
    ldr.cond = ARM_CC_NE
    it_block.append_child(ldr)
    fn.append_child(it_block)
    fn.append_child(IR(0, bytearray(b"\xef\xf3\x05\x8c")))  # mrs r12, ipsr
    fn.append_child(IR(0, bytearray(b"\xbc\xf1\x00\x0f")))  # cmp r12, #0
    cpsid = IR(0, bytearray(b"\x72\xb6"))  # cpsid i
    infinit_loop = BranchIR(0)
    infinit_loop.len = 2
    infinit_loop.ref = cpsid  # beq infinit_loop
    infinit_loop.cond = ARM_CC_EQ
    fn.append_child(infinit_loop)
    fn.append_child(IR(0, bytearray(b"\x5d\xf8\x04\xcb")))  # pop {r12}
    bx = IndirectBranchIR(0)  # bx lr
    bx.reg = ARM_REG_LR
    bx.link = False
    fn.append_child(bx)
    fn.append_child(cpsid)
    infinit_loop = BranchIR(0)
    infinit_loop.len = 2
    infinit_loop.ref = infinit_loop
    fn.append_child(infinit_loop)
    fn.append_child(lp_block)
    fn.layout_refresh()
    fw.append_child(fn)
    return fn


def fw_instrument(fw: FirmwareIR, entry_point: int):
    new_fw = FirmwareIR("new", entry_point)

    # instrument indirect call veneer
    fw.indirect_call_veneer = indirect_call_veneer_instrument(fw)
    fw.return_veneer = return_veneer_instrument(fw)
    fw.commit()

    # new_fw = FirmwareIR("new", 0x20180)
    for fn in fw.child_iter():
        if isinstance(fn, FunctionIR):
            if fn.name in ("return_veneer", "indirect_call_veneer"):
                new_fw.append_child(fn, 4)
            else:
                new_fn = fn_instrument(fn, fw)
                # new_fw.append_child(new_fn, 4 if fn.addr % 4 == 0 else 2)
                new_fw.append_child(new_fn)
            fn.layout_refresh()
        else:
            new_fw.append_child(fn)

    return new_fw


def do_relocate(fw: FirmwareIR, ir, reloc, offset=0):
    if isinstance(ir, LiteralIR):
        value = ir.value
    else:
        value = int.from_bytes(ir.code[offset:offset + 4], byteorder='little')

    new_value = -1

    if reloc["type"] in ("STT_OBJECT", "STT_NOTYPE"):
        # print("%s: %s = %s@%s new: %s" % (ir, hex(value), fw.fn_map[value]["symbol"].name,
        #                                   hex(fw.fn_map[value]["symbol"].address), hex(fw.fn_map[value]["ir"].addr)))
        new_value = fw.fn_map[value]["ir"].addr
    elif reloc["type"] == "STT_FUNC":
        # TODO: encode function pointer
        # print("%s: %s = %s@%s new: %s" % (ir, hex(value), fw.fn_map[value - 1]["symbol"].name,
        #                                   hex(fw.fn_map[value - 1]["symbol"].address),
        #                                   hex(fw.fn_map[value - 1]["ir"].addr + 1)))
        if isinstance(ir, VectorIR):
            # Do not encode ISR
            new_value = fw.fn_map[value - 1]["ir"].addr + 1
        else:
            # Encode function pointer as the shufferable form
            new_value = ((0x1002 << 16) | (fw.child_index(fw.fn_map[value - 1]["ir"]) << 1)) + 1
        pass
    else:
        # TODO: STT_SECTION
        if value not in fw.fn_map:
            for k in fw.fn_map:
                if k < value < k + fw.fn_map[k]["symbol"].size:
                    # print("%s: %s = %s@%s + %s new %s" % (ir, hex(value), fw.fn_map[k]["symbol"].name,
                    #                                       hex(fw.fn_map[k]["symbol"].address), hex(value - k),
                    #                                       hex(fw.fn_map[k]["ir"].addr + value - k)))
                    new_value = fw.fn_map[k]["ir"].addr + value - k
        else:
            new_value = fw.fn_map[value]["ir"].addr

    assert new_value != -1

    if isinstance(ir, LiteralIR):
        ir.value = new_value
    else:
        # print(ir)
        ir.code[offset:offset+4] = bytearray(new_value.to_bytes(4, byteorder="little"))


def relocate_recursive(fw: FirmwareIR, ir: IR):
    if hasattr(ir, "child_iter"):
        for i in ir.child_iter():
            relocate_recursive(fw, i)
    else:
        if hasattr(ir, "reloc"):
            do_relocate(fw, ir, ir.reloc)
        elif hasattr(ir, "reloc_map"):
            for k in ir.reloc_map:
                do_relocate(fw, ir, ir.reloc_map[k], offset=k)
        else:
            pass


def main(argv):
    input_file = ''
    output_path = ''
    entry_point = 0

    try:
        opts, args = getopt.getopt(argv, 'e:hi:o:', ['entry-point=', 'input-file=', 'output-path='])
    except getopt.GetoptError:
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-e', '--entry-point'):
            entry_point = int(arg, base=16)
        elif opt in ('-i', '--input-file'):
            input_file = arg
        elif opt in ('-o', '--output-file'):
            output_file = arg
        else:
            print('Invalid argument - %s' % opt)
            sys.exit(1)

    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        fn_symbols = export_fn_symbols(elf)
        fw = FirmwareIR(input_file, entry_point)

        for s in fn_symbols:
            fn = symbol_translate(s, fw)
            fw.append_child(fn)
            if s.type == "STT_FUNC":
                fw.fn_map[s.address - 1] = dict(symbol=s, ir=fn)
            else:
                fw.fn_map[s.address] = dict(symbol=s, ir=fn)

        fw.commit()

        new_fw = fw_instrument(fw, entry_point)
        new_fw.fn_map = fw.fn_map
        relocate_recursive(new_fw, new_fw)
        new_fw.asm()

        for fn in new_fw.child_iter():
            print(fn)
            if isinstance(fn, FunctionIR):
                if hasattr(fn, "child_iter"):
                    for ir in fn.child_iter():
                        print(ir)
            else:
                print(fn.code)
            print()

        new_fw.save_as_file(output_file)


if __name__ == '__main__':
    main(sys.argv[1:])
