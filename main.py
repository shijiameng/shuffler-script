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
from shuffler.ir.ret_encode import LoadReturnOffsetIR, LoadCallerIndexIR, LoadFuncPtrIR, LoadReturnIndexIR
from shuffler.ir.retrieve import RetrieveIR
from shuffler.ir.table_branch import TableBranchEntryIR
from shuffler.ir.vector import VectorIR
from shuffler.symbol import Symbol


def export_cmse_fn(elf):
    symtab = elf.get_section_by_name(".symtab")
    if not symtab:
        raise Exception("No symbol table found")

    cmse_fn = dict()
    for s in symtab.iter_symbols():
        if s['st_info']['type'] == "STT_FUNC":
            print("%s: %s" % (s.name, hex(s['st_value'])))
            cmse_fn[s.name] = s['st_value']

    return cmse_fn


def export_data_section(elf):
    data = elf.get_section_by_name(".data")
    ir = ObjectIR(".data", data.data())
    return ir


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

    etext = text_base + len(code)

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
                if s.name == '_etext':
                    print("_etext: %s" % hex(s['st_value']))
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

    return fn_symbols, etext


def symbol_translate(s, fw: FirmwareIR):
    if s.type == "STT_FUNC":
        ir = FunctionIR(s.name, 0, fw)
        print(ir)
        for i in s.disasm():
            # print("%s: %s\t%s\n" % (hex(i.address), i.mnemonic, i.op_str))
            if s.name == "pow":
                print(i)
            ir.append_child(i)
        ir.commit()
        if s.address in fw.vector.vector:
            ir.isr = True
            setattr(ir, "irq", fw.vector.vector.index(s.address))
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

    if fn.name[0:8] == "__Secure":
        first_ir = None
        for i in fn.child_iter():
            first_ir = i
            break
        # ir = IR(0, b"\x4e\xf0\x40\x5e")
        # do_instrument(first_ir, IR(0, b"\x4f\xea\x4e\x0e"))  # lsl lr, lr, #1
        do_instrument(first_ir, IR(0, b"\x4e\xf0\x40\x5e"))  # orr lr, lr, #0x30000000
        # do_instrument(first_ir, IR(0, b"\x4e\xf0\x01\x0e"))  # orr lr, lr, #1
    else:
        need_instrument = lambda x: isinstance(x, BranchIR) and x.link or \
                                    isinstance(x, IndirectBranchIR) or \
                                    isinstance(x, PopIR) or isinstance(x, ReturnIR)
        i_point = list()
        for i in fn.child_iter():
            if isinstance(i, BlockIR):
                i_point += list(filter(lambda x: need_instrument(x), [ir for ir in i.child_iter()]))
            else:
                if need_instrument(i):
                    i_point.append(i)

        objects = list(filter(lambda x: isinstance(x, VectorIR) or isinstance(x, FunctionIR),
                              [o for o in fw.child_iter()]))

        if len(i_point) > 0:
            for i in i_point:
                if isinstance(i, BranchIR):
                    assert i.link
                    i.link = False
                    # ir = LoadReturnOffsetIR(parent=fn)
                    # reference_handoff(ir, i)
                    # do_instrument(i, ir)
                    # do_instrument(i, LoadCallerIndexIR(objects.index(fn), parent=fn))
                    ir = LoadReturnIndexIR(objects.index(fn), parent=fn)
                    reference_handoff(ir, i)
                    do_instrument(i, ir)
                elif isinstance(i, IndirectBranchIR):
                    if i.link:
                        if str(i.reg) != 'r12':
                            ir = LoadFuncPtrIR(i.reg, parent=fn)
                            reference_handoff(ir, i)
                            do_instrument(i, ir)
                        # ir = LoadReturnOffsetIR(parent=fn)
                        ir = LoadReturnIndexIR(objects.index(fn), parent=fn)
                        if str(i.reg) == 'r12':
                            reference_handoff(ir, i)
                        do_instrument(i, ir)
                        # do_instrument(i, LoadCallerIndexIR(objects.index(fn), parent=fn))
                        ir = BranchIR(i.offset, parent=fn)
                        ir.len = 4
                        ir.ref = fw.indirect_call_veneer
                        do_instrument(i, ir, pos='replace')
                    elif str(i.reg) == 'lr':
                        if not fn.isr:
                            ir = BranchIR(i.offset, parent=fn)
                            ir.len = 4
                            ir.ref = fw.return_veneer.child_at(1)
                            reference_handoff(ir, i)
                            do_instrument(i, ir, pos='replace')
                    else:
                        if str(i.reg) != 'r12':
                            ir = LoadFuncPtrIR(i.reg, parent=fn)
                            reference_handoff(ir, i)
                            do_instrument(i, ir)
                        ir = BranchIR(i.offset, parent=fn)
                        ir.len = 4
                        ir.ref = fw.indirect_branch_veneer
                        if str(i.reg) == 'r12':
                            reference_handoff(ir, i)
                        do_instrument(i, ir, pos='replace')
                elif (isinstance(i, PopIR) or isinstance(i, ReturnIR)) and not fn.isr:
                    """
                    pop {pc} / ldr pc, [sp], #4
                    """
                    # ir1 = RetrieveIR(i.offset, parent=fn)
                    # if isinstance(i, PopIR):
                    #     i.remove_reg(ARM_REG_PC)
                    #     do_instrument(i, ir1, pos='after')
                    # else:
                    #     reference_handoff(ir1, i)
                    #     do_instrument(i, ir1, pos='replace')
                    # ir2 = BranchIR(ir1.offset, parent=fn)
                    # ir2.len = 4
                    # ir2.ref = fw.return_veneer
                    # do_instrument(ir1, ir2, pos='after')

                    ir = BranchIR(0)
                    ir.len = 4
                    ir.ref = fw.return_veneer

                    if isinstance(i, PopIR):
                        i.remove_reg(ARM_REG_PC)
                        do_instrument(i, ir, pos='after')
                    else:
                        reference_handoff(ir, i)
                        do_instrument(i, ir, pos='replace')
                else:
                    pass
    fn.commit()


def PendSV_Hook_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn, vid=0):
    fn = FunctionIR("PendSV_Hook%d_veneer" % vid, 0)

    ir1 = BlockIR(0)
    ir1.append_child(LiteralIR(0, value=cmse_fn["PendSV_hook%d" % vid]))

    ir2 = LoadLiteralIR(0)
    ir2.reg = ArmReg(ARM_REG_PC)
    ir2.ref = ir1
    ir2.len = 4

    fn.append_child(ir2)                                             # 0: ldr pc, PendSV_Hook
    fn.append_child(ir1)                                             # 4: PendSV_Hook
    fn.layout_refresh()

    fw.insert_child(src, fn, pos='after')
    orig_size = fn.len
    fw.stretch(fn, fn.len - orig_size)
    setattr(fw, "PendSV_Hook%d_veneer" % vid, fn)


def PendSV_instrument(fw: FirmwareIR, fn: FunctionIR):
    first_ir = None
    for i in fn.child_iter():
        if not first_ir:
            first_ir = i
            break

    ir = BranchIR(0)
    ir.ref = fw.PendSV_Hook0_veneer
    ir.link = True

    fn.insert_child(first_ir, IR(0, bytearray((b"\x70\x46"))))  # 0: mov r0, lr
    fn.insert_child(first_ir, ir)                               # 2: bl PendSV_Hook0_veneer
    fn.insert_child(first_ir, IR(0, bytearray(b"\x86\x46")))    # 6: mov lr r0

    # bx_ir = list(filter(lambda x: isinstance(x, IndirectBranchIR) and str(x.reg) == 'lr', [i for i in fn.child_iter()]))
    # for i in bx_ir:
    #     ir = BranchIR(0)
    #     ir.ref = fw.PendSV_Hook1_veneer
    #     fn.insert_child(i, ir, pos='replace')
    #     reference_handoff(ir, i)

    fn.layout_refresh()


def indirect_branch_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("indirect_branch_veneer", 0)
    fn.append_child(IR(0, b"\x01\xb4"))  # push {r0}
    fn.append_child(IR(0, b"\x4f\xf0\xff\x00"))  # mov r0, #0xFF
    fn.append_child(IR(0, b"\x90\xea\x1c\x60"))  # eors r0, r12, lsr #24
    fn.append_child(IR(0, b"\x01\xbc"))  # pop {r0}

    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_EQ
    ir = IndirectBranchIR(ARM_REG_R12)
    ir.cond = ARM_CC_EQ
    it_block.append_child(ir)

    fn.append_child(it_block)

    fn.append_child(IR(0, b"\x1c\xf0\x80\x5f"))  # tst r12, #0x10000000
    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_NE

    literal_pool = BlockIR(0)
    literal_pool.append_child(LiteralIR(0, value=cmse_fn["call_address_dispatch"]))    # indirect_call_dispatch
    literal_pool.append_child(LiteralIR(0, value=cmse_fn["return_address_dispatch"]))    # return_dispatch

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

    # it_block.append_child(ir)

    fn.append_child(it_block)
    fn.append_child(ir)
    fn.append_child(literal_pool)
    fw.insert_child(src, fn, pos='after')
    orig_size = fn.len
    fn.layout_refresh()
    fw.stretch(fn, fn.len - orig_size)
    setattr(fw, "indirect_branch_veneer", fn)


def indirect_call_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("indirect_call_veneer", 0)
    ir = LoadLiteralIR(0, fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=cmse_fn["call_address_dispatch"]))
    ir.ref = ir2
    fn.append_child(ir)
    fn.append_child(ir2)
    fw.insert_child(src, fn, pos='after')
    orig_size = fn.len
    fn.layout_refresh()
    fw.stretch(fn, fn.len - orig_size)
    setattr(fw, "indirect_call_veneer", fn)


def return_veneer_instrument(fw: FirmwareIR, src: FunctionIR, cmse_fn):
    fn = FunctionIR("return_veneer", 0)
    fn.append_child(IR(0, b"\x5d\xf8\x04\xeb"))
    fn.append_child(IR(0, b"\x4f\xea\x1e\x6c"))    # mov r12, lr, lsr #24
    fn.append_child(IR(0, b"\xbc\xf1\xff\x0f"))    # cmp r12, #0xFF

    it_block = ITBlockIR(0)
    it_block.first_cond = ARM_CC_EQ
    ir = IndirectBranchIR(ARM_REG_LR)
    ir.cond = ARM_CC_EQ
    it_block.append_child(ir)
    ir = LoadLiteralIR(0, fn)
    ir.reg = ArmReg(ARM_REG_PC)
    ir.len = 4
    ir2 = BlockIR(0)
    ir2.append_child(LiteralIR(0, value=cmse_fn["return_address_dispatch"]))
    ir.ref = ir2
    fn.append_child(it_block)
    fn.append_child(ir)
    fn.append_child(ir2)

    # fn0 = FunctionIR("return_veneer0", 0)
    #
    # fn0.append_child(IR(0, b"\x5d\xf8\x04\xeb"))
    # ir = BranchIR(0)
    # ir.ref = fn
    # ir.len = 4
    # fn0.append_child(ir)

    fw.insert_child(src, fn, pos='after')
    # fw.insert_child(src, fn0, pos='after')

    orig_size = fn.len
    fn.layout_refresh()
    fw.stretch(fn, fn.len - orig_size)

    setattr(fw, "return_veneer", fn)


def fw_instrument(fw, cmse_fn):
    fn_objs = list(filter(lambda x: isinstance(x, FunctionIR), [o for o in fw.child_iter()]))
    # instrument indirect call veneer
    indirect_branch_veneer_instrument(fw, fn_objs[-1], cmse_fn)
    indirect_call_veneer_instrument(fw, fn_objs[-1], cmse_fn)
    return_veneer_instrument(fw, fn_objs[-1], cmse_fn)
    PendSV_Hook_veneer_instrument(fw, fn_objs[-1], cmse_fn)
    PendSV_Hook_veneer_instrument(fw, fn_objs[-1], cmse_fn, vid=1)
    fw.commit()

    for fn in fw.child_iter():
        if isinstance(fn, FunctionIR) and fn.name not in ("indirect_call_veneer", "return_veneer",
                                                          "indirect_branch_veneer",
                                                          "PendSV_Hook0_veneer", "PendSV_Hook1_veneer"):
            if fn.name == "PendSV_Handler":
                PendSV_instrument(fw, fn)
            fn_instrument(fn, fw)


def do_relocate(fw: FirmwareIR, ir, reloc, offset=0):
    objects = list(filter(lambda x: isinstance(x, VectorIR) or isinstance(x, FunctionIR), [o for o in fw.child_iter()]))
    if isinstance(ir, LiteralIR):
        value = ir.value
    else:
        value = int.from_bytes(ir.code[offset:offset + 4], byteorder='little')

    new_value = -1

    if reloc["type"] in ("STT_OBJECT", "STT_NOTYPE"):
        new_value = fw.fn_map[value]["ir"].addr
    elif reloc["type"] == "STT_FUNC":
        if isinstance(ir, VectorIR):
            # Do not encode ISR
            new_value = fw.fn_map[value - 1]["ir"].addr + 1
        else:
            # Encode function pointer as the shuffleable form
            assert objects.index(fw.fn_map[value - 1]["ir"]) <= 0xFFFF
            # new_value = 0x10000001 | (objects.index(fw.fn_map[value - 1]["ir"]) << 12)
            new_value = ((0x1000 | objects.index(fw.fn_map[value - 1]["ir"])) << 16) + 1
    else:
        if value not in fw.fn_map:
            for k in fw.fn_map:
                if k < value <= k + fw.fn_map[k]["symbol"].size:
                    new_value = fw.fn_map[k]["ir"].addr + value - k
                    break
        else:
            new_value = fw.fn_map[value]["ir"].addr

    assert new_value != -1

    if isinstance(ir, LiteralIR):
        ir.value = new_value
    else:
        code = ir.code
        code[offset:offset + 4] = bytearray(new_value.to_bytes(4, byteorder="little"))
        ir.code = code


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


def output_revise_item(ir, fn, objects):
    if hasattr(ir, "child_iter"):
        ret = ""
        count = 0
        for i in ir.child_iter():
            s = output_revise_item(i, fn, objects)
            if s:
                ret += s[0]
                count += s[1]
        return (ret, count) if count > 0 else None
    else:
        if isinstance(ir, BranchIR):
            ref = ir.ref
            if isinstance(ref, FunctionIR):
                data = objects.index(ref) << 16
                rtype = "R_DIRECT_BRANCH"
            elif ref.parent is not fn:
                inner_offset = ref.addr - ref.parent.addr
                assert inner_offset == inner_offset & 0xFFFF
                # data = (inner_offset << 16) | (objects.index(ref.parent) & 0xFFFF)
                data = (objects.index(ref.parent) << 16) | inner_offset
                rtype = "R_DIRECT_BRANCH"
            else:
                return None
            return "\t/* %s (in %s) */\n\t{ 0x%04x, %s, 0x%08x },\n" % \
                   (repr(ir), ir.parent, ir.addr - fn.addr, rtype, data), 1
        elif isinstance(ir, TableBranchEntryIR) and ir.len == 4:
            # data = ((ir.ref.addr - fn.addr) << 1) + 1
            data = ir.ref.addr - fn.addr
            rtype = "R_TABLE_BRANCH"
            return "\t/* %s */\n\t{ 0x%04x, %s, 0x%08x },\n" % (repr(ir), ir.addr - fn.addr, rtype, data), 1
        else:
            return None


def data_section_relocate(fw, orig_data, new_addr):
    for ir in fw.child_iter():
        if isinstance(ir, ObjectIR) and ir.name == "__data_section_table":
            offset = 0
            code = ir.code
            while offset < ir.len:
                value = int.from_bytes(code[offset:offset + 4], byteorder='little')
                if value == orig_data:
                    code[offset:offset + 4] = bytearray(new_addr.to_bytes(4, byteorder="little"))
                    ir.code = code
                    print("===> %s -> %s" % (hex(value), hex(new_addr)))
                offset += 4
            break


def output_c_syntax(fw, path):
    objects = list(filter(lambda x: isinstance(x, FunctionIR) or isinstance(x, VectorIR),
                          [o for o in fw.child_iter()]))

    # export revise list in C syntax
    with open(path + "/revise_list.h", "w") as stream:
        stream.write("#ifndef SOURCE_REVISE_LIST_H_\n")
        stream.write("#define SOURCE_REVISE_LIST_H_\n\n")
        stream.write("/* DO NOT EDIT THIS FILE */\n\n")
        stream.write("const revise_item_t reviseItems[] = {\n")
        start, count = 0, 0
        for fn in objects:
            if isinstance(fn, FunctionIR):
                count = 0
                for ir in fn.child_iter():
                    revise_item = output_revise_item(ir, fn, objects)
                    if revise_item:
                        stream.write(revise_item[0])
                        count += revise_item[1]
                if count > 0:
                    setattr(fn, "revise_item", dict(start=start, count=count))
                    start += count
        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_REVISE_LIST_H_ */\n")

    # export object list in C syntax
    with open(path + "/object_list.h", "w") as stream:
        stream.write("#ifndef SOURCE_OBJECT_LIST_H_\n")
        stream.write("#define SOURCE_OBJECT_LIST_H_\n\n")
        stream.write("/* DO NOT EDIT THIS FILE */\n\n")
        stream.write("__attribute__((section(\".data.$GLOBAL_REGION\")))\n")
        stream.write("instance_t instanceList[] = {\n")
        for i in objects:
            stream.write("\t/* %d - %s */\n" % (objects.index(i), i.name))
            stream.write("\t{ { 0x%08XUL, 0x%08XUL } },\n" % (i.addr, i.addr))

        stream.write("};\n\n")
        stream.write("const object_t objectList[] = {\n")
        for i in objects:
            stream.write("\t/* %d - %s */\n" % (objects.index(i), i.name))
            flags = 0
            if isinstance(i, FunctionIR):
                if i.isr:
                    flags |= 1 << 1
                    flags |= (i.irq & 0xFF) << 2
            else:
                flags |= 1 << 0

            if hasattr(i, "revise_item"):
                assert i.revise_item["count"] < 0x400000
                flags |= (i.revise_item["count"] & 0x3FFFFF) << 10
                stream.write("\t{ &instanceList[%d], &reviseItems[%d], %s, %d },\n" %
                             (objects.index(i), i.revise_item["start"], hex(flags), i.len))
            else:
                stream.write("\t{ &instanceList[%d], NULL, %s, %d },\n" % (objects.index(i), hex(flags), i.len))

        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_OBJECT_LIST_H_ */\n")

    with open(path + "/branch_list.h", "w") as stream:
        stream.write("#ifndef SOURCE_BRANCH_LIST_H_\n")
        stream.write("#define SOURCE_BRANCH_LIST_H_\n\n")
        stream.write("/* DO NOT EDIT THIS FILE */\n\n")
        stream.write("const branch_t branchList[] = {\n")
        for fn in objects[1:]:
            for ir in fn.child_iter():
                if isinstance(ir, LoadReturnIndexIR):
                    stream.write("\t{ 0x%08XUL },\n" % ir.encode)
        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_BRANCH_LIST_H_ */\n")


def main(argv):
    input_file = ''
    output_file = ''
    output_path = ''
    entry_point = 0
    cmse_lib = ''

    try:
        opts, args = getopt.getopt(argv, 'c:e:hi:o:p:',
                                   ['--cmse-lib', 'entry-point=', 'input-file=', 'output-file=', 'output-path'])
    except getopt.GetoptError:
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-c', '--cmse-lib'):
            cmse_lib = arg
        elif opt in ('-e', '--entry-point'):
            entry_point = int(arg, base=16)
        elif opt in ('-i', '--input-file'):
            input_file = arg
        elif opt in ('-o', '--output-file'):
            output_file = arg
        elif opt in ('-p', '--output-path'):
            output_path = arg
        else:
            print('Invalid argument - %s' % opt)
            sys.exit(1)

    with open(cmse_lib, 'rb') as f:
        elf = ELFFile(f)
        cmse_fn = export_cmse_fn(elf)

    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        fn_symbols, text_end = export_fn_symbols(elf)
        fw = FirmwareIR(input_file, entry_point)

        for s in fn_symbols:
            fn = symbol_translate(s, fw)
            # if (s.address - 1) % 4 == 0:
            #     fw.append_child(fn, 4)
            # else:
            #     fw.append_child(fn)
            fw.append_child(fn)
            if s.type == "STT_FUNC":
                fw.fn_map[s.address - 1] = dict(symbol=s, ir=fn)
            else:
                fw.fn_map[s.address] = dict(symbol=s, ir=fn)

        data_ir = export_data_section(elf)
        fw.append_child(data_ir)
        fw.commit()

        fw_instrument(fw, cmse_fn)

        fw.layout_refresh()
        fw.verify()
        relocate_recursive(fw, fw)
        fw.asm()

        print(hex(data_ir.addr))
        data_section_relocate(fw, text_end, data_ir.addr)

        for fn in fw.child_iter():
            # if fn.name in ("PendSV_Handler", "__data_section_table", ".data", "indirect_call_veneer", "return_veneer",
            #                "PendSV_Hook0_veneer", "PendSV_Hook1_veneer"):
            print(fn)
            if isinstance(fn, FunctionIR):
                if hasattr(fn, "child_iter"):
                    for ir in fn.child_iter():
                        print(ir)
            else:
                print(fn.code)
            print()

        fw.save_as_file(output_file)
        print("New firmware length: %d (%d)" % (fw.len, len(fw.code)))

        output_c_syntax(fw, output_path)


if __name__ == '__main__':
    main(sys.argv[1:])
