import getopt
import sys

from elftools.elf.elffile import ELFFile

from elf_parser import export_cmse_fn, export_symbols
from librw.ir.branch import BranchIR
from librw.ir.firmware import FirmwareIR
from librw.ir.function import FunctionIR
from librw.ir.ir import IR
from librw.ir.literal import LiteralIR
from librw.ir.object import ObjectIR
from librw.ir.ret_encode import LoadFuncPtrIR, LoadReturnIndexIR
from librw.ir.table_branch import BranchTableIR
from librw.ir.vector import VectorIR
from librw.rw import fw_instrument
from librw.symbol import Symbol


def symbol_translate(s, fw: FirmwareIR):
    if s.type == "STT_FUNC":
        ir = FunctionIR(s.name, 0, fw)
        for i in s.disasm():
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
            if hasattr(s, "anonymous"):
                ir.align = 1
            else:
                if s.address % 4 == 0:
                    ir.align = 4
                elif s.address % 2 == 0:
                    ir.align = 2
                else:
                    ir.align = 1

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
                offset += 4
            break

def do_relocate(fw: FirmwareIR, ir, reloc, *, encode_fptr=True, offset=0):
    func_ptr_tbl_sz = 0
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
            if encode_fptr:
                assert objects.index(fw.fn_map[value - 1]["ir"]) <= 0xFFFF
                new_value = ((0x1000 | objects.index(fw.fn_map[value - 1]["ir"])) << 16) + 1
                func_ptr_tbl_sz += 4
            else:
                new_value = fw.fn_map[value - 1]["ir"].addr
                print(f"new_value:{hex(new_value)}")
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

    return func_ptr_tbl_sz


def relocate_recursive(fw: FirmwareIR, ir: IR, encode_fptr=True):
    func_ptr_tbl_sz = 0
    if hasattr(ir, "child_iter"):
        for i in ir.child_iter():
            func_ptr_tbl_sz += relocate_recursive(fw, i, encode_fptr)
    else:
        if hasattr(ir, "reloc"):
            func_ptr_tbl_sz += do_relocate(fw, ir, ir.reloc, encode_fptr=encode_fptr)
        elif hasattr(ir, "reloc_map"):
            for k in ir.reloc_map:
                func_ptr_tbl_sz += do_relocate(fw, ir, ir.reloc_map[k], offset=k, encode_fptr=encode_fptr)
        else:
            pass
    return func_ptr_tbl_sz


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
                # rtype = "R_DIRECT_BRANCH"
            elif ref.parent is not fn:
                inner_offset = ref.addr - ref.parent.addr
                assert inner_offset == inner_offset & 0xFFFF
                # data = (inner_offset << 16) | (objects.index(ref.parent) & 0xFFFF)
                data = (objects.index(ref.parent) << 16) | inner_offset
                # rtype = "R_DIRECT_BRANCH"
            else:
                return None
            return "\t/* %s (in %s) */\n\t{ 0x%04x, 0x%08x },\n" % \
                   (repr(ir), ir.parent, ir.addr - fn.addr, data), 1
        else:
            return None


def output_c_syntax(fw, path):
    objects = list(filter(lambda x: isinstance(x, FunctionIR) or isinstance(x, VectorIR),
                          [o for o in fw.child_iter()]))

    rev_tb_sz = 0

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
                        rev_tb_sz += 6
                        count += revise_item[1]
                if count > 0:
                    setattr(fn, "revise_item", dict(start=start, count=count))
                    start += count
        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_REVISE_LIST_H_ */\n")

    print("Revise Table Size: %d bytes." % rev_tb_sz)
    func_tbl_sz = 0

    # export object list in C syntax
    with open(path + "/object_list.h", "w") as stream:
        stream.write("#ifndef SOURCE_OBJECT_LIST_H_\n")
        stream.write("#define SOURCE_OBJECT_LIST_H_\n\n")
        stream.write("/* DO NOT EDIT THIS FILE */\n\n")
        stream.write("__attribute__((section(\".data.$GLOBAL_REGION\")))\n")
        stream.write("instance_t instanceList[%d];\n\n" % len(objects))

        stream.write("const object_t objectList[] = {\n")
        for i in objects:
            stream.write("\t/* %d - %s */\n" % (objects.index(i), i.name))
            flags = 0
            if isinstance(i, FunctionIR):
                func_tbl_sz += 14
                if i.isr:
                    flags |= 1 << 1
                    flags |= (i.irq & 0xFF) << 2
            else:
                flags |= 1 << 0

            if hasattr(i, "revise_item"):
                assert i.revise_item["count"] < 0x400000
                flags |= (i.revise_item["count"] & 0x3FFFFF) << 10
                stream.write("\t{ &instanceList[%d], &reviseItems[%d], %s, %s, %d },\n" %
                             (objects.index(i), i.revise_item["start"], hex(i.addr), hex(flags), i.len))
            else:
                stream.write("\t{ &instanceList[%d], NULL, %s, %s, %d },\n" % (objects.index(i), hex(i.addr), hex(flags), i.len))

        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_OBJECT_LIST_H_ */\n")

    print("Function Table Size: %d bytes" % func_tbl_sz)

    ret_tbl_sz = 0
    ret_offset_tbl_sz = 0

    with open(path + "/branch_list.h", "w") as stream:
        stream.write("#ifndef SOURCE_BRANCH_LIST_H_\n")
        stream.write("#define SOURCE_BRANCH_LIST_H_\n\n")
        stream.write("/* DO NOT EDIT THIS FILE */\n\n")
        stream.write("const callsite_t branchList[] = {\n")
        for fn in objects[1:]:
            for ir in fn.child_iter():
                if isinstance(ir, LoadReturnIndexIR):
                    stream.write("\t{ 0x%08XUL },\n" % ir.encode)
                    ret_tbl_sz += 4
                    ret_offset_tbl_sz += 4
        stream.write("};\n\n")
        stream.write("#endif /* SOURCE_BRANCH_LIST_H_ */\n")

    print("Return Address Dispatch Table Size: %d bytes" % ret_tbl_sz)

    indirect_branch_tbl = 0

    for fn in objects[1:]:
        for ir in fn.child_iter():
            if isinstance(ir, LoadFuncPtrIR):
                indirect_branch_tbl += 4

    print("Indirect Call Table Size: %d bytes" % indirect_branch_tbl)


def main(argv):
    input_file = ''
    output_file = ''
    output_path = ''
    entry_point = 0x20000
    cmse_lib = ''
    has_rtos = False
    do_inst = True

    try:
        opts, args = getopt.getopt(argv, 'c:e:hi:o:p:',
                                   ['--cmse-lib', 'entry-point=', 'input-file=', 'output-file=', 'output-path', 'rtos',
                                    'no-instrument'])
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
        elif opt == '--rtos':
            has_rtos = True
        elif opt == '--no-instrument':
            do_inst = False
        else:
            print('Invalid argument - %s' % opt)
            sys.exit(1)

    with open(cmse_lib, 'rb') as f:
        elf = ELFFile(f)
        cmse_fn = export_cmse_fn(elf)

    with open(input_file, 'rb') as f:
        elf = ELFFile(f)
        text_symbols, etext, data_symbols = export_symbols(elf)
        if not text_symbols:
            raise Exception("No text section found!")

        fw = FirmwareIR(input_file, entry_point)
        orig_fn_total_size = 0

        for s in text_symbols:
            ir = symbol_translate(s, fw)
            fw.append_child(ir)
            if s.type == "STT_FUNC":
                orig_fn_total_size += s.size
                fw.fn_map[s.address - 1] = dict(symbol=s, ir=ir)
            else:
                fw.fn_map[s.address] = dict(symbol=s, ir=ir)

        first_data_ir = None

        if data_symbols:
            for s in data_symbols:
                ir = symbol_translate(s, fw)
                fw.append_child(ir)
                if s is data_symbols[0]:
                    first_data_ir = ir

        fw.commit()

        if do_inst:
            report = fw_instrument(fw, cmse_fn, has_rtos)

        fw.layout_refresh()

        if do_inst:
            report["indirect_call_veneer"] = fw.indirect_call_veneer.len
            report["return_veneer"] = fw.return_veneer.len
            report["indirect_branch_veneer"] = fw.indirect_branch_veneer.len
            if hasattr(fw, "PendSV_Hook0_veneer"):
                report["pendsv_hook_veneer"] = fw.PendSV_Hook0_veneer.len

        fw.verify()
        func_ptr_tbl_sz = relocate_recursive(fw, fw, encode_fptr=do_inst)
        fw.asm()

        if first_data_ir:
            data_section_relocate(fw, etext, first_data_ir.addr)

        new_fn_total_size = 0
        fn_total = 0

        for fn in fw.child_iter():
            if isinstance(fn, FunctionIR):
                print(fn)
                new_fn_total_size += fn.len
                fn_total += 1
                if hasattr(fn, "child_iter"):
                    for ir in fn.child_iter():
                        print(ir)
            elif isinstance(fn, BranchTableIR):
                print("BranchTable: %s (referred by %s %s)" % (hex(fn.addr), fn.ref_by_load, fn.ref_by_branch))
                print(fn)
            else:
                print(fn)
                print(fn.code)
            print()

        fw.save_as_file(output_file)

        print("New firmware length: %d (%d) bytes" % (fw.len, len(fw.code)))
        output_c_syntax(fw, output_path)
        print("Function pointer table size: %d" % func_ptr_tbl_sz)
        print("Total function size (original): %d" % orig_fn_total_size)
        print("Total function size (new): %d" % new_fn_total_size)
        if do_inst:
            print(report)
        print("Total %d functions" % fn_total)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
