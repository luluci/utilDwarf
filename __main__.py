"""
from utilDwarf import Dwarf_expression
expr = Dwarf_expression.Dwarf_expression()
pass
"""


import util_dwarf
import pathlib

path = pathlib.Path(r"./test_obj/abs_test_RX.abs")
# path = pathlib.Path(r"./test_obj/dwarf_test_clang.out")
dwarf = util_dwarf.Decorder(path, "cp932")
dwarf._debug_warning = True
dwarf.analyze()
mmap = util_dwarf.memmap.memmap()
mmap.make(dwarf)
print("analyze finish.")


def dump_memmap(var: util_dwarf.memmap.VarInfo, depth: int = 0):
    # インデント作成
    indent = "\t" * depth
    # タグ作成
    tag = ""
    if var.typename is not None:
        tag = var.typename
    if var.tag == util_dwarf.debug_info.TAG.struct:
        tag = "struct/" + tag
    elif var.tag == util_dwarf.debug_info.TAG.union:
        tag = "union/" + tag
    if var.pointer:
        tag = tag + "*"
    # ファイル
    file = ""
    if var.decl_file is not None:
        var.decl_file: util_dwarf.Decorder.cu_info.file_entry
        if var.decl_file.proj_rel_path is None:
            file = var.decl_file.full_path
        else:
            file = var.decl_file.proj_rel_path

    if var.name == "":
        pass

    # データ出力
    if (var.tag & util_dwarf.memmap.VarInfo.TAG.array).value != 0:
        #
        print(f"0x{var.address:08X}\t{tag}\t{var.byte_size}\t{indent}{var.name}[{var.array_size}]\t({file})")
        # struct/unionのみmember出力
        if (var.tag & (util_dwarf.memmap.VarInfo.TAG.struct | util_dwarf.memmap.VarInfo.TAG.union)).value != 0:
            # memberを出力
            for member in var.member:
                dump_memmap(member, depth + 1)
        else:
            pass
    else:
        print(f"0x{var.address:08X}\t{tag}\t{var.byte_size}\t{indent}{var.name}\t({file})")
        # memberを出力
        member: util_dwarf.memmap.VarInfo
        for member in var.member:
            dump_memmap(member, depth + 1)


mmap._memmap.sort(key=lambda k: k.address)

for var in mmap._memmap:
    dump_memmap(var)
