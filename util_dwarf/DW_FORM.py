import enum
from typing import Tuple

from elftools.dwarf.die import AttributeValue, DIE

from .LEB128 import ULEB128, SLEB128
from .DWARF_expression import DWARF_expression, DW_OP


class DW_FORM(enum.Enum):
    addr = 0x01
    block1 = 0x0A
    block2 = 0x03
    block4 = 0x04
    block = 0x09
    data1 = 0x0B
    data2 = 0x05
    data4 = 0x06
    data8 = 0x07
    sdata = 0x0D
    udata = 0x0F
    string = 0x08
    strp = 0x0E
    flag = 0x0C
    ref_addr = 0x10
    ref1 = 0x11
    ref2 = 0x12
    ref4 = 0x13
    ref8 = 0x14
    ref_udata = 0x15
    indirect = 0x16
    sec_offset = 0x17
    exprloc = 0x18
    flag_present = 0x19
    ref_sig8 = 0x20


DW_FORM_map = {
    "DW_FORM_addr": DW_FORM.addr,
    "DW_FORM_block1": DW_FORM.block1,
    "DW_FORM_block2": DW_FORM.block2,
    "DW_FORM_block4": DW_FORM.block4,
    "DW_FORM_block": DW_FORM.block,
    "DW_FORM_data1": DW_FORM.data1,
    "DW_FORM_data2": DW_FORM.data2,
    "DW_FORM_data4": DW_FORM.data4,
    "DW_FORM_data8": DW_FORM.data8,
    "DW_FORM_sdata": DW_FORM.sdata,
    "DW_FORM_udata": DW_FORM.udata,
    "DW_FORM_string": DW_FORM.string,
    "DW_FORM_strp": DW_FORM.strp,
    "DW_FORM_flag": DW_FORM.flag,
    "DW_FORM_ref_addr": DW_FORM.ref_addr,
    "DW_FORM_ref1": DW_FORM.ref1,
    "DW_FORM_ref2": DW_FORM.ref2,
    "DW_FORM_ref4": DW_FORM.ref4,
    "DW_FORM_ref8": DW_FORM.ref8,
    "DW_FORM_ref_udata": DW_FORM.ref_udata,
    "DW_FORM_indirect": DW_FORM.indirect,
    "DW_FORM_exprloc": DW_FORM.exprloc,
    "DW_FORM_flag_present": DW_FORM.flag_present,
}

class Class(enum.Enum):
    exprloc = enum.auto()
    loclistptr = enum.auto()

class DW_FORM_decorder:
    def __init__(self, encoding: str = "utf-8") -> None:
        # 文字コード
        self._encoding = encoding
        # Dwarf expression
        self.dwarf_expr = DWARF_expression()
        self.offset = 0

    def set_address_size(self, size: int):
        self.dwarf_expr.set_address_size(size)

    def set_frame_base(self, addr: int):
        self.dwarf_expr.set_frame_base(addr)

    def set_offset(self, offset: int):
        self.offset = offset

    def decode(self, attr: AttributeValue) -> Tuple[Class, any]:
        if attr.form == "DW_FORM_indirect":
            # pyelftoolsでは、DW_FORM_indirectのときには
            # raw_valueにDW_FORMの値が入っている
            return self.decode_impl(attr.raw_value, attr.value)
        else:
            return self.decode_impl(DW_FORM_map[attr.form].value, attr.value)

    def decode_impl(self, form: int, value: any) -> Tuple[Class, any]:
        match form:
            case DW_FORM.addr.value:
                return (None, value)

            case DW_FORM.block1.value:
                # [ length data1 data2 ... ] or [ DWARF expr ]
                result = None
                length = 1 + value[0]
                if len(value) == length:
                    # length byte と valueの要素数が一致するとき、block1として解釈
                    result = int.from_bytes(bytearray(value[1:length]), "little")
                else:
                    # 上記以外のとき、DWARF expression として解釈
                    self.analyze_dwarf_expr(value)
                    result = self.get_dwarf_expr()
                return (None, result)

            case DW_FORM.block2.value:
                # [ length1 length2 data1 data2 ... ] or [ DWARF expr ]
                result = None
                len_size = 2
                length = int.from_bytes(bytearray(value[0:len_size]), "little") + len_size
                if len(value) == length:
                    # length byte と valueの要素数が一致するとき、block2として解釈
                    result = int.from_bytes(bytearray(value[len_size:length]), "little")
                else:
                    # 上記以外のとき、DWARF expression として解釈
                    self.analyze_dwarf_expr(value)
                    result = self.get_dwarf_expr()
                return (None, result)

            case DW_FORM.block4.value:
                # [ length1 length2 length3 length4 data1 data2 ... ] or [ DWARF expr ]
                result = None
                len_size = 4
                length = int.from_bytes(bytearray(value[0:len_size]), "little") + len_size
                if len(value) == length:
                    # length byte と valueの要素数が一致するとき、block4として解釈
                    result = int.from_bytes(bytearray(value[len_size:length]), "little")
                else:
                    # 上記以外のとき、DWARF expression として解釈
                    self.analyze_dwarf_expr(value)
                    result = self.get_dwarf_expr()
                return (None, result)

            case DW_FORM.block.value:
                result = None
                # [ ULEB128を表すバイト列 ] + [ ULEB128で示されたデータ長 ]
                uleb128 = ULEB128(value)
                len_size = uleb128.len_byte
                length = len_size + uleb128.value
                if len(value) == length:
                    # length byte と valueの要素数が一致するとき、block4として解釈
                    result = int.from_bytes(bytearray(value[len_size:length]), "little")
                else:
                    # 上記以外のとき、DWARF expression として解釈
                    self.analyze_dwarf_expr(value)
                    result = self.get_dwarf_expr()
                return (None, result)

            case DW_FORM.data1.value:
                return (None, value)
            case DW_FORM.data2.value:
                return (None, value)
            case DW_FORM.data4.value:
                return (None, value)
            case DW_FORM.data8.value:
                return (None, value)

            case DW_FORM.sdata.value:
                result = SLEB128(value).value
                return (None, result)

            case DW_FORM.udata.value:
                result = ULEB128(value).value
                return (None, result)
            case DW_FORM.string.value:
                result = value.decode(self._encoding)
                return (None, result)

            case DW_FORM.strp.value:
                # value: .debug_str から対象となる文字列までのoffset
                # 上記が示す位置から\0までの文字列を返す
                # elftoolsでは文字列をvalueで渡してくれる
                result = value.decode(self._encoding)
                return (None, result)

            case DW_FORM.flag.value:
                return (None, value)

            case DW_FORM.ref_addr.value:
                # .debug_info の先頭からのoffsetを加算する
                return (None, value)
            case DW_FORM.ref1.value:
                result = self.offset + value
                return (None, result)
            case DW_FORM.ref2.value:
                result = self.offset + value
                return (None, result)
            case DW_FORM.ref4.value:
                result = self.offset + value
                return (None, result)
            case DW_FORM.ref8.value:
                result = self.offset + value
                return (None, result)
            case DW_FORM.ref_udata.value:
                # ?合ってる?
                result = self.offset + ULEB128(value).value
                return (None, result)

            # case DW_FORM.indirect.value:
            # DW_FORM_indirectが再帰することは無い想定

            case DW_FORM.exprloc.value:
                # value に Dwarf expression が格納されているとみなす
                self.analyze_dwarf_expr(value)
                result = self.get_dwarf_expr()
                return (None, result)

            case DW_FORM.flag_present.value:
                return (None, value)

            case _:
                # 未実装多し
                raise Exception(f"Unknown DW_FORM detected: {DW_FORM(form)}")

    def analyze_dwarf_expr(self, value):
        # operation code
        code = value[0]
        # expression
        self.dwarf_expr.exec(DW_OP(code))(value[1:])

    def get_dwarf_expr(self):
        return self.dwarf_expr.get()
