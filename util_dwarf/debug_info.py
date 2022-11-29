import enum
from typing import List

from util_dwarf.DW_AT import attribute

class TAG(enum.Flag):
    none = 0
    base = enum.auto()  # primitive type
    array = enum.auto()  # array
    struct = enum.auto()  # struct
    union = enum.auto()  # union
    func = enum.auto()  # function type
    parameter = enum.auto()  # parameter
    typedef = enum.auto()  # typedef
    const = enum.auto()  # const
    volatile = enum.auto()  # volatile
    pointer = enum.auto()  # pointer
    restrict = enum.auto()  # restrict
    enum = enum.auto()  # enumeration type

    func_ptr = func | pointer  # function pointer






class CUInfo:
    """
    compile_unit info
    """

    class FileEntry:
        def __init__(self) -> None:
            self.dir_path = None
            self.filename = None
            self.proj_rel_path = None
            self.full_path = None

    def __init__(self) -> None:
        self.compile_dir = ""
        self.filename = ""
        self.debug_abbrev_offset = None
        self.unit_length = None
        self.address_size = None
        self.offset = None
        # 0 は「ファイル無し」定義なのでNoneを詰めておく
        self.file_list: List[CUInfo.FileEntry] = []
        self.include_dir_list: List[str] = []
        #
        self.producer = None
        self.language = None
        self.stmt_list = None
        self.low_pc = None
        self.high_pc = None


class VarInfo:
    def __init__(self) -> None:
        self.name = None
        self.type = None
        self.addr = None
        self.loclistptr = None
        self.decl_file: CUInfo.FileEntry = None
        self.decl_line = None
        self.decl_column = None
        self.not_declaration = None  # declarationなし. 不完全型等
        self.extern = None  # 外部結合, extern宣言
        self.external_file = None  # ファイル外定義(cファイル以外、hファイル等で定義)
        self.const_value = None
        self.sibling_addr = None

class func_info:
    def __init__(self) -> None:
        self.name = None
        self.return_type = None
        self.addr = None
        self.params = []
        # 関数フレームベースアドレス
        self.frame_base_addr = None
        #
        self.decl_file = None
        self.decl_line = None
        self.decl_column = None
        self.accessibility = None
        # DW_AT_high_pc
        self.high_pc = None
        # DW_AT_low_pc
        self.low_pc = None
        # DW_AT_declaration
        self.declaration = None
        # DW_AT_external: 外部結合
        self.external = None

class TypeInfo:
    def __init__(self) -> None:
        self.tag = TAG.none
        self.name = None
        self.description = None
        self.byte_size = None
        self.bit_size = None
        self.bit_offset = None
        self.address_class = None
        self.encoding = None
        self.member = []
        self.member_location = None
        # メンバ関数
        self.method = []
        # DW_AT_accessibility: 1:public 3:private
        self.accessibility = None
        self.child_type = None
        self.result_type = None
        self.range = None
        self.prototyped = None
        self.const = None
        self.pointer = 0  # double pointerで2になる
        self.restrict = None
        self.volatile = None
        self.params = []
        self.decl_file = CUInfo.FileEntry()
        self.decl_line = None
        self.decl_column = None
        # DW_AT_const_value
        self.const_value = None
        # DW_AT_sibling: 兄弟DIEへの参照(DIE内)アドレス
        self.sibling_addr = None
        # DW_AT_declaration: 宣言のみ、不完全型かどうか
        self.incomplete = None
        # 型情報統合データ用メンバ
        self.sub_type = None  # array: 配列の各要素の型情報


class Entry:
    """
    Dwarf形式は"Entry"の集合と定義する
    そのEntryの定義クラス
    DW_TAG_*, DW_ATTR_* の両方に対応する。
    """

    def __init__(self, tag: str, size: int, cu) -> None:
        # DW_TAG_*, DW_ATTR_*
        # 規格上はそれぞれ "tag names", "attribute names" と記載
        # pyelftoolsではtagというメンバ名で統一されているので、こちらに合わせる
        self.tag = tag
        self.size = size
        self.cu_info: CUInfo = cu
        # DW_AT_*
        self.at: attribute = None

        self.name = None
        self.compile_dir = None
        # compilerを示す文字列
        self.producer = None
        self.language = None

        # DW_AT_description
        self.description = None
        # DW_AT_external
        self.external = None
        # DW_AT_decl_file
        self.decl_file = None
        # DW_AT_decl_line
        self.decl_line = None
        # DW_AT_decl_column
        self.decl_column = None
        # DW_AT_type
        # 関数ポインタは戻り値の型を自身の型としている
        self.type = None
        # DW_AT_location
        self.location = None
        self.loclistptr = None
        # DW_AT_declaration
        self.declaration = None
        # DW_AT_const_value
        self.const_value = None
        # DW_AT_address_class
        self.address_class = None
        # DW_AT_prototyped
        self.prototyped = None
        # DW_AT_encoding
        self.encoding = None
        # DW_AT_byte_size
        self.byte_size = None
        # DW_AT_data_member_location
        self.data_member_location = None
        # DW_AT_bit_offset
        self.bit_offset = None
        # DW_AT_bit_size
        self.bit_size = None
        # DW_AT_count
        self.count = None
        # DW_AT_sibling: 兄弟DIEへの参照(DIE内)アドレス
        self.sibling_addr = None
        # DW_AT_declaration: 宣言のみ、不完全型かどうか
        self.incomplete = None
        # DW_AT_frame_base
        self.frame_base_addr = None
        # DW_AT_const_value
        self.const_value = None
        # DW_AT_accessibility: 1:public 3:private
        self.accessibility = None
        # DW_AT_return_addr
        self.return_addr = None
        # DW_AT_high_pc
        self.high_pc = None
        # DW_AT_low_pc
        self.low_pc = None
        # DW_AT_stmt_list
        self.stmt_list = None
        self.accessibility = None
        # DW_AT_artificial: 同じソース上で宣言されているかどうか？
        self.artificial = None

