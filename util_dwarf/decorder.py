import pathlib
from typing import List, Dict

from elftools.elf.elffile import ELFFile
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import AttributeValue, DIE
from elftools.dwarf.lineprogram import LineProgram, LineProgramEntry
from elftools.construct.lib.container import Container as elftools_container

from util_dwarf import debug_info
from util_dwarf.DW_AT import DW_AT_decorder, DW_AT, attribute
from util_dwarf.DW_FORM import Class

class Decorder:

    def __init__(self, path: pathlib.Path, encoding: str = "utf-8"):
        # 文字コード
        self._encoding = encoding
        self._arch = None
        # データコンテナ初期化
        # DwarfDebugInfoEntryとAddressの対応付けマップ
        # 基本情報をすべてここに集める
        self._entry_map: Dict[int, debug_info.Entry] = {}
        # 以下は必要なスコープでデータ整形したコンテナ
        self._cu_tbl: List[debug_info.CUInfo] = []
        self._active_cu: debug_info.CUInfo = None
        self._global_var_tbl: List[debug_info.VarInfo] = []
        self._func_tbl: List[debug_info.func_info] = []
        self._type_tbl: Dict[int, debug_info.TypeInfo] = {}
        self._addr_cls: Dict[int, List[debug_info.TypeInfo]] = {}
        # elfファイルを開く
        self._path = path
        self._open()
        # debug情報
        self._debug_warning = False

        #
        self.DW_attr = DW_AT_decorder(encoding)

    def _open(self) -> None:
        # pathチェック
        if not self._path:
            return
        # ファイルを開く
        with open(self._path, "rb") as f:
            self._elf_file = ELFFile(f)
            # dwarf_infoチェック
            if not self._elf_file.has_dwarf_info():
                print("file has no DWARF info.")
                return
            # DWARF情報取得
            self._dwarf_info = self._elf_file.get_dwarf_info()
            self._arch = self._dwarf_info.config.machine_arch

    def add_entry(self, addr: int, label: str, size: int) -> debug_info.Entry:
        return debug_info.Entry(label, size, self._active_cu)
        # DwarfAddresMap更新
        if addr not in self._entry_map.keys():
            self._entry_map[addr] = Decorder.entry(label, size, self._active_cu)
        else:
            # Dwarf上のアドレス=オフセットが重複した？
            if self._debug_warning:
                match self._entry_map[addr].tag:
                    case "DW_TAG_compile_unit":
                        # CompileUnitは事前チェックしているため
                        # 共通処理実行時に重複する
                        pass
                    case _:
                        print(f"Detect Duplicate: addr={addr}, label={label}")
        #
        return self._entry_map[addr]

    def get_entry(self, addr: int) -> debug_info.Entry:
        # DwarfAddres Entry取得
        if addr not in self._entry_map.keys():
            raise Exception(f"entry(offset:{addr}) is not exist!")
            # return self.add_entry(addr, None, None)
        else:
            return self._entry_map[addr]

    def analyze(self):
        # dwarf解析
        cu: CompileUnit
        for cu in self._dwarf_info.iter_CUs():
            self.analyze_cu(cu)
        # dwarfの解析が終わった後に、解析中に出現したDW_AT_address_classを解析
        self.analyze_address_class()

    def analyze_cu(self, cu: CompileUnit):
        # DW_TAG_compile_unit がCompileUnitの先頭に必ず配置されている前提
        die = cu.get_top_DIE()
        if die.tag == "DW_TAG_compile_unit":
            entry = self.add_entry(die.offset, die.tag, die.size)
            self.analyze_die_TAG_compile_unit(cu, die, entry)
        else:
            raise Exception("top DIE is not DW_TAG_compile_unit!")

        # .debug_line解析
        line_program = self._dwarf_info.line_program_for_CU(cu)
        if line_program is not None:
            self._debug_line = line_program
            self.analyze_line(line_program)

        # DIE解析
        die: DIE
        for die in cu.iter_DIEs():
            self.analyze_die(die)

    def analyze_line(self, line: LineProgram):
        # header
        # include_directory
        for path in line.header.include_directory:
            self._active_cu.include_dir_list.append(path.decode(self._encoding))
        # file_entry
        for entry in line.header.file_entry:
            entry: elftools_container
            file = debug_info.CUInfo.FileEntry()
            # name
            file.filename = entry.name.decode(self._encoding)
            # dir_index
            idx = entry.dir_index
            file.dir_path = self._active_cu.include_dir_list[idx]
            # DW_AT_comp_dirからのパス
            fpath = pathlib.Path(file.dir_path) / file.filename
            file.full_path = fpath
            # システムインクルードパスは相対パス設定なしとする
            try:
                file.proj_rel_path = str(fpath.relative_to(self._active_cu.compile_dir))
            except:
                file.proj_rel_path = None
            # file_entry登録
            self._active_cu.file_list.append(file)
        # line program entry
        """
        for entry in line.get_entries():
            if not entry.state or entry.state.file == 0:
                # entryが空、または、ファイルがない
                continue
            file_no = entry.state.file
        """

    def warn_noimpl(self, msg: str):
        if self._debug_warning:
            print("not impled: " + msg)

    def analyze_die(self, die: DIE):
        # debug comment
        # 		print("DIE tag: " + str(die.tag))
        # 		print("    offset: " + str(die.offset))
        # 		print("    size  : " + str(die.size))

        # entry生成
        entry = self.add_entry(die.offset, die.tag, die.size)

        match entry.tag:
            case "DW_TAG_compile_unit":
                # 最初に解析済み
                # self.analyze_die_TAG_compile_unit(die, entry)
                pass

            case "DW_TAG_dwarf_procedure":
                self.warn_noimpl(f"DW_TAG={entry.tag}")

            # 変数定義
            case "DW_TAG_variable":
                self.analyze_die_TAG_variable(die, entry)

            case "DW_TAG_constant":
                self.warn_noimpl(f"DW_TAG={entry.tag}")

            # 関数定義
            case "DW_TAG_subprogram":
                self.analyze_die_TAG_subprogram(die)

            # 型情報
            case "DW_TAG_base_type":
                self.analyze_die_TAG_base_type(die, entry)
            case "DW_TAG_unspecified_type":
                self.analyze_die_TAG_unspecified_type(die, entry)
            case "DW_TAG_enumeration_type":
                self.analyze_die_TAG_enumeration_type(die, entry)
            case "DW_TAG_enumerator":
                # おそらく全部重複
                pass
            case "DW_TAG_class_type":
                # 暫定でstructと同様に解析
                self.analyze_die_TAG_structure_type(die, entry)
            case "DW_TAG_structure_type":
                self.analyze_die_TAG_structure_type(die, entry)
            case "DW_TAG_union_type":
                self.analyze_die_TAG_union_type(die, entry)
            case "DW_TAG_typedef":
                self.analyze_die_TAG_typedef(die, entry)
            case "DW_TAG_array_type":
                self.analyze_die_TAG_array_type(die, entry)
            case "DW_TAG_subroutine_type":
                self.analyze_die_TAG_subroutine_type(die, entry)
            case "DW_TAG_inlined_subroutine":
                print("DW_TAG_inlined_subroutine tag.")
            case "DW_TAG_member":
                # print("DW_TAG_member tag.")
                # self.analyze_die_TAG_member(die)
                # おそらく全部重複
                pass
            case "DW_TAG_subrange_type":
                # print("DW_TAG_subrange_type tag.")
                # おそらく全部重複
                pass
            case "DW_TAG_formal_parameter":
                # print("DW_TAG_formal_parameter tag.")
                # おそらく全部重複
                pass

            # type-qualifier
            case "DW_TAG_const_type":
                self.analyze_die_TAG_type_qualifier(die, entry, debug_info.TAG.const)
            case "DW_TAG_pointer_type":
                self.analyze_die_TAG_type_qualifier(die, entry, debug_info.TAG.pointer)
            case "DW_TAG_restrict_type":
                self.analyze_die_TAG_type_qualifier(die, entry, debug_info.TAG.restrict)
            case "DW_TAG_volatile_type":
                self.analyze_die_TAG_type_qualifier(die, entry, debug_info.TAG.volatile)
            case "DW_TAG_packed_type" | "DW_TAG_reference_type" | "DW_TAG_shared_type":
                self.warn_noimpl(f"DW_TAG={entry.tag}")

            case "DW_TAG_unspecified_type":
                self.warn_noimpl(f"DW_TAG={entry.tag}")

            case _:
                if die.tag is not None:
                    self.warn_noimpl(f"DW_TAG={entry.tag}")

    """
    DW_TAG_* 解析
    """

    def analyze_die_TAG_compile_unit(self, cu: CompileUnit, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_compile_unit
        tag_entry: DW_TAG_compile_unit entry
        """
        # CompileUnitInfo格納インスタンスを作成
        self._active_cu = debug_info.CUInfo()
        self._cu_tbl.append(self._active_cu)

        # CompileUnitヘッダ解析
        # offset
        self._active_cu.offset = cu.cu_offset
        self.DW_attr.set_offset(self._active_cu.offset)
        # address size
        self._active_cu.address_size = cu.header["address_size"]
        self.DW_attr.set_address_size(self._active_cu.address_size)
        #
        self._active_cu.debug_abbrev_offset = cu.header["debug_abbrev_offset"]
        #
        self._active_cu.unit_length = cu.header["unit_length"]
        # file_entryは 0:存在しない になるので、Noneを入れておく
        self._active_cu.file_list.append(None)

        # DW_AT_* 取得
        for at in die.attributes.keys():
            # Attribute解析
            attr = self.DW_attr.decord(die.attributes[at])
            match attr.tag:
                case DW_AT._name:
                    # entry
                    tag_entry.name = attr.value
                    # cu_info
                    self._active_cu.filename = attr.value

                case DW_AT._comp_dir:
                    # entry
                    tag_entry.compile_dir = attr.value
                    # cu_info
                    self._active_cu.compile_dir = attr.value

                case DW_AT._producer:
                    tag_entry.producer = attr.value
                    self._active_cu.producer = attr.value

                case DW_AT._language:
                    tag_entry.language = attr.value
                    self._active_cu.language = attr.value

                case DW_AT._stmt_list:
                    tag_entry.stmt_list = attr.value
                    self._active_cu.stmt_list = attr.value

                case DW_AT._high_pc:
                    tag_entry.high_pc = attr.value
                    self._active_cu.high_pc = attr.value

                case DW_AT._low_pc:
                    tag_entry.low_pc = attr.value
                    self._active_cu.low_pc = attr.value

                case _:
                    self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)

        # failsafe: 必要なATが存在しない場合
        # コンパイルディレクトリはカレントディレクトリを見なす
        if self._active_cu.compile_dir is None:
            self._active_cu.compile_dir = "."
        # ファイル名は空文字にしておく
        if self._active_cu.filename is None:
            self._active_cu.filename = ""

        # include_directory は 0:カレントディレクトリ？ になるので、
        # DW_AT_comp_dirを入れておく
        self._active_cu.include_dir_list.append(self._active_cu.compile_dir)

        # ファイル情報
        if self._debug_warning:
            print("CU file: " + self._active_cu.compile_dir + "\\" + self._active_cu.filename)

        # debug comment
        # 		print("    address_size       : " + str(self._curr_cu_info.address_size))
        # 		print("    debug_abbrev_offset: " + str(self._curr_cu_info.debug_abbrev_offset))
        # 		print("    unit_length        : " + str(self._curr_cu_info.unit_length))

    def new_type_info(self, addr: int, tag: debug_info.TAG) -> debug_info.TypeInfo:
        # addr: Dwarf内でのアドレス
        # 必要ならノード作成
        if addr not in self._type_tbl.keys():
            self._type_tbl[addr] = debug_info.TypeInfo()
        else:
            # print("duplicate!")
            pass
        # 型情報インスタンスへの参照取得
        type_inf = self._type_tbl[addr]
        # 型情報更新
        type_inf.tag = tag

        return type_inf

    def set_type_inf(self, type_inf: debug_info.TypeInfo, tag_entry: debug_info.Entry, attr: attribute):
        """
        type_info作成共通処理
        type_infoへ DW_AT_* entry を展開する共通処理。
        個別処理は analyze_die_TAG_* 内で行う。
        DW_TAG_* entry にも展開して情報を集約して保持する。
        """
        match attr.tag:
            case DW_AT._name:
                type_inf.name = attr.value
                tag_entry.name = attr.value
            case DW_AT._type:
                type_inf.child_type = attr.value
                tag_entry.type = attr.value
            case DW_AT._sibling:
                type_inf.sibling_addr = attr.value
                tag_entry.sibling_addr = attr.value
            case DW_AT._const_value:
                type_inf.const_value = attr.value
                tag_entry.const_value = attr.value
            case DW_AT._byte_size:
                type_inf.byte_size = attr.value
                tag_entry.byte_size = attr.value
            case DW_AT._address_class:
                type_inf.address_class = attr.value
                self.register_address_class(type_inf)
                tag_entry.address_class = attr.value
            case DW_AT._declaration:
                type_inf.incomplete = attr.value
                tag_entry.incomplete = attr.value

            # struct/union系
            case DW_AT._data_member_location:
                type_inf.member_location = attr.value
                tag_entry.data_member_location = attr.value
            case DW_AT._bit_offset:
                type_inf.bit_offset = attr.value
                tag_entry.bit_offset = attr.value
            case DW_AT._bit_size:
                type_inf.bit_size = attr.value
                tag_entry.bit_size = attr.value
            case DW_AT._accessibility:
                type_inf.accessibility = attr.value
                tag_entry.accessibility = attr.value

            # fuction系
            case DW_AT._prototyped:
                type_inf.prototyped = attr.value
                tag_entry.prototyped = attr.value

            case DW_AT._encoding:
                type_inf.encoding = attr.value
                tag_entry.encoding = attr.value

            case DW_AT._description:
                type_inf.description = attr.value
                tag_entry.description = attr.value
            case DW_AT._decl_file:
                file_no = attr.value
                type_inf.decl_file = self._active_cu.file_list[file_no]
                tag_entry.decl_file = file_no
            case DW_AT._decl_line:
                type_inf.decl_line = attr.value
                tag_entry.decl_line = attr.value
            case DW_AT._decl_column:
                type_inf.decl_column = attr.value
                tag_entry.decl_column = attr.value
            case DW_AT._sibling:
                type_inf.sibling_addr = attr.value
                tag_entry.sibling_addr = attr.value
            case _:
                # 未実装DW_AT_*のときはFalseを返す
                return False
        # 解析を実施したらTrueを返す
        return True

    def set_type_inf_omit(self, type_inf: debug_info.TypeInfo, tag_entry: debug_info.Entry):
        """
        省略されたDW_AT_*を補完する
        """
        # DECL
        if type_inf.decl_file is None:
            type_inf.decl_file = self._active_cu.file_list[1]
            tag_entry.decl_file = 1

    def analyze_die_TAG_base_type(self, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_base_type
        tag_entry: DW_TAG_base_type entry
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.base)
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_allocated
                DW_AT_associated
                DW_AT_binary_scale
                DW_AT_bit_offset
                DW_AT_bit_size
                DW_AT_data_location
                DW_AT_decimal_scale
                DW_AT_decimal_sign
                DW_AT_description
                DW_AT_digit_count
                DW_AT_endianity
                DW_AT_picture_string
                DW_AT_small
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_unspecified_type(self, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_unspecified_type
        tag_entry: DW_TAG_* entry
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.base)
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """ """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_enumeration_type(self, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_enumeration_type
        tag_entry: DW_TAG_* entry
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.enum)
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_abstract_origin
                DW_AT_accessibility
                DW_AT_allocated
                DW_AT_associated
                DW_AT_bit_size
                DW_AT_bit_offset
                DW_AT_data_location
                DW_AT_decimal_scale
                DW_AT_decimal_sign
                DW_AT_description
                DW_AT_digit_count
                DW_AT_enum_class
                DW_AT_start_scope
                DW_AT_visibility
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            self.analyze_die_TAG_enumeration_type_child(die, type_inf)

    def analyze_die_TAG_enumeration_type_child(self, die: DIE, type_inf: debug_info.TypeInfo):
        child: DIE
        for child in die.iter_children():
            # entry生成
            tag_entry = self.add_entry(child.offset, child.tag, child.size)
            # tag解析
            match child.tag:
                case "DW_TAG_enumerator":
                    mem_inf = self.analyze_die_TAG_enumerator(child, tag_entry)
                    type_inf.member.append(mem_inf)
                case _:
                    # 未処理child
                    self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)


    def analyze_die_TAG_enumerator(self, die: DIE, tag_entry: debug_info.Entry) -> debug_info.TypeInfo:
        """
        DW_TAG_enumerator
        type_infoを作成して返す
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.none)

        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """ """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

        return type_inf

    def analyze_die_TAG_structure_type(self, die: DIE, parent: debug_info.Entry):
        """
        DW_TAG_structure_type
        """
        self.analyze_die_TAG_structure_union_type_impl(die, parent, debug_info.TAG.struct)

    def analyze_die_TAG_union_type(self, die: DIE, parent: debug_info.Entry):
        """
        DW_TAG_union_type
        """
        self.analyze_die_TAG_structure_union_type_impl(die, parent, debug_info.TAG.union)

    def analyze_die_TAG_structure_union_type_impl(self, die: DIE, tag_entry: debug_info.Entry, tag: debug_info.TAG):
        # type_info取得
        type_inf = self.new_type_info(die.offset, tag)
        # Attr取得
        # 情報取得
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_abstract_origin
                DW_AT_accessibility
                DW_AT_allocated
                DW_AT_associated
                DW_AT_data_location
                DW_AT_specification
                DW_AT_start_scope
                DW_AT_visibility
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child取得
        if die.has_children:
            self.analyze_die_TAG_structure_union_type_impl_child(die, type_inf)

    def analyze_die_TAG_structure_union_type_impl_child(self, die: DIE, type_inf: debug_info.TypeInfo):
        child: DIE
        for child in die.iter_children():
            # entry生成
            tag_entry = self.add_entry(child.offset, child.tag, child.size)

            match tag_entry.tag:
                case "DW_TAG_member":
                    mem_inf = self.analyze_die_TAG_member(child, tag_entry)
                    type_inf.member.append(mem_inf)
                case "DW_TAG_array_type":
                    # struct/union/class内で使う型の定義
                    # よって, member要素ではない
                    self.analyze_die_TAG_array_type(child, tag_entry)
                case "DW_TAG_const_type" | "DW_TAG_pointer_type" | "DW_TAG_restrict_type" | "DW_TAG_volatile_type":
                    # struct/union/class内で使う型の定義
                    self.analyze_die_TAG_type_qualifier(child, tag_entry, debug_info.TAG.pointer)
                case "DW_TAG_subprogram":
                    f_inf = self.analyze_die_TAG_subprogram_impl(child)
                    type_inf.method.append(f_inf)
                case _:
                    # ありえないパス
                    # 未処理child
                    self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_member(self, die: DIE, tag_entry: debug_info.Entry) -> debug_info.TypeInfo:
        """
        DW_TAG_member
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.none)

        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_accessibility
                DW_AT_mutable
                DW_AT_visibility
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # member_locationが必ず0の状況では省略される？
        if type_inf.member_location is None:
            type_inf.member_location = 0
            tag_entry.data_member_location = 0
        # child check
        if die.has_children:
            for child in die.iter_children():
                child: DIE
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)
        return type_inf

    def analyze_die_TAG_array_type(self, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_array_type
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.array)
        # Attr check
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_abstract_origin
                DW_AT_accessibility
                DW_AT_allocated
                DW_AT_associated
                DW_AT_bit_stride
                DW_AT_byte_size
                DW_AT_data_location
                DW_AT_declaration
                DW_AT_description
                DW_AT_name
                DW_AT_ordering
                DW_AT_specification
                DW_AT_start_scope
                DW_AT_visibility
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            for child in die.iter_children():
                child: DIE
                if child.tag == "DW_TAG_subrange_type":
                    # lower_boundが0であると自明なときは省略されるケースあり
                    upper_bound = 0
                    lower_bound = 0
                    # Attr check
                    for at in child.attributes.keys():
                        # Attribute Entry生成
                        attr = self.DW_attr.decord(child.attributes[at])
                        #
                        match attr.tag:
                            case DW_AT._count:
                                type_inf.range = attr.value
                            case DW_AT._upper_bound:
                                upper_bound = attr.value
                            case DW_AT._lower_bound:
                                lower_bound = attr.value
                            case _:
                                if self._debug_warning:
                                    print("array:?:" + at)
                        #
                        if type_inf.range is None:
                            type_inf.range = (upper_bound - lower_bound) + 1

                # elif child.tag == "DW_TAG_enumeration_type":
                else:
                    # 未処理child
                    self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_subroutine_type(self, die: DIE, tag_entry: debug_info.Entry):
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.func)
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            match attr.tag:
                case DW_AT._type:
                    type_inf.result_type = attr.value
                    tag_entry.type = attr.value
                case _:
                    result = self.set_type_inf(type_inf, tag_entry, attr)
                    if not result:
                        """ """
                        # 未処理DW_AT_*
                        self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                param_inf = self.analyze_parameter(child)
                type_inf.params.append(param_inf)

    def analyze_parameter(self, die: DIE) -> debug_info.TypeInfo:
        if die.tag == "DW_TAG_formal_parameter":
            return self.analyze_die_TAG_formal_parameter(die)
        elif die.tag == "DW_TAG_unspecified_parameters":
            return None

    def analyze_die_TAG_formal_parameter(self, param: DIE) -> debug_info.TypeInfo:
        # type要素追加
        param_inf = debug_info.TypeInfo()
        param_inf.tag = debug_info.TAG.parameter
        # 引数情報をtype_infoに格納
        for at in param.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(param.attributes[at])

            if attr.tag == DW_AT._type:
                param_inf.child_type = attr.value
            else:
                # 未処理DW_AT_*
                # self.warn_noimpl(f"{param.tag}: unknown attribute: " + at)
                pass
        #
        return param_inf

    def analyze_die_TAG_type_qualifier(self, die: DIE, tag_entry: debug_info.Entry, tag: debug_info.TAG):
        """
        DW_TAG_const_type
        DW_TAG_pointer_type
        DW_TAG_restrict_type
        DW_TAG_volatile_type
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, tag)
        # 情報取得
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DW_AT_allocated
                DW_AT_associated
                DW_AT_data_location
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_typedef(self, die: DIE, tag_entry: debug_info.Entry):
        """
        DW_TAG_typedef
        """
        # type_info取得
        type_inf = self.new_type_info(die.offset, debug_info.TAG.typedef)
        # 情報取得
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])
            # type_info更新
            result = self.set_type_inf(type_inf, tag_entry, attr)
            if not result:
                """
                DECL
                DW_AT_abstract_origin
                DW_AT_accessibility
                DW_AT_allocated
                DW_AT_associated
                DW_AT_data_location
                DW_AT_start_scope
                DW_AT_visibility
                """
                # 未処理DW_AT_*
                self.warn_noimpl(f"{tag_entry.tag}: unknown attribute: " + at)
        # omit DW_AT check
        self.set_type_inf_omit(type_inf, tag_entry)
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{tag_entry.tag}: unproc child: " + child.tag)

    def analyze_die_TAG_variable(self, die: DIE, parent: debug_info.Entry):
        """
        DW_TAG_variable
        """
        var = debug_info.VarInfo()
        # AT解析
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])

            match attr.tag:
                case DW_AT._external:
                    parent.external = attr.value
                    var.extern = attr.value
                case DW_AT._name:
                    parent.name = attr.value
                    var.name = attr.value
                case DW_AT._decl_file:
                    parent.decl_file = attr.value
                    # ファイル情報取得
                    var.decl_file = self._active_cu.file_list[attr.value]
                    # ファイルが現在解析中のものでない
                    if attr.value != 1:
                        var.external_file = True
                case DW_AT._decl_line:
                    parent.decl_line = attr.value
                    var.decl_line = attr.value
                case DW_AT._decl_column:
                    parent.decl_column = attr.value
                    var.decl_column = attr.value
                case DW_AT._type:
                    parent.type = attr.value
                    var.type = attr.value
                case DW_AT._location:
                    match attr.cls:
                        case Class.exprloc:
                            parent.location = attr.value
                            var.addr = attr.value
                        case Class.loclistptr:
                            parent.loclistptr = attr.value
                            var.loclistptr = attr.value
                    
                case DW_AT._declaration:
                    parent.declaration = attr.value
                    var.not_declaration = attr.value
                case DW_AT._const_value:
                    parent.const_value = attr.value
                    var.const_value = attr.value
                case DW_AT._sibling:
                    parent.sibling_addr = attr.value
                    var.sibling_addr = attr.value
                case _:
                    """
                    DECL
                    DW_AT_abstract_origin
                    DW_AT_accessibility
                    DW_AT_description
                    DW_AT_endianity
                    DW_AT_segment
                    DW_AT_specification
                    DW_AT_start_scope
                    DW_AT_visibility
                    """
                    # 未処理DW_AT_*
                    self.warn_noimpl(f"{parent.tag}: unknown attribute: " + at)
        # 省略DW_AT_*チェック
        if var.decl_file is None:
            if len(self._active_cu.file_list) > 1:
                # DW_AT_decl_file
                # CompileUnitのファイルが対象の場合省略されることがある？
                parent.decl_file = 1
                var.decl_file = self._active_cu.file_list[1]
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                # 未処理child
                self.warn_noimpl(f"{parent.tag}: unproc child: " + child.tag)
        # 変数登録
        if var.addr is None or var.name is None or var.type is None:
            # アドレスを持たない
            # ローカル変数, 定数, etc
            pass
        else:
            # アドレスを持っているとき
            # グローバル変数
            self._global_var_tbl.append(var)
        # debug comment

    # 		print("    name  : " + var_ref.name)
    # 		print("    type  : " + str(var_ref.type))
    # 		print("    loca  : " + str(var_ref.addr))

    def analyze_die_TAG_subprogram(self, die: DIE):
        f_inf = self.analyze_die_TAG_subprogram_impl(die)
        if f_inf.external is True:
            # 関数
            self._func_tbl.append(debug_info.func_info())
            f_inf = self._func_tbl[len(self._func_tbl) - 1]
        else:
            # おそらくすべて重複
            return

    def analyze_die_TAG_subprogram_impl(self, die: DIE) -> debug_info.func_info:
        f_inf = debug_info.func_info()
        # AT取得
        call_convention = 1  # デフォルトがDW_CC_normal
        for at in die.attributes.keys():
            # Attribute Entry生成
            attr = self.DW_attr.decord(die.attributes[at])

            match attr.tag:
                case DW_AT._external:
                    f_inf.external = attr.value
                case DW_AT._name:
                    f_inf.name = attr.value
                case DW_AT._type:
                    f_inf.return_type = attr.value
                case DW_AT._calling_convention:
                    call_convention = die.attributes[at].value
                case DW_AT._decl_file:
                    file_no = attr.value
                    f_inf.decl_file = self._active_cu.file_list[file_no]
                case DW_AT._decl_line:
                    f_inf.decl_line = attr.value
                case DW_AT._decl_column:
                    f_inf.decl_column = attr.value
                case DW_AT._low_pc:
                    f_inf.low_pc = attr.value
                case DW_AT._high_pc:
                    f_inf.high_pc = attr.value
                case DW_AT._accessibility:
                    f_inf.accessibility = attr.value
                case DW_AT._declaration:
                    f_inf.declaration = attr.value
                case DW_AT._frame_base:
                    f_inf.frame_base_addr = attr.value
                    self.DW_attr.set_frame_base(attr.value)
                case DW_AT._return_addr:
                    pass
                case _:
                    # 未処理DW_AT_*
                    self.warn_noimpl(f"{die.tag}: unknown attribute: " + at)

        # omit DW_AT_* check
        if f_inf.decl_file is None:
            # DW_AT_decl_file
            f_inf.decl_file = self._active_cu.file_list[1]
        # child check
        if die.has_children:
            child: DIE
            for child in die.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    param_inf = self.analyze_parameter(child)
                    f_inf.params.append(param_inf)
                elif child.tag == "DW_TAG_unspecified_parameters":
                    param_inf = self.analyze_parameter(child)
                    f_inf.params.append(param_inf)
                elif child.tag == "DW_TAG_variable":
                    pass
                else:
                    # 未処理child
                    self.warn_noimpl(f"{die.tag}: unproc child: " + child.tag)
        #
        return f_inf

    def register_address_class(self, t_inf: debug_info.TypeInfo):
        """
        DW_AT_address_class情報を登録する。
        アーキテクチャ特有のaddress_classを取得する手段が無い？ので
        """
        # address_class一覧を作成
        if t_inf.address_class not in self._addr_cls.keys():
            self._addr_cls[t_inf.address_class] = []
        # 逆参照を記憶しておく
        self._addr_cls[t_inf.address_class].append(t_inf)

    def analyze_address_class(self):
        """
        address_class作成
        address_class推論
        """
        # Address Class Definition
        address_class_list = {
            # RL78
            "Renesas RL78": {
                3: 4,  # 3 -> 4byte
                4: 2,  # 4 -> 2byte
            },
            "Renesas RX": {},
            "ARM": {},
            "AArch64": {},
        }
        # Address Class 決定
        address_class = address_class_list[self._arch]
        # byte_size 設定
        for key in self._addr_cls.keys():
            for t_inf in self._addr_cls[key]:
                t_inf.byte_size = address_class[key]
