
import copy
from typing import List, Dict

from util_dwarf import debug_info
from util_dwarf.decorder import Decorder

class VarInfo:
    """
    変数情報
    """
    TAG = debug_info.TAG

    def __init__(self) -> None:
        self.tag = None  # 変数タイプタグ
        # 変数情報
        self.name = None  # 変数名
        self.address = None  # 配置アドレス
        self.address_offset = None  # アドレスオフセット
        self.decl_file = None
        self.decl_line = None
        self.external = []  # 外部定義情報
        # 型情報
        self.byte_size = None  # 宣言型のバイトサイズ
        self.bit_size = None  # ビットフィールド宣言時のビットサイズ
        self.bit_offset = None  # ビットフィールド宣言時のビットオフセット
        self.array_size = None  # 配列宣言時の要素数
        self.member = []  # struct/union/classにおけるメンバ情報(mem_var_type)
        self.const = None  # const定数
        self.pointer = None  # const定数
        self.typename = None


class memmap:

    def __init__(self) -> None:
        # メモリマップ初期化
        self._memmap: List[VarInfo] = []
        # 重複チェックdict
        self._memmap_dup: Dict[int, VarInfo] = {}
        #
        self._memmap: List[VarInfo] = []


    def make(self, dwarf: Decorder) -> None:
        self._dwarf = dwarf
        # グローバル変数をすべてチェック
        for var in dwarf._global_var_tbl:
            # 型情報取得
            t_inf: debug_info.TypeInfo
            t_inf = self.get_type_info(var.type)
            #
            self.make_impl(var, t_inf)

    def make_impl(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo) -> None:
        # typeチェック
        # array + struct のような複合系ができてない
        match t_inf.tag:
            case tag if (tag & debug_info.TAG.array).value != 0:
                self.make_memmap_var_array(var, t_inf)
            case tag if (tag & debug_info.TAG.pointer).value != 0:
                self.make_memmap_var_base(var, t_inf)
            case tag if (tag & debug_info.TAG.func).value != 0:
                self.make_memmap_var_func(var, t_inf)
            case tag if (tag & debug_info.TAG.struct).value != 0:
                self.make_memmap_var_struct(var, t_inf)
            case tag if (tag & debug_info.TAG.union).value != 0:
                self.make_memmap_var_struct(var, t_inf)
            case tag if (tag & debug_info.TAG.enum).value != 0:
                self.make_memmap_var_base(var, t_inf)
            case tag if (tag & debug_info.TAG.base).value != 0:
                self.make_memmap_var_base(var, t_inf)
            case _:
                raise Exception("unknown variable type detected.")

    def make_memmap_var(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo) -> VarInfo:
        """
        memmap_var作成関数
        アドレス重複チェックも実施する
        """
        memmap_var: VarInfo = None
        # 重複チェック
        if var.addr in self._memmap_dup.keys():
            # 重複あり
            base_var = self._memmap_dup[var.addr]
            memmap_var = VarInfo()
            base_var.external.append(memmap_var)
        else:
            # 重複無し
            # 変数情報作成
            memmap_var = VarInfo()
            self._memmap_dup[var.addr] = memmap_var
            # 変数情報登録
            self._memmap.append(memmap_var)

        # 共通情報作成
        memmap_var.address = var.addr  # 配置アドレス
        memmap_var.name = var.name  # 変数名
        memmap_var.decl_file = var.decl_file
        memmap_var.decl_line = var.decl_line
        # 型情報作成
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.array_size = t_inf.range  # 配列要素数
        memmap_var.const = t_inf.const  # const
        memmap_var.pointer = t_inf.pointer  # pointer
        memmap_var.typename = t_inf.name
        #
        return memmap_var

    def make_memmap_var_base(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = self.make_memmap_var(var, t_inf)
        memmap_var.tag = debug_info.TAG.base  # 変数タイプタグ

    def make_memmap_var_func(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = self.make_memmap_var(var, t_inf)
        memmap_var.tag = debug_info.TAG.func  # 変数タイプタグ

    def make_memmap_var_array(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = self.make_memmap_var(var, t_inf)
        memmap_var.tag = debug_info.TAG.array  # 変数タイプタグ

        # 配列の各idxを個別にmemberとして登録
        member_t_inf = t_inf.sub_type
        for idx in range(0, memmap_var.array_size):
            # 再帰処理開始
            self.make_memmap_var_array_each(memmap_var, member_t_inf, idx)

    def make_memmap_var_array_each(self, parent: VarInfo, mem_inf: debug_info.TypeInfo, idx: int):
        # typeチェック
        match mem_inf.tag:
            case tag if (tag & debug_info.TAG.array).value != 0:
                self.make_memmap_var_array_each_array(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.pointer).value != 0:
                self.make_memmap_var_array_each_base(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.func).value != 0:
                self.make_memmap_var_array_each_func(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.struct).value != 0:
                self.make_memmap_var_array_each_struct(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.union).value != 0:
                self.make_memmap_var_array_each_struct(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.enum).value != 0:
                self.make_memmap_var_array_each_base(parent, mem_inf, idx)
            case tag if (tag & debug_info.TAG.base).value != 0:
                self.make_memmap_var_array_each_base(parent, mem_inf, idx)
            case _:
                raise Exception("unknown variable type detected.")

    def make_memmap_var_array_each_base(self, parent: VarInfo, mem_inf: debug_info.TypeInfo, idx: int):
        # 配列要素[idx]を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = parent.tag
        memmap_var.address = parent.address + (mem_inf.byte_size * idx)
        memmap_var.name = "[" + str(idx) + "]"
        memmap_var.byte_size = mem_inf.byte_size
        memmap_var.decl_file = mem_inf.decl_file
        memmap_var.decl_line = mem_inf.decl_line
        memmap_var.typename = mem_inf.name
        memmap_var.pointer = mem_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

    def make_memmap_var_array_each_func(self, parent: VarInfo, mem_inf: debug_info.TypeInfo, idx: int):
        # 配列要素[idx]を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = parent.tag
        memmap_var.address = parent.address + (mem_inf.byte_size * idx)
        memmap_var.name = "[" + str(idx) + "]"
        memmap_var.byte_size = mem_inf.byte_size
        memmap_var.decl_file = mem_inf.decl_file
        memmap_var.decl_line = mem_inf.decl_line
        memmap_var.typename = mem_inf.name
        memmap_var.pointer = mem_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

    def make_memmap_var_array_each_array(self, parent: VarInfo, mem_inf: debug_info.TypeInfo, idx: int):
        # 配列要素[idx]を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = parent.tag
        memmap_var.address = parent.address + (mem_inf.byte_size * idx)
        memmap_var.name = "[" + str(idx) + "]"
        memmap_var.byte_size = mem_inf.byte_size
        memmap_var.array_size = mem_inf.range
        memmap_var.decl_file = mem_inf.decl_file
        memmap_var.decl_line = mem_inf.decl_line
        memmap_var.typename = mem_inf.name
        memmap_var.pointer = mem_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

        # 配列の各idxを個別にmemberとして登録
        for child_idx in range(0, memmap_var.array_size):
            # 再帰処理開始
            self.make_memmap_var_array_each(memmap_var, mem_inf, child_idx)

    def make_memmap_var_array_each_struct(self, parent: VarInfo, mem_inf: debug_info.TypeInfo, idx: int):
        # 配列要素[idx]を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = parent.tag
        memmap_var.address = parent.address + (mem_inf.byte_size * idx)
        memmap_var.name = "[" + str(idx) + "]"
        memmap_var.byte_size = mem_inf.byte_size
        memmap_var.decl_file = mem_inf.decl_file
        memmap_var.decl_line = mem_inf.decl_line
        memmap_var.typename = mem_inf.name
        memmap_var.pointer = mem_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

        # メンバ変数を登録
        for member_t_inf in mem_inf.member:
            # 再帰処理開始
            self.make_memmap_var_member(memmap_var, member_t_inf)

    def make_memmap_var_struct(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # 構造体変数を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = debug_info.TAG.struct  # 変数タイプタグ
        memmap_var.address = var.addr  # 配置アドレス
        memmap_var.name = var.name  # 変数名
        memmap_var.decl_file = var.decl_file
        memmap_var.decl_line = var.decl_line
        # 型情報作成
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.const = t_inf.const  # const
        memmap_var.typename = t_inf.name
        memmap_var.pointer = t_inf.pointer  # pointer
        # 変数情報登録
        self._memmap.append(memmap_var)

        # メンバ変数を登録
        for member_t_inf in t_inf.member:
            # 再帰処理開始
            self.make_memmap_var_member(memmap_var, member_t_inf)

    def make_memmap_var_member(self, parent: VarInfo, mem_inf: debug_info.TypeInfo):
        # member型情報を取得
        mem_t_inf = self.get_type_info(mem_inf.child_type)
        # typeチェック
        match mem_t_inf.tag:
            case tag if (tag & debug_info.TAG.array).value != 0:
                self.make_memmap_var_member_array(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.pointer).value != 0:
                self.make_memmap_var_member_base(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.func).value != 0:
                self.make_memmap_var_member_func(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.struct).value != 0:
                self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.union).value != 0:
                self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.enum).value != 0:
                self.make_memmap_var_member_base(parent, mem_inf, mem_t_inf)
            case tag if (tag & debug_info.TAG.base).value != 0:
                self.make_memmap_var_member_base(parent, mem_inf, mem_t_inf)
            case _:
                raise Exception("unknown variable type detected.")

    def make_memmap_var_member_base(self, parent: VarInfo, member_inf: debug_info.TypeInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = debug_info.TAG.base  # 変数タイプタグ
        memmap_var.address = parent.address + member_inf.member_location  # アドレス
        memmap_var.address_offset = member_inf.member_location  # アドレスオフセット
        memmap_var.name = member_inf.name  # メンバ名
        if member_inf.bit_size is not None:
            memmap_var.bit_size = member_inf.bit_size  # ビットサイズ
            memmap_var.bit_offset = member_inf.bit_offset  # ビットオフセット
            # member_inf.member_inf  # ビットフィールドのみ存在? パディングを含むバイト単位サイズ, バイト境界をまたぐ(bit7-8とか)と2バイトになる
        memmap_var.decl_file = member_inf.decl_file
        memmap_var.decl_line = member_inf.decl_line
        # 型情報作成
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.typename = t_inf.name
        memmap_var.pointer = t_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

    def make_memmap_var_member_func(self, parent: VarInfo, member_inf: debug_info.TypeInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = debug_info.TAG.func  # 変数タイプタグ
        memmap_var.address = parent.address + member_inf.member_location  # アドレス
        memmap_var.address_offset = member_inf.member_location  # アドレスオフセット
        memmap_var.name = member_inf.name  # メンバ名
        memmap_var.decl_file = member_inf.decl_file
        memmap_var.decl_line = member_inf.decl_line
        # 型情報作成
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.typename = t_inf.name
        memmap_var.pointer = t_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

    def make_memmap_var_member_array(self, parent: VarInfo, member_inf: debug_info.TypeInfo, t_inf: debug_info.TypeInfo):
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.tag = debug_info.TAG.array  # 変数タイプタグ
        memmap_var.address = parent.address + member_inf.member_location  # アドレス
        memmap_var.address_offset = member_inf.member_location  # アドレスオフセット
        memmap_var.name = member_inf.name  # メンバ名
        memmap_var.decl_file = member_inf.decl_file
        memmap_var.decl_line = member_inf.decl_line
        # 型情報作成
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.array_size = t_inf.range  # 配列要素数
        memmap_var.typename = t_inf.name
        memmap_var.pointer = t_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

        # 配列の各idxを個別にmemberとして登録
        member_t_inf = t_inf.sub_type
        for idx in range(0, memmap_var.array_size):
            # 再帰処理開始
            self.make_memmap_var_array_each(memmap_var, member_t_inf, idx)

    def make_memmap_var_member_struct(self, parent: VarInfo, member_inf: debug_info.TypeInfo, t_inf: debug_info.TypeInfo):
        # 構造体変数を登録
        # 変数情報作成
        memmap_var = VarInfo()
        memmap_var.address = parent.address + member_inf.member_location  # アドレス
        memmap_var.address_offset = member_inf.member_location  # アドレスオフセット
        memmap_var.name = member_inf.name  # メンバ名
        memmap_var.decl_file = member_inf.decl_file
        memmap_var.decl_line = member_inf.decl_line
        # 型情報作成
        memmap_var.tag = t_inf.tag
        memmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        memmap_var.typename = t_inf.name
        memmap_var.pointer = t_inf.pointer  # pointer
        # 変数情報登録
        parent.member.append(memmap_var)

        # メンバ変数を登録
        for member_t_inf in t_inf.member:
            # 再帰処理開始
            self.make_memmap_var_member(memmap_var, member_t_inf)

    def get_type_info(self, type_id: int) -> debug_info.TypeInfo:
        # typedef
        TAG = debug_info.TAG
        # type 取得
        if type_id not in self._dwarf._type_tbl.keys():
            # ありえないはず
            raise Exception("undetected type appeared.")
        # 型情報がツリーになっているので順に辿って結合していくことで1つの型情報とする
        type_inf = debug_info.TypeInfo()
        next_type_id = type_id
        while next_type_id is not None:
            # child情報を結合していく
            child_type = self._dwarf._type_tbl[next_type_id]
            if child_type.tag == debug_info.TAG.base:
                # name 上書き
                type_inf.name = self.get_type_info_select_overwrite(type_inf.name, child_type.name)
                # encoding 上書き
                type_inf.encoding = self.get_type_info_select_overwrite(type_inf.encoding, child_type.encoding)
                # byte_size 選択
                type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.func:
                # name 選択
                type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
                # byte_size 選択
                type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
                # params 選択
                if not type_inf.params and child_type.params:
                    type_inf.params = child_type.params

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.typedef:
                # name 選択
                type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag in {TAG.struct, TAG.union}:
                # name 上書き
                type_inf.name = self.get_type_info_select_overwrite(type_inf.name, child_type.name)
                # byte_size 選択
                type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
                # member 選択
                if not type_inf.member and child_type.member:
                    type_inf.member = child_type.member

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.array:
                # name 選択
                type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
                # range 上書き
                type_inf.range = self.get_type_info_select(type_inf.range, child_type.range)

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.const:
                type_inf.const = True

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.pointer:
                # address_class 上書き
                type_inf.address_class = self.get_type_info_select(type_inf.address_class, child_type.address_class)
                # byte_size 上書き
                type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
                type_inf.pointer += 1

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.restrict:
                type_inf.restrict = True

                # tagマージ
                type_inf.tag |= child_type.tag
            elif child_type.tag == debug_info.TAG.volatile:
                type_inf.volatile = True

                # tagマージ
                type_inf.tag |= child_type.tag

            elif child_type.tag == debug_info.TAG.enum:
                # name 選択
                type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
                # byte_size 選択
                type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)

                # tagマージ
                type_inf.tag |= child_type.tag
            else:
                # 実装忘れ以外ありえない
                raise Exception("undetected type appeared.")
            # child要素チェック
            next_type_id = child_type.child_type
        # tagがNoneのとき、void型と推測
        if type_inf.tag == 0:
            type_inf.tag = debug_info.TAG.base
        if type_inf.name is None:
            type_inf.name = "void"
            # void型でbyte_size未指定の場合はvoid*と推測
            if type_inf.byte_size is None:
                type_inf.byte_size = self._dwarf._active_cu.address_size
        # byte_sizeチェック
        if type_inf.byte_size is None:
            # サイズ指定されていない場合のケアを入れる
            if (type_inf.tag & debug_info.TAG.func_ptr).value != 0:
                # 関数ポインタ
                type_inf.byte_size = self._dwarf._active_cu.address_size
            else:
                raise Exception(f"type:{type_inf.name} is unknown size.")
        # array後処理
        if (type_inf.tag & debug_info.TAG.array).value != 0:
            # array要素の型情報を作成
            # array周りの情報を除去する
            sub_type = copy.copy(type_inf)
            sub_type.tag = type_inf.tag & ~debug_info.TAG.array
            sub_type.range = None
            type_inf.sub_type = sub_type
        return type_inf

    def get_type_info_select_overwrite(self, org, new) -> None:
        """
        new が None でなければ上書きする
        """
        if new is not None:
            return new
        else:
            return org

    def get_type_info_select(self, org, new) -> None:
        """
        new が None でなければ、org が None のとき値を設定する
        """
        if org is None and new is not None:
            return new
        else:
            return org

