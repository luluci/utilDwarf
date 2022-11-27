
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
            # # 型情報取得
            # t_inf: debug_info.TypeInfo
            # t_inf = self.get_type_info(var.type)
            # #
            # self.make_impl2(var, t_inf)
            self.make_impl(var)

    def make_impl(self, var: debug_info.VarInfo):
        # 型情報取得
        t_inf: debug_info.TypeInfo
        t_inf = self.get_type_info(var.type)
        # 
        mmap_var = self.make_memmap_var(var, t_inf)
        # 登録
        self.register_memmap_node(mmap_var)

    def register_memmap_node(self, var: VarInfo):
        # 重複チェック
        if var.address in self._memmap_dup.keys():
            # 重複あり
            base_var = self._memmap_dup[var.address]
            base_var.external.append(var)
        else:
            # 重複無し
            self._memmap_dup[var.address] = var
            # 変数情報登録
            self._memmap.append(var)

    def make_memmap_var(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo) -> VarInfo:
        """
        VarInfo作成
        """
        # 基本情報作成
        mmap_var = self.make_memmap_var_common(var, t_inf)
        # tagに応じて情報付与
        # type-specifierが必ず出現する想定
        match t_inf.tag:
            case tag if self.check_tag_or(tag, VarInfo.TAG.func):
                self.set_memmap_var_func(mmap_var, var, t_inf)
            case tag if self.check_tag_or(tag, VarInfo.TAG.pointer):
                self.set_memmap_var_pointer(mmap_var, var, t_inf)
            case tag if self.check_tag_or(tag, VarInfo.TAG.enum):
                self.set_memmap_var_enum(mmap_var, var, t_inf)
            case tag if self.check_tag_or(tag, VarInfo.TAG.base):
                self.set_memmap_var_base(mmap_var, var, t_inf)
            case tag if self.check_tag_or(tag, VarInfo.TAG.struct):
                self.set_memmap_var_struct(mmap_var, var, t_inf, VarInfo.TAG.struct)
            case tag if self.check_tag_or(tag, VarInfo.TAG.union):
                self.set_memmap_var_struct(mmap_var, var, t_inf, VarInfo.TAG.union)
            case _:
                raise Exception("unknown variable type detected.")

        # 
        # const
        check = self.check_tag_or(t_inf.tag, VarInfo.TAG.const)
        if check:
            pass
        # volatile
        check = self.check_tag_or(t_inf.tag, VarInfo.TAG.volatile)
        if check:
            pass
        # restrict
        check = self.check_tag_or(t_inf.tag, VarInfo.TAG.restrict)
        if check:
            pass

        # 
        # array
        check = self.check_tag_or(t_inf.tag, VarInfo.TAG.array)
        if check:
            self.set_memmap_var_array(mmap_var, var, t_inf)
        # pointer
        check = self.check_tag_or(t_inf.tag, VarInfo.TAG.pointer)
        if check:
            pass

        return mmap_var

    def check_tag_or(self, tgt: VarInfo.TAG, cond: VarInfo.TAG):
        """
        condがtgtに含まれるかチェック
        """
        return (tgt & cond) == cond

    def make_memmap_var_common(self, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo) -> VarInfo:
        """
        基本VarInfo作成
        """
        mmap_var = VarInfo()
        # 共通情報作成
        mmap_var.address = var.addr  # 配置アドレス
        mmap_var.name = var.name  # 変数名
        mmap_var.decl_file = var.decl_file
        mmap_var.decl_line = var.decl_line
        # 型情報作成
        mmap_var.byte_size = t_inf.byte_size  # 宣言型サイズ
        mmap_var.array_size = t_inf.range  # 配列要素数
        mmap_var.const = t_inf.const  # const
        mmap_var.pointer = t_inf.pointer  # pointer
        mmap_var.typename = t_inf.name
        #
        mmap_var.tag = VarInfo.TAG.none
        return mmap_var

    def set_memmap_var_base(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # tag付与
        mmap_var.tag |= VarInfo.TAG.base

    def set_memmap_var_pointer(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # tag付与
        mmap_var.tag |= VarInfo.TAG.pointer

    def set_memmap_var_func(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # tag付与
        mmap_var.tag |= VarInfo.TAG.func

    def set_memmap_var_enum(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # tag付与
        mmap_var.tag |= VarInfo.TAG.enum

    def set_memmap_var_array(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo):
        # tag付与
        mmap_var.tag |= VarInfo.TAG.array
        # # 配列の各idxを個別にmemberとして登録
        # each_t_inf = t_inf.sub_type
        # for idx in range(0, mmap_var.array_size):
        #     # 再帰処理開始
        #     each_var = self.make_memmap_var_array_each(mmap_var, each_t_inf, idx)
        #     #
        #     mmap_var.member.append(each_var)

    def make_memmap_var_array_each(self, mmap_parent: VarInfo, each_t_inf: debug_info.TypeInfo, idx: int) -> VarInfo:
        # member_infからdebug_info.VarInfoを作成
        var = self.make_memmap_var_array_each_var(mmap_parent, each_t_inf, idx)
        # VarInfoを作成
        mmap_var = self.make_memmap_var(var, each_t_inf)
        return mmap_var

    def make_memmap_var_array_each_var(self, mmap_parent: VarInfo, each_t_inf: debug_info.TypeInfo, idx: int) -> debug_info.VarInfo:
        """
        arrayのTypeInfoから、make_memmap_varに渡す用のdebug_info.VarInfoを作成する
        make_memmap_var/make_memmap_var_commonで使う要素だけ作成する。
        """
        var = debug_info.VarInfo()
        #
        var.addr = mmap_parent.address + (each_t_inf.byte_size * idx)
        var.name = "[" + str(idx) + "]"
        var.decl_file = each_t_inf.decl_file
        var.decl_line = each_t_inf.decl_line
        #
        return var

    def set_memmap_var_struct(self, mmap_var: VarInfo, var: debug_info.VarInfo, t_inf: debug_info.TypeInfo, tag: VarInfo.TAG):
        # tag付与
        mmap_var.tag |= tag
        # memberチェック
        for member_inf in t_inf.member:
            # member情報作成
            member_inf: debug_info.TypeInfo
            member_var = self.make_memmap_var_member(mmap_var, member_inf)
            #
            mmap_var.member.append(member_var)

    def make_memmap_var_member(self, mmap_parent: VarInfo, member_inf: debug_info.TypeInfo) -> VarInfo:
        # 型情報取得
        t_inf: debug_info.TypeInfo
        t_inf = self.get_type_info(member_inf.child_type)
        # member_infからdebug_info.VarInfoを作成
        var = self.make_memmap_var_member_var(mmap_parent, member_inf)
        # VarInfoを作成
        mmap_var = self.make_memmap_var(var, t_inf)
        return mmap_var

    def make_memmap_var_member_var(self, mmap_parent: VarInfo, member_inf: debug_info.TypeInfo) -> debug_info.VarInfo:
        """
        memberのTypeInfoから、make_memmap_varに渡す用のdebug_info.VarInfoを作成する
        make_memmap_var/make_memmap_var_commonで使う要素だけ作成する。
        """
        var = debug_info.VarInfo()
        #
        var.addr = mmap_parent.address + member_inf.member_location
        var.name = member_inf.name
        var.decl_file = member_inf.decl_file
        var.decl_line = member_inf.decl_line
        #
        return var



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

