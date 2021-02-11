import pathlib
import enum
from typing import List, Dict, Tuple
from elftools.elf.elffile import ELFFile
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import AttributeValue, DIE
from elftools.dwarf.lineprogram import (LineProgram, LineProgramEntry)
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.callframe import (RegisterRule, CFARule)

from .memmap import memmap

class utilDwarf:

	class cu_info:
		def __init__(self) -> None:
			self.compile_dir = ""
			self.filename = ""
			self.debug_abbrev_offset = None
			self.unit_length = None
			self.address_size = None

	class var_info:
		def __init__(self) -> None:
			self.name = None
			self.type = None
			self.addr = None

	class type_info:
		class TAG(enum.Enum):
			base = enum.auto()			# primitive type
			array = enum.auto()			# array
			struct = enum.auto()		# struct
			union = enum.auto()			# union

		def __init__(self) -> None:
			self.tag = None
			self.name = None
			self.byte_size = None
			self.bit_size = None
			self.bit_offset = None
			self.encoding = None
			self.member = []
			self.member_location = None
			self.typedef = None
			self.range = None

	def __init__(self, path: pathlib.Path):
		# 文字コード
		self._encode = "ShiftJIS"
		# データコンテナ初期化
		self._global_var_tbl: List[utilDwarf.var_info] = []
		self._type_tbl: Dict[int, utilDwarf.type_info] = {}
		self._typedef_tbl: Dict[int, utilDwarf.type_info] = {}
		self._memmap: List[memmap] = []
		# elfファイルを開く
		self._path = path
		self._open()

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

	def analyze(self):
		cu: CompileUnit
		for cu in self._dwarf_info.iter_CUs():
			self.analyze_cu(cu)

	def analyze_cu(self, cu:CompileUnit):
		# CompileUnit情報を取得
		self._curr_cu_info = utilDwarf.cu_info()
		# CompileUnit=fileなので(?)、ファイル名、パスを取得
		top_die = cu.get_top_DIE()
		# コンパイル時ディレクトリ情報を取得
		if "DW_AT_comp_dir" in top_die.attributes.keys():
			self._curr_cu_info.compile_dir = top_die.attributes["DW_AT_comp_dir"].value.decode(self._encode)
		else:
			self._curr_cu_info.compile_dir = ""
		# ファイル名取得
		if "DW_AT_name" in top_die.attributes.keys():
			self._curr_cu_info.filename = top_die.attributes["DW_AT_name"].value.decode(self._encode)
		else:
			self._curr_cu_info.filename = ""
		# ファイル情報
		print("CU file: " + self._curr_cu_info.compile_dir + "\\" + self._curr_cu_info.filename)

		# CompileUnitヘッダ解析
		self._curr_cu_info.address_size = cu.header['address_size']
		self._curr_cu_info.debug_abbrev_offset = cu.header['debug_abbrev_offset']
		self._curr_cu_info.unit_length = cu.header['unit_length']
		#
		print("    address_size       : " + str(self._curr_cu_info.address_size))
		print("    debug_abbrev_offset: " + str(self._curr_cu_info.debug_abbrev_offset))
		print("    unit_length        : " + str(self._curr_cu_info.unit_length))

		die: DIE
		for die in cu.iter_DIEs():
			self.analyze_die(die)

	def analyze_die(self, die:DIE):
		print("DIE tag: " + str(die.tag))
		print("    offset: " + str(die.offset))
		print("    size  : " + str(die.size))
		if die.tag == "DW_TAG_variable":
			self.analyze_die_TAG_variable(die)
		elif die.tag == "DW_TAG_base_type":
			self.analyze_die_TAG_base_type(die)
		elif die.tag == "DW_TAG_structure_type":
			self.analyze_die_TAG_structure_type(die)
		elif die.tag == "DW_TAG_union_type":
			self.analyze_die_TAG_union_type(die)
		elif die.tag == "DW_TAG_typedef":
			self.analyze_die_TAG_typedef(die)
		elif die.tag == "DW_TAG_array_type":
			self.analyze_die_TAG_array_type(die)
		else:
			pass

	def analyze_die_TAG_base_type(self, die: DIE):
		# type要素追加
		idx = die.offset
		self._type_tbl[idx] = utilDwarf.type_info()
		type_inf = self._type_tbl[idx]
		type_inf.tag = utilDwarf.type_info.TAG.base
		for at in die.attributes.keys():
			if at == "DW_AT_name":
				type_inf.name = die.attributes[at].value.decode(self._encode)
			if at == "DW_AT_encoding":
				type_inf.encoding = die.attributes[at].value
			if at == "DW_AT_byte_size":
				type_inf.byte_size = die.attributes[at].value

	def analyze_die_TAG_structure_type(self, die: DIE):
		self.analyze_die_TAG_structure_union_type_impl(die, utilDwarf.type_info.TAG.struct)

	def analyze_die_TAG_union_type(self, die: DIE):
		self.analyze_die_TAG_structure_union_type_impl(die, utilDwarf.type_info.TAG.union)

	def analyze_die_TAG_structure_union_type_impl(self, die: DIE, tag: type_info.TAG):
		# type要素追加
		idx = die.offset
		self._type_tbl[idx] = utilDwarf.type_info()
		type_inf = self._type_tbl[idx]
		type_inf.tag = tag
		# Attr取得
		# 情報取得
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]
			if at == "DW_AT_name":
				type_inf.name = attr.value.decode(self._encode)
			elif at == "DW_AT_byte_size":
				type_inf.byte_size = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_decl_file":
				pass
			elif at == "DW_AT_decl_line":
				pass
		# child取得
		if die.has_children:
			self.analyze_die_TAG_structure_union_type_impl_child(die, type_inf)

	def analyze_die_TAG_structure_union_type_impl_child(self, die: DIE, type_inf: type_info):
		for child in die.iter_children():
			if child.tag == "DW_TAG_member":
				type_inf.member.append(utilDwarf.type_info())
				mem_inf = type_inf.member[len(type_inf.member)-1]
				self.analyze_die_TAG_member(child, mem_inf)
			elif child.tag == "DW_TAG_array_type":
				# struct/union/class内で使う型の定義
				# よって, member要素ではない
				self.analyze_die_TAG_array_type(child)
			else:
				# ありえないパス
				print("?: " + child.tag)

	def analyze_die_TAG_member(self, die: DIE, type_inf: type_info):
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]
			if at == "DW_AT_name":
				type_inf.name = attr.value.decode(self._encode)
			elif at == "DW_AT_type":
				type_inf.typedef = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_data_member_location":
				type_inf.member_location = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_byte_size":
				type_inf.byte_size = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_bit_offset":
				type_inf.bit_offset = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_bit_size":
				type_inf.bit_size = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_decl_file":
				pass
			elif at == "DW_AT_decl_line":
				pass
			else:
				print("?: " + at)
		# child check
		if die.has_children:
			pass
		#
		print("    DIE tag   : " + die.tag)
		print("        offset: " + str(die.offset))
		print("        name  : " + type_inf.name)
		print("        type  : " + str(type_inf.typedef))
		print("        memloc: " + str(type_inf.member_location))

	def analyze_die_TAG_array_type(self, die: DIE):
		# type要素追加
		idx = die.offset
		if idx not in self._type_tbl.keys():
			self._type_tbl[idx] = utilDwarf.type_info()
		type_inf = self._type_tbl[idx]
		# tag
		type_inf.tag = utilDwarf.type_info.TAG.array
		# Attr check
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]
			if at == "DW_AT_type":
				type_inf.typedef = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_allocated":
				pass
			elif at == "DW_AT_associated":
				pass
			elif at == "DW_AT_data_location":
				pass
		# child check
		if die.has_children:
			for child in die.iter_children():
				if child.tag == "DW_TAG_subrange_type":
					# Attr check
					for at in child.attributes.keys():
						attr: AttributeValue = child.attributes[at]
						if at == "DW_AT_count":
							type_inf.range = self.analyze_die_AT_FORM(attr.form, attr.value)
				elif child.tag == "DW_TAG_enumeration_type":
					pass
		#
		print("    type  : " + str(type_inf.typedef))
		print("    range : " + str(type_inf.range))


	def analyze_die_TAG_typedef(self, die: DIE):
		# typedef要素追加
		idx = die.offset
		self._typedef_tbl[idx] = utilDwarf.type_info()
		type_inf = self._typedef_tbl[idx]
		# 情報取得
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]
			if at == "DW_AT_name":
				type_inf.name = attr.value.decode(self._encode)
			elif at == "DW_AT_type":
				type_inf.typedef = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_decl_file":
				pass
			elif at == "DW_AT_decl_line":
				pass
		print("    name  : " + type_inf.name)
		print("    type  : " + str(type_inf.typedef))


	def analyze_die_TAG_variable(self, die:DIE):
		#print("analyze: TAG_variable")
		var_ref: utilDwarf.var_info = None
		if "DW_AT_external" in die.attributes.keys():
			# グローバル変数
			self._global_var_tbl.append(utilDwarf.var_info())
			var_ref = self._global_var_tbl[len(self._global_var_tbl)-1]
		else:
			# ローカル変数
			return
		#
		for at in die.attributes.keys():
			if at == "DW_AT_external":
				pass
			elif at == "DW_AT_name":
				var_ref.name = die.attributes[at].value.decode(self._encode)
			elif at == "DW_AT_decl_file":
				pass
			elif at == "DW_AT_decl_line":
				pass
			elif at == "DW_AT_type":
				var_ref.type = die.attributes[at].value
			elif at == "DW_AT_location":
				var_ref.addr = self.analyze_die_AT_location(die.attributes[at])
		#
		print("    name  : " + var_ref.name)
		print("    type  : " + str(var_ref.type))
		print("    loca  : " + str(var_ref.addr))

	def analyze_die_AT_location(self, attr: AttributeValue):
		# location解析
		return self.analyze_die_AT_FORM(attr.form, attr.value)

	def analyze_die_AT_FORM(self, form: str, value: any):
		if form == "DW_FORM_ref_addr":
			return value
		if form == "DW_FORM_udata":
			return value
		if form == "DW_FORM_data1":
			return value
		if form == "DW_FORM_block1":
			val_len = (1 + value[0]) + 1
			ary_len = len(value)
			if val_len > ary_len:
				val_len = ary_len
			data = bytearray(value[1:val_len])
			return int.from_bytes(data, "little")
		#
		print("Unknown DW_FORM detected: " + form)
		return None


	def make_memmap(self) -> None:
		# メモリマップ初期化
		self._memmap = []
		# グローバル変数をすべてチェック
		for var in self._global_var_tbl:
			# 型情報取得
			t_inf: utilDwarf.type_info
			t_inf = self.get_type_info(var.type)
			#
			self.make_memmap_impl(var, t_inf)


	def make_memmap_impl(self, var: var_info, t_inf: type_info) -> None:
		# typeチェック
		if t_inf.tag == utilDwarf.type_info.TAG.base:
			self.make_memmap_var_base(var, t_inf)
		elif t_inf.tag == utilDwarf.type_info.TAG.array:
			self.make_memmap_var_array(var, t_inf)
		elif t_inf.tag == utilDwarf.type_info.TAG.struct:
			self.make_memmap_var_struct(var, t_inf)
		elif t_inf.tag == utilDwarf.type_info.TAG.union:
			self.make_memmap_var_struct(var, t_inf)
		else:
			raise Exception("unknown variable type detected.")

	def make_memmap_var_base(self, var: var_info, t_inf: type_info):
		# 変数情報作成
		mem_var = memmap.var_type()
		mem_var.tag = memmap.var_type.TAG.base		# 変数タイプタグ
		mem_var.address = var.addr					# 配置アドレス
		mem_var.name = var.name						# 変数名
		# 型情報作成
		mem_var.byte_size = t_inf.byte_size			# 宣言型サイズ
		# 変数情報登録
		self._memmap.append(mem_var)

	def make_memmap_var_array(self, var: var_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.array		# 変数タイプタグ
		memmap_var.address = var.addr					# 配置アドレス
		memmap_var.name = var.name						# 変数名
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size			# 宣言型サイズ
		memmap_var.array_size = t_inf.range				# 配列要素数
		# 変数情報登録
		self._memmap.append(memmap_var)

		# 配列の各idxを個別にmemberとして登録
		member_t_inf = self.get_type_info(t_inf.typedef)
		for idx in range(0, memmap_var.array_size):
			# 再帰処理開始
			self.make_memmap_var_array_each(memmap_var, member_t_inf, idx)

	def make_memmap_var_array_each(self, parent: memmap.var_type, mem_inf: type_info, idx: int):
		# typeチェック
		if mem_inf.tag == utilDwarf.type_info.TAG.base:
			self.make_memmap_var_array_each_base(parent, mem_inf, idx)
		elif mem_inf.tag == utilDwarf.type_info.TAG.array:
			self.make_memmap_var_array_each_array(parent, mem_inf, idx)
		elif mem_inf.tag == utilDwarf.type_info.TAG.struct:
			self.make_memmap_var_array_each_struct(parent, mem_inf, idx)
		elif mem_inf.tag == utilDwarf.type_info.TAG.union:
			self.make_memmap_var_array_each_struct(parent, mem_inf, idx)
		else:
			raise Exception("unknown variable type detected.")

	def make_memmap_var_array_each_base(self, parent: memmap.var_type, mem_inf: type_info, idx: int):
		# 配列要素[idx]を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = parent.tag
		memmap_var.address = parent.address + (mem_inf.byte_size * idx)
		memmap_var.name = "[" + str(idx) + "]"
		memmap_var.byte_size = mem_inf.byte_size
		# 変数情報登録
		parent.member.append(memmap_var)

	def make_memmap_var_array_each_array(self, parent: memmap.var_type, mem_inf: type_info, idx: int):
		# 配列要素[idx]を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = parent.tag
		memmap_var.address = parent.address + (mem_inf.byte_size * idx)
		memmap_var.name = "[" + str(idx) + "]"
		memmap_var.byte_size = mem_inf.byte_size
		memmap_var.array_size = mem_inf.range
		# 変数情報登録
		parent.member.append(memmap_var)

		# 配列の各idxを個別にmemberとして登録
		for child_idx in range(0, memmap_var.array_size):
			# 再帰処理開始
			self.make_memmap_var_array_each(memmap_var, mem_inf, child_idx)

	def make_memmap_var_array_each_struct(self, parent: memmap.var_type, mem_inf: type_info, idx: int):
		# 配列要素[idx]を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = parent.tag
		memmap_var.address = parent.address + (mem_inf.byte_size * idx)
		memmap_var.name = "[" + str(idx) + "]"
		memmap_var.byte_size = mem_inf.byte_size
		# 変数情報登録
		parent.member.append(memmap_var)

		# メンバ変数を登録
		for member_t_inf in mem_inf.member:
			# 再帰処理開始
			self.make_memmap_var_member(memmap_var, member_t_inf)

	def make_memmap_var_struct(self, var: var_info, t_inf: type_info):
		# 構造体変数を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.struct		# 変数タイプタグ
		memmap_var.address = var.addr					# 配置アドレス
		memmap_var.name = var.name						# 変数名
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size			# 宣言型サイズ
		# 変数情報登録
		self._memmap.append(memmap_var)

		# メンバ変数を登録
		for member_t_inf in t_inf.member:
			# 再帰処理開始
			self.make_memmap_var_member(memmap_var, member_t_inf)

	def make_memmap_var_member(self, parent: memmap.var_type, mem_inf: type_info):
		# member型情報を取得
		mem_t_inf = self.get_type_info(mem_inf.typedef)
		# typeチェック
		if mem_t_inf.tag == utilDwarf.type_info.TAG.base:
			self.make_memmap_var_member_base(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.array:
			self.make_memmap_var_member_array(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.struct:
			self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.union:
			self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
		else:
			raise Exception("unknown variable type detected.")

	def make_memmap_var_member_base(self, parent: memmap.var_type, member_inf: type_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.base								# 変数タイプタグ
		memmap_var.address = parent.address + member_inf.member_location		# アドレス
		memmap_var.address_offset = member_inf.member_location					# アドレスオフセット
		memmap_var.name = member_inf.name										# メンバ名
		if member_inf.bit_size is not None:
			memmap_var.bit_size = member_inf.bit_size							# ビットサイズ
			memmap_var.bit_offset = member_inf.bit_offset						# ビットオフセット
			# member_inf.member_inf  # ビットフィールドのみ存在? パディングを含むバイト単位サイズ, バイト境界をまたぐ(bit7-8とか)と2バイトになる
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		# 変数情報登録
		parent.member.append(memmap_var)

	def make_memmap_var_member_array(self, parent: memmap.var_type, member_inf: type_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.array								# 変数タイプタグ
		memmap_var.address = parent.address + member_inf.member_location		# アドレス
		memmap_var.address_offset = member_inf.member_location					# アドレスオフセット
		memmap_var.name = member_inf.name										# メンバ名
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		memmap_var.array_size = t_inf.range										# 配列要素数
		# 変数情報登録
		parent.member.append(memmap_var)

		# 配列の各idxを個別にmemberとして登録
		member_t_inf = self.get_type_info(t_inf.typedef)
		for idx in range(0, memmap_var.array_size):
			# 再帰処理開始
			self.make_memmap_var_array_each(memmap_var, member_t_inf, idx)

	def make_memmap_var_member_struct(self, parent: memmap.var_type, member_inf: type_info, t_inf: type_info):
		# 構造体変数を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.struct								# 変数タイプタグ
		memmap_var.address = parent.address + member_inf.member_location		# アドレス
		memmap_var.address_offset = member_inf.member_location					# アドレスオフセット
		memmap_var.name = member_inf.name										# メンバ名
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		# 変数情報登録
		parent.member.append(memmap_var)

		# メンバ変数を登録
		for member_t_inf in t_inf.member:
			# 再帰処理開始
			self.make_memmap_var_member(memmap_var, member_t_inf)



	def get_type_info(self, type:int) -> type_info:
		# typedef チェック
		while type in self._typedef_tbl.keys():
			type = self._typedef_tbl[type].typedef
		# type 取得
		if type not in self._type_tbl.keys():
			# ありえないはず
			raise Exception("undetected type appeared.")
		return self._type_tbl[type]

