from os import O_NOINHERIT
import pathlib
import enum
import copy
from typing import Container, List, Dict, Tuple, Any
from elftools.elf.elffile import ELFFile
#from elftools.dwarf.structs import DWARFStructs
from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import AttributeValue, DIE
from elftools.dwarf.lineprogram import (LineProgram, LineProgramEntry)
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.callframe import (RegisterRule, CFARule)
#from elftools.common.construct_utils import ULEB128
from elftools.construct.lib.container import Container as elftools_container

from .memmap import memmap


class ULEB128:
	"""
	unsigned LEB128
	"""

	def __init__(self, values: List[int]) -> None:
		"""
		@value 1バイトデータ列
		"""
		# 初期化
		self.value = 0
		# 解析
		for n_th, value in enumerate(values):
			# 7bit目(0開始)をチェック
			# bit演算より四則演算の方が速いらしい
			if value / 0x80 >= 1:
				self.value += (value % 0x80) * (2 ** (7 * (n_th)))
			else:
				self.value += value * (2 ** (7 * (n_th)))


class DWARF_expression:

	@staticmethod
	def DW_OP_plus_uconst(value):
		return ULEB128(value).value


DW_OP = {
	0x23: DWARF_expression.DW_OP_plus_uconst
}



class utilDwarf:

	class entry:
		"""
		Dwarf形式は"Entry"の集合と定義する
		そのEntryの定義クラス
		"""

		def __init__(self, label: str, size: int) -> None:
			# DW_TAG_*, DW_ATTR_*
			self.label = label
			self.size = size

			# DW_AT_name
			self.name = None
			# 
			self.compile_dir = None
			# DW_AT_external
			self.external = None
			# DW_AT_decl_file
			self.decl_file = None
			# DW_AT_decl_line
			self.decl_line = None
			# DW_AT_type
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

	class cu_info:

		class file_entry:
			def __init__(self) -> None:
				self.dir_path = None
				self.filename = None
				self.proj_rel_path = None

		def __init__(self) -> None:
			self.compile_dir = ""
			self.filename = ""
			self.debug_abbrev_offset = None
			self.unit_length = None
			self.address_size = None
			# 0 は「ファイル無し」定義なのでNoneを詰めておく
			self.file_list: List[utilDwarf.cu_info.file_entry] = []
			self.include_dir_list: List[str] = []

	class var_info:
		def __init__(self) -> None:
			self.name = None
			self.type = None
			self.addr = None
			self.loclistptr = None
			self.decl_file = utilDwarf.cu_info.file_entry()
			self.decl_line = None
			self.not_declaration = None		# declarationなし. 不完全型等
			self.extern = None				# 外部結合, extern宣言
			self.external_file = None		# ファイル外定義(cファイル以外、hファイル等で定義)
			self.const_value = None

	class func_info:
		def __init__(self) -> None:
			self.name = None
			self.return_type = None
			self.addr = None
			self.params = []

	class type_info:
		class TAG(enum.Enum):
			base = enum.auto()			# primitive type
			array = enum.auto()			# array
			struct = enum.auto()		# struct
			union = enum.auto()			# union
			func = enum.auto()			# function type
			parameter = enum.auto()		# parameter
			typedef = enum.auto()		# typedef
			const = enum.auto()			# const
			volatile = enum.auto()		# volatile
			pointer = enum.auto()		# pointer
			restrict = enum.auto()		# restrict

		def __init__(self) -> None:
			self.tag = None
			self.name = None
			self.byte_size = None
			self.bit_size = None
			self.bit_offset = None
			self.address_class = None
			self.encoding = None
			self.member = []
			self.member_location = None
			self.child_type = None
			self.result_type = None
			self.range = None
			self.prototyped = None
			self.const = None
			self.pointer = None
			self.restrict = None
			self.volatile = None
			self.params = []
			self.decl_file = utilDwarf.cu_info.file_entry()
			self.decl_line = None

	def __init__(self, path: pathlib.Path, encoding:str = 'utf-8'):
		# 文字コード
		self._encoding = encoding
		self._arch = None
		# データコンテナ初期化
		# DwarfDebugInfoEntryとAddressの対応付けマップ
		# 基本情報をすべてここに集める
		self._entry_map: Dict[int, utilDwarf.entry] = {}
		# 以下は必要なスコープでデータ整形したコンテナ
		self._global_var_tbl: List[utilDwarf.var_info] = []
		self._func_tbl: List[utilDwarf.func_info] = []
		self._type_tbl: Dict[int, utilDwarf.type_info] = {}
		self._addr_cls: Dict[int, List[utilDwarf.type_info]] = {}
		self._memmap: List[memmap] = []
		# elfファイルを開く
		self._path = path
		self._open()
		# debug情報
		self._debug_warning = False

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

	def add_entry(self, addr: int, label: str, size: int) -> entry:
		# DwarfAddresMap更新
		if addr not in self._entry_map.keys():
			self._entry_map[addr] = utilDwarf.entry(label, size)
		else:
			if self._debug_warning:
				print(f"Detect Duplicate: addr={addr}, label={label}")
		#
		return self._entry_map[addr]

	def get_entry(self, addr: int) -> entry:
		# DwarfAddres Entry取得
		if addr not in self._entry_map.keys():
			return self.add_entry(addr, None)
		else:
			return self._entry_map[addr]


	def analyze(self):
		cu: CompileUnit
		for cu in self._dwarf_info.iter_CUs():
			self.analyze_cu(cu)

	def analyze_cu(self, cu:CompileUnit):
		# CompileUnit情報を取得
		self._cu_info = utilDwarf.cu_info()
		# CompileUnit=fileなので(?)、ファイル名、パスを取得
		top_die = cu.get_top_DIE()
		# コンパイル時ディレクトリ情報を取得
		if "DW_AT_comp_dir" in top_die.attributes.keys():
			self._cu_info.compile_dir = top_die.attributes["DW_AT_comp_dir"].value.decode(self._encoding)
		else:
			self._cu_info.compile_dir = "."
		# ファイル名取得
		if "DW_AT_name" in top_die.attributes.keys():
			self._cu_info.filename = top_die.attributes["DW_AT_name"].value.decode(self._encoding)
		else:
			self._cu_info.filename = ""
		# ファイル情報
		if self._debug_warning:
			print("CU file: " + self._cu_info.compile_dir + "\\" + self._cu_info.filename)

		# CompileUnitヘッダ解析
		self._cu_info.address_size = cu.header['address_size']
		self._cu_info.debug_abbrev_offset = cu.header['debug_abbrev_offset']
		self._cu_info.unit_length = cu.header['unit_length']
		# debug comment
#		print("    address_size       : " + str(self._curr_cu_info.address_size))
#		print("    debug_abbrev_offset: " + str(self._curr_cu_info.debug_abbrev_offset))
#		print("    unit_length        : " + str(self._curr_cu_info.unit_length))

		# file_entryは 0:存在しない になるので、Noneを入れておく
		self._cu_info.file_list.append(None)
		# include_directory は 0:カレントディレクトリ？ になるので、
		# DW_AT_comp_dirを入れておく
		self._cu_info.include_dir_list.append(self._cu_info.compile_dir)
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
			self._cu_info.include_dir_list.append(path.decode(self._encoding))
		# file_entry
		for entry in line.header.file_entry:
			entry: elftools_container
			file = utilDwarf.cu_info.file_entry()
			# name
			file.filename = entry.name.decode(self._encoding)
			# dir_index
			idx = entry.dir_index
			file.dir_path = self._cu_info.include_dir_list[idx]
			# DW_AT_comp_dirからの相対パス
			fpath = pathlib.Path(file.dir_path) / file.filename
			# システムインクルードパスは相対パス設定なしとする
			try:
				file.proj_rel_path = str(fpath.relative_to(self._cu_info.compile_dir))
			except:
				file.proj_rel_path = None
			# file_entry登録
			self._cu_info.file_list.append(file)
		# line program entry
		"""
		for entry in line.get_entries():
			if not entry.state or entry.state.file == 0:
				# entryが空、または、ファイルがない
				continue
			file_no = entry.state.file
		"""

	def analyze_die(self, die: DIE):
		# debug comment
#		print("DIE tag: " + str(die.tag))
#		print("    offset: " + str(die.offset))
#		print("    size  : " + str(die.size))

		# entry生成
		entry = self.add_entry(die.offset, die.tag, die.size)

		if die.tag == "DW_TAG_compile_unit":
			self.analyze_die_TAG_compile_unit(die, entry)

		elif die.tag == "DW_TAG_dwarf_procedure":
			if self._debug_warning:
				print("DW_TAG_dwarf_procedure tag.")

		# 変数定義
		elif die.tag == "DW_TAG_variable":
			self.analyze_die_TAG_variable(die, entry)


		elif die.tag == "DW_TAG_constant":
			if self._debug_warning:
				print("DW_TAG_constant.")

		# 関数定義
		elif die.tag == "DW_TAG_subprogram":
			self.analyze_die_TAG_subprogram(die)

		# 型情報
		elif die.tag == "DW_TAG_base_type":
			self.analyze_die_TAG_base_type(die, entry)
		elif die.tag == "DW_TAG_structure_type":
			self.analyze_die_TAG_structure_type(die, entry)
		elif die.tag == "DW_TAG_union_type":
			self.analyze_die_TAG_union_type(die, entry)
		elif die.tag == "DW_TAG_typedef":
			self.analyze_die_TAG_typedef(die, entry)
		elif die.tag == "DW_TAG_array_type":
			self.analyze_die_TAG_array_type(die, entry)
		elif die.tag == "DW_TAG_subroutine_type":
			self.analyze_die_TAG_subroutine_type(die, entry)
		elif die.tag == "DW_TAG_inlined_subroutine":
			print("DW_TAG_inlined_subroutine tag.")
		elif die.tag == "DW_TAG_member":
			#print("DW_TAG_member tag.")
			#self.analyze_die_TAG_member(die)
			# おそらく全部重複
			pass
		elif die.tag == "DW_TAG_subrange_type":
			#print("DW_TAG_subrange_type tag.")
			# おそらく全部重複
			pass
		elif die.tag == "DW_TAG_formal_parameter":
			#print("DW_TAG_formal_parameter tag.")
			# おそらく全部重複
			pass

		# type-qualifier
		elif die.tag == "DW_TAG_const_type":
			self.analyze_die_TAG_type_qualifier(die, entry, utilDwarf.type_info.TAG.const)
		elif die.tag == "DW_TAG_pointer_type":
			self.analyze_die_TAG_type_qualifier(die, entry, utilDwarf.type_info.TAG.pointer)
		elif die.tag == "DW_TAG_restrict_type":
			self.analyze_die_TAG_type_qualifier(die, entry, utilDwarf.type_info.TAG.restrict)
		elif die.tag == "DW_TAG_volatile_type":
			self.analyze_die_TAG_type_qualifier(die, entry, utilDwarf.type_info.TAG.volatile)
		elif die.tag == {"DW_TAG_packed_type", "DW_TAG_reference_type", "DW_TAG_shared_type"}:
			pass

		elif die.tag == "DW_TAG_unspecified_type":
			if self._debug_warning:
				print("DW_TAG_unspecified_type tag.")

		else:
			if die.tag is not None:
				if self._debug_warning:
					print("unimplemented tag: " + die.tag)

	"""
	DW_AT_* 解析
	"""
	def analyze_die_AT(self, attr: AttributeValue) -> entry:
		# entry生成
		entry = self.add_entry(attr.offset, attr.name, 0)
		# AT解析
		match attr.name:
			case "DW_AT_external":
				entry.external = self.analyze_die_AT_FORM(attr.form, attr.value)
			
			case "DW_AT_name":
				entry.name = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_decl_file":
				entry.decl_file = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_decl_line":
				entry.decl_line = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_type":
				entry.type = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_location":
				self.analyze_die_AT_location(attr, entry)

			case "DW_AT_declaration":
				entry.declaration = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_const_value":
				entry.const_value = attr.value

			case "DW_AT_address_class":
				entry.address_class = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_prototyped":
				entry.prototyped = attr.value

			case "DW_AT_encoding":
				entry.encoding = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_byte_size":
				entry.byte_size = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_data_member_location":
				entry.data_member_location = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_bit_offset":
				entry.bit_offset = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_bit_size":
				entry.bit_size = self.analyze_die_AT_FORM(attr.form, attr.value)

			case "DW_AT_count":
				entry.count = self.analyze_die_AT_FORM(attr.form, attr.value)

			case _:
				print("unimplemented AT: " + attr.name)
		# 
		return entry

	"""
	DW_TAG_* 解析
	"""
	def analyze_die_TAG_compile_unit(self, die: DIE, parent: entry):
		"""
		DW_TAG_compile_unit
		"""
		# DW_AT_* 取得
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]

			# entry生成
			entry = self.add_entry(attr.offset, attr.name, 0)

			# 初期化
			parent.name = ""
			parent.compile_dir = "."
			entry.name = ""
			entry.compile_dir = "."

			# Attribute解析
			match at:
				case "DW_AT_name":
					entry.name = attr.value.decode(self._encoding)
					parent.name = entry.name

				case "DW_AT_comp_dir":
					entry.compile_dir = attr.value.decode(self._encoding)
					parent.compile_dir = entry.compile_dir

				case _:
					if self._debug_warning:
						print("unknown attribute detected: " + at)



	def analyze_die_TAG_base_type(self, die: DIE, parent: entry):
		"""
		DW_TAG_base_type
		"""
		# type_info取得
		type_inf = self.new_type_info(die.offset, utilDwarf.type_info.TAG.base)
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_encoding":
				type_inf.encoding = entry.encoding
				parent.encoding = entry.encoding
			elif at == "DW_AT_byte_size":
				type_inf.byte_size = entry.byte_size
				parent.byte_size = entry.byte_size
			else:
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
				DW_AT_sibling
				DW_AT_small
				"""
				if self._debug_warning:
					print("base_type:?:" + at)
		# child check
		if die.has_children:
			child: DIE
			for child in die.iter_children():
				if self._debug_warning:
					print("unproc child.")

	def analyze_die_TAG_structure_type(self, die: DIE, parent: entry):
		"""
		DW_TAG_structure_type
		"""
		self.analyze_die_TAG_structure_union_type_impl(die, parent, utilDwarf.type_info.TAG.struct)

	def analyze_die_TAG_union_type(self, die: DIE, parent: entry):
		"""
		DW_TAG_union_type
		"""
		self.analyze_die_TAG_structure_union_type_impl(die, parent, utilDwarf.type_info.TAG.union)

	def analyze_die_TAG_structure_union_type_impl(self, die: DIE, parent: entry, tag: type_info.TAG):
		# type_info取得
		type_inf = self.new_type_info(die.offset, tag)
		# Attr取得
		# 情報取得
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_byte_size":
				type_inf.byte_size = entry.byte_size
				parent.byte_size = entry.byte_size
			elif at == "DW_AT_decl_file":
				file_no = entry.decl_file
				type_inf.decl_file = self._cu_info.file_list[file_no]
				parent.decl_file = entry.decl_file
			elif at == "DW_AT_decl_line":
				type_inf.decl_line = entry.decl_line
				parent.decl_line = entry.decl_line
			else:
				"""
				DECL
				DW_AT_abstract_origin
				DW_AT_accessibility
				DW_AT_allocated
				DW_AT_associated
				DW_AT_data_location
				DW_AT_declaration
				DW_AT_description
				DW_AT_sibling
				DW_AT_specification
				DW_AT_start_scope
				DW_AT_visibility
				"""
				if self._debug_warning:
					print("struct/union:?:" + at)
		# child取得
		if die.has_children:
			self.analyze_die_TAG_structure_union_type_impl_child(die, type_inf)

	def analyze_die_TAG_structure_union_type_impl_child(self, die: DIE, type_inf: type_info):
		child: DIE
		for child in die.iter_children():
			# entry生成
			entry = self.add_entry(child.offset, child.tag, child.size)

			if child.tag == "DW_TAG_member":
				#type_inf.member.append(utilDwarf.type_info())
				#mem_inf = type_inf.member[len(type_inf.member)-1]
				#self.analyze_die_TAG_member(child, mem_inf)
				mem_inf = self.analyze_die_TAG_member(child, entry)
				type_inf.member.append(mem_inf)
			elif child.tag == "DW_TAG_array_type":
				# struct/union/class内で使う型の定義
				# よって, member要素ではない
				self.analyze_die_TAG_array_type(child, entry)
			else:
				# ありえないパス
				if self._debug_warning:
					print("?: " + child.tag)

	def analyze_die_TAG_member(self, die: DIE, parent: entry) -> type_info:
		"""
		DW_TAG_member
		"""
		# type_info取得
		type_inf = self.new_type_info(die.offset, None)

		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_type":
				type_inf.child_type = entry.type
				parent.type = entry.type
			elif at == "DW_AT_data_member_location":
				type_inf.member_location = entry.data_member_location
				parent.data_member_location = entry.data_member_location
			elif at == "DW_AT_byte_size":
				type_inf.byte_size = entry.byte_size
				parent.byte_size = entry.byte_size
			elif at == "DW_AT_bit_offset":
				type_inf.bit_offset = entry.bit_offset
				parent.bit_offset = entry.bit_offset
			elif at == "DW_AT_bit_size":
				type_inf.bit_size = entry.bit_size
				parent.bit_size = entry.bit_size
			elif at == "DW_AT_decl_file":
				file_no = entry.decl_file
				type_inf.decl_file = self._cu_info.file_list[file_no]
				parent.decl_file = entry.decl_file
			elif at == "DW_AT_decl_line":
				type_inf.decl_line = entry.decl_line
				parent.decl_line = entry.decl_line
			else:
				"""
				DECL
				DW_AT_accessibility
				DW_AT_declaration
				DW_AT_description
				DW_AT_mutable
				DW_AT_sibling
				DW_AT_visibility
				"""
				if self._debug_warning:
					print("unknown attribute detected: " + at)
		# child check
		if die.has_children:
			for child in die.iter_children():
				pass
		# debug comment
#		print("    DIE tag   : " + die.tag)
#		print("        offset: " + str(die.offset))
#		print("        name  : " + type_inf.name)
#		print("        type  : " + str(type_inf.typedef))
#		print("        memloc: " + str(type_inf.member_location))
		return type_inf

	def analyze_die_TAG_array_type(self, die: DIE, parent: entry):
		"""
		DW_TAG_array_type
		"""
		# type_info取得
		type_inf = self.new_type_info(die.offset, utilDwarf.type_info.TAG.array)
		# Attr check
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_type":
				type_inf.child_type = entry.type
				parent.type = entry.type
			elif at == "DW_AT_allocated":
				pass
			elif at == "DW_AT_associated":
				pass
			elif at == "DW_AT_data_location":
				pass
			else:
				"""
				DECL
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
				DW_AT_sibling
				DW_AT_specification 
				DW_AT_start_scope
				DW_AT_visibility
				"""
				if self._debug_warning:
					print("array:?:" + at)
		# child check
		if die.has_children:
			for child in die.iter_children():
				if child.tag == "DW_TAG_subrange_type":
					# Attr check
					for at in child.attributes.keys():
						# Attribute Entry生成
						entry = self.analyze_die_AT(child.attributes[at])

						if at == "DW_AT_count":
							type_inf.range = entry.count
				elif child.tag == "DW_TAG_enumeration_type":
					pass
		# debug comment
#		print("    type  : " + str(type_inf.typedef))
#		print("    range : " + str(type_inf.range))


	def analyze_die_TAG_subroutine_type(self, die: DIE, parent: entry):
		# type_info取得
		type_inf = self.new_type_info(die.offset, utilDwarf.type_info.TAG.func)
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_type":
				# 返り値型
				type_inf.result_type = entry.type
				parent.type = entry.type
			elif at == "DW_AT_prototyped":
				type_inf.prototyped = entry.prototyped
				parent.prototyped = entry.prototyped
			else:
				if self._debug_warning:
					print("subroutine_type:?:" + at)
		# child check
		if die.has_children:
			child: DIE
			for child in die.iter_children():
				param_inf = self.analyze_parameter(child)
				type_inf.params.append(param_inf)

	def analyze_parameter(self, die:DIE) -> type_info:
		if die.tag == "DW_TAG_formal_parameter":
			return self.analyze_die_TAG_formal_parameter(die)
		elif die.tag == "DW_TAG_unspecified_parameters":
			return None


	def analyze_die_TAG_formal_parameter(self, param: DIE) -> type_info:
		# type要素追加
		param_inf = utilDwarf.type_info()
		param_inf.tag = utilDwarf.type_info.TAG.parameter
		# 引数情報をtype_infoに格納
		for attr in param.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(param.attributes[attr])

			if attr == "DW_AT_type":
				param_inf.child_type = entry.type
		# 
		return param_inf


	def analyze_die_TAG_type_qualifier(self, die: DIE, parent: entry, tag: type_info.TAG):
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
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_type":
				type_inf.child_type = entry.type
				parent.type = entry.type
			elif at == "DW_AT_address_class":
				type_inf.address_class = entry.address_class
				self.register_address_class(type_inf)
				parent.address_class = entry.address_class
			elif at == "DW_AT_count":
				pass
			else:
				"""
				DW_AT_allocated
				DW_AT_associated
				DW_AT_data_location
				DW_AT_sibling
				"""
				if self._debug_warning:
					print("unknown attr: " + at)
		# child check
		if die.has_children:
			child: DIE
			for child in die.iter_children():
				if self._debug_warning:
					print("unproc child.")
		# debug comment
#		print("    name  : " + type_inf.name)
#		print("    type  : " + str(type_inf.typedef))

	def analyze_die_TAG_typedef(self, die: DIE, parent: entry):
		"""
		DW_TAG_typedef
		"""
		# type_info取得
		type_inf = self.new_type_info(die.offset, utilDwarf.type_info.TAG.typedef)
		# 情報取得
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_name":
				type_inf.name = entry.name
				parent.name = entry.name
			elif at == "DW_AT_type":
				type_inf.child_type = entry.type
				parent.type = entry.type
			elif at == "DW_AT_decl_file":
				file_no = entry.decl_file
				parent.decl_file = entry.decl_file
				type_inf.decl_file = self._cu_info.file_list[file_no]
			elif at == "DW_AT_decl_line":
				type_inf.decl_line = entry.decl_line
				parent.decl_line = entry.decl_line
			else:
				"""
				DECL
				DW_AT_abstract_origin
				DW_AT_accessibility
				DW_AT_allocated
				DW_AT_associated
				DW_AT_data_location
				DW_AT_declaration
				DW_AT_description
				DW_AT_sibling
				DW_AT_start_scope
				DW_AT_visibility
				"""
				if self._debug_warning:
					print("typedef:?:" + at)
		# child check
		if die.has_children:
			child: DIE
			for child in die.iter_children():
				if self._debug_warning:
					print("unproc child.")
		# debug comment
#		print("    name  : " + type_inf.name)
#		print("    type  : " + str(type_inf.typedef))

	def new_type_info(self, addr: int, tag: type_info.TAG) -> type_info:
		# addr: Dwarf内でのアドレス
		# 必要ならノード作成
		if addr not in self._type_tbl.keys():
			self._type_tbl[addr] = utilDwarf.type_info()
		else:
			# print("duplicate!")
			pass
		# 型情報インスタンスへの参照取得
		type_inf = self._type_tbl[addr]
		# 型情報更新
		type_inf.tag = tag

		return type_inf

	def analyze_die_TAG_variable(self, die:DIE, parent: entry):
		"""
		DW_TAG_variable
		"""
		var = utilDwarf.var_info()
		# AT解析
		for at in die.attributes.keys():
			# Attribute Entry生成
			entry = self.analyze_die_AT(die.attributes[at])

			if at == "DW_AT_external":
				parent.external = entry.external
				var.extern = entry.external
			elif at == "DW_AT_name":
				parent.name = entry.name
				var.name = entry.name
			elif at == "DW_AT_decl_file":
				parent.decl_file = entry.decl_file
				# ファイル情報取得
				var.decl_file = self._cu_info.file_list[entry.decl_file]
				# ファイルが現在解析中のものでない
				if entry.decl_file != 1:
					var.external_file = True
			elif at == "DW_AT_decl_line":
				parent.decl_line = entry.decl_line
				var.decl_line = entry.decl_line
			elif at == "DW_AT_type":
				parent.type = entry.type
				var.type = entry.type
			elif at == "DW_AT_location":
				parent.location = entry.location
				parent.loclistptr = entry.loclistptr
				var.addr = entry.location
				var.loclistptr = entry.loclistptr
			elif at == "DW_AT_declaration":
				parent.declaration = entry.declaration
				var.not_declaration = entry.declaration
			elif at == "DW_AT_const_value":
				parent.const_value = entry.const_value
				var.const_value = entry.const_value
			else:
				"""
				DECL
				DW_AT_abstract_origin
				DW_AT_accessibility
				DW_AT_description
				DW_AT_endianity
				DW_AT_segment
				DW_AT_sibling
				DW_AT_specification
				DW_AT_start_scope
				DW_AT_visibility
				"""
				if self._debug_warning:
					print("variable:?:" + at)
		# child check
		if die.has_children:
			child: DIE
			for child in die.iter_children():
				if self._debug_warning:
					print("unproc child.")
		# 変数登録
		if var.addr is not None:
			# アドレスを持っているとき
			# グローバル変数
			self._global_var_tbl.append(var)
		else:
			# アドレスを持たない
			# ローカル変数, 定数, etc
			pass
		# debug comment
#		print("    name  : " + var_ref.name)
#		print("    type  : " + str(var_ref.type))
#		print("    loca  : " + str(var_ref.addr))

	def analyze_die_AT_location(self, attr: AttributeValue, entry: entry):
		"""
		DW_AT_location
		"""
		# 2.6 Location Descriptions
		value = self.analyze_die_AT_FORM(attr.form, attr.value)
		if attr.form.startswith('DW_FORM_block'):
			# Simple location descriptions
			# DW_FORM_block1, DW_FORM_block2, DW_FORM_block4, DW_FORM_block
			entry.location = value
		elif attr.form in ('DW_FORM_data4', 'DW_FORM_data8'):
			# Location lists
			entry.loclistptr = value
		else:
			raise Exception("unimplemented AT_localtion form: " + attr.form)


	def analyze_die_TAG_subprogram(self, die: DIE):
		f_inf: utilDwarf.func_info = None
		if "DW_AT_external" in die.attributes.keys():
			# 関数
			self._func_tbl.append(utilDwarf.func_info())
			f_inf = self._func_tbl[len(self._func_tbl)-1]
		else:
			# ？
			return
		# AT取得
		call_convention = 1		# デフォルトがDW_CC_normal
		for at in die.attributes.keys():
			attr: AttributeValue = die.attributes[at]
			if at == "DW_AT_external":
				pass
			elif at == "DW_AT_name":
				f_inf.name = die.attributes[at].value.decode(self._encoding)
			elif at == "DW_AT_type":
				f_inf.return_type = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_calling_convention":
				call_convention = die.attributes[at].value
			elif at == "DW_AT_decl_file":
				file_no = self.analyze_die_AT_FORM(attr.form, attr.value)
				f_inf.decl_file = self._cu_info.file_list[file_no]
			elif at == "DW_AT_decl_line":
				f_inf.decl_line = self.analyze_die_AT_FORM(attr.form, attr.value)
			elif at == "DW_AT_low_pc":
				pass
			elif at == "DW_AT_high_pc":
				pass
			elif at == "DW_AT_frame_base":
				pass
			elif at == "DW_AT_return_addr":
				pass
			else:
				if self._debug_warning:
					print("subprogram:?:" + at)
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
				


	def analyze_die_AT_FORM(self, form: str, value: any):
		if form == "DW_FORM_ref_addr":
			return value
		elif form == "DW_FORM_flag":
			return value
		elif form == "DW_FORM_string":
			return value.decode(self._encoding)
		elif form == "DW_FORM_udata":
			return value
		elif form == "DW_FORM_data1":
			return value
		elif form == "DW_FORM_data2":
			return value
		elif form == "DW_FORM_data4":
			return value
		elif form == "DW_FORM_block1":
			result = None
			length = (1 + value[0]) + 1
			if len(value) == length:
				# length byte と valueの要素数が一致するとき、block1として解釈
				result = int.from_bytes(bytearray(value[1:length]), "little")
			else:
				# 上記以外のとき、DWARF expression として解釈
				result = self.analyze_dwarf_expr(value)
			return result
		elif form == "DW_FORM_block":
			return ULEB128(value).value
		else:
			# 未実装多し
			raise Exception("Unknown DW_FORM detected: " + form)


	def analyze_dwarf_expr(self, value):
		# operation code
		code = value[0]
		# expression
		if code in DW_OP.keys():
			return DW_OP[code](value[1:])
		else:
			raise Exception("unimplemented DWARF expression: code" + f"0x{code:02X}")


	def register_address_class(self, t_inf: type_info):
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
		"""
		# Address Class Definition
		address_class_list = {
			# RL78
			'Renesas RL78' : {
				3: 4,			# 3 -> 4byte
				4: 2,			# 4 -> 2byte
			}
		}
		# Address Class 決定
		address_class = address_class_list[self._arch]
		# byte_size 設定
		for key in self._addr_cls.keys():
			for t_inf in self._addr_cls[key]:
				t_inf.byte_size = address_class[key]


	def make_memmap(self) -> None:
		# address_class推論
		self.analyze_address_class()
		# メモリマップ初期化
		self._memmap = []
		# 重複チェックdict
		self._memmap_dup = {}
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
		elif t_inf.tag == utilDwarf.type_info.TAG.func:
			self.make_memmap_var_func(var, t_inf)
		else:
			raise Exception("unknown variable type detected.")

	def make_memmap_var(self, var: var_info, t_inf: type_info) -> memmap.var_type:
		"""
		memmap_var作成関数
		アドレス重複チェックも実施する
		"""
		memmap_var: memmap.var_type = None
		# 重複チェック
		if var.addr in self._memmap_dup.keys():
			# 重複あり
			base_var = self._memmap_dup[var.addr]
			memmap_var = memmap.var_type()
			base_var.external.append(memmap_var)
		else:
			# 重複無し
			# 変数情報作成
			memmap_var = memmap.var_type()
			self._memmap_dup[var.addr] = memmap_var
			# 変数情報登録
			self._memmap.append(memmap_var)

		# 共通情報作成
		memmap_var.address = var.addr					# 配置アドレス
		memmap_var.name = var.name						# 変数名
		memmap_var.decl_file = var.decl_file.filename
		memmap_var.decl_line = var.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size			# 宣言型サイズ
		memmap_var.array_size = t_inf.range				# 配列要素数
		memmap_var.const = t_inf.const					# const
		memmap_var.pointer = t_inf.pointer				# pointer
		memmap_var.typename = t_inf.name
		#
		return memmap_var

	def make_memmap_var_base(self, var: var_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = self.make_memmap_var(var, t_inf)
		memmap_var.tag = memmap.var_type.TAG.base		# 変数タイプタグ


	def make_memmap_var_func(self, var: var_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = self.make_memmap_var(var, t_inf)
		memmap_var.tag = memmap.var_type.TAG.func		# 変数タイプタグ

	def make_memmap_var_array(self, var: var_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = self.make_memmap_var(var, t_inf)
		memmap_var.tag = memmap.var_type.TAG.array		# 変数タイプタグ

		# 配列の各idxを個別にmemberとして登録
		member_t_inf = self.get_type_info(t_inf.child_type)
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
		elif mem_inf.tag == utilDwarf.type_info.TAG.func:
			self.make_memmap_var_array_each_func(parent, mem_inf, idx)
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
		memmap_var.decl_file = mem_inf.decl_file.filename
		memmap_var.decl_line = mem_inf.decl_line
		memmap_var.typename = mem_inf.name
		memmap_var.pointer = mem_inf.pointer				# pointer
		# 変数情報登録
		parent.member.append(memmap_var)

	def make_memmap_var_array_each_func(self, parent: memmap.var_type, mem_inf: type_info, idx: int):
		# 配列要素[idx]を登録
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = parent.tag
		memmap_var.address = parent.address + (mem_inf.byte_size * idx)
		memmap_var.name = "[" + str(idx) + "]"
		memmap_var.byte_size = mem_inf.byte_size
		memmap_var.decl_file = mem_inf.decl_file.filename
		memmap_var.decl_line = mem_inf.decl_line
		memmap_var.typename = mem_inf.name
		memmap_var.pointer = mem_inf.pointer				# pointer
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
		memmap_var.decl_file = mem_inf.decl_file.filename
		memmap_var.decl_line = mem_inf.decl_line
		memmap_var.typename = mem_inf.name
		memmap_var.pointer = mem_inf.pointer				# pointer
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
		memmap_var.decl_file = mem_inf.decl_file.filename
		memmap_var.decl_line = mem_inf.decl_line
		memmap_var.typename = mem_inf.name
		memmap_var.pointer = mem_inf.pointer				# pointer
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
		memmap_var.decl_file = var.decl_file.filename
		memmap_var.decl_line = var.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size			# 宣言型サイズ
		memmap_var.const = t_inf.const					# const
		memmap_var.typename = t_inf.name
		memmap_var.pointer = t_inf.pointer				# pointer
		# 変数情報登録
		self._memmap.append(memmap_var)

		# メンバ変数を登録
		for member_t_inf in t_inf.member:
			# 再帰処理開始
			self.make_memmap_var_member(memmap_var, member_t_inf)

	def make_memmap_var_member(self, parent: memmap.var_type, mem_inf: type_info):
		# member型情報を取得
		mem_t_inf = self.get_type_info(mem_inf.child_type)
		# typeチェック
		if mem_t_inf.tag == utilDwarf.type_info.TAG.base:
			self.make_memmap_var_member_base(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.array:
			self.make_memmap_var_member_array(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.struct:
			self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.union:
			self.make_memmap_var_member_struct(parent, mem_inf, mem_t_inf)
		elif mem_t_inf.tag == utilDwarf.type_info.TAG.func:
			self.make_memmap_var_member_func(parent, mem_inf, mem_t_inf)
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
		memmap_var.decl_file = member_inf.decl_file.filename
		memmap_var.decl_line = member_inf.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		memmap_var.typename = t_inf.name
		memmap_var.pointer = t_inf.pointer				# pointer
		# 変数情報登録
		parent.member.append(memmap_var)

	def make_memmap_var_member_func(self, parent: memmap.var_type, member_inf: type_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.func								# 変数タイプタグ
		memmap_var.address = parent.address + member_inf.member_location		# アドレス
		memmap_var.address_offset = member_inf.member_location					# アドレスオフセット
		memmap_var.name = member_inf.name										# メンバ名
		memmap_var.decl_file = member_inf.decl_file.filename
		memmap_var.decl_line = member_inf.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		memmap_var.typename = t_inf.name
		memmap_var.pointer = t_inf.pointer				# pointer
		# 変数情報登録
		parent.member.append(memmap_var)

	def make_memmap_var_member_array(self, parent: memmap.var_type, member_inf: type_info, t_inf: type_info):
		# 変数情報作成
		memmap_var = memmap.var_type()
		memmap_var.tag = memmap.var_type.TAG.array								# 変数タイプタグ
		memmap_var.address = parent.address + member_inf.member_location		# アドレス
		memmap_var.address_offset = member_inf.member_location					# アドレスオフセット
		memmap_var.name = member_inf.name										# メンバ名
		memmap_var.decl_file = member_inf.decl_file.filename
		memmap_var.decl_line = member_inf.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		memmap_var.array_size = t_inf.range										# 配列要素数
		memmap_var.typename = t_inf.name
		memmap_var.pointer = t_inf.pointer				# pointer
		# 変数情報登録
		parent.member.append(memmap_var)

		# 配列の各idxを個別にmemberとして登録
		member_t_inf = self.get_type_info(t_inf.child_type)
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
		memmap_var.decl_file = member_inf.decl_file.filename
		memmap_var.decl_line = member_inf.decl_line
		# 型情報作成
		memmap_var.byte_size = t_inf.byte_size									# 宣言型サイズ
		memmap_var.typename = t_inf.name
		memmap_var.pointer = t_inf.pointer				# pointer
		# 変数情報登録
		parent.member.append(memmap_var)

		# メンバ変数を登録
		for member_t_inf in t_inf.member:
			# 再帰処理開始
			self.make_memmap_var_member(memmap_var, member_t_inf)



	def get_type_info(self, type_id:int) -> type_info:
		# typedef
		TAG = utilDwarf.type_info.TAG
		# type 取得
		if type_id not in self._type_tbl.keys():
			# ありえないはず
			raise Exception("undetected type appeared.")
		# 結果の型情報を作成
		# 修飾子等はツリーになっているので、コピーを作って反映させる
		type_inf = copy.copy(self._type_tbl[type_id])
		if type_inf.tag in {TAG.typedef, TAG.const, TAG.pointer, TAG.restrict, TAG.volatile}:
			type_inf.tag = None
		# typedef チェック
		next_type_id = type_inf.child_type
		while next_type_id is not None:
			# type-qualifierチェック
			if type_inf.const is not None:
				is_const = True
			# child情報を結合していく
			child_type = self._type_tbl[next_type_id]
			if child_type.tag == utilDwarf.type_info.TAG.base:
				# name 上書き
				type_inf.name = self.get_type_info_select_overwrite(type_inf.name, child_type.name)
				# encoding 上書き
				type_inf.encoding = self.get_type_info_select_overwrite(type_inf.encoding, child_type.encoding)
				# byte_size 選択
				type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
				# tag 上書き
				type_inf.tag = self.get_type_info_select(type_inf.tag, child_type.tag)
			elif child_type.tag == utilDwarf.type_info.TAG.func:
				# name 選択
				type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
				# byte_size 選択
				type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
				# params 選択
				if not type_inf.params and child_type.params:
					type_inf.params = child_type.params
				# tag 上書き
				type_inf.tag = child_type.tag
			elif child_type.tag == utilDwarf.type_info.TAG.typedef:
				# name 選択
				type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
			elif child_type.tag in {TAG.struct, TAG.union}:
				# name 上書き
				type_inf.name = self.get_type_info_select_overwrite(type_inf.name, child_type.name)
				# byte_size 選択
				type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
				# member 選択
				if not type_inf.member and child_type.member:
					type_inf.member = child_type.member
				# tag 上書き
				type_inf.tag = child_type.tag
			elif child_type.tag == utilDwarf.type_info.TAG.array:
				# name 選択
				type_inf.name = self.get_type_info_select(type_inf.name, child_type.name)
				# range 上書き
				type_inf.range = self.get_type_info_select(type_inf.range, child_type.range)
				# tag 上書き
				type_inf.tag = child_type.tag
			elif child_type.tag == utilDwarf.type_info.TAG.const:
				type_inf.const = True
			elif child_type.tag == utilDwarf.type_info.TAG.pointer:
				# address_class 上書き
				type_inf.address_class = self.get_type_info_select(type_inf.address_class, child_type.address_class)
				# byte_size 上書き
				type_inf.byte_size = self.get_type_info_select(type_inf.byte_size, child_type.byte_size)
				type_inf.pointer = True
			elif child_type.tag == utilDwarf.type_info.TAG.restrict:
				type_inf.restrict = True
			elif child_type.tag == utilDwarf.type_info.TAG.volatile:
				type_inf.volatile = True
			else:
				# 実装忘れ以外ありえない
				raise Exception("undetected type appeared.")
			# child要素チェック
			next_type_id = child_type.child_type
		# tagがNoneのとき、void型と推測
		if type_inf.tag is None:
			type_inf.tag = utilDwarf.type_info.TAG.base
		if type_inf.name is None:
			type_inf.name = "void"
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
