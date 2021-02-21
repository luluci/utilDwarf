import enum

class memmap:

	class var_type:
		class TAG(enum.Enum):
			base = enum.auto()			# primitive type
			array = enum.auto()			# array
			struct = enum.auto()		# struct
			union = enum.auto()			# union
			func = enum.auto()			# function type

		def __init__(self) -> None:
			self.tag = None				# 変数タイプタグ
			self.address = None			# 配置アドレス
			self.address_offset = None	# アドレスオフセット
			self.name = None			# 変数名
			self.byte_size = None		# 宣言型のバイトサイズ
			self.bit_size = None		# ビットフィールド宣言時のビットサイズ
			self.bit_offset = None		# ビットフィールド宣言時のビットオフセット
			self.array_size = None		# 配列宣言時の要素数
			self.member = []			# struct/union/classにおけるメンバ情報(mem_var_type)
			self.const = None			# const定数
