import enum
from .LEB128 import ULEB128, SLEB128


"""
DW_OP define
"""


class DW_OP(enum.Enum):
    # 2.5.1 General Operations
    # 2.5.1.1 Literal Encodings
    lit0 = 0x30
    lit1 = 0x31
    lit2 = 0x32
    lit3 = 0x33
    lit4 = 0x34
    lit5 = 0x35
    lit6 = 0x36
    lit7 = 0x37
    lit8 = 0x38
    lit9 = 0x39
    lit10 = 0x3A
    lit11 = 0x3B
    lit12 = 0x3C
    lit13 = 0x3D
    lit14 = 0x3E
    lit15 = 0x3F
    lit16 = 0x40
    lit17 = 0x41
    lit18 = 0x42
    lit19 = 0x43
    lit20 = 0x44
    lit21 = 0x45
    lit22 = 0x46
    lit23 = 0x47
    lit24 = 0x48
    lit25 = 0x49
    lit26 = 0x4A
    lit27 = 0x4B
    lit28 = 0x4C
    lit29 = 0x4D
    lit30 = 0x4E
    lit31 = 0x4F
    addr = 0x03
    const1u = 0x08
    const1s = 0x09
    const2u = 0x0A
    const2s = 0x0B
    const4u = 0x0C
    const4s = 0x0D
    const8u = 0x0E
    const8s = 0x0F
    constu = 0x10
    consts = 0x11
    # 2.5.1.2 Register Based Addressing
    fbreg = 0x91
    breg0 = 0x70
    breg1 = 0x71
    breg2 = 0x72
    breg3 = 0x73
    breg4 = 0x74
    breg5 = 0x75
    breg6 = 0x76
    breg7 = 0x77
    breg8 = 0x78
    breg9 = 0x79
    breg10 = 0x7A
    breg11 = 0x7B
    breg12 = 0x7C
    breg13 = 0x7D
    breg14 = 0x7E
    breg15 = 0x7F
    breg16 = 0x80
    breg17 = 0x81
    breg18 = 0x82
    breg19 = 0x83
    breg20 = 0x84
    breg21 = 0x85
    breg22 = 0x86
    breg23 = 0x87
    breg24 = 0x88
    breg25 = 0x89
    breg26 = 0x8A
    breg27 = 0x8B
    breg28 = 0x8C
    breg29 = 0x8D
    breg30 = 0x8E
    breg31 = 0x8F
    bregx = 0x92
    # 2.5.1.3 Stack Operations
    dup = 0x12
    drop = 0x13
    pick = 0x15
    over = 0x14
    swap = 0x16
    rot = 0x17
    deref = 0x06
    deref_size = 0x94
    xderef = 0x18
    xderef_size = 0x95
    push_object_address = 0x97
    form_tls_address = 0x9B
    call_frame_cfa = 0x9C
    # 2.5.1.4 Arithmetic and Logical Operations
    abs = 0x19
    and_ = 0x1A
    div = 0x1B
    minus = 0x1C
    mod = 0x1D
    mul = 0x1E
    neg = 0x1F
    not_ = 0x20
    or_ = 0x21
    plus = 0x22
    plus_uconst = 0x23
    shl = 0x24
    shr = 0x25
    shra = 0x26
    xor = 0x27
    # 2.5.1.5 Control Flow Operations
    eq = 0x29
    ge = 0x2A
    gt = 0x2B
    le = 0x2C
    lt = 0x2D
    ne = 0x2E
    skip = 0x2F
    bra = 0x28
    call2 = 0x98
    call4 = 0x99
    call_ref = 0x9A
    nop = 0x96
    #
    reg0 = 0x50
    reg1 = 0x51
    reg2 = 0x52
    reg3 = 0x53
    reg4 = 0x54
    reg5 = 0x55
    reg6 = 0x56
    reg7 = 0x57
    reg8 = 0x58
    reg9 = 0x59
    reg10 = 0x5A
    reg11 = 0x5B
    reg12 = 0x5C
    reg13 = 0x5D
    reg14 = 0x5E
    reg15 = 0x5F
    reg16 = 0x60
    reg17 = 0x61
    reg18 = 0x62
    reg19 = 0x63
    reg20 = 0x64
    reg21 = 0x65
    reg22 = 0x66
    reg23 = 0x67
    reg24 = 0x68
    reg25 = 0x69
    reg26 = 0x6A
    reg27 = 0x6B
    reg28 = 0x6C
    reg29 = 0x6D
    reg30 = 0x6E
    reg31 = 0x6F


class DWARF_expression:
    def __init__(self) -> None:
        self.DW_OP_map = {
            # 2.5.1.1 Literal Encodings
            # DW_OP_litX: 0x30-0x4F は動的生成
            DW_OP.addr: self.DW_OP_addr,
            DW_OP.const1u: self.DW_OP_const_n,
            DW_OP.const1s: self.DW_OP_const_n,
            DW_OP.const2u: self.DW_OP_const_n,
            DW_OP.const2s: self.DW_OP_const_n,
            DW_OP.const4u: self.DW_OP_const_n,
            DW_OP.const4s: self.DW_OP_const_n,
            DW_OP.const8u: self.DW_OP_const_n,
            DW_OP.const8s: self.DW_OP_const_n,
            # 2.5.1.2 Register Based Addressing
            # レジスタとはどれを指してる？
            DW_OP.fbreg: self.DW_OP_fbreg,
            # 2.5.1.3 Stack Operations
            DW_OP.dup: self.DW_OP_dup,
            DW_OP.drop: self.DW_OP_drop,
            DW_OP.pick: self.DW_OP_pick,
            DW_OP.over: self.DW_OP_over,
            DW_OP.swap: self.DW_OP_unimpl,
            DW_OP.rot: self.DW_OP_unimpl,
            DW_OP.deref: self.DW_OP_unimpl,
            DW_OP.deref_size: self.DW_OP_unimpl,
            DW_OP.xderef: self.DW_OP_unimpl,
            DW_OP.xderef_size: self.DW_OP_unimpl,
            DW_OP.push_object_address: self.DW_OP_unimpl,
            DW_OP.form_tls_address: self.DW_OP_unimpl,
            DW_OP.call_frame_cfa: self.DW_OP_call_frame_cfa,
            # 2.5.1.4 Arithmetic and Logical Operations
            DW_OP.plus_uconst: self.DW_OP_plus_uconst,
        }

        # DWARF stack
        self.stack = []
        self.address_size = 0
        self.frame_base_addr = 0

        # init DW_OP_lit_n
        for val, code in enumerate(range(DW_OP.lit0.value, DW_OP.lit31.value + 1)):
            self.DW_OP_map[DW_OP(code)] = self.DW_OP_lit_n(val)

        # init DW_OP_breg_n
        for val, code in enumerate(range(DW_OP.breg0.value, DW_OP.breg31.value + 1)):
            self.DW_OP_map[DW_OP(code)] = self.DW_OP_breg_n(val)

        # init DW_OP_reg_n
        for val, code in enumerate(range(DW_OP.reg0.value, DW_OP.reg31.value + 1)):
            self.DW_OP_map[DW_OP(code)] = self.DW_OP_reg_n(val)

    def set_address_size(self, size: int):
        self.address_size = size

    def set_frame_base(self, addr: int):
        self.frame_base_addr = addr

    def init_stack(self):
        self.stack.clear()

    def exec(self, op: int):
        return self.DW_OP_map[DW_OP(op)]

    def get(self):
        return self.stack.pop()

    def DW_OP_unimpl(self, value):
        raise Exception("unimplemented DW_OP!")

    def DW_OP_lit_n(self, val: int):
        def impl(value):
            self.stack.append(val)

        return impl

    def DW_OP_breg_n(self, val: int):
        def impl(value):
            sleb128 = SLEB128(value)
            self.stack.append(0 + sleb128.value)

        return impl

    def DW_OP_reg_n(self, val: int):
        def impl(value):
            self.stack.append(0)

        return impl

    def DW_OP_addr(self, value):
        val = int.from_bytes(bytearray(value[0 : self.address_size]), "little")
        self.stack.append(val)

    def DW_OP_const_n(self, val):
        self.stack.append(val)

    def DW_OP_constu(self, value):
        val = ULEB128(value).value
        self.stack.append(val)

    def DW_OP_consts(self, value):
        val = SLEB128(value).value
        self.stack.append(val)

    def DW_OP_fbreg(self, value):
        val = SLEB128(value).value
        val = self.frame_base_addr + val
        self.stack.append(val)

    def DW_OP_dup(self):
        val = self.stack[-1]
        self.stack.append(val)

    def DW_OP_drop(self):
        self.stack.pop()

    def DW_OP_pick(self, index: int):
        # コピーをpushでいいのか？
        val = self.stack(index)
        self.stack.append(val)

    def DW_OP_over(self):
        self.DW_OP_pick(1)

    def DW_OP_call_frame_cfa(self, value):
        # DW_OP_call_frame_cfa is not meaningful
        # 読み捨てる
        self.stack.append(0)

    def DW_OP_plus_uconst(self, value):
        val = 0
        if len(self.stack) > 0:
            val = self.stack.pop()
        val += ULEB128(value).value
        self.stack.append(val)
