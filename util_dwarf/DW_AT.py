import enum

from elftools.dwarf.die import AttributeValue, DIE

from util_dwarf.DW_FORM import DW_FORM_decorder


class DW_AT(enum.Enum):
    _null = 0

    _sibling = 0x01
    _location = 0x02
    _name = 0x03

    _ordering = 0x09

    _byte_size = 0x0B
    _bit_offset = 0x0C
    _bit_size = 0x0D

    _stmt_list = 0x10
    _low_pc = 0x11
    _high_pc = 0x12
    _language = 0x13

    _discr = 0x15
    _discr_value = 0x16
    _visibility = 0x17
    _import = 0x18
    _string_length = 0x19
    _common_reference = 0x1A
    _comp_dir = 0x1B
    _const_value = 0x1C
    _containing_type = 0x1D
    _default_value = 0x1E

    _inline = 0x20
    _is_optional = 0x21
    _lower_bound = 0x22

    _producer = 0x25

    _prototyped = 0x27

    _return_addr = 0x2A

    _start_scope = 0x2C

    _bit_stride = 0x2E
    _upper_bound = 0x2F

    _abstract_origin = 0x31
    _accessibility = 0x32
    _address_class = 0x33
    _artificial = 0x34
    _base_types = 0x35
    _calling_convention = 0x36
    _count = 0x37
    _data_member_location = 0x38
    _decl_column = 0x39
    _decl_file = 0x3A
    _decl_line = 0x3B
    _declaration = 0x3C
    _discr_list = 0x3D
    _encoding = 0x3E
    _external = 0x3F
    _frame_base = 0x40

    _type = 0x49

    _description = 0x5A


class attribute:
    def __init__(self) -> None:
        self.tag: DW_AT = None
        self.value = None


class DW_AT_decorder:
    def __init__(self, encoding: str = "utf-8") -> None:
        #
        self.DW_form = DW_FORM_decorder(encoding)

    def set_address_size(self, size: int):
        self.DW_form.set_address_size(size)

    def set_frame_base(self, addr: int):
        self.DW_form.set_frame_base(addr)

    def set_offset(self, offset: int):
        self.DW_form.set_offset(offset)

    def decord(self, attr_val: AttributeValue) -> attribute:
        # AT解析
        attr = attribute()
        match attr_val.name:
            case "DW_AT_sibling":
                attr.tag = DW_AT._sibling
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_name":
                attr.tag = DW_AT._name
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_location":
                attr.tag = DW_AT._location
                attr.value = self.analyze_die_AT_location(attr_val)

            case "DW_AT_byte_size":
                attr.tag = DW_AT._byte_size
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_bit_offset":
                attr.tag = DW_AT._bit_offset
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_bit_size":
                attr.tag = DW_AT._bit_size
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_stmt_list":
                attr.tag = DW_AT._stmt_list
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_low_pc":
                attr.tag = DW_AT._low_pc
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_high_pc":
                attr.tag = DW_AT._high_pc
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_language":
                attr.tag = DW_AT._language
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_comp_dir":
                attr.tag = DW_AT._comp_dir
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_const_value":
                attr.tag = DW_AT._const_value
                # attr.value = attr_val.value
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_lower_bound":
                attr.tag = DW_AT._lower_bound
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_producer":
                attr.tag = DW_AT._producer
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_prototyped":
                attr.tag = DW_AT._prototyped
                attr.value = attr_val.value

            case "DW_AT_return_addr":
                attr.tag = DW_AT._return_addr
                # attr.value = self.DW_form.decode(attr_val)
                attr.value = self.analyze_die_AT_location(attr_val)

            case "DW_AT_upper_bound":
                attr.tag = DW_AT._upper_bound
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_accessibility":
                attr.tag = DW_AT._accessibility
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_address_class":
                attr.tag = DW_AT._address_class
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_artificial":
                attr.tag = DW_AT._artificial
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_count":
                attr.tag = DW_AT._count
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_data_member_location":
                attr.tag = DW_AT._data_member_location
                attr.value = self.analyze_die_AT_location(attr_val)

            case "DW_AT_decl_column":
                attr.tag = DW_AT._decl_column
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_decl_file":
                attr.tag = DW_AT._decl_file
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_decl_line":
                attr.tag = DW_AT._decl_line
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_declaration":
                attr.tag = DW_AT._declaration
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_encoding":
                attr.tag = DW_AT._encoding
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_external":
                attr.tag = DW_AT._external
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_frame_base":
                attr.tag = DW_AT._frame_base
                attr.value = self.analyze_die_AT_location(attr_val)

            case "DW_AT_type":
                attr.tag = DW_AT._type
                attr.value = self.DW_form.decode(attr_val)

            case "DW_AT_description":
                attr.tag = DW_AT._description
                attr.value = self.DW_form.decode(attr_val)

            case _:
                print("unimplemented AT: " + attr_val.name)
        #
        return attr

    def analyze_die_AT_location(self, attr: AttributeValue):
        """
        DW_AT_location
        """
        # 2.6 Location Descriptions
        value = self.DW_form.decode(attr)
        if attr.form.startswith("DW_FORM_block"):
            # Simple location descriptions
            # DW_FORM_block1, DW_FORM_block2, DW_FORM_block4, DW_FORM_block
            # valueをそのまま返す
            return value
        elif attr.form in ("DW_FORM_data4", "DW_FORM_data8", "DW_FORM_exprloc"):
            # Location lists
            # .debug_locへの参照を解決して値を返す
            # 未対応
            print("unimplemented AT_localtion:loclistptr:" + str(value))
            return value
        else:
            raise Exception("unimplemented AT_localtion form: " + attr.form)
