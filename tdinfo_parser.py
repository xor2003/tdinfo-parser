import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_struct
import idc

import tdinfo_structs
ida_idaapi.require('tdinfo_structs')


TDINFO_MEMBER_INFO_END_MARKER = 0xC0


class TdinfoParserException(Exception):
    pass


class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass


class TdinfoParserNullNameIndexException(TdinfoParserException):
    pass


class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass


class TdinfoParserIdaAddStrucFailedException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedTypeException(TdinfoParserException):
    pass


class TdinfoParser(object):
    def __init__(self):
        # A heuristic, since get_imagebase returns wrong result
        self._image_base = ida_segment.get_first_seg().start_ea
        self._parsed_exe = self._parse_exe_file()

        self._first_member_index_to_struct_tid = {}

    @staticmethod
    def _parse_exe_file():
        input_file_path = ida_kernwin.ask_file(False, ida_nalt.get_input_file_path(), 'Input file')
        parsed_exe = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

        print('Borland TLink symbolic information version: {}.{}'.format(
            parsed_exe.tdinfo_header.major_version,
            parsed_exe.tdinfo_header.minor_version))

        return parsed_exe

    def apply(self):
        applied_global_symbols_count = 0
        already_existing_global_symbols_count = 0

        self._create_types()

        for symbol in self._parsed_exe.symbol_records:
            try:
                if self._is_global_symbol(symbol):
                    self._apply_global_symbol(symbol)
                    applied_global_symbols_count += 1
                elif self._is_type_symbol(symbol):
                    pass
                else:
                    raise TdinfoParserUnsupportedSymbolClassException()
            except TdinfoParserSymbolAlreadyAppliedException:
                already_existing_global_symbols_count += 1
            except TdinfoParserIdaSetNameFailedException:
                pass
            except TdinfoParserUnsupportedSymbolClassException:
                pass

        for segment in self._parsed_exe.segment_records:
            self._apply_segment(segment)
            self._apply_scopes(segment)

        print('Detected {} global symbols.'.format(
            self._parsed_exe.tdinfo_header.globals_count)),
        print('{} identical symbols already existed, {} new symbols were applied.'.format(
            already_existing_global_symbols_count,
            applied_global_symbols_count))

    def _create_types(self):
        # Parsing the types not in a separate pass introduces a lot of edge cases
        for symbol in self._parsed_exe.symbol_records:
            if self._is_struct_symbol(symbol):
                self._create_struct(symbol)

    def _get_name_from_pool(self, name_index):
        if name_index == 0:
            raise TdinfoParserNullNameIndexException()
        return str(self._parsed_exe.name_pool[name_index - 1])

    def _apply_struct_symbol(self, symbol):
        struct_type_record = self._parsed_exe.type_records[symbol.type - 1]
        struct_name = self._get_name_from_pool(symbol.index)
        self._create_struct(struct_type_record, struct_name)

    def _apply_global_symbol(self, symbol):
        symbol_ea = self._image_base + symbol.segment * 0x10 + symbol.offset
        symbol_name = self._get_name_from_pool(symbol.index)

        try:
            self._apply_type(symbol, symbol_ea)
        except TdinfoParserUnsupportedTypeException:
            pass

        if ida_name.get_name(symbol_ea) == symbol_name:
            raise TdinfoParserSymbolAlreadyAppliedException()

        if ida_name.set_name(symbol_ea, symbol_name):
            print('Applied name {} to address {:04X}:{:04X}'.format(
                symbol_name,
                self._image_base // 0x10 + symbol.segment,
                symbol.offset))
        else:
            raise TdinfoParserIdaSetNameFailedException()

    def _apply_type(self, symbol, symbol_ea):
        if not symbol.type:
            return

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        type_flag = self._type_record_to_ida_type_flag(type_record)
        if type_flag == ida_bytes.stru_flag():
            struct_type_record = self._get_array_inner_type_record(type_record)
            tid = self._get_struct_tid(struct_type_record)
            size = ida_struct.get_struc_size(tid)
        else:
            tid = ida_netnode.BADNODE
            size = type_record.size

        ida_bytes.del_items(symbol_ea, ida_bytes.DELIT_SIMPLE, size)
        ida_bytes.create_data(symbol_ea, type_flag, size, tid)

    def _get_array_inner_type_record(self, type_record):
        """
        Returns the type record of an array elements.
        Works for n-dimensional arrays, including where n == 0.
        """
        if type_record.id == tdinfo_structs.TypeId.ARRAY.name:
            member_type_record = self._parsed_exe.type_records[type_record.member_type - 1]
            return self._get_array_inner_type_record(member_type_record)
        else:
            return type_record

    def _type_record_to_ida_type_flag(self, type_record):
        type_id = type_record.id
        if type_id in [tdinfo_structs.TypeId.SCHAR.name,
                       tdinfo_structs.TypeId.UCHAR.name]:
            return ida_bytes.byte_flag()
        if type_id in [tdinfo_structs.TypeId.SINT.name,
                       tdinfo_structs.TypeId.UINT.name,
                       tdinfo_structs.TypeId.NEAR.name]:
            return ida_bytes.word_flag()
        if type_id in [tdinfo_structs.TypeId.SLONG.name,
                       tdinfo_structs.TypeId.ULONG.name,
                       tdinfo_structs.TypeId.FAR.name]:
            return ida_bytes.dword_flag()
        if type_id == tdinfo_structs.TypeId.ARRAY.name:
            inner_type_record = self._get_array_inner_type_record(type_record)
            return self._type_record_to_ida_type_flag(inner_type_record)
        if type_id == tdinfo_structs.TypeId.STRUCT.name:
            return ida_bytes.stru_flag()

        raise TdinfoParserUnsupportedTypeException()

    def _create_struct(self, symbol):
        assert(self._is_struct_symbol(symbol))

        type_record = self._parsed_exe.type_records[symbol.type - 1]
        struct_name = self._get_name_from_pool(symbol.index)

        existing_struct_tid = ida_struct.get_struc_id(struct_name)
        if existing_struct_tid != ida_idaapi.BADADDR:
            # When a struct name already exists, we use the existing struct instead.
            # This is user-error prone, but less aggressive.
            self._first_member_index_to_struct_tid[type_record.member_type] = existing_struct_tid
            return

        tid = ida_struct.add_struc(ida_idaapi.BADADDR, struct_name)
        if tid == ida_idaapi.BADADDR:
            raise TdinfoParserIdaAddStrucFailedException()

        struct_ptr = ida_struct.get_struc(tid)

        max_members_count = self._parsed_exe.tdinfo_header.members_count
        for member_index in range(type_record.member_type - 1, max_members_count + 1):
            member = self._parsed_exe.member_records[member_index]
            if member.info == TDINFO_MEMBER_INFO_END_MARKER:
                break

            member_name = self._get_name_from_pool(member.name)
            member_type = self._parsed_exe.type_records[member.type - 1]

            type_flag = self._type_record_to_ida_type_flag(member_type)
            ida_struct.add_struc_member(
                struct_ptr,
                member_name,
                ida_idaapi.BADADDR,
                type_flag,
                ida_nalt.opinfo_t(),
                member_type.size)

        print('Created struct {}.'.format(struct_name))
        self._first_member_index_to_struct_tid[type_record.member_type] = tid

    def _get_struct_tid(self, type_record):
        return self._first_member_index_to_struct_tid[type_record.member_type]

    def _is_type_symbol(self, symbol):
        return symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.TYPEDEF.name

    def _is_struct_symbol(self, symbol):
        if not symbol.type:
            return False

        symbol_class = symbol.bitfield.symbol_class
        if symbol_class not in [tdinfo_structs.SymbolClass.STRUCT_UNION_OR_ENUM.name,
                                tdinfo_structs.SymbolClass.TYPEDEF.name]:
            return False

        type_id = self._parsed_exe.type_records[symbol.type - 1].id
        return type_id == tdinfo_structs.TypeId.STRUCT.name

    def _is_global_symbol(self, symbol):
        return symbol.bitfield.symbol_class == tdinfo_structs.SymbolClass.STATIC.name

    def _apply_segment(self, segment):
        segment_ea = self._image_base + segment.code_segment * 0x10 + segment.code_offset
        module = self._parsed_exe.module_records[segment.module - 1]
        module_name = self._get_name_from_pool(module.name)

        if set_segm_name(segment_ea, module_name):
            print('Applied name {} to segment {:04X}:{:04X}'.format(
                module_name,
                self._image_base // 0x10 + segment.code_segment, segment.code_offset))

    def _apply_scopes(self, segment):
        for i in range(segment.scope_count):
            scope = self._parsed_exe.scope_records[segment.scope_index - 1 + i]
            self._apply_scope(segment, scope)

    def _apply_scope(self, segment, scope):
        scope_offset = scope.offset if scope.parent == 0 else self._parsed_exe.scope_records[scope.parent - 1].offset
        scope_ea = self._image_base + segment.code_segment * 0x10 + scope_offset

        for i in range(scope.symbol_count):
            symbol = self._parsed_exe.symbol_records[scope.symbol_index - 1 + i]
            self._apply_local_variable(symbol, segment, scope_ea, scope_offset)

    def _apply_local_variable(self, symbol, segment, scope_ea, scope_offset):
        if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.AUTO.name:
            return

        symbol_name = self._get_name_from_pool(symbol.index)
        offset = symbol.offset - 0x10000 if symbol.offset > 0x7fff else symbol.offset
        operator = '+' if offset >= 0 else '-'

        idc.add_func(scope_ea, BADADDR) # create function if needed
        if (idc.define_local_var(scope_ea, scope_ea, '[bp{}{}]'.format(operator, abs(offset)), symbol_name)):
            print('Applied name {} to [bp{}{}] at address {:04X}:{:04X}'.format(
                symbol_name,
                operator, abs(offset),
                self._image_base // 0x10 + segment.code_segment, scope_offset))
