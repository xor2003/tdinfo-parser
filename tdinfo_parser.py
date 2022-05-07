import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import idc

ida_idaapi.require('tdinfo_structs')


class TdinfoParserException(Exception):
    pass


class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass


class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass


class TdinfoParser(object):
    def __init__(self):
        # A heuristic, since get_imagebase returns wrong result
        self._image_base = ida_segment.get_first_seg().start_ea
        self._parsed_exe = self._parse_exe_file()

    @staticmethod
    def _parse_exe_file():
        input_file_path = ida_kernwin.ask_file(False, ida_nalt.get_input_file_path(), 'Input file')
        parsed_exe = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

        print('Borland TLink symbolic information version: {}.{}'.format(
            parsed_exe.tdinfo_header.major_version,
            parsed_exe.tdinfo_header.minor_version))

        return parsed_exe

    def apply_tdinfo(self):
        applied_symbols_count = 0
        already_existing_symbols_count = 0
        for symbol in self._parsed_exe.symbol_records:
            try:
                self._apply_tdinfo_symbol(symbol)
                self._apply_tdinfo_type(symbol)
                applied_symbols_count += 1
            except TdinfoParserSymbolAlreadyAppliedException:
                already_existing_symbols_count += 1
            except TdinfoParserException:
                pass

        for segment in self._parsed_exe.segment_records:
            self._apply_tdinfo_segment(segment)
            self._apply_tdinfo_scopes(segment)

        print('Detected {} global symbols.'.format(
            self._parsed_exe.tdinfo_header.globals_count)),
        print('{} identical symbols already existed, {} new symbols were applied.'.format(
            already_existing_symbols_count,
            applied_symbols_count))

    def _apply_tdinfo_symbol(self, symbol):
        if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.STATIC.name:
            raise TdinfoParserUnsupportedSymbolClassException()

        symbol_ea = self._image_base + symbol.segment * 0x10 + symbol.offset
        symbol_name = str(self._parsed_exe.name_pool[symbol.index - 1])

        if ida_name.get_name(symbol_ea) == symbol_name:
            raise TdinfoParserSymbolAlreadyAppliedException()

        if ida_name.set_name(symbol_ea, symbol_name):
            print('Applied name {} to address {:04X}:{:04X}'.format(
                symbol_name,
                self._image_base // 0x10 + symbol.segment,
                symbol.offset))
        else:
            raise TdinfoParserIdaSetNameFailedException()

    def _apply_tdinfo_type(self, symbol):
        if (symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.STATIC.name or
            symbol.type == 0):
            return

        symbol_ea = self._image_base + symbol.segment * 0x10 + symbol.offset
        symbol_name = str(self._parsed_exe.name_pool[symbol.index - 1])

        type = self._parsed_exe.type_records[symbol.type - 1]
        self._apply_tdinfo_type_rec(symbol_ea, symbol_name, type)

    def _apply_tdinfo_type_rec(self, symbol_ea, symbol_name, type):
        if (type.id == tdinfo_structs.TypeId.SCHAR.name or
            type.id == tdinfo_structs.TypeId.UCHAR.name):
            idc.create_byte(symbol_ea)
        elif (type.id == tdinfo_structs.TypeId.SINT.name or
            type.id == tdinfo_structs.TypeId.UINT.name):
            idc.create_word(symbol_ea)
        elif (type.id == tdinfo_structs.TypeId.SLONG.name or
            type.id == tdinfo_structs.TypeId.ULONG.name or
            type.id == tdinfo_structs.TypeId.FAR.name):
            idc.create_dword(symbol_ea)
        elif type.id == tdinfo_structs.TypeId.ARRAY.name:
            member = self._parsed_exe.type_records[type.member_type - 1]
            if member.id == tdinfo_structs.TypeId.ARRAY.name: # array of arrays
                idc.make_array(symbol_ea, type.size)
            else:
                self._apply_tdinfo_type_rec(symbol_ea, symbol_name, member)
                idc.make_array(symbol_ea, type.size // member.size)
        elif type.id == tdinfo_structs.TypeId.STRUCT.name:
            struct_name = 'struct' + symbol_name
            if get_struc_id(struct_name) == BADADDR: #check if struct already exists
                self._apply_tdinfo_struct(struct_name, type)
            idc.create_struct(symbol_ea, -1, struct_name)

    def _apply_tdinfo_struct(self, struct_name, type): #create struct + members
        id = idc.add_struc(-1, struct_name, 0)

        memberIndex = type.member_type - 1
        member = self._parsed_exe.member_records[memberIndex]
        while True: # loop on struct members
            member_name = str(self._parsed_exe.name_pool[member.name - 1])
            member_type = self._parsed_exe.type_records[member.type - 1]

            if (member_type.id == tdinfo_structs.TypeId.SINT.name or
                member_type.id == tdinfo_structs.TypeId.UINT.name):
                flag = FF_WORD
            elif (member_type.id == tdinfo_structs.TypeId.SLONG.name or
                member_type.id == tdinfo_structs.TypeId.ULONG.name or
                member_type.id == tdinfo_structs.TypeId.FAR.name):
                flag = FF_DWORD
            else:
                flag = FF_BYTE

            idc.add_struc_member(id, member_name, -1, flag, -1, member_type.size)

            memberIndex += 1
            member = self._parsed_exe.member_records[memberIndex]
            if member.info == 0xC0: #end marker
                break

    def _apply_tdinfo_segment(self, segment):
        segment_ea = self._image_base + segment.code_segment * 0x10 + segment.code_offset
        module = self._parsed_exe.module_records[segment.module - 1]
        module_name = str(self._parsed_exe.name_pool[module.name - 1])

        if set_segm_name(segment_ea, module_name):
            print('Applied name {} to segment {:04X}:{:04X}'.format(
                module_name,
                self._image_base // 0x10 + segment.code_segment, segment.code_offset))

    def _apply_tdinfo_scopes(self, segment):
        for i in range(segment.scope_count):
            scope = self._parsed_exe.scope_records[segment.scope_index - 1 + i]
            self._apply_tdinfo_scope(segment, scope)

    def _apply_tdinfo_scope(self, segment, scope):
        scope_offset = scope.offset if scope.parent == 0 else self._parsed_exe.scope_records[scope.parent - 1].offset
        scope_ea = self._image_base + segment.code_segment * 0x10 + scope_offset

        for i in range(scope.symbol_count):
            symbol = self._parsed_exe.symbol_records[scope.symbol_index - 1 + i]
            self._apply_tdinfo_localvar(symbol, segment, scope_ea, scope_offset)

    def _apply_tdinfo_localvar(self, symbol, segment, scope_ea, scope_offset):
        if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.AUTO.name:
            return

        symbol_name = str(self._parsed_exe.name_pool[symbol.index - 1])
        offset = symbol.offset - 0x10000 if symbol.offset > 0x7fff else symbol.offset
        operator = '+' if offset >= 0 else '-'

        idc.add_func(scope_ea, BADADDR) # create function if needed
        if (idc.define_local_var(scope_ea, scope_ea, '[bp{}{}]'.format(operator, abs(offset)), symbol_name)):
            print('Applied name {} to [bp{}{}] at address {:04X}:{:04X}'.format(
                symbol_name,
                operator, abs(offset),
                self._image_base // 0x10 + segment.code_segment, scope_offset))
