import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment

ida_idaapi.require('tdinfo_structs')


class TdinfoParserException(Exception):
    pass


class TdinfoParserSymbolAlreadyAppliedException(TdinfoParserException):
    pass


class TdinfoParserIdaSetNameFailedException(TdinfoParserException):
    pass


class TdinfoParserUnsupportedSymbolClassException(TdinfoParserException):
    pass


def _parse_exe_file():
    input_file_path = ida_kernwin.ask_file(False, ida_nalt.get_input_file_path(), 'Input file')
    parsed_file = tdinfo_structs.DOS_MZ_EXE_STRUCT.parse_file(input_file_path)

    print('Borland TLink symbolic information version: {}.{:02}'.format(
        parsed_file.tdinfo_header.major_version,
        parsed_file.tdinfo_header.minor_version))

    return parsed_file


def _apply_tdinfo_symbol(image_base, name_pool, symbol):
    if symbol.bitfield.symbol_class != tdinfo_structs.SymbolClass.STATIC.name:
        raise TdinfoParserUnsupportedSymbolClassException()

    symbol_ea = image_base + symbol.segment * 0x10 + symbol.offset
    symbol_name = str(name_pool[symbol.index - 1])

    if ida_name.get_name(symbol_ea) == symbol_name:
        raise TdinfoParserSymbolAlreadyAppliedException()

    if ida_name.set_name(symbol_ea, symbol_name):
        print('Applied name {} to address {:04X}:{:04X}'.format(
            symbol_name,
            image_base // 0x10 + symbol.segment,
            symbol.offset))
    else:
        raise TdinfoParserIdaSetNameFailedException()


def apply_tdinfo_symbols():
    # A heuristic, since get_imagebase returns wrong result
    image_base = ida_segment.get_first_seg().start_ea

    parsed_exe_file = _parse_exe_file()

    applied_symbols_count = 0
    already_existing_symbols_count = 0
    for symbol in parsed_exe_file.symbol_records:
        try:
            _apply_tdinfo_symbol(image_base, parsed_exe_file.name_pool, symbol)
            applied_symbols_count += 1
        except TdinfoParserSymbolAlreadyAppliedException:
            already_existing_symbols_count += 1
        except TdinfoParserException:
            pass

    print('Detected {} global symbols.'.format(
        parsed_exe_file.tdinfo_header.globals_count)),
    print('{} identical symbols already existed, {} new symbols were applied.'.format(
        already_existing_symbols_count,
        applied_symbols_count))

import ida_auto
import idc
import sys


class TDImportPlugin(ida_idaapi.plugin_t):
    """
    XML Exporter plugin class
    """
    flags = 0
    comment = "TD Import"
    help = "TD Import"
    wanted_name = "TD Import"
    wanted_hotkey = "Ctrl-Shift-t"


    def init(self):
        """
        init function for XML Exporter plugin.
        
        Returns:
            Constant PLUGIN_OK if this IDA version supports the plugin,
            else returns PLUGIN_SKIP if this IDA is older than the supported
            baseline version.
        """
        return ida_idaapi.PLUGIN_OK 


    def run(self, arg):
        """
        run function for XML Exporter plugin.
        
        Args:
            arg: Integer, non-zero value enables auto-run feature for
                IDA batch (no gui) processing mode. Default is 0.
        """
        st = idc.set_ida_state(idc.IDA_STATUS_WORK)
        try:
            try:
                apply_tdinfo_symbols()
            except:
                ida_kernwin.hide_wait_box()
                msg = "***** Exception occurred: XML Exporter failed! *****"
                print "\n" + msg + "\n", sys.exc_type, sys.exc_value
                idc.warning(msg)
        finally:
            ida_auto.set_ida_state(st)


    def term(self):
        pass


def PLUGIN_ENTRY():
    return TDImportPlugin()
