
import json
import pathlib

import idaapi
import idautils
import ida_kernwin


def get_basic_blocks():
    filepath = ida_kernwin.ask_file(True, "*.cov", "Save coverage file")
    image_base = idaapi.get_imagebase()
    filepath = pathlib.Path(filepath)
    # filepath = pathlib.Path(idc.get_input_file_path())
    rvas = set()
    for funcea in idautils.Functions():

        for block in idaapi.FlowChart(idaapi.get_func(funcea)):
            ea = block.start_ea
            if idaapi.is_code(idaapi.get_full_flags(ea)):
                # Write signed 32-bit offset from base of function
                rva = ea - image_base
                rvas.add(rva)

    blocks = {
        'name': filepath.with_suffix('').name,
        'rvas': sorted(rvas)
    }

    outfile = filepath.with_suffix('.cov')
    with open(outfile, 'w') as fp:
        json.dump(blocks, fp, indent=2)


if __name__ == "__main__":
    idaapi.auto_wait()
    get_basic_blocks()
