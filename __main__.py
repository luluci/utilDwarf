from utilDwarf import utilDwarf
import pathlib

path = pathlib.Path(r"./test_obj/abs_test.abs")
dwarf = utilDwarf.utilDwarf(path, 'cp932')
dwarf.analyze()
dwarf.make_memmap()
print("analyze finish.")
