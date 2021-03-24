from utilDwarf import utilDwarf
import pathlib

path = pathlib.Path(r"./test_obj/abs_test.abs")
dwarf = utilDwarf.utilDwarf(path, 'cp932')
dwarf.analyze()
dwarf.make_memmap()
print("analyze finish.")


def dump_memmap(var: utilDwarf.memmap.var_type, depth:int = 0):
	#
	indent = "\t" * depth
	print(f'{var.address}\t{var.byte_size}\t{indent}{var.name}')
	#
	for member in var.member:
		dump_memmap(member, depth+1)


dwarf._memmap.sort(key=lambda k: k.address)

for var in dwarf._memmap:
	dump_memmap(var)
