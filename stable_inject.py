#!/usr/bin/env python3

import sys

import lief

from ElfInjection.Binary import ElfBinary
from ElfInjection.CodeInjector import ElfCodeInjector
from ElfInjection.Manipulators.DynamicManipulator import *
from ElfInjection.Manipulators.StringManipulator import *


def main():
	
	# 0. Check command line
	if (len(sys.argv) != 3):
		print('Usage: %s <target file name>'
			+ ' <shared object file name>')
		exit(1)

	# 1. Open binary by file name
	binary = ElfBinary(sys.argv[1])

	# 2. Create injector from binary
	injector = ElfCodeInjector(binary)

	# 3. Create .dynamic manipulator
	# Parameters will be ignored -> lief: add_library
	dynamic_manip = ElfDynamicInserter(
		lief.ELF.DYNAMIC_TAGS.NEEDED,
		0
	)

	# 4. Create .dynstr manipulator
	dynstr_manip = ElfStringInserter(sys.argv[2])

	# 5. Run .dynamic - based injection -> uses lief interally
	new_entry = injector.injectDynamic(
		dynstr_manip,
		dynamic_manip
	)

	# 6. Output new entry
	print(new_entry)

	# 7. Further info
	print('Next step is to use e.g. LD_LIBRARY_PATH s.t. the dynamic'
		+ ' linker is able to find {}.'.format(sys.argv[2])
		+ ' You may use \"LD_LIBRARY_PATH=. {}\"'.format(sys.argv[1]))

	# 8. Write manipulations to file
	binary.store('manipulated.bin')

if (__name__ == '__main__'):
	main()