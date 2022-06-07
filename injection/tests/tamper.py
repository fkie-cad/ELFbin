#!/usr/bin/env python3

import lief

from ElfInjection.Binary import ElfBinary
from ElfInjection.CodeInjector import ElfCodeInjector
from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryOverwriter
from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryInserter


def main():
	offset = 8192 # offsets[offsetIndex]
	size = 256 #sizes[sizeIndex]


	elfbin = ElfBinary('arm_android_bin')
	inj = ElfCodeInjector(elfbin)

	binary = inj.getElfBinary().getBinary()

	# Get original sizes of segment
	seg_start = binary.segment_from_offset(offset)

	# Construct inserter
	inserter = ElfMemoryInserter(
		offset,
		b'\x42' * size
	)

	# Perform injection
	inserter._manipulateMemory(
		inj
	)

	elfbin.store('tmp')

if (__name__ == '__main__'):
	main()