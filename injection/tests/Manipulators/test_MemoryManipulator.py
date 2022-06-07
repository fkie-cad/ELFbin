import pytest
import lief

from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryOverwriter
from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryInserter


class TestMemoryManipulator:
	
	@pytest.fixture
	def offsets(self, lief_arm_android_bin):
		binary = lief_arm_android_bin
		return [
			segment.file_offset
			for segment in binary.segments
			if (segment.type == lief.ELF.SEGMENT_TYPES.LOAD and
				segment.physical_size > 0 and
				segment.file_offset > 0)
		]

	@pytest.fixture
	def sizes(self):
		# Chosen s.t. we stay in same loadable segment
		# for arm_android_bin!
		return [
			i * 0x100
			for i in range(1, 3)
		]

	@pytest.mark.memory
	@pytest.mark.parametrize('offsetIndex', range(4))
	@pytest.mark.parametrize('sizeIndex', range(2))
	def test_overwrite_memory(
			self,
			inj_arm_android_bin,
			offsets,
			offsetIndex,
			sizes,
			sizeIndex
		):
		offset = offsets[offsetIndex]
		size = sizes[sizeIndex]
		binary = inj_arm_android_bin.getElfBinary().getBinary()
		
		# Construct overwriter
		overwriter = ElfMemoryOverwriter(
			offset,
			b'\x42' * size
		)

		# Overwrite memory. Do not consider 'updatedOffset'
		# and 'updatedData', because they merely change
		# offset and data, but NOT the behaviour of the
		# function.
		overwriter._manipulateMemory(
			inj_arm_android_bin,
			updatedOffset=None,
			updatedData=None
		)

		binary = inj_arm_android_bin.getElfBinary().getBinary()

		# Check memory
		seg_start = binary.segment_from_offset(offset)
		seg_end = binary.segment_from_offset(offset + size - 1)

		assert(seg_start)
		assert(seg_end)
		assert(seg_start == seg_end)

		roff = offset - seg_start.file_offset
		assert(seg_start.content[roff] == ord(b'\x42'))
		assert(seg_start.content[roff + size - 1] == ord(b'\x42'))

	@pytest.mark.skip(reason='LIEF parser error causes python to crash')
	@pytest.mark.memory
	@pytest.mark.parametrize('offsetIndex', range(4))
	@pytest.mark.parametrize('sizeIndex', range(2))
	def test_inject_memory(
			self,
			inj_arm_android_bin,
			offsets,
			offsetIndex,
			sizes,
			sizeIndex
		):

		offset = offsets[offsetIndex]
		size = sizes[sizeIndex]
		binary = inj_arm_android_bin.getElfBinary().getBinary()

		# Get original sizes of segment
		seg_start = binary.segment_from_offset(offset)
		fileSize = seg_start.physical_size
		memSize = seg_start.virtual_size

		# Construct inserter
		inserter = ElfMemoryInserter(
			offset,
			b'\x42' * size
		)

		# Perform injection
		inserter._manipulateMemory(
			inj_arm_android_bin
		)

		# Reload binary
		binary = inj_arm_android_bin.getElfBinary().getBinary()

		# Check memory
		seg_start = binary.segment_from_offset(offset)
		seg_end = binary.segment_from_offset(offset + size - 1)

		assert(seg_start)
		assert(seg_end)
		assert(seg_start == seg_end)
		assert(seg_start.physical_size == fileSize + size)
		assert(seg_start.virtual_size == memSize + size)

		roff = offset - seg_start.file_offset
		assert(seg_start.content[roff] == ord(b'\x42'))
		assert(seg_start.content[roff + size - 1] == ord(b'\x42'))