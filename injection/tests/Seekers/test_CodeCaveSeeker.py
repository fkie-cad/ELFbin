import pytest
from ElfInjection.Seekers.CodeCaveSeeker import *

class TestElfSegmentSeeker:

	@pytest.mark.codeCaves
	def test_seek_cave(
			self,
			inj_arm_android_bin,
			arm_android_bin_caves):
		"""
		Note that those caves have been calculated with a BUILT LIEF
		binary, i.e. lief.ELF.Builder(bin).build() was called
		"""
		
		found_caves = inj_arm_android_bin.findCodeCaves(ElfSegmentSeeker(0x100))
		assert(len(found_caves) == len(arm_android_bin_caves))

		for found, cave in zip(found_caves, arm_android_bin_caves):
			assert(found == cave)