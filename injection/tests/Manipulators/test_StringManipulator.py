import pytest
import lief

from ElfInjection.Manipulators.StringManipulator import ElfStringFinder
from ElfInjection.Manipulators.StringManipulator import ElfStringData

class TestStringManipulator:

	@pytest.mark.string
	@pytest.mark.parametrize('defaultLength', range(len('libc')))
	# @pytest.mark.parametrize('fallbackIndex', range(10))
	def test_string_finder(
			self,
			inj_arm_android_bin,
			defaultLength
		):
		# Cannot check 'fallbackIndex', because in this
		# binary there is always a .so name
		libc = 'libc'
		libcStart = 1
		libcEnd = libcStart + len(libc)

		binary = inj_arm_android_bin.getElfBinary()
		finder = ElfStringFinder(
			defaultLength=defaultLength
		)

		string_info = finder._manipulateString(
			inj_arm_android_bin
		)

		# defaultLength can never by less than 1!
		if (defaultLength == 0):
			defaultLength = 1
		assert(
			string_info.index == libcEnd - defaultLength
		)
		assert(
			string_info.string == libc[-defaultLength:] + '.so'
		)