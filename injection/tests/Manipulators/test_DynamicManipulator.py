import pytest
import lief

from ElfInjection.Manipulators.DynamicManipulator import ElfDynamicOverwriter
from ElfInjection.Manipulators.DynamicManipulator import ElfDynamicInserter
from ElfInjection.Manipulators.DynamicManipulator import DYN_TAGS
from ElfInjection.Manipulators.StringManipulator import ElfStringData

class TestDynamicManipulator:

	@pytest.fixture
	def string_data(self):
		return ElfStringData(1, 'ibc.so')

	@pytest.mark.dynamic
	@pytest.mark.parametrize('index', [ 6, 0, 1, 2 ])
	def test_overwrite_dynamic(
			self,
			inj_arm_android_bin,
			string_data,
			index
		):
		binary = inj_arm_android_bin.getElfBinary()
		overwriter = ElfDynamicOverwriter(
			lief.ELF.DYNAMIC_TAGS.NEEDED,
			4,
			index
		)

		old = binary.getBinary()
		dyn = overwriter._manipulateDynamic(
			inj_arm_android_bin,
			updatedString=string_data
		)
		new = binary.getBinary()

		assert(
			len(old.dynamic_entries)
				== len(new.dynamic_entries)
		)

		new_dyn = new.dynamic_entries[index]
		assert(dyn.value == new_dyn.value)
		assert(dyn.tag == new_dyn.tag)

	@pytest.mark.dynamic
	@pytest.mark.parametrize('entry', [
		(lief.ELF.DYNAMIC_TAGS.NEEDED, 0),
		(lief.ELF.DYNAMIC_TAGS.DEBUG, 0x42),
		(lief.ELF.DYNAMIC_TAGS.SYMTAB, 0x4242),
	])
	def test_insert_dynamic(
			self,
			inj_arm_android_bin,
			entry,
			string_data
		):
		binary = inj_arm_android_bin.getElfBinary()
		inserter = ElfDynamicInserter(*entry)

		old = binary.getBinary()
		old_num = len(old.dynamic_entries)

		# Only use 'string_data' for DT_NEEDED:
		if (entry[0] != lief.ELF.DYNAMIC_TAGS.NEEDED):
			string_data = None

		dyn = inserter._manipulateDynamic(
			inj_arm_android_bin,
			updatedString=string_data
		)
		new = binary.getBinary()

		# Check increase in size of .dynamic. Use 'old_num'
		# because 'old' is the same object as 'binary' in
		# '_manipulateDynamic'. For that 'binary', we add
		# a dummy entry -->
		# len(old.dynamic_entries) = len(new.dynamic_entries)
		assert(
			old_num == len(new.dynamic_entries) - 1
		)

		# Check content of new entry
		assert(dyn.tag == entry[0])

		# If 'string_data' is used, then value differs
		if (string_data):
			assert(dyn.value == string_data.index)
		else:
			assert(dyn.value == entry[1])

		# Check presence in .dynamic
		for d in new.dynamic_entries:
			if (d == dyn):
				return
		assert(False)