import pytest
import lief

from ElfInjection.Manipulators.DynsymManipulator import ElfDynsymOverwriter
from ElfInjection.Manipulators.DynsymManipulator import ElfDynsymInserter

class TestDynsymManipulator:

	@pytest.fixture
	def symbols(self):
		syms = []

		# Construct symbols
		sym = lief.ELF.Symbol()
		sym.value = 0x42424242
		sym.size = 0x8
		sym.visibility = lief.ELF.SYMBOL_VISIBILITY.PROTECTED
		sym.binding = lief.ELF.SYMBOL_BINDINGS.LOCAL
		sym.shndx = 0x0
		sym.type = lief.ELF.SYMBOL_TYPES.FUNC
		sym.name = 'test'
		sym.information = 0x0

		# Append symbols to list
		syms.append(sym)

		return syms

	@pytest.mark.symbol
	@pytest.mark.parametrize('symIndex', range(1))
	def test_overwrite_dynsym(
			self,
			inj_arm_android_bin,
			symbols,
			symIndex
		):
		symbol = symbols[symIndex]
		binary = inj_arm_android_bin.getElfBinary()

		# Construct overwriter
		overwriter = ElfDynsymOverwriter(
			'write',
			symbol.name,
			symbol.value,
			symbol.size,
			symbol.binding,
			symbol.visibility,
			symbol.type,
			symbol.shndx
		)

		# Perform injection
		sym = overwriter._manipulateDynsym(
			inj_arm_android_bin
		)

		# Check correctness of symbol
		assert(sym.value == symbol.value)
		assert(sym.size == symbol.size)
		assert(sym.visibility == symbol.visibility)
		assert(sym.binding == symbol.binding)
		assert(sym.shndx == symbol.shndx)
		assert(sym.type == symbol.type)
		assert(
			binary.getBinary().get_symbol(symbol.name).value
				!= 0
		)

	@pytest.mark.symbol
	@pytest.mark.parametrize('symIndex', range(1))
	def test_insert_dynsym(
			self,
			inj_arm_android_bin,
			symbols,
			symIndex
		):
		symbol = symbols[symIndex]
		binary = inj_arm_android_bin.getElfBinary()

		# Construct inserter
		inserter = ElfDynsymInserter(
			symbol.name,
			symbol.value,
			symbol.size,
			symbol.binding,
			symbol.visibility,
			symbol.type,
			symbol.shndx
		)

		# Perform injection
		sym = inserter._manipulateDynsym(
			inj_arm_android_bin
		)

		# Check symbol correctness
		assert(sym.value == symbol.value)
		assert(sym.size == symbol.size)
		assert(sym.visibility == symbol.visibility)
		assert(sym.binding == symbol.binding)
		assert(sym.shndx == symbol.shndx)
		assert(sym.type == symbol.type)
		assert(sym.name == symbol.name)
		assert(binary.getBinary().get_symbol('test'))