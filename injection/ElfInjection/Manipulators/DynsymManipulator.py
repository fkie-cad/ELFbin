from abc import ABC, abstractmethod
from dataclasses import dataclass

from lief.ELF import Symbol
from lief.ELF import SYMBOL_BINDINGS
from lief.ELF import SYMBOL_VISIBILITY
from lief.ELF import SYMBOL_TYPES


@dataclass
class ElfSymbolEntry:
	name : str
	value : int
	size : int
	binding : SYMBOL_BINDINGS
	visibility : SYMBOL_VISIBILITY
	symType : SYMBOL_TYPES
	shndx : int

	def __init__(
			self,
			name : str,
			value : int,
			size : int,
			binding : SYMBOL_BINDINGS,
			visibility : SYMBOL_VISIBILITY,
			symType : SYMBOL_TYPES,
			shndx : int):
		self.name = name
		self.value = value
		self.size = size
		self.binding = binding
		self.visibility = visibility
		self.symType = symType
		self.shndx = shndx

	def asSymbol(self) -> Symbol:
		sym = Symbol()
		sym.name = self.name
		sym.value = self.value
		sym.size = self.size
		sym.binding = self.binding
		sym.visibility = self.visibility
		sym.type = self.symType
		sym.shndx = self.shndx
		return sym

class ElfDynsymManipulator(ABC):
	""".dynsym manipulator

	Abstract .dynsym manipulator that will be used to
	describe a common interface for all .dynsym manipulators.

	As .dynsym is a symbol table, this class will work with
	LIEF's symbols.

	Attributes:
		__symbol (ElfSymbolEntry): Symbol data used to create
			a new symbol

	"""

	__symbol : ElfSymbolEntry

	def __init__(
			self,
			name : str,
			value : int,
			size : int,
			binding : SYMBOL_BINDINGS,
			visibility : SYMBOL_VISIBILITY,
			symType : SYMBOL_TYPES,
			shndx : int
		):
		"""Initialize attributes with constructor

		Args:
			name (str): Name of the symbol, i.e. string in
				.dynstr, if any
			value (int): Value of the symbol, e.g. a vaddr
			size (int): Size of the symbol
			binding (SYMBOL_BINDINGS): Binding of the symbol
			visibility (SYMBOL_VISIBILITY): Visibility of
				the symbol. E.g. local vs. global
			symType (SYMBOL_TYPES): Type of symbol. E.g.
				a function symbol
			shndx (int): SHT index of section this symbol
				is related to.

		"""
		self.__symbol = ElfSymbolEntry(
			name,
			value,
			size,
			binding,
			visibility,
			symType,
			shndx
		)

	@abstractmethod
	def _manipulateDynsym(
			self,
			inj) -> Symbol:
		"""Manipulates .dynsym

		Abstract declaration of .dynsym manipulation that will be
		overwritten by any .dynsym manipulator.

		Args:
			inj (ElfCodeInjector): Injector used to manipulate
				the binary.

		Returns:
			Changed/new symbol

		"""
		pass

	def _getSymbol(self):
		"""Returns the new symbol's data

		Returns:
			Symbol info

		"""
		return self.__symbol

class ElfDynsymOverwriter(ElfDynsymManipulator):
	""".dynsym manipulation by overwrite

	Realizes .dynsym manipulation by overwriting a specified symbol
	entry in .dynsym.

	The name is not relevant, as this is an overwriter class. Thus
	the name of the symbol to overwrite will be taken.

	Attributes:
		__targetName (str): Name of symbol to overwrite

	"""

	__targetName : str

	def __init__(
			self,
			targetName : str,
			newName : str,
			newValue : int,
			newSize : int,
			newBinding : SYMBOL_BINDINGS,
			newVisibility : SYMBOL_VISIBILITY,
			newSymType : SYMBOL_TYPES,
			newShndx : int):
		"""Initialize attributes with constructor

		Args:
			targetName (str): Name of symbol to overwrite
			newName (str): New name of symbol. Set to None
				if name should stay the same.
			newValue (int): New value of symbol.
			newSize (int): New size of symbol.
			newBinding (SYMBOL_BINDINGS): New binding of
				symbol.
			newVisibility (SYMBOL_VISIBILITY): New visibility
				of symbol.
			newSymType (SYMBOL_TYPES): New type of symbol.
			newShndx (int): New SHT index of symbol.

		"""
		super().__init__(
			newName,
			newValue,
			newSize,
			newBinding,
			newVisibility,
			newSymType,
			newShndx
		)
		self.__targetName = targetName

	def _manipulateDynsym(
			self,
			inj) -> Symbol:
		"""Overwrite specified symbol with new symbol

		The symbol name will remain the same, if the name
		passed to constructor is 'None'. This is just for
		convenience.

		Args:
			inj (ElfCodeInjector): Injector used to manipulate
				the binary.
		
		Returns:
			New old symbol

		"""
		elfbin = inj.getElfBinary()
		sym = elfbin.getBinary().get_symbol(self.__targetName)
		if (not sym):
			raise RuntimeError(
				'Symbol with name {} not found.'.format(
					self.__targetName
				)
			)

		newSymbol = self._getSymbol()

		if (newSymbol.name):
			sym.name = newSymbol.name

		sym.value = newSymbol.value
		sym.size = newSymbol.size
		sym.visibility = newSymbol.visibility
		sym.binding = newSymbol.binding
		sym.type = newSymbol.symType
		sym.shndx = newSymbol.shndx
		return sym

class ElfDynsymInserter(ElfDynsymManipulator):
	""".dynsym manipulation by appending

	Realizes .dynsym manipulation by appending a specified symbol
	entry to .dynsym.

	"""
	def __init__(
			self,
			newName : str,
			newValue : int,
			newSize : int,
			newBinding : SYMBOL_BINDINGS,
			newVisibility : SYMBOL_VISIBILITY,
			newSymType : SYMBOL_TYPES,
			newShndx : int):
		"""Initialize attributes with constructor

		Args:
			newName (str): New name of symbol. Set to None
				if name should stay the same.
			newValue (int): New value of symbol.
			newSize (int): New size of symbol.
			newBinding (SYMBOL_BINDINGS): New binding of
				symbol.
			newVisibility (SYMBOL_VISIBILITY): New visibility
				of symbol.
			newSymType (SYMBOL_TYPES): New type of symbol.
			newShndx (int): New SHT index of symbol.

		"""
		super().__init__(
			newName,
			newValue,
			newSize,
			newBinding,
			newVisibility,
			newSymType,
			newShndx
		)

	def _manipulateDynsym(
			self,
			inj) -> Symbol:
		"""Append specified symbol to .dynsym

		This function is heavily based on
		'lief.ELF.Binary.add_dynamic_symbol', which appends a dynamic
		symbol to .dynsym.

		Note that this only works if the given binary contains a SHT.

		Args:
			inj (ElfCodeInjector): Injector used to manipulate
				the binary.

		Returns:
			Symbol that was injected

		"""
		elfbin = inj.getElfBinary()
		return elfbin.getBinary().add_dynamic_symbol(
			self._getSymbol().asSymbol())