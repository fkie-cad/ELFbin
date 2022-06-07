from os import remove

from lief import parse
from lief.ELF import Binary
from lief.ELF import Builder
from lief.ELF import ELF_CLASS
from lief.ELF import ARCH
from lief import EXE_FORMATS


class ElfBinary:
	"""Represents an ELF binary
	
	Attributes:
		__bin (Binary): LIEF binary object
		__builder (Builder): LIEF builder used to patch offets etc.
		__fileName (str): Name of opened binary.
		__tempName (str): Name of temporary file used for swapping
			ELF parsers.

	"""

	__bin : Binary
	__builder : Builder

	__fileName : str

	__tempName : str
	
	def __init__(self, path : str):
		"""Initializes the binary

		Args:
			path (str): Path of binary to open, parse and manipulate.

		"""
		# Open binary
		self.__fileName = path
		self.__bin = parse(self.__fileName)
		if (not self.__bin):
			raise RuntimeError('Failed to load {}'.format(self.__fileName))

		if (self.__bin.header.identity_class != ELF_CLASS.CLASS64 or
				self.__bin.header.machine_type != ARCH.AARCH64 or
				self.__bin.format != EXE_FORMATS.ELF):
			raise ValueError('Currently only 64-bit ELF binaries are supported')

		# Build elf file such that offsets etc. are valid
		self.__builder = Builder(self.__bin)
		self.__builder.build()

		# For parser swapping
		self.__tempName = 'temp'
		self.__isLoaded = False

	def store(self, name : str) -> None:
		self.__bin.write(name)

	def getBinary(self) -> Binary:
		return self.__bin

	def getFileName(self) -> str:
		return self.__fileName

	def _storetemp(self) -> None:
		self.__bin.write(self.__tempName)

	def _reparsetemp(self) -> None:
		self.__bin = parse(self.__tempName)
		remove(self.__tempName)

	def _getTempName(self) -> None:
		return self.__tempName