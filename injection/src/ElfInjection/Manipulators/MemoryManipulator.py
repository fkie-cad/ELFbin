from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ElfMemoryChunk:
	offset : int
	size : int

	def __init__(self, offset : int, size : int):
		self.offset = offset
		self.size = size

class ElfMemoryManipulator(ABC):
	"""Memory Manipulator

	Abstract memory manipulator that will be used to describe a
	commong interface for all memory manipulators.

	This can e.g. be used for inserting new memory to be used
	as a segment.

	Attributes:
		__chunk (ElfMemoryChunk): Memory chunk to manipulate
		__data (bytes): Data to be used for manipulation

	"""

	__chunk : ElfMemoryChunk
	__data : bytes

	def __init__(self, offset : int, data : bytes):
		"""Initialize attributes with constructor

		Args:
			offset (int): File offset of memory chunk to
				manipulate.
			data (bytes): Data to be used for manipulation.
				Its length determines the amount of bytes
				to manipulate.
		
		"""
		self.__chunk = ElfMemoryChunk(offset, len(data))
		self.__data = data

	@abstractmethod
	def _manipulateMemory(
			self,
			inj,
			updatedOffset=None,
			updatedData=None) -> None:
		"""Manipulates a memory
		
		Abstract declaration of memory manipulation that will be
		overwritten by any memory manipulator.

		Note that inserting new memory and writing specified data to
		it is also considered a manipulation. Of course manipulating
		existing chunks is aswell.
	
		Args:
			inj (ElfCodeInjector): Injector used to manipulate a
				binary.
			updatedOffset (int): If not None, it will be used as
				file offset. This is only relevant if this
				manipulator is called in a call - chain, where
				previous manipulations influence offsets, vaddrs etc.
			updatedData (bytes): If not None, it will be used as
				data to use for manipulation.

		Returns:
			None

		"""
		pass

	def _getChunk(self) -> ElfMemoryChunk:
		"""Returns chunk description
		
		Returns:
			Chunk

		"""
		return self.__chunk

	def _getData(self) -> bytes:
		"""Returns data

		Returns:
			Data used for manipulation

		"""
		return self.__data

class ElfMemoryOverwriter(ElfMemoryManipulator):
	"""Memory manipulation by overwrite

	Realizes memory manipulation by overwriting a specified
	memory region. Note that overwriting arbitrary memory
	can break vital ELF structures and thus correctness of
	the binary.

	"""

	def __init__(self, offset : int, data : bytes):
		"""Initialize attributes by constructor

		Args:
			offset (int): File offset of memory chunk to
				manipulate.
			data (bytes): Data to write into the chunk. The
				length of data determines the size of the chunk
				to overwrite.

		"""
		super().__init__(offset, data)

	def _manipulateMemory(
			self,
			inj,
			updatedOffset=None,
			updatedData=None) -> None:
		"""Overwrite chunk with specified data
		
		Args:
			inj (ElfCodeInjector): Injector used to manipulate a
				binary.
			updatedOffset (int): If not None, it will be used as
				file offset. This is only relevant if this
				manipulator is called in a call - chain, where
				previous manipulations influence offsets, vaddrs etc.
			updatedData (bytes): If not None, it will be used as
				data to use for manipulation.

		Returns:
			None

		"""
		chunk = self._getChunk()

		offset = chunk.offset
		if updatedOffset:
			offset = updatedOffset

		data = self._getData()
		if updatedData:
			data = updatedData

		return inj.raw.overwriteMemory(offset, data)

class ElfMemoryInserter(ElfMemoryManipulator):
	"""Memory manipulation by insertion

	Realizes memory manipulation by inserting new memory
	at specified offset and of specified size.

	Note that inserting memory into the binary can not
	just invalidate vital ELF structures, but also break
	cross - references. Also CPU - instructions can be
	affected (e.g. on ARM64 see 'adrp').
	
	"""
	
	def __init__(self, offset : int, data : bytes):
		"""Initialize attributes by constructor
		
		Args:
			offset (int): File offset of new memory chunk
			data (bytes): Data to write to new chunk. Its
				length determines the amount of bytes to
				insert.

		"""
		super().__init__(offset, data)

	def _manipulateMemory(
			self,
			inj,
			updatedOffset=None,
			updatedData=None) -> None:
		"""Inserts new memory into binary

		Args:
			inj (ElfCodeInjector): Injector used to manipulate a
				binary.
			updatedOffset (int): If not None, it will be used as
				file offset. This is only relevant if this
				manipulator is called in a call - chain, where
				previous manipulations influence offsets, vaddrs etc.
			updatedData (bytes): If not None, it will be used as
				data to use for manipulation.

		Returns:
			None
			
		"""
		chunk = self._getChunk()

		offset = chunk.offset
		if updatedOffset:
			offset = updatedOffset

		data = self._getData()
		if updatedData:
			data = updatedData

		return inj.raw.insertMemory(offset, data)