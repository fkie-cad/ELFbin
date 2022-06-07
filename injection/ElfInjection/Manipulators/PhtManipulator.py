from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum

from lief.ELF import Segment
from lief.ELF import SEGMENT_TYPES
from lief.ELF import SEGMENT_FLAGS


class SEG_TYPES(IntEnum):
	PT_NULL = 0
	PT_LOAD = 1
	PT_DYNAMIC = 2
	PT_INTERP = 3
	PT_NOTE = 4
	PT_PHDR = 6

class SEG_FLAGS(IntEnum):
	PF_X = 0x1
	PF_W = 0x2
	PF_R = 0x4

@dataclass
class ElfPhtEntry:
	phtType : SEG_TYPES
	phtTypeLIEF : SEGMENT_TYPES
	flags : SEG_FLAGS
	flagsLIEF : SEGMENT_FLAGS
	offset : int
	vaddr : int
	fileSize : int
	memSize : int
	alignment : int

	def __init__(
			self,
			phtType : SEGMENT_TYPES,
			flags : SEGMENT_FLAGS,
			offset : int,
			vaddr : int,
			fileSize : int,
			memSize : int,
			alignment : int):
		"""Initializes members

		It also converts LIEF representation of a segment
		type and segment flags to their corresponding interger
		representations (according to System V gABI).

		Args:
			phtType (int): Type of segment
			flags (int): Flags describe e.g. whether
				the corresponding segment is readable, writable
				or executable
			offset (int): File offset of corresponding segment
			vaddr (int): Virtual address of corresponding segment
			fileSize (int): Size of corres. segment in file view
			memSize (int): Size of corres. segment in process image
			alignment (int): Alignment describes relation of
				'offset' and 'vaddr', i.e. they must be equal
				modulo 'alignment'

		Returns:
			None

		"""
		# Convert segment type of LIEF to int representation
		# for rawelf call
		self.phtTypeLIEF = phtType
		if (phtType == SEGMENT_TYPES.LOAD):
			self.phtType = SEG_TYPES.PT_LOAD
		elif (phtType == SEGMENT_TYPES.DYNAMIC):
			self.phtType = SEG_TYPES.PT_DYNAMIC
		elif (phtType == SEGMENT_TYPES.INTERP):
			self.phtType = SEG_TYPES.PT_INTERP
		elif (phtType == SEGMENT_TYPES.NOTE):
			self.phtType = SEG_TYPES.PT_NOTE
		elif (phtType == SEGMENT_TYPES.PHDR):
			self.phtType = SEG_TYPES.PT_PHDR
		else:
			raise NotImplementedError(
				'Unsupported segment type {}'.format(phtType)
			)

		# Convert segment flags of LIEF to int
		self.flagsLIEF = flags
		self.flags = 0
		if ((flags & SEGMENT_FLAGS.X) != 0):
			self.flags |= SEG_FLAGS.PF_X
		if ((flags & SEGMENT_FLAGS.W) != 0):
			self.flags |= SEG_FLAGS.PF_W
		if ((flags & SEGMENT_FLAGS.R) != 0):
			self.flags |= SEG_FLAGS.PF_R

		self.offset = offset
		self.vaddr = vaddr
		self.fileSize = fileSize
		self.memSize = memSize
		self.alignment = alignment

	def asSegment(self):
		seg = Segment()
		seg.file_offset = self.offset
		seg.physical_size = self.fileSize
		seg.virtual_address = self.vaddr
		seg.virtual_size = self.memSize
		seg.physical_address = seg.virtual_address
		seg.type = self.phtTypeLIEF
		seg.flags = self.flagsLIEF
		seg.alignment = self.alignment
		return seg

class ElfPhtManipulator(ABC):
	"""Program - Header - Table Manipulator

	Abstract pht manipulator class that will be used to provide a common interface
	for all classes that manipulate the PHT in some form in the context of code
	injection.

	Note that all methods are 'private', i.e. they should not be used
	outside of this class or subclass.

	Attributes:
		__entry (ElfPhtEntry): Describes the new PHT entry that will be
			injected.
	
	"""
	
	__entry : ElfPhtEntry

	def __init__(
			self,
			phtType : SEGMENT_TYPES,
			flags : SEGMENT_FLAGS,
			offset : int,
			vaddr : int,
			fileSize : int,
			memSize : int,
			alignment : int):
		"""Initialize attributes with constructor

		Args;
			phtType (SEGMENT_TYPES): Type of segment
			flags (SEGMENT_FLAGS): Flags describe e.g. whether
				the corresponding segment is readable, writable
				or executable
			offset (int): File offset of corresponding segment
			vaddr (int): Virtual address of corresponding segment
			fileSize (int): Size of corres. segment in file view
			memSize (int): Size of corres. segment in process image
			alignment (int): Alignment describes relation of
				'offset' and 'vaddr', i.e. they must be equal
				modulo 'alignment'

		Returns:
			None

		"""
		self.__entry = ElfPhtEntry(
			phtType,
			flags,
			offset,
			vaddr,
			fileSize,
			memSize,
			alignment
		)

	@abstractmethod
	def _manipulatePht(
			self,
			inj) -> Segment:
		"""Injects the new PHT entry

		Abstract declaration of PHT manipulation that will be
		overwritten by all PHT manipulators. It realizes the approach
		used to insert, overwrite etc. a new PHT entry into PHT.

		Args:
			inj (ElfCodeInjector): Injector used to manipulate.

		Returns:
			Description of PHT

		"""
		pass

	def _getEntry(self):
		"""Returns new PHT entry to inject

		Returns:
			New PHT entry of type 'ElfPhtEntry'.
		"""
		return self.__entry

"""
PHT manipulator that will overwrite a PHT entry.
"""
class ElfPhtOverwriter(ElfPhtManipulator):
	"""PHT injection by overwrite

	This class realizes injection of a new PHT entry be overwriting
	an existing PHT entry. The PHT entry to overwrite is identified by
	an index.

	Note that overwriting 'critical' segments may render the target
	binary unusable.

	Attributes:
		__index (int): Index of PHT entry to overwrite.

	"""

	__index : int

	def __init__(
			self,
			phtType : SEGMENT_TYPES,
			flags : SEGMENT_FLAGS,
			offset : int,
			vaddr : int,
			fileSize : int,
			memSize : int,
			alignment : int,
			index : int):
		"""Initialize attributes with constructor

		Args;
			phtType (SEGMENT_TYPES): Type of segment
			flags (SEGMENT_FLAGS): Flags describe e.g. whether
				the corresponding segment is readable, writable
				or executable
			offset (int): File offset of corresponding segment
			vaddr (int): Virtual address of corresponding segment
			fileSize (int): Size of corres. segment in file view
			memSize (int): Size of corres. segment in process image
			alignment (int): Alignment describes relation of
				'offset' and 'vaddr', i.e. they must be equal
				modulo 'alignment'
			index (int): Index of PHT entry to overwrite

		Returns:
			None

		"""
		super().__init__(
			phtType,
			flags,
			offset,
			vaddr,
			fileSize,
			memSize,
			alignment,
		)
		self.__index = index

	def _manipulatePht(self, inj) -> Segment:
		"""Overwrites specified PHT entry

		Args:
			inj (ElfCodeInjector): Injector used to manipulate
				the PHT of a binary

		Returns:
			Segment description

		"""
		entry = self._getEntry()
		elfbin = inj.getElfBinary()

		# Finally perform overwrite
		inj.raw.overwritePhtEntry(
			entry.phtType,
			entry.flags,
			entry.offset,
			entry.vaddr,
			entry.fileSize,
			entry.memSize,
			entry.alignment,
			self.__index
		)

		# Return new segment description
		return elfbin.getBinary().segments[self.__index]

	def _getIndex(self):
		"""Returns index of PHT entry to overwrite
		
		Returns:
			Index
		"""
		return self.__index

class ElfPhtAppender(ElfPhtManipulator):
	"""PHT injection by insertion

	This class realizes injection of a new PHT entry by appending the
	new entry to the existing PHT.

	Inserting at a specified index is currently out of scope,
	because this requires to rewrite patching routines of rawelf
	(and maybe LIEF).

	"""

	def __init__(
			self,
			phtType : SEGMENT_TYPES,
			flags : SEGMENT_FLAGS,
			offset : int,
			vaddr : int,
			fileSize : int,
			memSize : int,
			alignment : int):
		"""Initialize attributes with constructor

		Args;
			phtType (SEGMENT_TYPES): Type of segment
			flags (SEGMENT_FLAGS): Flags describe e.g. whether
				the corresponding segment is readable, writable
				or executable
			offset (int): File offset of corresponding segment
			vaddr (int): Virtual address of corresponding segment
			fileSize (int): Size of corres. segment in file view
			memSize (int): Size of corres. segment in process image
			alignment (int): Alignment describes relation of
				'offset' and 'vaddr', i.e. they must be equal
				modulo 'alignment'

		Returns:
			None

		"""
		super().__init__(
			phtType,
			flags,
			offset,
			vaddr,
			fileSize,
			memSize,
			alignment,
		)

	def _manipulatePht(self, inj) -> Segment:
		"""Appends new entry to PHT

		Args:
			inj (ElfCodeInjector): Injector used to manipulate
				the PHT of a binary.
		
		Returns:
			Segment description

		"""
		entry = self._getEntry()
		elfbin = inj.getElfBinary()

		# Finally perform overwrite
		result = inj.raw.appendPhtEntry(
			entry.phtType,
			entry.flags,
			entry.offset,
			entry.vaddr,
			entry.fileSize,
			entry.memSize,
			entry.alignment,
		)

		# Return new segment description
		segs = elfbin.getBinary().segments
		return segs[len(segs) - 1]