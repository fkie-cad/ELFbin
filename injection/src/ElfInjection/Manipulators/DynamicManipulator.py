from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum

from lief.ELF import DynamicEntry
from lief.ELF import DYNAMIC_TAGS


class DYN_TAGS(IntEnum):
    """Symbols for .dynamic tags"""

    DT_NULL = 0
    DT_NEEDED = 1
    DT_SYMTAB = 6
    DT_DEBUG = 21


@dataclass
class ElfDynamicEntry:
    """Contains information on .dynamic - based actions

    Attributes:
            tag (int): Tag of .dynamic entry, e.g. DT_NEEDED
            tagLIEF (DYNAMIC_TAGS): LIEF dynamic tag
            value (int): Value of entry

    """

    tag: int
    tagLIEF: DYNAMIC_TAGS
    value: int

    def __init__(self, tagLIEF: int, value: int):
        """Initialize attributes by constructor

        Also converts LIEF - .dynamic tag to int
        representation.

        Args:
                tag (int): Tag of .dynamic entry, e.g. DT_NEEDED
                value (int): Value of entry

        """
        self.tagLIEF = tagLIEF
        if tagLIEF == DYNAMIC_TAGS.NULL:
            self.tag = DYN_TAGS.DT_NULL
        elif tagLIEF == DYNAMIC_TAGS.NEEDED:
            self.tag = DYN_TAGS.DT_NEEDED
        elif tagLIEF == DYNAMIC_TAGS.SYMTAB:
            self.tag = DYN_TAGS.DT_SYMTAB
        elif tagLIEF == DYNAMIC_TAGS.DEBUG:
            self.tag = DYN_TAGS.DT_DEBUG
        else:
            raise NotImplementedError("Unsupported .dynamic tag {}".format(tagLIEF))

        self.value = value

    def asDynamicEntry(self):
        entry = DynamicEntry()
        entry.tag = self.tag
        entry.value = self.value
        return entry


class ElfDynamicManipulator(ABC):
    """.dynamic manipulator

    Abstract .dynamic manipulator that provides a common
    interface for all .dynamic manipulators.

    Attributes:
            __entry (ElfDynamicEntry): Dynamic entry used for
                    manipulations of .dynamic.

    """

    __entry: ElfDynamicEntry

    def __init__(self, tag: DYNAMIC_TAGS, value: int):
        """Initialize attribute with constructor

        Args:
                tag (DYNAMIC_TAGS): Tag of dynamic entry
                value (int): Value of dynamic entry

        """
        self.__entry = ElfDynamicEntry(tag, value)

    @abstractmethod
    def _manipulateDynamic(self, inj, updatedString=None) -> DynamicEntry:
        """Manipulates .dynamic

        Abstract declaration of .dynamic manipulation that
        will be overwritten by any .dynamic manipulator.

        Args:
                inj (ElfCodeInjector): Injector used for
                        manipulating the binary
                updatedString (ElfStringData): If not None, this
                        will contain string information that can be
                        used especially for DT_NEEDED entries.

        Returns:
                None

        """
        pass

    def _getEntry(self):
        return self.__entry


class ElfDynamicOverwriter(ElfDynamicManipulator):
    """.dynamic manipulation by overwrite

    Realizes .dynamic manipulation by overwriting a specified
    .dynamic entry.

    Attribute:
            __index (int): Index of .dynamic entry to overwrite

    """

    __index: int

    def __init__(self, tag: DYNAMIC_TAGS, value: int, index: int):
        """Initialize attributes with constructor

        Args:
                tag (DYNAMIC_TAGS): Tag of dynamic entry
                value (int): Value of dynamic entry
                index (int): Index of .dynamic entry to overwrite

        """
        super().__init__(tag, value)
        self.__index = index

    def _manipulateDynamic(self, inj, updatedString=None) -> DynamicEntry:
        """Overwrite specified .dynamic entry with new entry

        Note that overwriting arbitrary entries in .dynamic
        will most likely result in an unusable binary. There
        are a few exceptions which can 'securely' be
        overwritten (e.g. DT_DEBUG).

        Args:
                inj (ElfCodeInjector): Injector used for
                        manipulating the binary
                updatedString (ElfStringData): If not None, this
                        will contain string information that can be
                        used especially for DT_NEEDED entries.

        Returns:
                Description of new .dynamic - entry

        """
        elfbin = inj.getElfBinary()
        binary = elfbin.getBinary()
        entry = self._getEntry()

        if updatedString:
            entry.value = updatedString.index

        inj.raw.overwriteDynamicEntry(entry.tag, entry.value, self.__index)

        binary = elfbin.getBinary()
        return binary.dynamic_entries[self.__index]

    def _getIndex(self):
        """Returns index of .dynamic - entry

        Returns:
                Index

        """
        return self.__index


class ElfDynamicInserter(ElfDynamicManipulator):
    """.dynamic manipulation by appending

    Realizes .dynamic manipulation by inserting a new
    .dynamic entry into .dynamic.

    """

    def __init__(self, tag: DYNAMIC_TAGS, value: int):
        """Initialize attributes with constructor

        Args:
                tag (DYNAMIC_TAGS): Tag of dynamic entry
                value (int): Value of dynamic entry

        """
        super().__init__(tag, value)

    def _manipulateDynamic(self, inj, updatedString=None) -> DynamicEntry:
        """Insert new .dynamic entry to .dynamic

        This function temporarily deactivates LIEF and uses rawelf
        to overwrite the dummy debug entry with the new entry.
        This is done because LIEF injects additional data
        for special 'DynamicEntry' - instances, i.e. e.g. for
        DT_NEEDED - entries LIEF will inject a new string into
        .dynstr.

        Args:
                inj (ElfCodeInjector): Injector used to manipulate
                        the binary
                updatedString (ElfStringData): If not None, this
                        will contain string information that can be
                        used especially for DT_NEEDED entries.

        Returns:
                Description of new .dynamic - entry.

        """
        elfbin = inj.getElfBinary()
        binary = elfbin.getBinary()

        # Add dummy entry in .dynamic with LIEF
        debug = DynamicEntry(DYNAMIC_TAGS.DEBUG, 0)
        result = binary.add(debug)

        # Search for dummy entry. LIEF might have shuffled
        # .dynamic for some reason.
        index = -1
        for (i, dyn) in enumerate(binary.dynamic_entries):
            if dyn == result:
                index = i
                break

        # Get entry info
        entry = self._getEntry()

        # Check for updated string
        if updatedString:
            entry.value = updatedString.index

        # Overwrite dummy entry
        inj.raw.overwriteDynamicEntry(entry.tag, entry.value, index)

        # After rawelf operations, binary is invalid
        binary = elfbin.getBinary()
        return binary.dynamic_entries[index]
