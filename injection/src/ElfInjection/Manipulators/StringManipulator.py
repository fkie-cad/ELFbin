from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ElfStringData:
    """Contains all data required for string -related actions

    Attributes:
            index (int): Index of string in .dynstr
            string (str): String in .dynstr

    """

    index: int
    string: str

    def __init__(self, index, string):
        """Initialize attributes with constructor

        Args:
                index (int): Index of string in .dynstr
                string (str): String in .dynstr

        """
        self.index = index
        self.string = string


class ElfStringManipulator(ABC):
    """.dynstr manipulator

    Abstract .dynstr manipulator that provides a common
    interface for all .dynstr manipulators.

    """

    @abstractmethod
    def _manipulateString(self, inj) -> ElfStringData:
        """Manipulates .dynstr

        Abstract declaration of .dynstr manipulation that
        will be overwritten by any .dynstr manipulator.

        Args:
                inj (ElfCodeInjector): Injector used to manipulate
                        the binary.

        Returns:
                None

        """
        pass


class ElfStringInserter(ElfStringManipulator):
    """.dynstr manipulation by appending

    Realizes .dynstr manipulation by appending a specified
    string to .dynstr section.

    Note that we cannot simply insert a string at a
    specified index, because there are other references
    that point to strings that would come after the
    inserted string. Thus inserting a string would break
    those references and fixing those references is hard.

    Attributes:
            __string (str): String to append to .dynstr

    """

    __string: str

    def __init__(self, string: str):
        """Initialize attributes with constructor

        Args:
                string (str): String to append to .dynstr

        """
        self.__string = string

    def _manipulateString(self, inj) -> ElfStringData:
        """Appends a specified string to .dynstr.

        Args:
                inj (ElfCodeInjector): Injector used to manipulate
                        the binary.

        Returns:
                String data, if any

        """
        pass

    def _getString(self) -> str:
        """Returns string

        Returns:
                String to be inserted/that was inserted into .dynstr.

        """
        return self.__string


class ElfStringFinder(ElfStringManipulator):
    """Searches for 'fitting' strings

    Instead of manipulating content of .dynstr, this class
    attempts to find 'fitting' substrings of already
    existing strings in .dynstr, which can be used as e.g.
    library names in the context of .dynamic based injection.

    Attributes:
            __defaultLength (int): Describes length of the
                    substring of the name of a library. E.g. if
                    there is a library name 'libc.so', setting
                    '__defaultLength=1' will return 'c.so', setting
                    '__defaultLength=3' will return 'ibc.so' etc.
            __fallbackIndex (int): Index into .dynstr used if
                    there is no string of form '<name>.so'
    """

    __defaultLength: int
    __fallbackIndex: int

    def __init__(self, defaultLength=1, fallbackIndex=1):
        """Initialize attributes with contrustor

        Args:
                __defaultLength (int): Describes length of the
                substring of the name of a library. E.g. if
                there is a library name 'libc.so', setting
                '__defaultLength=1' will return 'c.so', setting
                '__defaultLength=3' will return 'ibc.so' etc.
                Beware of too large values for '__defaultLength'
                        --> out of bounds possible
        __fallbackIndex (int): Index into .dynstr used if
                there is no string of form '<name>.so'

        """
        if defaultLength < 1:
            self.__defaultLength = 1
        else:
            self.__defaultLength = defaultLength

        if fallbackIndex < 0:
            self.__fallbackIndex = 1
        else:
            self.__fallbackIndex = fallbackIndex

    def _manipulateString(self, inj) -> ElfStringData:
        """Seeks for a 'fitting' substring in .dynstr

        Substrings will be searched for in the following way:
        1. Look for substrings of the form '<subname>.so'.
        2. If 1. does not work, take any arbitrary substring.

        Args:
                inj (ElfCodeInjector): Injector used to manipulate
                        the binary.

        Returns:
                Index of substring and substring

        """
        elfbin = inj.getElfBinary()

        # Search for .dynstr.
        dynstr = [sec for sec in elfbin.getBinary().sections if sec.name == ".dynstr"][
            0
        ]

        # Search for '<subname>.so'
        data = bytes(dynstr.content)
        substrings = [
            (
                data.find(sub) + sub.find(b".so") - self.__defaultLength,
                sub[sub.find(b".so") - self.__defaultLength:].decode("UTF-8"),
            )
            for sub in data.split(b"\x00")
            if b".so" == sub[-3:]
        ]

        if substrings and len(substrings) >= 1:
            return ElfStringData(*(substrings[0]))

        # Search for any other string
        return ElfStringData(
            self.__fallbackIndex,
            data.split(b"\x00")[self.__fallbackIndex].decode("UTF-8"),
        )
