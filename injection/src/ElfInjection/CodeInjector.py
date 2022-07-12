from dataclasses import dataclass
from typing import List, Tuple  # need this because we are currently in python 3.8.10

from lief.ELF import Binary
from lief.ELF import Segment
from lief.ELF import SEGMENT_TYPES
from lief.ELF import Symbol
from lief.ELF import DynamicEntry

from .Binary import ElfBinary
from .Manipulators.PhtManipulator import ElfPhtManipulator
from .Manipulators.PhtManipulator import ElfPhtOverwriter
from .Manipulators.PhtManipulator import ElfPhtAppender
from .Manipulators.MemoryManipulator import ElfMemoryManipulator
from .Manipulators.MemoryManipulator import ElfMemoryOverwriter
from .Manipulators.MemoryManipulator import ElfMemoryInserter
from .Manipulators.StringManipulator import ElfStringManipulator
from .Manipulators.StringManipulator import ElfStringInserter
from .Manipulators.DynamicManipulator import ElfDynamicManipulator
from .Manipulators.DynamicManipulator import ElfDynamicInserter
from .Manipulators.DynamicManipulator import ElfDynamicOverwriter
from .Manipulators.DynsymManipulator import ElfDynsymManipulator
from .Seekers.CodeCaveSeeker import ElfCodeCaveSeeker
from .Seekers.CodeCaveSeeker import ElfCodeCave
from .RawElfInjection import RawElfInjector
from .Manipulators.DynamicManipulator import DYN_TAGS


@dataclass
class ElfShellcode:
    """Shell Code Information

    Describes the position of shellcode that has been injected.

    Attributes:
            offset (int): File offset of injected shell code
            vaddr (int): Virtual address of injected shell code
            size (int): Size in bytes of injected shell code
    """

    offset: int
    vaddr: int  # Is this necessary??
    size: int

    def __init__(self, offset: int, vaddr: int, size: int):
        """Initialize attributes by constructor

        Args:
                offset (int): File offset of injected shell code
                vaddr (int): Virtual address of injected shell code
                size (int): Size in bytes of injected shell code

        """
        self.offset = offset
        self.vaddr = vaddr
        self.size = size


class ElfCodeInjector:
    """Elf - based Code Injector

    CAUTION: Some functions use a different ELF parser and thus
    require calls to 'lief.ELF.Binary.write'. This might invalidate
    references in segment objects etc., because LIEF likes to
    "restructure" (i.e. build) the binary before writing it to file.

    Provides different ways to inject code and make that injected code
    executable.

    TODO: CHECK BELOW
    Note that with LIEF being the underlying ELF parser, all code
    injection techniques will NOT work on binaries that do not have a
    SHT, i.e. that are maximally stripped.

    Attributes:
            __bin (ElfBinary): Binary to manipulate
            raw (Raw): Encapsulates injections based on rawelf parser

    """

    class Raw:
        """Rawelf injection encapsulator

        Encapsulates rawelf - based injection s.t. the user can easily
        access them without fighting RawElfInjector.

        """

        __bin: ElfBinary

        def __init__(self, elfbin: ElfBinary):
            self.__bin = elfbin

        def overwriteMemory(self, offset: int, buffer: bytes):
            """Overwrites specified memory region

            The size of the memory region to overwrite is indirectly given
            by the length of 'buffer'. The buffer must not be empty.
            Args:
                    offset (int): File offset of memory region to overwrite
                    buffer (bytes): Bytes to write into memory region

            Returns:
                    None

            """
            if len(buffer) == 0:
                raise ValueError("Invalid buffer length")

            self.__bin._storetemp()
            rawInj = RawElfInjector(self.__bin._getTempName())
            rawInj.overwriteMemory(offset, buffer)
            self.__bin._reparsetemp()

        def insertMemory(self, offset: int, buffer: bytes):
            """Inserts new memory into specified region

            The amount of bytes to be inserted is given implicitly by
            the length of 'buffer'.

            Inserting memory can break cross - references.

            Args:
                    offset (int): File offset that specifies where to "open
                            a gap" and to fill that gap with given buffer.
                    buffer (bytes): Bytes to write into gap.

            Returns:
                    None

            """
            # raise NotImplementedError(
            # 	'Currently causes python to crash after'
            # 	+ ' successfully inserting memory...'
            # )
            self.__bin._storetemp()
            rawInj = RawElfInjector(self.__bin._getTempName())
            rawInj.insertMemory(offset, buffer)
            self.__bin._reparsetemp()

        def appendPhtEntry(
            self,
            ptype: int,
            flags: int,
            offset: int,
            vaddr: int,
            fileSize: int,
            memSize: int,
            align: int,
        ) -> int:
            """Appends a new PHT entry to PHT
            Args:
                    ptype (int): Type of the segment
                    flags (int): Access rights for described segment. Either
                            PF_X(0x1), PF_W(0x2), PF_R(0x4) or a combination of
                            those.
                    offset (int): File offset of described segment.
                    vaddr (int): Virtual address of described segment.
                    fileSize (int): Size of segment in file.
                    memSize (int): Size of segment in process image.
                    align (int): Alignment s.t. offset = vaddr mod align.

            Returns:
                    Offset of appended PHT entry.

            """
            self.__bin._storetemp()
            rawInj = RawElfInjector(self.__bin._getTempName())
            result = rawInj.appendPhtEntry(
                ptype, flags, offset, vaddr, fileSize, memSize, align
            )
            self.__bin._reparsetemp()
            return result

        def overwritePhtEntry(
            self,
            ptype: int,
            flags: int,
            offset: int,
            vaddr: int,
            fileSize: int,
            memSize: int,
            align: int,
            index: int,
        ) -> None:
            """Overwrites an existing PHT entry
            Args:
                    ptype (int): Type of the segment
                    flags (int): Access rights for described segment. Either
                            PF_X(0x1), PF_W(0x2), PF_R(0x4) or a combination of
                            those.
                    offset (int): File offset of described segment.
                    vaddr (int): Virtual address of described segment.
                    fileSize (int): Size of segment in file.
                    memSize (int): Size of segment in process image.
                    align (int): Alignment s.t. offset = vaddr mod align.
                    index (int): Index of PHT entry to overwrite.

            Returns:
                    None

            """
            self.__bin._storetemp()
            rawInf = RawElfInjector(self.__bin._getTempName())
            rawInf.overwritePhtEntry(
                ptype, flags, offset, vaddr, fileSize, memSize, align, index
            )
            self.__bin._reparsetemp()

        def appendDynamicEntry(self, tag: DYN_TAGS, value: int) -> int:
            """Appends a .dynamic entry

            This function "naively" appends a new entry to .dynamic. Notice
            that with "normal" gcc builds, the .got section comes
            immediately after .dynamic. For x86_64 PIEs that use addressing
            of a form like "[rip + <offset to got entry>]", this function
            will break the reference and most likely cause a crash.

            Args:
                    tag (DYN_TAGS): Tag of the entry
                    value (int): Value of the entry

            Returns:
                    File offset of the new entry

            """
            self.__bin._storetemp()
            rawInf = RawElfInjector(self.__bin._getTempName())
            result = rawInf.appendDynamicEntry(tag, value)
            self.__bin._reparsetemp()
            return result

        def overwriteDynamicEntry(self, tag: DYN_TAGS, value: int, index: int) -> None:
            """Overwrites a .dynamic entry

            Args:
                    tag (DYN_TAGS): Tag of new entry
                    value (int): Value of new entry
                    index (int): Index of entry to overwrite

            Returns:
                    None

            """
            self.__bin._storetemp()
            rawInf = RawElfInjector(self.__bin._getTempName())
            result = rawInf.overwriteDynamicEntry(tag, value, index)
            self.__bin._reparsetemp()
            return result

    __bin: ElfBinary
    raw: Raw

    def __init__(self, elfbin: ElfBinary):
        """Initialize attributes with constructor

        Args:
                elfbin (ElfBinary): Binary to manipulate

        """
        self.__bin = elfbin
        self.raw = ElfCodeInjector.Raw(self.__bin)

    def injectCodeCave(
        self, phtManip: ElfPhtManipulator, codeCave: ElfCodeCave, data: bytes
    ) -> Tuple[ElfShellcode, Segment]:
        """Injects data into given code cave

        Note that there are several ways of adding a code cave into
        the process image. Theoretically, a new PHT entry can be
        inserted. Similarly an existing PHT entry may be overwritten
        to fully describe the code cave as a new segment. For these
        behaviours, set 'phtManip' to the corresponding manipulator.

        If the code cave should be part of another segment, i.e. an
        existing segment should be expanded, 'phtManip' can be set to
        None. Thus an adjacent segment will be expanded manually.

        This function assumes that there is no code cave
        before the first loadable segment and after the last loadable
        segment. Also it assumes that a code cave does not contain a
        valid segment, i.e. it will only check the first and last
        offset of the code cave for lying in a segment. In addition
        to that it assumes that a code cave is at most split up over
        two different segments, i.e. e.g. the first half of the cave
        may lie in one segment and the other half may lie in another
        segment. In the latter case the user is responsible for
        ensuring that the access rights (i.e. R,W,X) fit.

        There is a plethora of side effects. LIEF's "usual" side
        effect is that every call to 'lief.ELF.Binary.write' results
        in a resize of the binary. Other possible side effects are
        redefining an existing NOTE-segment to a loadable segment;
        soft permutation of pht etc..

        As 'codeCave' contains two code caves, one in file
        view and one in process image, for 'phtManip = None'
        only the file view code cave is used. This is due to
        the fact that this function expands some segment in
        the file view as well as in the process image, thus
        not considering other virtual code caves. Thus it
        would be an "upgrade", if this function handles file
        view code cave and process image code cave separately.

        Due to LIEF changing the binary on write to file,
        the values in the returned shellcode object are
        only valid at runtime before 'lief.ELF.Binary.write'
        is called.

        Args:
                phtManip (ElfPhtManipulator): Carries information on pht-
                        based injection and implements injection routines.
                codeCave (ElfCodeCave): Code cave to use.
                data (bytes): Data to write into the code cave.

        Returns:
                A description of injected data, or None, if not
                        supported. Also a corresponding segment is
                        returned, if PHT - based injection is used.

        """

        def findLoadable(b: Binary, cave: ElfCodeCave):
            """Tries to find a loadable segment

            The result must precede or contain the code cave.

            Args:
                    b (Binary): Binary to search in
                    cave (ElfCodeCave): Code cave, for which to find a
                            preceding loadable segment that can 'swallow' the
                            cave.

            Returns:
                    Loadable segment that precedes or contains the cave, or None if
                    no such segment exists

            """
            loadables = [
                (seg, cave.offset - seg.file_offset)
                for seg in b.segments
                if (seg.type == SEGMENT_TYPES.LOAD and cave.offset >= seg.file_offset)
            ]
            if loadables:
                return min(loadables, key=lambda x: x[1])[0]
            return None

        binary = self.__bin.getBinary()

        if phtManip:
            result = phtManip._manipulatePht(self)

            # Find segment index. Notice that everything
            # needs to be reloaded after rawelf.
            binary = self.__bin.getBinary()
            index = -1
            for i, s in enumerate(binary.segments):
                if result == s:
                    index = i
                    break

            sc = ElfShellcode(
                result.file_offset, result.virtual_address, result.physical_size
            )

            # Write code into cave
            self.raw.overwriteMemory(sc.offset, data)

            # Return segment, if it could be found earlier
            binary = self.__bin.getBinary()
            segment = None
            if index != -1:
                segment = binary.segments[index]
            return (sc, segment)

        if len(data) > codeCave.size:
            raise ValueError("Data size exceeds code cave size.")

        # Note that 'segment_from_offset' seems to always
        # return a loadable segment if possible.
        start = binary.segment_from_offset(codeCave.offset)
        end = binary.segment_from_offset(codeCave.offset + codeCave.size - 1)

        # By assumption there is always a preceding or containing
        # loadable segment. If 'predecessor_size' <= 0, then
        # 'start == end != None'.
        predecessor = findLoadable(binary, codeCave)
        if not predecessor:
            raise RuntimeError(
                "Invariant that there is always a loadable"
                + " segment preceding the code cave is"
                + " violated."
            )

        predecessor_size = (codeCave.offset + codeCave.size) - (
            predecessor.file_offset + predecessor.physical_size
        )

        if not start and not end:
            # Code cave is in not segment. By assumptions
            # 'predecessor' cannot be None
            predecessor.physical_size += predecessor_size
            predecessor.virtual_size += predecessor_size

        elif start and not end:

            # Beginning of code cave partially lies in a segment.
            if start.type == SEGMENT_TYPES.LOAD:
                # Extend loadable segment
                size = (codeCave.offset + codeCave.size) - (
                    start.file_offset + start.physical_size
                )
                start.physical_size += size
                start.virtual_size += size

            else:
                # Expand predecessor
                predecessor.physical_size += predecessor_size
                predecessor.virtual_size += predecessor_size

        elif not start and end:

            # End of code cave partially lies in a segment.
            if end.type == SEGMENT_TYPES.LOAD:
                # Extend loadable segment manually with offsets
                size = end.file_offset - codeCave.offset
                end.file_offset -= size
                end.virtual_address -= size
                end.physical_address -= size
                end.physical_size += size
                end.virtual_size += size

            else:
                # Expand predecessor
                predecessor.physical_size += predecessor_size
                predecessor.virtual_size += predecessor_size

        elif start and end:

            if start == end:

                # Code cave is FULLY contained in a segment
                if start.type != SEGMENT_TYPES.LOAD:
                    # Expand predecessor
                    predecessor.physical_size += predecessor_size
                    predecessor.virtual_size += predecessor_size

            # In this case the code cave is split among (at least)
            # two segments. By assumption the cave can only stretch
            # over two segments.
            elif start.type == SEGMENT_TYPES.LOAD and end.type == SEGMENT_TYPES.LOAD:

                # Expand first segment until it contains the whole
                # cave. Note that at runtime it is not guaranteed
                # that segments are adjacent. Also this may
                # violate assumptions of Dynamic Linker etc.
                # (see AOSP, linker_phdr.c)
                size = (codeCave.offset + codeCave.size) - (
                    start.file_offset + start.physical_size
                )
                start.physical_size += size
                start.virtual_size += size

            elif start.type == SEGMENT_TYPES.LOAD and end.type != SEGMENT_TYPES.LOAD:
                # Extend first segment
                size = (codeCave.offset + codeCave.size) - (
                    start.file_offset + start.physical_size
                )
                start.physical_size += size
                start.virtual_size += size

            elif start.type != SEGMENT_TYPES.LOAD and end.type == SEGMENT_TYPES.LOAD:
                # Extend second segment manually
                size = end.file_offset - codeCave.offset
                end.file_offset -= size
                end.virtual_address -= size
                end.physical_address -= size
                end.physical_size += size
                end.virtual_size += size

            else:
                # Both segments are not loadable
                # Thus expand predecessor
                predecessor.physical_size += predecessor_size
                predecessor.virtual_size += predecessor_size

        # Finally write into code cave
        self.raw.overwriteMemory(codeCave.offset, data)

        # Binary is invalid after rawelf -> renew
        binary = self.__bin.getBinary()

        # We cannot use 'codeCave.vaddr' as virtual address
        # for the shell code, because a code cave consists
        # of a file view code cave and a process image code
        # cave. They may be surrounded by completely
        # different loadables. Thus, either we do not use the
        # process image code cave in case 'phtManip = None'
        # and use LIEF to find the correct virtual address.
        # Or we take the process image code cave and do
        # above calculations again for that cave. We will
        # take the first approach!
        return (
            ElfShellcode(
                codeCave.offset,
                binary.offset_to_virtual_address(codeCave.offset),
                codeCave.size,
            ),
            None,
        )

    def findCodeCaves(self, caveSeeker: ElfCodeCaveSeeker) -> List[ElfCodeCave]:
        """Searches for code caves

        Based upon the given seeker, this function will determine a
        list of code caves that can be used in conjunction with
        'injectCodeCave'.

        Args:
                caveSeeker (ElfCodeCaveSeeker): Seeker that carries
                        information on what code caves to look for and
                        implements the search routine.

        Returns:
                List of code caves

        """
        return caveSeeker._seekCave(self.__bin)

    def injectSegment(
        self, phtManip: ElfPhtManipulator, memManip: ElfMemoryManipulator, useLief=False
    ) -> Segment:
        """Handles segment - based injection

        Assumptions:
        1. If rawelf - based injection is used, then it will
                be assumed that the memory manipulator will NOT
                insert memory into PHT again!
        2. If rawelf - based injection is used, then LIEF does
                NOT change the order to PHT entries after memory
                manipulation --> would invalidate index

        For rawelf - based injection, an index is used to
        keep track a the segment injected, because an
        object of type 'Segment' will be invalid after a
        call to 'memManip._manipulateMemory'.

        Notice that LIEF seems to dislike 'PT_NOTE' segments,
        as LIEF seems to occasionally replace them with 'PT_LOAD'.
        Maybe LIEF strips segments from binary that are not
        part of the process image?

        Also notice that LIEF will reparse the binary after
        each call to rawelf. This means that offsets and
        virtual addresses aswell as sizes of segments can
        change drastically. If above assumptions are met, it
        should not matter what changes are made, because we
        use an index into PHT. Although it is possible for
        offsets to point to different locations afterwards,
        thus resulting in different memory manipulation
        behaviour. This also holds if 'useLief=True' :)

        Trying to insert memory beyond the binary file using
        rawelf will NOT work. It is simply not designed to do
        this.

        Args:
                phtManip (ElfPhtManipulator): Used to manipulate
                        the PHT. Its behaviour depends on given subclass.
                memManip (ElfMemoryManipulator): Used to manipulate
                        memory regions that are supposed to become a
                        segment. Notice that a segment is just a PHT
                        entry with an associated memory region.
                useLief (bool): Defaults to 'False'. Determines
                        whether to use LIEF - based injection, which
                        is more stable than rawelf - based injection
                        but also hard to understand, or rawelf - based
                        injection, which is more direct but allows
                        making small errors that cause immense headache
                        --> know what you are doing!

        Returns:
                LIEF - segment that can be used for further
                        processing

        """
        if useLief:
            # Use LIEF specific function for injection
            if isinstance(phtManip, ElfPhtAppender) and isinstance(
                memManip, ElfMemoryInserter
            ):
                # Construct segment to add
                seg = phtManip._getEntry().asSegment()
                seg.content = list(memManip._getData())
                return self.__bin.getBinary().add(seg)
            elif isinstance(phtManip, ElfPhtOverwriter) and isinstance(
                memManip, ElfMemoryOverwriter
            ):
                # Construct segment to replace with
                seg = phtManip._getEntry().asSegment()
                seg.content = list(memManip._getData())

                # Find segment to replace
                target = self.__bin.getBinary().segments[phtManip._getIndex()]

                return self.__bin.getBinary().replace(seg, target)
            else:
                raise ValueError(
                    "Combination of {} and {}".format(type(phtManip), type(memManip))
                    + " is not supported using LIEF!"
                )
        else:
            # Use rawelf functions for injection

            # Do PHT manipulation
            segment = phtManip._manipulatePht(self)

            # Query index of new PHT entry.
            index = -1
            for i, s in enumerate(self.__bin.getBinary().segments):
                if s == segment:
                    index = i
                    break

            # Do memory manipulation
            memManip._manipulateMemory(self, updatedOffset=segment.file_offset)
            return self.__bin.getBinary().segments[index]

    def overwriteEntryPoint(self, newEntryPoint: int) -> int:
        """Overwrite entry point

        This function will overwrite the entry point sepcified
        in the elf header.

        Note that the entry point is a virtual address and most
        of the code injection techniques work with file offsets.
        Thus a conversion from file offset to virtual address
        might be necessary.

        Also note that the final virtual address in the
        'e_entry' field might NOT correspond to the specified
        value. The reason for this might be that LIEF inserts
        memory regardless of whether some injection took
        place or not. Thus, depending on the location, where
        the data is injected, virtual addresses, file offsets
        and references have to be recomputed, resulting in
        different values.

        Args:
                newEntryPoint (int): New entry point (virtual address)

        Returns:
                Old entry point (virtual address)

        """
        elfhdr = self.__bin.getBinary().header
        oldEntryPoint = elfhdr.entrypoint
        elfhdr.entrypoint = newEntryPoint
        return oldEntryPoint

    def injectDynsym(self, dynsymManip: ElfDynsymManipulator) -> Symbol:
        """.dynsym - based injection

        This function supports injection that focusses on .dynsym.

        Args:
                dynsymManip (ElfDynsymManipulator): .dynsym manipulator
                        carrying information on .dynsym - based injection and
                        implementing manipulation of .dynsym.

        Returns:
                New symbol

        """
        return dynsymManip._manipulateDynsym(self)

    def injectDynamic(
        self, stringManip: ElfStringManipulator, dynamicManip: ElfDynamicManipulator
    ) -> DynamicEntry:
        """.dynamic - based injection

        This function handles various .dynamic-based injection
        types, such as inserting a new .dynamic - entry aswell as
        a new string. It focusses on DT_NEEDED - entries.

        Note that in the setting that an 'ElfDynamicInserter' and
        an 'ElfStringInserter are used, this function will 'ignore'
        the manipulators and only passes the name of the library to
        'lief.ELF.Binary.add_library'.

        Also note that in the case, where an 'ElfDynamicOverwriter'
        and an 'ElfStringInserter' are used, this function will again
        'ignore' the manipulator functions and only pass their
        member variables to 'lief.ELF.Binary.add_library'. First this
        function will call 'lief.ELF.Binary.remove' on the entry to
        overwrite and then it will use 'lief.ELF.Binary.add_library'
        to insert the string (and another .dynamic entry). To that
        end the new DT_NEEDED entry will NOT be placed at the
        specified index, but rather at the very beginning of
        .dynamic. Still the entry referenced by the index will be
        removed.

        In general, one MUST NOT assume that inserting a .dynamic
        entry or overwriting a .dynamic entry results in the new
        entry being at a specified location. Due to this problem,
        this function returns a description of the new entry.

        IMPORTANT NOTE: If 'ElfDynamicOverwriter' is used in
        conjunction with (currently) any other 'ElfStringManipulator'
        than 'ElfStringFinder', then one MUST NOT assume that any
        offsets, virtual addresses and sizes of other objects
        describing the binary's structures are valid. I.e. this
        combination results in an internal call to
        'lief.ELF.Binary.write' that will alter the state of the
        binary and thus probably invalidate objects like
        'ElfShellcode' etc.

        Args:
                stringManip (ElfStringManipulator): String manipulator
                        carrying information on string data for .dynamic
                        and implementing manipulation of .dynstr.
                dynamicManip (ElfDynamicManipulator): .dynamic
                        manipulator carrying information on a .dynamic entry
                        and implementing manipulation of .dynamic.
        Returns:
                Description of new .dynamic - entry

        """
        if isinstance(stringManip, ElfStringInserter) and isinstance(
            dynamicManip, ElfDynamicInserter
        ):
            return self.__bin.getBinary().add_library(stringManip._getString())
        elif isinstance(stringManip, ElfStringInserter) and isinstance(
            dynamicManip, ElfDynamicOverwriter
        ):
            self.__bin.getBinary().remove(
                self.__bin.getBinary().dynamic_entries[dynamicManip._getIndex()]
            )
            return self.__bin.getBinary().add_library(stringManip._getString())

        result = None
        if stringManip:
            result = stringManip._manipulateString(self)

        return dynamicManip._manipulateDynamic(self, updatedString=result)

    def getElfBinary(self) -> ElfBinary:
        """Return current binary

        Returns:
                Binary of type 'ElfBinary'

        """
        return self.__bin
