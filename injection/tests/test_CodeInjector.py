import pytest
import lief
import random

from ElfInjection.CodeInjector import *
from ElfInjection.Seekers.CodeCaveSeeker import *
from ElfInjection.Manipulators.PhtManipulator import ElfPhtOverwriter
from ElfInjection.Manipulators.PhtManipulator import ElfPhtAppender
from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryOverwriter
from ElfInjection.Manipulators.MemoryManipulator import ElfMemoryInserter
from ElfInjection.Manipulators.StringManipulator import ElfStringFinder
from ElfInjection.Manipulators.StringManipulator import ElfStringInserter


class TestElfCodeInjector:
    """
    There will be no tests for segment - based code injection, because
    those techniques are either fully based on LIEF or rawelf
    """

    @pytest.mark.parametrize("caveIndex", range(3))
    @pytest.fixture
    def pht_overwriter(self, lief_loadable_segment, arm_android_bin_caves, caveIndex):
        cave = arm_android_bin_caves[caveIndex]
        return ElfPhtOverwriter(
            lief.ELF.SEGMENT_TYPES.LOAD,
            lief.ELF.SEGMENT_FLAGS(1 + 4),  # r+x
            cave.offset,
            cave.vaddr,
            cave.size,
            cave.size,
            0x1000,
            12,
        )

    @pytest.mark.codeCaves
    @pytest.mark.parametrize("caveIndex", range(3))
    def test_inject_code_cave_pht_overwriter(
        self,
        arm_android_bin,
        inj_arm_android_bin,
        arm_android_bin_caves,
        caveIndex,
        lief_loadable_segment,
        pht_overwriter,
    ):
        # Perform code cave based injection
        cave = arm_android_bin_caves[caveIndex]
        sc, seg = inj_arm_android_bin.injectCodeCave(
            pht_overwriter, cave, b"\x42" * cave.size
        )

        # Compare returned shellcode and cave
        assert sc.offset == cave.offset
        assert sc.vaddr == cave.vaddr
        assert sc.size == cave.size

        # Check segment
        assert seg.type == lief.ELF.SEGMENT_TYPES.LOAD
        assert seg.file_offset == sc.offset
        assert seg.virtual_address == sc.vaddr
        assert seg.physical_address == sc.vaddr
        assert seg.physical_size == sc.size
        assert seg.virtual_size == sc.size
        assert seg.has(lief.ELF.SEGMENT_FLAGS(1 + 4))
        assert seg.content[0] == ord(b"\x42")
        assert seg.alignment == 0x1000

    @pytest.mark.parametrize("caveIndex", range(3))
    @pytest.fixture
    def pht_appender(self, lief_loadable_segment, arm_android_bin_caves, caveIndex):
        cave = arm_android_bin_caves[caveIndex]
        return ElfPhtAppender(
            lief.ELF.SEGMENT_TYPES.LOAD,
            lief.ELF.SEGMENT_FLAGS(1 + 4),  # r+x
            cave.offset,
            cave.vaddr,
            cave.size,
            cave.size,
            0x1000,
        )

    @pytest.mark.codeCaves
    @pytest.mark.parametrize("caveIndex", range(3))
    def test_inject_code_cave_pht_inserter(
        self,
        arm_android_bin,
        inj_arm_android_bin,
        arm_android_bin_caves,
        caveIndex,
        lief_loadable_segment,
        pht_appender,
    ):
        # Perform injection
        cave = arm_android_bin_caves[caveIndex]
        sc, seg = inj_arm_android_bin.injectCodeCave(
            pht_appender, cave, b"\x42" * cave.size
        )

        # Inserting a pht entry shifts everything by 0x38
        # (64 bit), unless there is already additional
        # space allocated by LIEF, which is the case for
        # 'arm_android_bin'
        assert sc.offset == cave.offset
        assert sc.vaddr == cave.vaddr
        assert sc.size == cave.size

        # Fixture lief binary is still outdated after patch
        elfbin = inj_arm_android_bin.getElfBinary()
        lief_arm_android_bin = elfbin.getBinary()

        assert seg.type == lief.ELF.SEGMENT_TYPES.LOAD
        assert seg.file_offset == sc.offset
        assert seg.virtual_address == sc.vaddr
        assert seg.physical_size == sc.size
        assert seg.virtual_size == sc.size
        assert seg.has(lief.ELF.SEGMENT_FLAGS(1 + 4))
        assert seg.content[0] == ord(b"\x42")
        assert seg.alignment == 0x1000

    # TODO: FIX THIS
    @pytest.mark.codeCaves
    @pytest.mark.parametrize("caveIndex", range(6))
    def test_inject_code_cave(
        self,
        lief_arm_android_bin,
        inj_arm_android_bin,
        arm_android_bin_caves_nopht,
        caveIndex,
    ):
        """
        NOTE: This test does NOT cover all cases in
        'injectCodeCave(None,..)', because it would be too time
        consuming to write them.
        """
        cave = arm_android_bin_caves_nopht[caveIndex]
        sc, seg = inj_arm_android_bin.injectCodeCave(None, cave, b"\x42" * cave.size)

        assert not seg
        assert sc.offset == cave.offset
        assert sc.size == cave.size

        # We do NOT check this anymore, because code cave seeker now
        # finds file and process image caves at once and thus the vaddr
        # of a cave can differ, because the process image cave
        # might be surrounded by different loadables than
        # the file view code cave --> different vaddr
        # -> in case 'phtManip=None', only file view caves
        # are considered
        # assert(sc.vaddr == cave.vaddr)

        # Get updated version of binary
        elfbin = inj_arm_android_bin.getElfBinary()
        lief_arm_android_bin_second = elfbin.getBinary()

        # Get segment(s) that contain code cave
        seg = lief_arm_android_bin_second.segment_from_offset(sc.offset)
        seg2 = lief_arm_android_bin_second.segment_from_offset(sc.offset + sc.size - 1)

        # Verify that cave is in ONE loadble segment
        assert seg
        assert seg.type == lief.ELF.SEGMENT_TYPES.LOAD
        assert seg == seg2

        # Get segment in old binary, i.e. before injection
        # and adjustment of PHT took place, that is at the
        # same offset as the code cave --> most likely None
        old = lief_arm_android_bin.segment_from_offset(seg.file_offset)

        # If segment was expanded to the bottom
        if seg.file_offset < sc.offset:

            # If segment and cave overlap
            overlap = (old.file_offset + old.physical_size) - sc.offset
            if overlap < 0:
                overlap = 0

            # Check contents of cave
            assert seg.content[sc.offset - seg.file_offset] == ord(b"\x42")
            assert seg.content[sc.offset - seg.file_offset + sc.size - 1] == ord(
                b"\x42"
            )

            # Check sizes
            assert old.physical_size + sc.size - overlap == seg.physical_size
            assert old.virtual_size + sc.size - overlap == seg.virtual_size

        # If segment was expanded to the top and the
        # segment contains more than just the cave, i.e.
        # its size has not been 0. We have to ensure the
        # latter, because there might be something off
        # with what 'old' is, i.e. 'segment_from_offset'
        # can return segment that is not meant.
        elif seg.file_offset == sc.offset and seg.physical_size > sc.size:

            # Check contents
            assert seg.content[0] == ord(b"\x42")
            assert seg.content[sc.size - 1] == ord(b"\x42")

            # In case cave starts not in loadable
            if not old:
                # Get old segment, in which code cave ends.
                # As caves that do not overlap with any
                # loadables will be assigned to their
                # predecessor: If segment is expanded to top
                # then cave is partially ending in loadable
                # -> must be 'old != None'
                old = lief_arm_android_bin.segment_from_offset(sc.offset + sc.size)

            # If segment and cave overlap
            overlap = sc.offset + sc.size - old.file_offset
            if overlap < 0:
                overlap = 0
            assert old.file_offset - sc.size + overlap == seg.file_offset
            assert old.physical_size + sc.size - overlap == seg.physical_size
            assert old.virtual_size + sc.size - overlap == seg.virtual_size

            # Cannot check this, as LIEF might shuffle around
            # segments again. Thus the virtual address might
            # be off.
            # assert(old.virtual_address - sc.size + overlap == seg.virtual_address)

    @pytest.mark.entry
    @pytest.mark.parametrize("entry", [0x42424242, 0x41424142, 0x0])
    def test_overwrite_entrypoint(
        self, lief_arm_android_bin, inj_arm_android_bin, entry
    ):

        # Check for old value given by injection
        assert (
            inj_arm_android_bin.overwriteEntryPoint(entry)
            == lief_arm_android_bin.entrypoint
        )

        # Check new value
        binary = inj_arm_android_bin.getElfBinary().getBinary()
        assert binary.entrypoint == entry

    @pytest.fixture
    def pht_manipulators(self):
        offset = 0x4000
        vaddr = 0xC000
        fileSize = 0x1740
        memSize = 0x1740
        segType = lief.ELF.SEGMENT_TYPES.LOAD
        return [
            ElfPhtOverwriter(
                segType,
                lief.ELF.SEGMENT_FLAGS(1 + 4),
                offset,
                vaddr,
                fileSize,
                memSize,
                0x1,
                12,
            ),
            ElfPhtAppender(
                lief.ELF.SEGMENT_TYPES.LOAD,
                lief.ELF.SEGMENT_FLAGS(1 + 4),
                offset,
                vaddr,
                fileSize,
                memSize,
                0x1000,
            ),
        ]

    @pytest.fixture
    def memory_manipulators(self):
        offset = 0x4000
        size = 0x1740
        return [
            ElfMemoryOverwriter(offset, b"\x42" * size),
            ElfMemoryInserter(offset, b"\x42" * size),
        ]

    @pytest.mark.segment
    @pytest.mark.parametrize("phtIndex", range(2))
    @pytest.mark.parametrize("memoryIndex", range(2))
    @pytest.mark.parametrize("useLief", [True, False])
    def test_inject_segment(
        self,
        inj_arm_android_bin,
        pht_manipulators,
        phtIndex,
        memory_manipulators,
        memoryIndex,
        useLief,
    ):
        phtManip = pht_manipulators[phtIndex]
        newSeg = phtManip._getEntry().asSegment()
        memoryManip = memory_manipulators[memoryIndex]

        # First check support
        if useLief:
            if (
                isinstance(phtManip, ElfPhtAppender)
                and isinstance(memoryManip, ElfMemoryOverwriter)
            ) or (
                isinstance(phtManip, ElfPhtOverwriter)
                and isinstance(memoryManip, ElfMemoryInserter)
            ):
                pytest.skip("Unsupported combination")
            else:
                pytest.skip("Assume LIEF is correct")
        else:
            if isinstance(memoryManip, ElfMemoryInserter):
                pytest.skip(
                    "ElfCodeInjector.raw.insertMemory"
                    + " will crash LIEF upon reparse -> skip"
                )

        # Get old LIEF binary
        oldBinary = inj_arm_android_bin.getElfBinary().getBinary()

        # Perform segment injection
        seg = inj_arm_android_bin.injectSegment(phtManip, memoryManip, useLief=useLief)

        # Get updates LIEF binary object
        binary = inj_arm_android_bin.getElfBinary().getBinary()

        # Check returned segment. We do this manually,
        # because 'newSeg' is just a PHT entry, i.e.
        # 'newSeg.content' is undefined
        assert seg.file_offset == newSeg.file_offset
        assert seg.virtual_address == newSeg.virtual_address
        assert seg.physical_size == newSeg.physical_size
        assert seg.virtual_size == newSeg.virtual_size
        assert seg.physical_address == newSeg.physical_address
        assert seg.type == newSeg.type
        assert seg.has(newSeg.flags)
        assert seg.alignment == newSeg.alignment
        assert seg.content[0] == ord(b"\x42")
        assert seg.content[seg.physical_size - 1] == ord(b"\x42")

        # Check existence of segment at specified
        # position
        if isinstance(phtManip, ElfPhtOverwriter):
            assert binary.segments[phtManip._getIndex()] == seg

            # Check memory
            if isinstance(memoryManip, ElfMemoryOverwriter):
                assert oldBinary.eof_offset == binary.eof_offset
            elif isinstance(memoryManip, ElfMemoryInserter):
                assert oldBinary.eof_offset + seg.physical_size == binary.eof_offset
            else:
                assert False

        elif isinstance(phtManip, ElfPhtAppender):
            assert binary.segments[len(binary.segments) - 1] == seg

            # Check memory
            if isinstance(memoryManip, ElfMemoryOverwriter):
                # arm_android_bin was already prepared using
                # LIEF --> PHT extended --> rawelf injector
                # will overwrite dummy memory after last
                # PHT entry
                assert (
                    oldBinary.eof_offset
                    # + binary.header.program_header_size
                    == binary.eof_offset
                )
            elif isinstance(memoryManip, ElfMemoryInserter):
                assert (
                    oldBinary.eof_offset
                    + binary.header.program_header_size
                    + seg.physical_size
                    == binary.eof_offset
                )
            else:
                assert False
        else:
            assert False

    @pytest.fixture
    def dynamic_manipulators(self):
        value = 100
        return [
            ElfDynamicOverwriter(
                lief.ELF.DYNAMIC_TAGS.NEEDED, value + 100, random.randint(0, 10)
            ),
            ElfDynamicOverwriter(
                lief.ELF.DYNAMIC_TAGS.DEBUG, value + 100, random.randint(0, 10)
            ),
            ElfDynamicInserter(lief.ELF.DYNAMIC_TAGS.NEEDED, value + 100),
        ]

    @pytest.fixture
    def string_manipulators(self):
        return [ElfStringFinder(), ElfStringInserter("hello_there")]

    @pytest.mark.dynamic
    @pytest.mark.parametrize("dynamicIndex", range(3))
    @pytest.mark.parametrize("stringIndex", range(1))
    def test_inject_dynamic(
        self,
        inj_arm_android_bin,
        dynamic_manipulators,
        dynamicIndex,
        string_manipulators,
        stringIndex,
    ):
        stringManip = string_manipulators[stringIndex]
        dynamicManip = dynamic_manipulators[dynamicIndex]

        # If we use LIEF, we dont test it -> assume
        # LIEF is correct
        if (
            isinstance(stringManip, ElfStringInserter)
            and isinstance(dynamicManip, ElfDynamicInserter)
        ) or (
            isinstance(stringManip, ElfStringInserter)
            and isinstance(dynamicManip, ElfDynamicOverwriter)
        ):
            pytest.skip("Assume LIEF is correct.")

        # Perform injection
        dyn = inj_arm_android_bin.injectDynamic(stringManip, dynamicManip)

        # Check contents of entry
        entry = dynamicManip._getEntry()
        assert dyn.tag == entry.tagLIEF
        assert dyn.value == entry.value

        # Check position
        binary = inj_arm_android_bin.getElfBinary().getBinary()
        if isinstance(dynamicManip, ElfDynamicOverwriter):
            assert binary.dynamic_entries[dynamicManip._getIndex()] == dyn
        elif isinstance(dynamicManip, ElfDynamicInserter):
            for d in binary.dynamic_entries:
                if d == dyn:
                    return
            assert False
        else:
            assert False
