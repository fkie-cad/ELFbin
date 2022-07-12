import pytest

import lief
from ElfInjection.Binary import ElfBinary
from ElfInjection.CodeInjector import ElfCodeInjector
from ElfInjection.Seekers.CodeCaveSeeker import ElfCodeCave


@pytest.fixture
def arm_android_bin():
    return ElfBinary("./arm_android_bin")


@pytest.fixture
def inj_arm_android_bin():
    return ElfCodeInjector(ElfBinary("./arm_android_bin"))


@pytest.fixture
def lief_arm_android_bin():
    b = lief.parse("./arm_android_bin")
    builder = lief.ELF.Builder(b)
    builder.build()
    return b


@pytest.fixture
def arm_android_bin_caves():
    return [
        ElfCodeCave(
            0x19B8, 0x0 + 0x1740, min(0x2000 - 0x19B8, 0x2740 - (0x0 + 0x1740))
        ),
        ElfCodeCave(
            0x2000 + 0x1740,
            0x2740 + 0x278,
            min(0x4000 - (0x2000 + 0x1740), 0x39B8 - (0x2740 + 0x278)),
        ),
        ElfCodeCave(
            0x4000 + 0x1740,
            0x39B8 + 0x8,
            min(0x6000 - (0x4000 + 0x1740), 0x6000 - (0x39B8 + 0x8)),
        ),
    ]


@pytest.fixture
def arm_android_bin_caves_nopht(arm_android_bin_caves):
    return [
        # Expand to top
        ElfCodeCave(
            0x19B8, 0x0 + 0x1740, min(0x2000 - 0x19B8, 0x2740 - (0x0 + 0x1740)) + 0x10
        ),
        # Expand to bottom due to overlap
        ElfCodeCave(
            0x2000 + 0x1740 - 0x10,
            0x2740 + 0x278,
            min(0x4000 - (0x2000 + 0x1740), 0x39B8 - (0x2740 + 0x278)),
        ),
        # Fully in loadable
        ElfCodeCave(0x4000, 0x39B8, 0x100),
    ] + arm_android_bin_caves


@pytest.fixture
def lief_loadable_segment():
    seg = lief.ELF.Segment()
    seg.type = lief.ELF.SEGMENT_TYPES.LOAD
    seg.physical_size = 0x1000
    seg.virtual_size = 0x1000
    seg.file_offset = 0x4000
    seg.virtual_address = 0xC000
    seg.physical_address = seg.virtual_address
    seg.add(lief.ELF.SEGMENT_FLAGS.R)
    seg.add(lief.ELF.SEGMENT_FLAGS.X)
    seg.alignment = 0x1000
    seg.content = [0x42 for _ in range(0x1000)]

    return seg
