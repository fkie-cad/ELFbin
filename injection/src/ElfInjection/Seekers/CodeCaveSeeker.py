from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple

from lief.ELF import SEGMENT_TYPES

from ..Binary import ElfBinary


@dataclass
class ElfCodeCave:
    """Code Cave Information

    Stores all required information on a code cave such that
    it can be used for injection.

    Attributes:
            offset (int): File offset of the code cave
            vaddr (int): Virtual address of code cave
            size (int): Size of the code cave in bytes

    """

    offset: int
    vaddr: int
    size: int

    def __init__(self, offset: int, vaddr: int, size: int):
        """Initialize attributes by constructor

        Args:
                offset (int): File offset of the code cave
                vaddr (int): Virtual address of code cave
                size (int): Size of the code cave in bytes
        """
        self.offset = offset
        self.vaddr = vaddr
        self.size = size

    def __eq__(self, other):
        """Compares this instance to another instance

        Args:
            other (ElfCodeCave): Other instance to compare with

        Result:
            True, of this instance and the other instance are
                equal as regards their members.

        """
        return (
            self.offset == other.offset
            and self.vaddr == other.vaddr
            and self.size == other.size
        )


class ElfCodeCaveSeeker(ABC):
    """Code Cave Seeker

    Abstract seeker class that will be used for providing a
    common interface for all concrete seeker classes.

    """

    __caveSize: int

    def __init__(self, caveSize: int):
        """Initialize attributes by constructor

        Args:
                caveSize (int): Lower bound on cave size.

        """
        self.__caveSize = caveSize

    @abstractmethod
    def _seekCave(self, elfbin: ElfBinary) -> ElfCodeCave:
        """Tries to find a code cave

        Declaration of seeker function that will be
        implemented by all other, concrete seekers.

        Args:
            elfbin (ElfBinary): Extended binary object
                that represents the binary to search in

        Returns:
                A list of code caves (can be empty)

        """
        pass

    def _getCaveSize(self):
        """Returns cave size

        Returns:
                Cave size

        """
        return self.__caveSize


class ElfSegmentSeeker(ElfCodeCaveSeeker):
    """Segment - based Code Cave Seeker

    Provides functionality to search for code caves.

    """

    def __init__(self, caveSize: int):
        super().__init__(caveSize)

    def __getCaves(self, segments: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Search for code caves in given segments

        Uses that segments are no more than memory chunks at
        their core. Thus seeking code caves boils down to
        analysing the size and position of those chunks.

        Args:
            segments (List[Tuple[int, int]]): List of memory
                chunk descriptions of all "relevant" (e.g.
                loadable) segments.

        Returns:
            List of memory chunks representing code caves.
                Those memory chunks are just unused regions
                between the memory chunks of given segments.
        """
        # Sort segments descendingly by size
        segments = sorted(segments, key=lambda s: -s[1])

        # Identify segments that are part of another segment.
        # Key observation is that a bigger segment can never
        # be contained in a smaller segment.
        contained = []
        for ndx, big in enumerate(segments):
            for small in segments[ndx + 1:]:
                if big[0] <= small[0] and big[0] + big[1] >= small[0] + small[1]:
                    # big contains small
                    contained.append(small)

        # Remove contained segments as only their containing
        # segments are relevant
        segments = [s for s in segments if s not in contained]
        segments = sorted(segments, key=lambda s: s[0])

        # Compute empty space between segments, i.e. code caves
        caves = [
            (s1[0] + s1[1], s2[0] - (s1[0] + s1[1]))
            for s1, s2 in zip(segments[:-1], segments[1:])
            if s2[0] - (s1[0] + s1[1]) >= self._getCaveSize()
        ]

        return caves

    def _seekCave(self, elfbin: ElfBinary) -> List[ElfCodeCave]:
        """Tries to find code caves

        Searches for a code cave by looking at all segments and
        determining unused memory between top-level loadable
        segments.

        For that it first searches for caves in the file view and
        in process image. Then it will create pairs of file view
        caves and process image caves. Theoretically, every
        code cave in file view can be combined with any code
        cave in the process image.

        Args:
            elfbin (ElfBinary): Binary to search in

        Returns:
            List of code caves

        """
        b = elfbin.getBinary()

        # Get loadable segments by descending size wrt. file view
        segments = [
            (seg.file_offset, seg.physical_size)
            for seg in b.segments
            if seg.type == SEGMENT_TYPES.LOAD
        ]

        fileViewCaves = self.__getCaves(segments)
        if not fileViewCaves:
            return []

        # Get code caves in process image
        segments = [
            (seg.virtual_address, seg.virtual_size)
            for seg in b.segments
            if seg.type == SEGMENT_TYPES.LOAD
        ]

        processImageCaves = self.__getCaves(segments)
        if not processImageCaves:
            return []

        # Combine one file view cave with one process image
        # cave. There can be different amounts of caves.
        caves = [
            ElfCodeCave(
                fileViewCaves[i][0],
                processImageCaves[i][0],
                min(fileViewCaves[i][1], processImageCaves[i][1]),
            )
            for i in range(min(len(fileViewCaves), len(processImageCaves)))
        ]

        return caves
