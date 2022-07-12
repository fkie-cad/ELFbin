from ._rawelf_injection import rawelf_injection

from .Manipulators.DynamicManipulator import DYN_TAGS


class RawElfInjector:
    """Injection technique supplement for LIEF

    CAUTION: Inserting new memory between a section and its
    references can break those references. E.g. .plt uses
    relative addressing for x86_64 PIEs. Appending a new entry
    to .dynamic for a "classic" gcc build will result in
    broken references to .got.

    CAUTION: Using this class will need the current working
    directory to be writable. This is due to the fact that
    the raw elf parser can only parse a file and is not able
    to take over LIEF's memory representation of the ELF file.
    Thus this class will use 'Binary.write' to store the
    state of the LIEF binary and then reopen the file with the
    raw parser. Eventually, after a function call, LIEF will
    again manage the binary.

    Attributes:
            inj (rawelf_injection.rawelf_injector): Provides
                    missing injection techniques.

    """

    __inj: rawelf_injection.rawelf_injector

    def __init__(self, binName):
        self.__inj = rawelf_injection.rawelf_injector(binName)
        if not self.__inj:
            raise RuntimeError("Failed to load {}".format(binName))

    def appendDynamicEntry(self, tag: DYN_TAGS, value: int) -> int:
        """Appends a .dynamic entry

        This function "naively" appends a new entry to
        .dynamic. Notice that with "normal" gcc builds, the
        .got section comes immediately after .dynamic. For
        x86_64 PIEs that use addressing of a form like
        "[rip + <offset to got entry>]", this function will
        break the reference and most likely cause a crash.

        Args:
                tag (DYN_TAGS): Tag of the entry
                value (int): Value of the entry

        Returns:
                File offset of the new entry

        """
        result = self.__inj.append_dynamic_entry(tag=tag, value=value)
        return result

    def overwriteDynamicEntry(
        self, new_tag: DYN_TAGS, new_value: int, index: int
    ) -> None:
        """Overwrites a .dynamic entry

        Args:
                new_tag (DYN_TAGS): Tag of new entry
                new_value (int): Value of new entry
                index (int): Index of entry to overwrite

        Returns:
                None

        """
        result = self.__inj.overwrite_dynamic_entry(
            tag=new_tag, value=new_value, index=index
        )
        return result

    def appendPhtEntry(
        self,
        ptype: int,
        flags: int,
        offset: int,
        vaddr: int,
        file_size: int,
        mem_size: int,
        align: int,
    ) -> int:
        """Appends a new PHT entry to PHT

        Args:
                ptype (int): Type of the segment
                flags (int): Access rights for described segment.
                        Either PF_X(0x1), PF_W(0x2), PF_R(0x4) or a
                        combination of those.
                offset (int): File offset of described segment.
                vaddr (int): Virtual address of described segment.
                file_size (int): Size of segment in file.
                mem_size (int): Size of segment in process image.
                align (int): Alignment s.t. offset = vaddr mod
                        align.

        Returns:
                Offset of appended PHT entry.

        """
        result = self.__inj.append_pht_entry(
            ptype=ptype,
            flags=flags,
            offset=offset,
            vaddr=vaddr,
            file_size=file_size,
            mem_size=mem_size,
            align=align,
        )
        return result

    def overwritePhtEntry(
        self,
        ptype: int,
        flags: int,
        offset: int,
        vaddr: int,
        file_size: int,
        mem_size: int,
        align: int,
        index: int,
    ) -> None:
        """Overwrites an existing PHT entry

        Args:
                ptype (int): Type of the segment
                flags (int): Access rights for described segment.
                        Either PF_X(0x1), PF_W(0x2), PF_R(0x4) or a
                        combination of those.
                offset (int): File offset of described segment.
                vaddr (int): Virtual address of described segment.
                file_size (int): Size of segment in file.
                mem_size (int): Size of segment in process image.
                align (int): Alignment s.t. offset = vaddr mod
                        align.
                index (int): Index of PHT entry to overwrite.

        Returns:
                None

        """
        result = self.__inj.overwrite_pht_entry(
            ptype=ptype,
            flags=flags,
            offset=offset,
            vaddr=vaddr,
            file_size=file_size,
            mem_size=mem_size,
            align=align,
            index=index,
        )
        return result

    def overwriteMemory(self, offset: int, buffer: bytes) -> None:
        """Overwrites specified memory region

        The size of the memory region to overwrite is
        indirectly given by the length of 'buffer'.

        Args:
                offset (int): File offset of memory region to
                        overwrite
                buffer (bytes): Bytes to write into memory region

        Returns:
                None

        """
        result = self.__inj.overwrite_memory(offset=offset, buffer=buffer)
        return result

    def insertMemory(self, offset: int, buffer: bytes) -> None:
        """Inserts new memory into specified region

        The amount of bytes to be inserted is given implicitly
        by the length of 'buffer'.

        Inserting memory can break cross - references.

        Args:
                offset (int): File offset that specifies where to
                "open a gap" and to fill that gap with given buffer.
                buffer (bytes): Bytes to write into gap.

        Returns:
                None

        """
        result = self.__inj.insert_memory(offset=offset, buffer=buffer)

        return result
