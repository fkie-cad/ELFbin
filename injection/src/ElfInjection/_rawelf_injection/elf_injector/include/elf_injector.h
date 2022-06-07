/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_INJECTOR_H_
#define _ELF_INJECTOR_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"
#include "elf_patcher.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_injector elf_injector;
typedef struct _elf_binary elf_binary;
typedef struct _elf_section_string_table elf_section_string_table;

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
/*
* Specifies to what segment/section injected data belongs to in case its
*	affiliation cannot be determined unambiguously.
* @ELF_AFFILIATION_NONE: Nothing will be done regarding affiliation of data.
* @ELF_AFFILIATION_UPPER: Data will be 'assigned' to the segment and/or section
*	whose offset + size is less than or equal to the offset of the data.
* @ELF_AFFILIATION_LOWER: Data will be 'assigned' to the segment and/or section
*	whose offset is greater than or equal to the offset + size of the data.
*/
enum elf_injected_data_affiliation;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_injector *elf_injector_init(void);
void elf_injector_free(elf_injector *injector);

// Getter / Setter

// Utility
/*
* 'elf_injector_inject_memory' attempts to inject 'memory' into the target
*	binary. This type of injection inserts additional/new information
*	into the binary, which results in a file being bigger than the
*	original. This technique is the opposite of overriding memory regions,
*	as overriding does not necessarly need the adjustment of offsets/sizes.
* 	Rough approach:
*	1. Resize file, so that the data can fit.
*	2. Move all data, starting at the location where to inject, for
*		memory_size bytes to the back.
*	3. Insert injection memory.
*	4. Adjust all offsets/sizes.
*	This function is not suitable for injecting/creating new sections/
*	segments! Please use dedicated functions or manually adjust e.g. PHT
*	or SHT. It tries to affiliate injected memory with an existing section/
*	segment. Also note that debugging can reveal failure for patching e.g.
*	a DT_RELA section. This is most likely due to the fact that this
*	section does not exist. It is most likely no severe error.
* @injector: Injector to use for injection.
* @bin: Target binary where to inject memory.
* @memory: Buffer of memory to inject.
* @memory_size: Size of 'memory' in bytes.
* @offset: File offset at which to inject 'memory'.
* @affiliation: Determines where injected data belongs in case of ambiguity.
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- calloc
*	- object init failed
* 	- error returned by 'elf_binary_resize'
*	- error returned by 'elf_binary_has_section_header_table'
*	- sht not found
*	- error returned by 'elf_patcher_patch_ehdr' (elf_patcher.h)
*	- error returned by 'elf_patcher_patch_sht' (elf_patcher.h)
*	- error returned by 'elf_patcher_patch_pht' (elf_patcher.h)
*	- error returned by 'elf_get_dynamic' (elf_misc.h)
*	- error returned by 'elf_patcher_patch_dynamic' (elf_patcher.h)
*	- error returned by 'elf_patcher_patch_func_array' (elf_patcher.h)
*	- error returned by 'elf_patcher_patch_dynsym' (elf_patcher.h)
*	- error returned by 'elf_patcher_patch_reloc' (elf_patcher.h)
*/
enum elf_result elf_injector_inject_memory(elf_injector *injector,
	elf_binary *bin, const uint8_t *memory, uint64_t memory_size,
	uint64_t offset,
	enum elf_injected_data_affiliation affiliation);

/*
* 'elf_injector_override_memory' tries to override memory located at 'offset'
*	relative to the base address of the binary. No recalculations are done,
*	as overriding existing memory does not change offsets or sizes of
*	sections, segments...
* @injector: Injector to use for injection.
* @bin: Target binary where memory to override resides in.
* @memory: Buffer with new data. New data will be written to binary.
* @memory_size: Amount of bytes to write to binary.
* @offset: Points to a location where to write the memory to. It is relative
*	to the base address of the binary (base address = mmap).
* @return: Either success or invalid parameters.
*/
enum elf_result elf_injector_override_memory(elf_injector *injector,
	elf_binary *bin, const uint8_t *memory, uint64_t memory_size,
	uint64_t offset);

/*
* 'elf_injector_inject_string' attempts to inject a string into the specified
*	string table. The offset of injected string relative to the beginning
*	of the string table will be returned. This function will first try to
*	abuse padding, if possible, and override the padding. Otherwise new
*	memory will be inserted/injected.
* @injector: Injector to use for injection.
* @bin: Target binary where to inject string.
* @strtab: String table to expand.
* @string: String to insert into 'strtab'.
* @offset: On success this will reference the offset of injected string in
*	relation to the offset of 'strtab'. Otherwise 0 (after parameter
*	validation).
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- error returned by 'elf_section_string_table_get_size'
* 	- error returned by 'elf_get_max_align' (elf_misc.h)
*	- error returned by 'elf_injector_inject_memory'
*	- error returned by 'elf_injector_override_memory'
*/
enum elf_result elf_injector_inject_string(elf_injector *injector,
	elf_binary *bin, elf_section_string_table *strtab, const char *string,
	uint64_t *offset);

/*
* 'elf_injector_inject_segment' tries to inject a new, legitimate segment
*	into 'bin'. The new segment will be described by 'phdr' and contain
*	memory referenced by 'memory'.
* @injector: Injector to use for injection.
* @bin: Target binary where to inject segment.
* @phdr: Program header table entry that will be injected into PHT. Note that
*	this phdr describes the offset and size of the segment and will be used
*	to inject 'memory'. Thus phdr must contain valid information. Currently
*	it is not possible to inject a segment with 'filesz' != 'memsz' by
*	predefined functions. If PHT lies before the new segment, 'phdr' will
*	contain updated values for 'p_offset', 'p_vaddr' and 'p_paddr'.
* @memory: Segment memory that will represent the actual contents of the
*	segment.
* @return: Either success or one of the following:
*	- invalid parameters
* 	- error returned by 'elf_injector_inject_memory'
*/
enum elf_result elf_injector_inject_segment(elf_injector *injector,
	elf_binary *bin, Elf64_Phdr *phdr, uint8_t *memory);

#endif