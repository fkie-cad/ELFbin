/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_MISC_H_
#define _ELF_MISC_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_binary elf_binary;
typedef struct _elf_segment elf_segment;
typedef struct _elf_section elf_section;
typedef struct _elf_section_dynamic elf_section_dynamic;
typedef struct _elf_section_string_table elf_section_string_table;
typedef struct _elf_section_relocation_table elf_section_relocation_table;
typedef struct _elf_section_symbol_table elf_section_symbol_table;

typedef enum elf_callback_retval (*elf_code_cave_condition)(Elf64_Phdr *cur,
			Elf64_Phdr *fol, uint64_t sz_cave, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
enum elf_code_cave_type {
	ELF_CODE_CAVE_TYPE_FILE = 0,
	ELF_CODE_CAVE_TYPE_VIRTUAL,
	ELF_CODE_CAVE_TYPE_MAX,
};

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
/*
* 'elf_abs_section' represents a section that is extracted from .dynamic.
*	As the existence of SHT cannot be assumed, general representation
*	of a section based on .dynamic breaks down to this structure.
* 	The indirection (pointers) allows for manipulation of .dynamic entries.
*	It is possible that only one of the fields (most likely 'vaddr') will
*	contain a valid value.
* @vaddr: Virtual address of a structure. All addresses in .dynamic are
*	virtual.
* @size: Size of extracted section.
* @entsize: Size of a single entry in bytes, if represented section contains
*	a table.
*/
struct elf_abs_section {
	uint64_t *vaddr;
	uint64_t *size;
	uint64_t *entsize;
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
/*
* 'elf_get_containing_segment_off' attempts to find the segment that contains
*	the given offset. The comparison is done using '.p_offset' and
*	'.p_filesz' fields of a program header in combination with
*	'elf_translator'.
* @list_segments: List of segments to compare to 'off_bin_data'.
* @amount_segments: Amount of segments in 'list_segments'.
* @off_bin_data: Offset relative to the beginning of the file. E.g. an offset
*	of 0 indicates the very first byte in the binary.
* @loadable: See 'elf_translator_get_surrounding_segment_offset' loadable.
* @container: On success this will reference an element of 'list_segments'
*	matching the criteria. Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- object failed init
*	- error returned by 'elf_translator_get_surrounding_segment_offset'
*/
enum elf_result elf_get_containing_segment_off(elf_segment **list_segments,
			uint32_t amount_segments, uint64_t off_bin_data,
			uint8_t loadable, elf_segment **container);

/*
* 'elf_get_containing_segment_vaddr' attempts to find the segment that contains
*	the given vaddr. The comparison is done using '.p_vaddr' and
*	'.p_memsz' fields of a program header in combination with 
*	'elf_translator'.
* @list_segments: List of segments to compare to 'vaddr_bin_data'.
* @amount_segments: Amount of segments in 'list_segments'.
* @vaddr_bin_data: Virtual address relative to the beginning of the file.
* @loadable: See 'elf_translator_get_surrounding_segment_virtual' loadable.
* @container: On success this will reference an element of 'list_segments'
*	matching the criteria. Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
* 	- object failed init
*	- error returned by 'elf_translator_get_surrounding_segment_virtual'
*/
enum elf_result elf_get_containing_segment_vaddr(elf_segment **list_segments,
			uint32_t amount_segments, uint64_t vaddr_bin_data,
			uint8_t loadable, elf_segment **container);

/*
* 'elf_get_containing_section_off' tries to find the section that contains
*	the given file offset. The comparison is done using '.sh_offset' and
*	'.sh_size'.
* @list_sections: List of sections to compare 'off_bin_data' to.
* @amount_sections: Amount of sections in 'list_sections'.
* @off_bin_data: File offset, for which to find a surrounding section.
* @container: On success, this will reference an element of 'list_sections'
*	matching the criteria. Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- section not found
*/
enum elf_result elf_get_containing_section_off(elf_section **list_sections,
			uint32_t amount_sections, uint64_t off_bin_data,
			elf_section **container);

/*
* 'elf_get_max_align' tries to get the maximum alignment value over all
*	segments in 'list_segments'. This function assumes that there is at
*	least one segment in 'list_segments'.
* @list_segments: List of segments to search in.
* @amount_segments: Amount of segments in 'list_segments'.
* @max_align: On success it will point to the maximum value over all '.p_align'
*	fields in 'list_segments'.
* @return: Either success or one of the following:
*	- invalid parameters
*/
enum elf_result elf_get_max_align(elf_segment **list_segments,
				uint32_t amount_segments, uint64_t *max_align);

/*
* 'elf_get_dynamic' attempts to find the segment containing .dynamic. Thus this
*	function assumes that the underlying binary participates in dynamic
*	linking.
* @list_segments: List of segments to search in.
* @amount_segments: Amount fo segments in 'list_segments'.
* @dynamic: On success this will reference a fully initialized dynamic section
*	object. Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- error of 'elf_segment_map_to_dynamic'
* @NOTE: Free 'dynamic' using 'elf_section_dynamic_free'!
*/
enum elf_result elf_get_dynamic(elf_segment **list_segments,
		uint32_t amount_segments, elf_section_dynamic **dynamic);

/*
* 'elf_extract_section' attempts to extract a representation of a section
*	by using only the .dynamic - section. If there is an attribute of a
*	section that cannot be described by a .dynamic entry type, just pass
*	'DT_NULL'. If there are, for some reason, multiple entries with the
*	same type, only the first match will be returned. Notice that .dynamic
*	does not guarantee any order on its entries. Thus returned 'vaddr' and
*	'size' do not necessarly belong to the same section!
* @dynamic: Dynamic section object.
* @vaddr_type: Type of a .dynamic entry that describes a section's vaddr.
* @size_type: Type of a .dynamic entry that describes a sections's size.
* @entsize_type: Type of a dynamic entry that describes a section's entry size.
* @abs: On success it will reference an abstract section structure that holds
*	all available information regarding the preceding types. Otherwise all
*	members will be set to NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*/
enum elf_result elf_extract_section(elf_section_dynamic *dynamic,
	int64_t vaddr_type, int64_t size_type, int64_t entsize_type,
	struct elf_abs_section *abs);

/*
* 'elf_get_dynstr' tries to find .dynstr using .dynamic. This function assumes
*	a fully initialized binary (i.e. loaded) and dynamic section object.
*	Notice that the returned string table object must eventually be freed
*	by calling 'elf_section_string_table_free'!
* @bin: Binary to search in.
* @dynamic: Dynamic section object.
* @dynstr: On success this will reference a fully initiliazed string table
*	object that is mapped on top of .dynstr. Otherwise NULL (after
*	parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- entry not found
* 	- error returned by 'elf_extract_section'
*	- error returned by 'elf_get_containing_segment_vaddr'
*	- error returned by 'elf_binary_memblock_as_string_table'
*/
enum elf_result elf_get_dynstr(elf_binary *bin, elf_section_dynamic *dynamic,
					elf_section_string_table **dynstr);

/*
* 'elf_get_rtab' tries to find the relocation table referenced by .dynamic.
*	The entries consist of instances of Elf64_Rel/a. The given binary must
*	be fully initialized (i.e. loaded) and it must contain a .dynamic
*	section that can be represented by a dynamic section object. 'rel'
*	must eventually be freed by calling 
*	'elf_section_relocation_table_free'.
* @bin: Binary to search in.
* @dynamic: Dynamic section object.
* @type: Type of .dynamic entry that will be used as a base for mapping.
*	Currently only 'DT_REL', 'DT_RELA' or 'DT_JMPREL' are supported.
* @rel: On success this will reference a fully initiliazed relocation table
*	object that is mapped on top of a section containing Elf64_Rel/a
* 	entries. Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- entry not found
*	- error returned by 'elf_extract_section'
*	- error returned by 'elf_get_containing_segment_vaddr'
*	- error returned by 'elf_binary_memblock_as_reloc_table'
*/
enum elf_result elf_get_rel(elf_binary *bin, elf_section_dynamic *dynamic,
			int64_t type, elf_section_relocation_table **rel);

/*
* 'elf_get_dynsym' attempts to find .dynsym using only .dynamic and PHT.
*	Due to the fact that .dynamic does not hold any information on the
*	size of .dynsym, used heuristic will attempt to first query
*	.rel(a).plt to find the amount of imported function. Secondly it will
*	increase constructed .dynsym one by one. For each new entry all fields
*	will be checked for correctness. Once a potential symbol has an
*	incorrect field, constructed .dynsym is considered to be complete. The
*	given binary is assumed to be fully initialized as well as dynamic.
*	Note that 'dynsym' must eventually be released by calling
*	'elf_section_symbol_table_free'. Also the existence of a 1:1 mapping
*	between rel(a).plt entries and .dynsym import entries is assumed. As
*	regards patching, this function assumes a patched ELF - header, PHT and
*	.dynamic.
* @bin: Binary to search in for .dynsym.
* @dynamic: Dynamic section object.
* @segments: List of segments to use for containment checks for symbol values.
*	This is useful for patching .dynsym!
* @num_segments: Amount of segments in 'segments':
* @dynsym: On success it will reference a fully initialized symbol table that,
*	following above heuristic, is complete and correct. Otherwise NULL
*	(after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- entry not found
*	- error returned by 'elf_extract_section'
*	- error returned by 'elf_get_containing_segment_vaddr'
*	- error returned by 'elf_get_dynstr'
* 	- error returned by 'elf_binary_memblock_as_symbol_table'
*/
enum elf_result elf_get_dynsym(elf_binary *bin, elf_section_dynamic *dynamic,
				elf_segment **segments, uint32_t num_segments, 
				elf_section_symbol_table **dynsym);

/*
* 'elf_find_code_cave' attempts to find a code cave based upon user demands.
*	It will go through the PHT and call 'condition' for each pair
*	of loadable, ascending segments (based upon code cave type). As there
*	is no guaranteed order regarding '.p_offset', this function will
*	attempt to qsort those entries. Note that a code cave is a file code
*	cave, if it lies between two loadable segments. Every other segment
*	that is not part of the process image is considered irrelevant.
*	This function does not seek for caves that can appear before the first
*	loadable segment, because this behaviour might invalidate elf
*	structures.
* @segments: List of segments, i.e. the PHT.
* @num_segments: Amount of segments in 'segments'.
* @sz_cave: Size of code cave in bytes.
* @type: Type of code cave to look for.
* @predecessor: Segment that precedes found code cave.
* @successor: Segment that succeeds found code cave.
* @condition: A user - supplied function that will be called for each ascending
*	pair of segments. It will be used to determine whether there is a code
*	cave between two segments or not. If 'ELF_CALLBACK_BREAK' is returned,
*	it will be considered a successful finding.
* @user_data: User - supplied information that will be passed to 'condition'.
* @return: Either success or one of the following:
*	- invalid parameters
* 	- code cave not found
*/
enum elf_result elf_find_code_cave(elf_segment **segments,
	uint32_t num_segments, uint64_t sz_cave, enum elf_code_cave_type type,
	elf_segment **predecessor, elf_segment **successor,
	elf_code_cave_condition condition, void *user_data);

/*
* 'elf_pht_is_equal' compare two pht entries entry by entry.
* @first: First entry to compare to 'second'.
* @second: Second entry to compare to 'first'.
* @equal: On success this will point to the result of the comparison. If both
*	entries reference semantically and syntactically identical memory,
*	they are considered equal. Otherwise not.
* @return: Either success or invalid parameters.
*/
enum elf_result elf_pht_is_equal(Elf64_Phdr *first, Elf64_Phdr *second,
					uint8_t *equal);

#endif