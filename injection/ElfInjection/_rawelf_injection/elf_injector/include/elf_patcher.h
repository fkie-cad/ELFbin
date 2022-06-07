/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_PATCHER_H_
#define _ELF_PATCHER_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_patcher elf_patcher;
typedef struct _elf_binary elf_binary;
typedef struct _elf_segment elf_segment;
typedef struct _elf_section elf_section;
typedef struct _elf_section_dynamic elf_section_dynamic;

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
enum elf_injected_data_affiliation {
	ELF_AFFILIATION_NONE = 0,
	ELF_AFFILIATION_UPPER,
	ELF_AFFILIATION_LOWER,
	ELF_AFFILIATION_MAX,
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_patcher *elf_patcher_init(void);
void elf_patcher_free(elf_patcher *patcher);

// Getter / Setter
// Utility
/*
* 'elf_patcher_patch_ehdr' attempts to patch the ELF - header using offset
*	and size of already injected data. Only 'ehdr.e_entry', 'ehdr.e_phoff'
*	and 'ehdr.e_shoff' will be adjusted.
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @return: Either success or one of the following:
* 	- invalid parameters
*	- error returned by 'elf_get_containing_segment_vaddr'
*/
enum elf_result elf_patcher_patch_ehdr(elf_patcher *patcher, elf_binary *bin,
					uint64_t off_data, uint64_t sz_data);

/*
* 'elf_patcher_patch_pht' tries to patch PHT using offset of injected data
*	and size of injected data. Note that calling this function assumes
*	that the injection already took place. As future patching requires
*	both, new and old segment information, this function also returns
*	a copy of the old segment list, if requested. Note that this list
*	must eventually be freed, aswell as each Elf64_Phdr entry (see
*	'elf_patcher_free_segments'). Also the ELF - header is assumed to
*	be valid, i.e. 'ehdr.ph_off' was already adjusted!
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @old_segments: On success, if not NULL, it will reference a copy of the old
*	segment list. Otherwise NULL (after parameter validation).
* @affiliation: Determines where injected data belongs in case of ambiguity.
* @return: Either success or one of the following:
*	- invalid parameters
*	- calloc
* 	- object creation
*	- error returned by 'elf_binary_reload'
*/
enum elf_result elf_patcher_patch_pht(elf_patcher *patcher, elf_binary *bin,
	uint64_t off_data, uint64_t sz_data, elf_segment ***old_segments,
	enum elf_injected_data_affiliation affiliation);

/*
* 'elf_patcher_patch_sht' tries to patch SHT using offset of injected data
*	and size of injected data. Note that calling this function assumes
*	that the injection already took place. As future patching requires
*	both, new and old section information, this function also returns
*	a copy of the old section list, if requested. Note that this list
*	must eventually be freed, aswell as each Elf64_Phdr entry(see
*	'elf_patcher_free_sections'). Also the ELF - header is assumed to
*	be valid, i.e. 'ehdr.sh_off' was already adjusted!
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @old_sections: On success, if not NULL, it will reference a copy of the old
*	section list. Otherwise NULL (after parameter validation). Note that
*	the name of the section will not be copied as it is not relevant for
*	adjusting offsets and sizes.
* @affiliation: Determines where injected data belongs in case of ambiguity.
* @return: Either success or one of the following:
*	- invalid parameters
*	- error returned by 'elf_get_containing_section_off'
*	- section not found
*	- calloc
* 	- object creation
*	- error returned by 'elf_binary_reload'
*/
enum elf_result elf_patcher_patch_sht(elf_patcher *patcher, elf_binary *bin,
	uint64_t off_data, uint64_t sz_data, elf_section ***old_sections,
	enum elf_injected_data_affiliation affiliation);

/*
* 'elf_patcher_patch_dynamic' tries to patch .dynamic by only using the offset
*	and size of injected data aswell as a list of segments from before PHT
*	was patched. This function assumes that the ELF - header and PHT have
*	already been patched.
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @dynamic: Dynamic section object.
* @old_segments: List of segments with offsets and sizes as they were before
*	injecting data. This list can be obtained by providing a non - NULL
*	'old_segments' parameter to 'elf_patcher_patch_pht'.
* @num_old_segments: Amount of segments in 'old_segments'.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @affiliation: Determines where injected data belongs in case of ambiguity.
* @return: Either success or one of the following:
* 	- invalid parameters
*	- error returned by 'elf_extract_section'
* 	- calloc
*	- reallocarray
*/
enum elf_result elf_patcher_patch_dynamic(elf_patcher *patcher,
	elf_binary *bin, elf_section_dynamic *dynamic, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data,
	enum elf_injected_data_affiliation affiliation);

/*
* 'elf_patcher_patch_func_array' tries to patch a specified array of function
*	pointers based upon the offset of injected data. This function assumes
*	that the ELF - header, PHT and .dynamic have already been patched.
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @dynamic: Dynamic section object.
* @old_segments: List of segments with offsets and sizes as they were before
*	injecting data. This list can be obtained by providing a non - NULL
*	'old_segments' parameter to 'elf_patcher_patch_pht'.
* @num_old_segments: Amount of segments in 'old_segments'.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @type: Either DT_INIT_ARRAY, DT_FINI_ARRAY or DT_PREINIT_ARRAY. Specifies,
*	what array of function pointers to patch.
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- error returned by 'elf_extract_section'
*	- error returned by 'elf_get_containing_segment_vaddr' (elf_misc.h)
* 	- entry not found
*/
enum elf_result elf_patcher_patch_func_array(elf_patcher *patcher,
	elf_binary *bin, elf_section_dynamic *dynamic,
	elf_segment **old_segments, uint32_t num_old_segments,
	uint64_t off_data, uint64_t sz_data, int64_t type);

/*
* 'elf_patcher_patch_dynsym' attempts to patch .dynsym by using only .dynamic,
*	aswell as offset and size of injected data. This function assumes that
*	the ELF - header, PHT and .dynamic have been patched.
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @dynamic: Dynamic section object.
* @old_segments: List of segments with offsets and sizes as they were before
*	injecting data. This list can be obtained by providing a non - NULL
*	'old_segments' parameter to 'elf_patcher_patch_pht'.
* @num_old_segments: Amount of segments in 'old_segments'.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @return: Either success or one of the following:
* 	- invalid parameters
*	- error returned by 'elf_get_dynsym'
* 	- error returned by 'elf_get_containing_segment_vaddr' (elf_misc.h)
*/
enum elf_result elf_patcher_patch_dynsym(elf_patcher *patcher, elf_binary *bin,
	elf_section_dynamic *dynamic, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data);

/*
* 'elf_patcher_patch_reloc' tries to patch a relocation table referenced by
*	.dynamic using .dynamic aswell as offset and size of injected data.
*	This function assumes that the ELF - header, PHT and .dynamic have
*	already been patched.
* @patcher: Patcher object to use for patching.
* @bin: Binary to patch a structure in.
* @dynamic: Dynamic section object.
* @old_segments: List of segments with offsets and sizes as they were before
*	injecting data. This list can be obtained by providing a non - NULL
*	'old_segments' parameter to 'elf_patcher_patch_pht'.
* @num_old_segments: Amount of segments in 'old_segments'.
* @type: DT_REL, DT_RELA or DT_JMPREL. Specifies what table to patch.
* @off_data: File offset of injected data.
* @sz_data: Size of injected data in bytes.
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- error returned by 'elf_get_rel'
*	- error returned by 'elf_platform_patch_rel'
*	- error returned by 'elf_platform_patch_rela'
*/
enum elf_result elf_patcher_patch_reloc(elf_patcher *patcher, elf_binary *bin,
	elf_section_dynamic *dynamic, elf_segment **new_segments,
	uint32_t num_new_segments, elf_segment **old_segments,
	uint32_t num_old_segments, int64_t type, uint64_t off_data,
	uint64_t sz_data);

/*
* 'elf_patcher_free_segments' tries to free a copy of segments obtained by
*	calling e.g. 'elf_patcher_patch_pht' with 'old_segments' being not
*	NULL. 'segments' will eventually be set to NULL.
* @patcher: Patcher object associated with this list.
* @segments: List of segments to free.
* @num_segments: Amount of segments in 'segments'.
* @return: Success
*/
enum elf_result elf_patcher_free_segments(elf_patcher *patcher,
				elf_segment **segments, uint32_t num_segments);

/*
* 'elf_patcher_free_sections' tries to free a copy of sections obtained by
*	calling e.g. 'elf_patcher_patch_sht' with 'old_sections' being not
*	NULL. 'sections' will eventually be set to NULL.
* @patcher: Patcher object associated with this list.
* @sections: List of sections to free.
* @num_sections: Amount of sections in 'sections'.
* @return: Success
*/
enum elf_result elf_patcher_free_sections(elf_patcher *patcher,
				elf_section **sections, uint64_t num_sections);

#endif