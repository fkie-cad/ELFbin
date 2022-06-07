/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_binary.h"
#include "elf_segment.h"
#include "elf_section.h"
#include "elf_section_dynamic.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_segment_map_to_dynamic' attempts to map memory of the provided segment
* to a structure representing a dynamic section.
* @segment: Pointer to a fully initialized memory segment that needs to be
* 		interpreted as a dynamic section.
* @dyn_section: Pointer to a block of memory that will receive a fully
* 		initialized dynamic section structure on success. Otherwise
*		it will be set to NULL.
* @return: Returns an error that resulted from an underlying function or
* 		from invalid parameters; otherwise success. 
*/
enum elf_result elf_segment_map_to_dynamic(elf_segment *segment,
					elf_section_dynamic **dyn_section)
{
	enum elf_result result = ELF_COMMON_SUCCESS;
	Elf64_Phdr *segment_header;
	elf_section *section;
	elf_binary *bin;

	if (segment == NULL || dyn_section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*dyn_section = NULL;
	segment_header = elf_segment_get_program_header(segment);

	// Check if segment really contains .dynamic
	if (segment_header->p_type != PT_DYNAMIC)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SEGMENT_INVALID_TYPE,
				ELF_PRINTTYPE_NONE);

	// Construct a section object and call existing mapping function
	section = elf_section_init();
	if (section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_ERRNO);

	Elf64_Shdr section_header = {
		sh_name: 0,
		sh_type: SHT_DYNAMIC,
		sh_flags: 0,
		sh_addr: 0,
		sh_offset: segment_header->p_offset,
		sh_size: segment_header->p_filesz,
		sh_link: 0,
		sh_info: 0,
		sh_addralign: segment_header->p_align,
		sh_entsize: 0,
	};
	bin = elf_segment_get_binary(segment);
	elf_section_set_section_header(section, &section_header);
	elf_section_set_binary(section, bin);

	// Finally call the mapping function.
	result = elf_section_map_to_dynamic(section, dyn_section);
	if (result == ELF_COMMON_SUCCESS)
		elf_binary_add_section_to_list(bin, section);

	// Free temporary section object.
	// elf_section_free(section);

	// Also set .section member of dynamic section object to NULL
	// as this call assumes that there is no SHT.
	elf_section_dynamic_set_section(*dyn_section, NULL);

	return result;
}