/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_binary.h"
#include "elf_section.h"
#include "elf_segment.h"
#include "elf_section_string_table.h"
#include "elf_section_relocation_table.h"
#include "elf_section_symbol_table.h"

// Standard
#include <string.h>

// System
#include <unistd.h>	// Syscalls

/*------------------------------------------------------------------------*/
/* Local Structure Definitions                                            */
/*------------------------------------------------------------------------*/
struct elf_find_section_info {
	// Pointer to the name of the section to search for.
	const char *target_section_name;

	// Output pointer to a pointer to a section struct.
	elf_section **out_section;
};

struct elf_find_segment_info {
	// Type of segment to find. If there are multiple segments of the
	// same type, only the first match will be returned.
	uint32_t type;

	// segment fitting type.
	elf_segment **out_segment;
};

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
static enum elf_callback_retval _elf_find_section_by_name_callback(
					elf_section *current, void *user_data);
static enum elf_callback_retval _elf_find_segment_by_name_callback(
					elf_segment *current, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_binary_iterate_sections' attempts to iterate over the list of sections
*	available in the provided binary.
* @bin: Binary to analyse.
* @callback: Function to call for each section in binary.
* @user_data: Data handed to the callback on each call.
* @return: Returns success or one of the following:
*	invalid parameters,
*	binary not loaded,
*	sht does not exist,
*/
enum elf_result elf_binary_iterate_sections(elf_binary *bin,
			lpfn_elf_section_callback callback, void *user_data)
{
	enum elf_result result;
	uint8_t has_table;
	uint64_t i;
	elf_section *current;

	if (bin == NULL || callback == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_has_section_header_table(bin, &has_table);
	if (result != ELF_COMMON_SUCCESS) {
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);
	}
	else if (has_table == 0) {
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);
	}

	for (i = 0; i < elf_binary_get_amount_sections(bin); i++) {
		current = elf_binary_get_sections(bin)[i];
		if (callback(current, user_data) == ELF_CALLBACK_BREAK)
			break;
	}

	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_iterate_segments' attempts to iterate over the list of segments
*	available in the provided binary.
* @bin: Binary to analyse.
* @callback: Function to call for each segment in binary.
* @user_data: Data handed to the callback on each call.
* @return: Returns success or one of the following:
*	invalid parameters,
*	binary not loaded,
*	pht does not exist,
*/
enum elf_result elf_binary_iterate_segments(elf_binary *bin,
			lpfn_elf_segment_callback callback, void *user_data)
{
	enum elf_result result;
	uint8_t has_table;
	uint32_t i;
	elf_segment *current;

	if (bin == NULL || callback == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_has_segment_header_table(bin, &has_table);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (has_table == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_PHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	for (i = 0; i < elf_binary_get_amount_segments(bin); i++) {
		current = elf_binary_get_segments(bin)[i];
		if (callback(current, user_data) == ELF_CALLBACK_BREAK)
			break;
	}

	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_has_section_header_table' checks whether the binary contains a
*	section header table or not.
* @bin: Binary to check.
* @has_table: Will be set to 1, if a SHT exists, or 0, if not (after parameter
*	validation).
* @return: Returns success or either invalid parameters or binary not loaded.
*/
enum elf_result elf_binary_has_section_header_table(elf_binary *bin,
						uint8_t *has_table)
{
	uint8_t loaded;

	if (bin == NULL || has_table == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	elf_binary_is_loaded(bin, &loaded); // This call cannot fail
	if (loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	*has_table = (elf_binary_get_elf_header(bin)->e_shoff != 0) ? 1 : 0;
	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_has_segment_header_table' checks whether the binary contains a
*	program header table or not.
* @bin: Binary to check.
* @has_table: Will be set to 1, if a PHT exists, or 0, if not (after parameter
*	validation).
* @return: Returns success or either invalid parameters or binary not loaded.
*/
enum elf_result elf_binary_has_segment_header_table(elf_binary *bin,
						uint8_t *has_table)
{
	uint8_t loaded;

	if (bin == NULL || has_table == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	elf_binary_is_loaded(bin, &loaded); // This call cannot fail
	if (loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	*has_table = (elf_binary_get_elf_header(bin)->e_phoff != 0) ? 1 : 0;
	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_find_section_by_name' tries to find a section named as specified.
* @bin: Binary to search the section in.
* @section_name: Name of the section to search.
* @section: If section is found, this will contain a fully initialized
*	section structure; otherwise NULL (after parameter validation).
* @return: Returns success or one of the following:
* 	invalid parameters,
* 	binary not loaded,
* 	sht does not exist,
* 	target section not found
*/
enum elf_result elf_binary_find_section_by_name(elf_binary *bin,
			const char *section_name, elf_section **section)
{
	enum elf_result result;
	uint8_t has_table;
	struct elf_find_section_info info = {
		target_section_name: section_name,
		out_section: section
	};

	if (bin == NULL || section_name == NULL || section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*section = NULL;

	result = elf_binary_has_section_header_table(bin, &has_table);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (has_table == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	elf_binary_iterate_sections(bin, _elf_find_section_by_name_callback,
					&info);

	if (*section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SECTION_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_find_section_by_name' tries to find a segment with specified
* 	type.
* @bin: Binary to search the section in.
* @type: Type of segment to search for.
* @segment: If segment is found, this will contain a fully initialized
*	segment structure; otherwise NULL (after parameter validation).
* @return: Returns success or one of the following:
* 	invalid parameters,
* 	binary not loaded,
* 	pht does not exist,
* 	target segment not found
*/
enum elf_result elf_binary_find_segment_by_type(elf_binary *bin, uint32_t type,
						elf_segment **segment)
{
	enum elf_result result;
	uint8_t has_table;
	struct elf_find_segment_info info = {
		type: type,
		out_segment: segment,
	};

	if (bin == NULL || segment == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*segment = NULL;

	result = elf_binary_has_segment_header_table(bin, &has_table);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (has_table == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_PHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	elf_binary_iterate_segments(bin, _elf_find_segment_by_name_callback,
					&info);
	if (*segment == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SEGMENT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);
	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_memblock_as_string_table' attempts to interpret a specified
* 	memory location as a string table.
* @bin: Binary that contains specified memory block.
* @offset: Offset relative to the start of the binary. Points to beginning
*	the memory block.
* @size: Size in bytes of the memory block.
* @strtab: On success, this will contain a fully initialized string table;
*	otherwise NULL (after parameter validation).
* @return: Returns success or one of the following:
* 	invalid parameters,
* 	forwarded errors of underlying functions
*/
enum elf_result elf_binary_memblock_as_string_table(elf_binary *bin,
	uint64_t offset, uint64_t size, elf_section_string_table **strtab)
{
	enum elf_result result;
	elf_section *section;
	Elf64_Shdr section_header = {
		sh_offset: offset,
		sh_size: size,
		sh_type: SHT_STRTAB,
	};

	if (bin == NULL || strtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*strtab = NULL;

	// Construct valid section:
	section = elf_section_init();
	if (section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_ERRNO);

	elf_section_set_section_header(section, &section_header);
	elf_section_set_binary(section, bin);

	// Finally construct string table.
	result = elf_section_map_to_string_table(section, strtab);
	if (result != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to map section to string table.");
	else
		elf_section_string_table_set_section(*strtab, NULL);

	elf_section_free(section);

	return result;
}

/*
* 'elf_binary_memblock_as_reloc_table' tries to map given memory block to a
*	relocation table. Note that the mapping can still succeed although the
*	memory does not actually represent a relocation table.
* @bin: Binary that contains given memory block.
* @offset: Offset to memory block that needs to be interpreted as a relocation
*	table. This offset is relative to the beginning of the binary.
* @size: Size of memory block.
* @type: Type of relocation entries. Either 'SHT_REL' or 'SHT_RELA'.
* @rtab: On success it will reference a fully initialized relocation table.
*	Otherwise NULL (after parameter validation).
* @return: Either success or one of the following:
* 	- invalid parameters
* @Note: 'rtab' must eventually be freed using
*	'elf_section_relocation_table_free'!
*/
enum elf_result elf_binary_memblock_as_reloc_table(elf_binary *bin,
	uint64_t offset, uint64_t size, uint32_t type, 
	elf_section_relocation_table **rtab)
{
	enum elf_result result;
	uint8_t is_loaded;
	Elf64_Shdr section_header = {
		sh_type: type,
		sh_offset: offset,
		sh_size: size,
	};
	elf_section *section;

	if (bin == NULL || rtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_is_loaded(bin, &is_loaded);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (is_loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	section = elf_section_init();
	if (section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	elf_section_set_binary(section, bin);
	elf_section_set_section_header(section, &section_header);

	result = elf_section_map_to_reloc_table(section, rtab);

	if (result != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to map section to relocation table.");
	else
		elf_section_relocation_table_set_section(*rtab, NULL);

	elf_section_free(section);

	return result;
}

enum elf_result elf_binary_memblock_as_symbol_table(elf_binary *bin,
			uint64_t offset, uint64_t size, uint64_t off_strtab,
			elf_section_symbol_table **symtab)
{
	enum elf_result result;
	uint8_t is_loaded;
	Elf64_Shdr section_header = {
		sh_offset: offset,
		sh_size: size,
		sh_entsize: sizeof(Elf64_Sym),
		sh_type: SHT_SYMTAB,
	};
	elf_section *section;

	if (bin == NULL || symtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_is_loaded(bin, &is_loaded);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (is_loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	section = elf_section_init();
	if (section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);
	elf_section_set_binary(section, bin);
	elf_section_set_section_header(section, &section_header);

	result = elf_section_map_to_symbol_table(section, off_strtab, symtab);
	if (result != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to map section to symbol table.");
	else
		elf_section_symbol_table_set_section(*symtab, NULL);
	elf_section_free(section);

	return result;
}

/*
* 'elf_binary_resize' tries to resize the underlying file and memory mapping.
* 	This is achieved by re - mapping the file after truncation. More
*	precisely the original binary is fully reloaded! Reason for this is
*	that re - mapping a file will result in diffent pointers/addresses.
*	Thus all structures need to be rebuilt.
* @bin: Binary to resize.
* @new_size: New size of binary in bytes.
* @return: Either success or one of the following:
*	- invalid parameters
* Inspired by:
* 'https://github.com/nicolascormier/freebsd-elf-injection/blob/master/elf.c'
*/
enum elf_result elf_binary_resize(elf_binary *bin, uint64_t new_size)
{
	enum elf_result result;
	uint8_t is_loaded;

	if (bin == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS, 
				ELF_PRINTTYPE_NONE);

	result = elf_binary_is_loaded(bin, &is_loaded);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (is_loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	if (ftruncate(elf_binary_get_fd(bin), (off_t)new_size) == -1)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SYSCALL_FTRUNCATE,
				ELF_PRINTTYPE_ERRNO);

	return elf_binary_reload(bin, ELF_RELOAD_ALL);
}

/*
* 'elf_binary_add_section_to_list' attempts to append a given section object
*	to the list of all sections. Note that there are currently two uses
*	for this approach:
*	1. Creating a list of theoretically present (i.e. mapped from segment)
*		sections in the absence of a SHT.
*	2. Appending new sections to SHT or adding sections that can not be
*		discovered by classic approaches (i.e. elf_binary_load).
* @bin: Binary, whose section list to expand.
* @section: Section to append.
* @return: Either success or one of the following:
*	- invalid parameters
* 	- reallocarray error
*/
enum elf_result elf_binary_add_section_to_list(elf_binary *bin,
						elf_section *section)
{
	uint64_t amount_sections;
	elf_section **list_sections;
	elf_section **temp;

	if (bin == NULL || section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	amount_sections = elf_binary_get_amount_sections(bin);
	list_sections = elf_binary_get_sections(bin);
	temp = (elf_section**)reallocarray(list_sections, amount_sections + 1,
				sizeof(elf_section*));
	if (temp == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
				ELF_PRINTTYPE_ERRNO);
	list_sections = temp;
	list_sections[amount_sections] = section;
	
	elf_binary_set_sections(bin, list_sections);
	elf_binary_set_amount_sections(bin, amount_sections + 1);

	return ELF_COMMON_SUCCESS;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
enum elf_callback_retval _elf_find_section_by_name_callback(
					elf_section *current, void *user_data)
{
	struct elf_find_section_info* info =
		(struct elf_find_section_info*)user_data;
	if (strcmp(elf_section_get_name(current),
		info->target_section_name) == 0) {
		*(info->out_section) = current;
		return ELF_CALLBACK_BREAK;
	}

	return ELF_CALLBACK_CONTINUE;
}

enum elf_callback_retval _elf_find_segment_by_name_callback(
					elf_segment *current, void *user_data)
{
	struct elf_find_segment_info* info =
		(struct elf_find_segment_info*)user_data;
	if (elf_segment_get_program_header(current)->p_type == info->type) {
		*(info->out_segment) = current;
		return ELF_CALLBACK_BREAK;
	}

	return ELF_CALLBACK_CONTINUE;
}