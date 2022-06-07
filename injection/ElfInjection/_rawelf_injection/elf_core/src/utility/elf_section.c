/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section.h"
#include "elf_binary.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"
#include "elf_section_symbol_table.h"
#include "elf_section_symbol_table_entry.h"
#include "elf_section_string_table.h"
#include "elf_section_string_table_entry.h"
#include "elf_section_relocation_table.h"
#include "elf_section_relocation_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_section_map_to_dynamic' attempts to interpret a section as the specific
*	.dynamic section.
* @section: Section to interpret as .dynamic.
* @dyn_section: On success, referenced memory will contain a fully initialized
*	dynamic section structure; otherwise NULL after parameter validation.
* @return: On success, success is returned; otherwise:
*	invalid parameter,
*	invalid section type,
*	forwarding of error codes of underlying functions
*/
enum elf_result elf_section_map_to_dynamic(elf_section *section,
					elf_section_dynamic **dyn_section)
{
	__label__ label_error_free_entries;
	enum elf_result result = ELF_COMMON_SUCCESS;
	Elf64_Shdr *section_header;
	elf_section_dynamic_entry **list_entries;
	elf_section_dynamic_entry **temp;
	Elf64_Dyn *raw_entry;
	uint64_t num_entries;
	uint64_t i;

	if (section == NULL || dyn_section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*dyn_section = NULL;

	section_header = elf_section_get_section_header(section);

	// First check 'section' for being the .dynamic section.
	if (section_header->sh_type != SHT_DYNAMIC)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_TYPE,
				ELF_PRINTTYPE_NONE);

	// Create dynamic section object.
	*dyn_section = elf_section_dynamic_init();
	if (*dyn_section == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_ERRNO);

	// Iterate through table of dynamic entries. For each entry
	// construct a dynamic section entry object.
	list_entries = NULL;
	temp = NULL;
	raw_entry = (Elf64_Dyn*)OFFSET(
		elf_binary_get_elf_header(elf_section_get_binary(section)),
		section_header->sh_offset);
	num_entries = 0;
	do {
		// Once this loop is entered, we know there is a new
		// entry in the .dynamic section
		// -> reallocarray (safer than realloc!)
		temp = (elf_section_dynamic_entry**)reallocarray(list_entries,
			num_entries + 1,
			sizeof (elf_section_dynamic_entry*));
		if (temp == NULL) {
			result = ELF_STD_REALLOCARRAY;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_error_free_entries;
		}
		list_entries = temp;

		// Create entry object.
		list_entries[num_entries] = elf_section_dynamic_entry_init();
		if (list_entries[num_entries] != NULL) {
			elf_section_dynamic_entry_set_raw_entry(
				list_entries[num_entries], raw_entry);
		} else {
			result = ELF_OBJECT_FAILED_INIT;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_error_free_entries;
		}

		// Update counter and pointer. Note that incrementation of
		// the pointer needs to be delayed until the check for 
		// DT_NULL is done!
		num_entries++;

	} while((raw_entry++)->d_tag != DT_NULL);

	// From now on there nothing that can severly damage the process.
	// Thus initialise the dynamic section structure.
	elf_section_dynamic_set_section(*dyn_section, section);
	elf_section_dynamic_set_amount_entries(*dyn_section, num_entries);
	elf_section_dynamic_set_list_entries(*dyn_section, list_entries);

	return ELF_COMMON_SUCCESS;

label_error_free_entries:
	for (i = 0; i < num_entries; i++)
		elf_section_dynamic_entry_free(list_entries[i]);

	free(list_entries);

	elf_section_dynamic_free(*dyn_section);

	return result;
}

/*
* 'elf_section_map_to_symbol_table' attempts to interpret a section as a symbol
*	table.
* @section: Section to interpret as a symbol table.
* @off_strtab: If 0, this function will attempt to use SHT to find the related
*	string table. Otherwise 'off_strtab' points to the string table to use.
* @symtab: On success, referenced memory will contain a fully initialized
*	symbol table section structure; otherwise NULL after parameter
* 	validation.
* @return: On success, success is returned; otherwise:
*	invalid parameter,
*	invalid section type,
*	forwarding of error codes of underlying functions
*/
enum elf_result elf_section_map_to_symbol_table(elf_section *section,
			uint64_t off_strtab, elf_section_symbol_table **symtab)
{
	__label__ label_error_free_section, label_error_free_entries;
	uint8_t has_symtab;
	Elf64_Shdr *section_header;
	uint64_t num_entries;
	elf_section_symbol_table_entry **list_entries;
	Elf64_Sym *raw_entry;
	uint64_t i;
	Elf64_Shdr strtab_hdr;
	char *strtab;
	uint64_t j;

	if (section == NULL || symtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*symtab = NULL;

	elf_section_has_symbol_table(section, &has_symtab);
	if (has_symtab == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_TYPE,
				ELF_PRINTTYPE_NONE);

	section_header = elf_section_get_section_header(section);

	// Calculate amount of symbol table entries. Note
	// that 'sh_entsize' is only 0 for sections that
	// do not contain some kind of table with fixed
	// entry sizes.
	// Problem: What about hidden tables?
	num_entries = section_header->sh_size / section_header->sh_entsize;

	// Allocate symbol table.
	*symtab = elf_section_symbol_table_init();
	if (*symtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_ERRNO);

	// Allocate memory to hold a list of table entries.
	list_entries = (elf_section_symbol_table_entry**)calloc(num_entries,
				sizeof(elf_section_symbol_table_entry*));
	if (list_entries == NULL) {
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
		goto label_error_free_section;
	}

	raw_entry = (Elf64_Sym*)OFFSET(
		elf_binary_get_elf_header(elf_section_get_binary(section)),
		section_header->sh_offset);
	for (i = 0; i < num_entries; i++, raw_entry++) {
		list_entries[i] = elf_section_symbol_table_entry_init();
		if (list_entries[i] == NULL) {
			log(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
					ELF_PRINTTYPE_ERRNO);
			goto label_error_free_entries;
		}

		if (raw_entry->st_name != 0) {
			if (off_strtab == 0)
				strtab_hdr = *(Elf64_Shdr*)(SECTION_ADDRESS_BY_INDEX(
					elf_section_get_binary(section),
					section_header->sh_link));
			else
				strtab_hdr.sh_offset = off_strtab;

			strtab = (char*)OFFSET(elf_binary_get_elf_header(
				elf_section_get_binary(section)),
				strtab_hdr.sh_offset);
			elf_section_symbol_table_entry_set_name(
				list_entries[i],
				(char*)OFFSET(strtab, raw_entry->st_name));
		}

		elf_section_symbol_table_entry_set_raw_entry(list_entries[i],
								raw_entry);
	}

	// Finally fill in symbol table structure.
	elf_section_symbol_table_set_section(*symtab, section);
	elf_section_symbol_table_set_amount_entries(*symtab, num_entries);
	elf_section_symbol_table_set_list_entries(*symtab, list_entries);

	return ELF_COMMON_SUCCESS;

label_error_free_entries:
	for (j = 0; j < i; j++)
		elf_section_symbol_table_entry_free(list_entries[j]);

	free(list_entries);

label_error_free_section:
	elf_section_symbol_table_free(*symtab);

	return ELF_STD_CALLOC;
}

/*
* 'elf_section_map_to_string_table' attempts to interpret a section as a string
*	table.
* @section: Section to interpret as a string table.
* @symtab: On success, referenced memory will contain a fully initialized
*	string table section structure; otherwise NULL after parameter
* 	validation.
* @return: On success, success is returned; otherwise:
*	invalid parameter,
*	invalid section type,
*	forwarding of error codes of underlying functions
*/
enum elf_result elf_section_map_to_string_table(elf_section *section,
					elf_section_string_table **strtab)
{
	__label__ label_free_list_entries;
	uint8_t has_strtab;
	Elf64_Shdr *section_header;
	char *string_base;
	char *string_start;
	elf_section_string_table_entry **list_entries;
	elf_section_string_table_entry **temp;
	uint64_t num_entries;
	uint64_t i;

	if (section == NULL || strtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	*strtab = NULL;

	elf_section_has_string_table(section, &has_strtab);
	if (has_strtab == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_TYPE,
				ELF_PRINTTYPE_NONE);

	*strtab = elf_section_string_table_init();
	if (*strtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_ERRNO);

	// Sum of lengths of all strings is at most the section size.
	section_header = elf_section_get_section_header(section);
	string_base = (char*)OFFSET(
		elf_binary_get_elf_header(elf_section_get_binary(section)),
		section_header->sh_offset);
	string_start = string_base;
	list_entries = NULL;
	temp = NULL;
	num_entries = 0;
	for (i = 0; i < section_header->sh_size; i++) {
		if (*(string_base + i) == 0) {	// hit a null - terminator
			// This workarround is necessary because on failure
			// reallocarray returns NULL and does not free list.
			temp = (elf_section_string_table_entry**)reallocarray(
				list_entries, ++num_entries,
				sizeof(elf_section_string_table_entry*));
			if (temp == NULL) {
				log(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
				goto label_free_list_entries;
			}
			list_entries = temp;

			//list_entries[num_entries - 1] = string_start;
			list_entries[num_entries - 1] = 
					elf_section_string_table_entry_init();
			if (list_entries[num_entries - 1] == NULL) {
				log(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
					ELF_PRINTTYPE_ERRNO);
				goto label_free_list_entries;
			}

			elf_section_string_table_entry_set_string(
				list_entries[num_entries - 1], string_start);
			elf_section_string_table_entry_set_offset(
				list_entries[num_entries - 1],
				string_start - string_base);
			elf_section_string_table_entry_set_length(
				list_entries[num_entries - 1],
				string_base + i - string_start);

			// assuming that after null - terminator there is
			// another string
			string_start = string_base + i + 1;
		}
	}

	// Finally fill in the string table structure
	elf_section_string_table_set_section(*strtab, section);
	elf_section_string_table_set_amount_entries(*strtab, num_entries);
	elf_section_string_table_set_list_entries(*strtab, list_entries);

	return ELF_COMMON_SUCCESS;

label_free_list_entries:;
	for (i = 0; i < num_entries - 1; i++)
		elf_section_string_table_entry_free(list_entries[i]);
	free(list_entries);

	elf_section_string_table_free(*strtab);

	return ELF_STD_REALLOCARRAY;
}

/*
* 'elf_section_map_to_reloc_table' tries to interpret a given section as
*	relocation table. This function assumes that
*	shdr->sh_size / shdr->entsize = amount_entries, where entsize is
*	extracted from shdr->sh_type (either SHT_REL or SHT_RELA).
* @section: Section to interpret as relocation table.
* @rtab: On success this will reference a fully initialized relocation table
*	object. Otherwise NULL (after parameter validation).
* @return: Either sucess or one of the following:
* 	- invalid parameters
*/
enum elf_result elf_section_map_to_reloc_table(elf_section *section,
					elf_section_relocation_table **rtab)
{
	__label__ label_free_list_entries;
	enum elf_result result;
	uint8_t has_rtab;
	Elf64_Shdr *raw;
	uint64_t amount_entries;
	elf_section_relocation_table_entry **list_entries;
	uint64_t entsize;
	uint64_t i;
	void *current;

	if (section == NULL || rtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*rtab = NULL;

	result = elf_section_has_reloc_table(section, &has_rtab);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (has_rtab == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_TYPE,
				ELF_PRINTTYPE_NONE);

	raw = elf_section_get_section_header(section);
	entsize = (raw->sh_type == SHT_REL) ? sizeof(Elf64_Rel)
					    : sizeof(Elf64_Rela);
	amount_entries = raw->sh_size / entsize;
	list_entries = calloc(amount_entries,
				sizeof(elf_section_relocation_table_entry*));
	if (list_entries == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);

	current = OFFSET(
		elf_binary_get_elf_header(elf_section_get_binary(section)),
		raw->sh_offset);
	for (i = 0; i < amount_entries; i++) {
		list_entries[i] = elf_section_relocation_table_entry_init();
		if (list_entries[i] == NULL) {
			result = ELF_OBJECT_FAILED_INIT;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
			goto label_free_list_entries;
		}

		if (raw->sh_type == SHT_REL)
			elf_section_relocation_table_entry_set_rel(
				list_entries[i], (Elf64_Rel*)current);
		else
			elf_section_relocation_table_entry_set_rela(
				list_entries[i], (Elf64_Rela*)current);
		
		current += entsize;
	}

	*rtab = elf_section_relocation_table_init();
	if (*rtab == NULL) {
		result = ELF_OBJECT_FAILED_INIT;
		log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
		goto label_free_list_entries;
	}

	elf_section_relocation_table_set_section(*rtab, section);
	elf_section_relocation_table_set_type(*rtab, raw->sh_type);
	elf_section_relocation_table_set_amount_entries(*rtab, amount_entries);
	elf_section_relocation_table_set_list_entries(*rtab, list_entries);
	return ELF_COMMON_SUCCESS;

label_free_list_entries:
	for (i = 0; i < amount_entries; i++)
		elf_section_relocation_table_entry_free(list_entries[i]);
	free(list_entries);

	return result;
}

/*
* 'elf_section_has_symbol_table' checks whether the given section contains
*	a symbol table based upon existence of symtab or dynsym.
* @section: Section to check.
* @has_symtab: Will be set to either 1, if given section contains a symbol
*	table; otherwise 0 (after parameter validation).
* @return: Either success or invalid parameter.
*/
enum elf_result elf_section_has_symbol_table(elf_section *section,
					uint8_t *has_symtab)
{
	Elf64_Shdr *section_header;

	if (section == NULL || has_symtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	section_header = elf_section_get_section_header(section);
	*has_symtab = (section_header->sh_type == SHT_SYMTAB ||
		       section_header->sh_type == SHT_DYNSYM) ? 1 : 0;

	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_section_has_string_table' checks whether the given section contains
*	a string table based upon existence of section of type strtab.
* @section: Section to check.
* @has_symtab: Will be set to either 1, if given section contains a string
*	table; otherwise 0 (after parameter validation).
* @return: Either success or invalid parameter.
*/
enum elf_result elf_section_has_string_table(elf_section *section,
					uint8_t *has_strtab)
{
	Elf64_Shdr *section_header;

	if (section == NULL || has_strtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	section_header = elf_section_get_section_header(section);
	*has_strtab = (section_header->sh_type == SHT_STRTAB) ? 1 : 0;

	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_section_has_reloc_table' checks whether the given section contains
*	a relocation table based upon the types SHT_REL and SHT_RELA.
* @section: Section to check.
* @has_rtab: Either 1, if section contains a relocation table, or 0
*	(after parameter validation).
* @return: Either success of invalid parameters.
*/
enum elf_result elf_section_has_reloc_table(elf_section *section,
						uint8_t *has_rtab)
{
	Elf64_Shdr *section_header;
	if (section == NULL || has_rtab == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	section_header = elf_section_get_section_header(section);
	*has_rtab = (section_header->sh_type == SHT_REL ||
		     section_header->sh_type == SHT_RELA) ? 1 : 0;
	return ELF_COMMON_SUCCESS;
}