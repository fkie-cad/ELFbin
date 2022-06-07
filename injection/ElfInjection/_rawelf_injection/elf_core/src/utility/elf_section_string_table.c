/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_string_table.h"
#include "elf_section_string_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_section_string_table_iterate_entries' attempts to iterate over the list
*	of strings in the provided string table. For each string the callback
* 	is called and provided with user data.
* @strtab: Pointer to a structure representing the string table.
* @callback: Function to call for each string in the string table.
* @user_data: Data handed to the callback on each call.
* @return: Returns an error that resulted from an underlying function or
* 		from invalid parameters; otherwise success. 
*/
enum elf_result elf_section_string_table_iterate_entries(
			elf_section_string_table *strtab,
			lpfn_elf_section_string_table_callback callback,
			void *user_data)
{
	elf_section_string_table_entry **list_entries;
	uint64_t i;

	if (strtab == NULL || callback == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	list_entries = elf_section_string_table_get_list_entries(strtab);
	if (list_entries == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_ENTRY_LIST,
				ELF_PRINTTYPE_NONE);

	for (i = 0;
	     i < elf_section_string_table_get_amount_entries(strtab);
	     i++) {
		if (callback(list_entries[i], user_data) == ELF_CALLBACK_BREAK)
			break;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_section_string_table_get_size(
	elf_section_string_table *strtab, uint64_t *size)
{
	elf_section_string_table_entry **list_entries;
	uint64_t i;

	if (strtab == NULL || size == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	list_entries = elf_section_string_table_get_list_entries(strtab);
	if (list_entries == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_ENTRY_LIST,
				ELF_PRINTTYPE_NONE);

	
	for (i = 0, *size = 0;
	     i < elf_section_string_table_get_amount_entries(strtab);
	     i++)
		*size += elf_section_string_table_entry_get_length(
							list_entries[i]) + 1;

	return ELF_COMMON_SUCCESS;
}