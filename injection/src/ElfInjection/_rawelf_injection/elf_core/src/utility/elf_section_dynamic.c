/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_binary.h"
#include "elf_segment.h"
#include "elf_section.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_section_dynamic_iterate_entries' attempts to iterate over the list
*	of entries in the provided dynamic table. For each entry the callback
* 	is called and provided with user data.
* @dyn_section: Pointer to a structure representing the dynamic table.
* @callback: Function to call for each entry in the dynamic table.
* @user_data: Data handed to the callback on each call.
* @return: Returns an error that resulted from an underlying function or
* 		from invalid parameters; otherwise success. 
*/
enum elf_result elf_section_dynamic_iterate_entries(
			elf_section_dynamic *dyn_section,
			lpfn_elf_section_dynamic_callback callback,
			void *user_data)
{
	elf_section_dynamic_entry **list_entries;
	uint64_t i;

	if (dyn_section == NULL || callback == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	list_entries = elf_section_dynamic_get_list_entries(dyn_section);
	if (list_entries == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_ENTRY_LIST,
				ELF_PRINTTYPE_NONE);

	for (i = 0;
	     i < elf_section_dynamic_get_amount_entries(dyn_section);
	     i++) {
		if (callback(list_entries[i], user_data) == ELF_CALLBACK_BREAK)
			break;
	}

	return ELF_COMMON_SUCCESS;
}
