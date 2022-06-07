/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_symbol_table.h"
#include "elf_section_symbol_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* 'elf_section_symbol_table_iterate_entries' attempts to iterate over the list
*	of symbols in the provided symbol table. For each symbol the callback
* 	is called and provided with user data.
* @symtab: Pointer to a structure representing the symbol table.
* @callback: Function to call for each symbol in the symbol table.
* @user_data: Data handed to the callback on each call.
* @return: Returns an error that resulted from an underlying function or
* 		from invalid parameters; otherwise success. 
*/
enum elf_result elf_section_symbol_table_iterate_entries(
			elf_section_symbol_table *symtab,
			lpfn_elf_section_symbol_table_callback callback,
			void *user_data)
{
	elf_section_symbol_table_entry **list_entries;
	uint64_t i;

	if (symtab == NULL || callback == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	list_entries = elf_section_symbol_table_get_list_entries(symtab);
	if (list_entries == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_INVALID_ENTRY_LIST,
				ELF_PRINTTYPE_NONE);

	for (i = 0;
	     i < elf_section_symbol_table_get_amount_entries(symtab);
	     i++) {
		if (callback(list_entries[i], user_data) == ELF_CALLBACK_BREAK)
			break;
	}

	return ELF_COMMON_SUCCESS;
}