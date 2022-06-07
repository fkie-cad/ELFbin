/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_symbol_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_symbol_table_entry {
	// Pointer to the symbol name, if present.
	char *name;

	// Pointer to raw symbol structure.
	Elf64_Sym *raw_entry;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_symbol_table_entry *elf_section_symbol_table_entry_init(void)
{
	elf_section_symbol_table_entry *new_entry;
	new_entry = calloc(1, sizeof (elf_section_symbol_table_entry));
	if (new_entry == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_entry;
}

void elf_section_symbol_table_entry_free(elf_section_symbol_table_entry *entry)
{
	if (entry != NULL)
		free(entry);
}

// Getter / Setter
char *elf_section_symbol_table_entry_get_name(
					elf_section_symbol_table_entry *entry)
{
	return entry->name;
}

Elf64_Sym *elf_section_symbol_table_entry_get_raw_entry(
					elf_section_symbol_table_entry *entry)
{
	return entry->raw_entry;
}

void elf_section_symbol_table_entry_set_name(
			elf_section_symbol_table_entry *entry, char *name)
{
	entry->name = name;
}

void elf_section_symbol_table_entry_set_raw_entry(
		elf_section_symbol_table_entry *entry, Elf64_Sym *raw_entry)
{
	entry->raw_entry = raw_entry;
}