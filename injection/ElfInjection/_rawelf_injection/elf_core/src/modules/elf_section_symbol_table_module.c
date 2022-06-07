/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_symbol_table.h"
#include "elf_section_symbol_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_symbol_table {
	// Pointer to abstract section view.
	elf_section *section;

	// Amount of entries in this symbol table.
	uint64_t num_entries;

	// List of entries, aka the table itself.
	elf_section_symbol_table_entry **list_entries;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_symbol_table *elf_section_symbol_table_init(void)
{
	elf_section_symbol_table *new_strtab = calloc(1,
		sizeof(elf_section_symbol_table));
	if (new_strtab == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_strtab;
}

void elf_section_symbol_table_free(elf_section_symbol_table *symtab)
{
	uint64_t i;
	if (symtab != NULL) {
		if (symtab->list_entries != NULL) {
			for (i = 0; i < symtab->num_entries; i++)
				elf_section_symbol_table_entry_free(
					symtab->list_entries[i]);

			free(symtab->list_entries);
		}

		free(symtab);
	}
}

// Getter / Setter
elf_section *elf_section_symbol_table_get_section(
					elf_section_symbol_table *symtab)
{
	return symtab->section;
}

uint64_t elf_section_symbol_table_get_amount_entries(
					elf_section_symbol_table *symtab)
{
	return symtab->num_entries;
}

elf_section_symbol_table_entry **elf_section_symbol_table_get_list_entries(
					elf_section_symbol_table *symtab)
{
	return symtab->list_entries;
}

void elf_section_symbol_table_set_section(elf_section_symbol_table *symtab,
						elf_section *section)
{
	symtab->section = section;
}

void elf_section_symbol_table_set_amount_entries(elf_section_symbol_table *symtab,
							uint64_t num_entries)
{
	symtab->num_entries = num_entries;
}

void elf_section_symbol_table_set_list_entries(
	elf_section_symbol_table *symtab,
	elf_section_symbol_table_entry **list_entries)
{
	symtab->list_entries = list_entries;
}