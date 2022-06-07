/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_string_table.h"
#include "elf_section_string_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_string_table {
	// Pointer to abstract section view.
	elf_section *section;

	// Amount of string table entries.
	uint64_t num_entries;

	// List of entries.
	elf_section_string_table_entry **list_entries;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_string_table *elf_section_string_table_init(void)
{
	elf_section_string_table *new_table;
	new_table = calloc(1, sizeof (elf_section_string_table));
	if (new_table == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_table;
}

void elf_section_string_table_free(elf_section_string_table *strtab)
{
	uint64_t i;
	if (strtab != NULL) {
		if (strtab->list_entries != NULL) {
			for (i = 0; i < strtab->num_entries; i++)
				elf_section_string_table_entry_free(
					strtab->list_entries[i]);
			free(strtab->list_entries);
		}
		free(strtab);
	}
}

// Getter / Setter

elf_section *elf_section_string_table_get_section(
					elf_section_string_table *strtab)
{
	return strtab->section;
}

uint64_t elf_section_string_table_get_amount_entries(
					elf_section_string_table *strtab)
{
	return strtab->num_entries;
}

elf_section_string_table_entry **elf_section_string_table_get_list_entries(
					elf_section_string_table *strtab)
{
	return strtab->list_entries;
}

void elf_section_string_table_set_section(elf_section_string_table *strtab,
						elf_section *section)
{
	strtab->section = section;
}

void elf_section_string_table_set_amount_entries(
			elf_section_string_table *strtab, uint64_t num_entries)
{
	strtab->num_entries = num_entries;
}

void elf_section_string_table_set_list_entries(
	elf_section_string_table *strtab,
	elf_section_string_table_entry **list_entries)
{
	strtab->list_entries = list_entries;
}