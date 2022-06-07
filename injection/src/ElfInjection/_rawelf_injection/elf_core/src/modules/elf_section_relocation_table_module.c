/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_relocation_table.h"
#include "elf_section_relocation_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
/*
* '_elf_section_relocation_table' represents a relocation table with entries
*	describing single relocations.
* @section: Abstract section view of the table.
* @type: Type of relocation this table is used for. Currently only 'SHT_REL'
*	and 'SHT_RELA' are supported. It is used to determine how
*	to interpret 'raw' of elf_section_relocation_table_entry. It determines
*	the underlying structure (either Elf64_Rel or Elf64_Rela) of a
* 	relocation table.
* @amount_entries: Amount of entries in 'list_entries'.
* @list_entries: List of relocation table entries.
*/
struct _elf_section_relocation_table {
	elf_section *section;
	uint32_t type;
	uint64_t amount_entries;
	elf_section_relocation_table_entry **list_entries;
};
typedef struct _elf_section_relocation_table elf_section_relocation_table;

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
elf_section_relocation_table *elf_section_relocation_table_init(void)
{
	elf_section_relocation_table *new = calloc(1,
					sizeof(elf_section_relocation_table));
	if (new == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new;
}

void elf_section_relocation_table_free(elf_section_relocation_table *rtab)
{
	uint64_t i;
	if (rtab != NULL) {
		if (rtab->list_entries != NULL) {
			for (i = 0; i < rtab->amount_entries; i++)
				elf_section_relocation_table_entry_free(
							rtab->list_entries[i]);
			free(rtab->list_entries);
		}

		free(rtab);
	}
}

// Getter / Setter
elf_section *elf_section_relocation_table_get_section(
					elf_section_relocation_table *rtab)
{
	return rtab->section;
}

uint32_t elf_section_relocation_table_get_type(
					elf_section_relocation_table *rtab)
{
	return rtab->type;
}

uint64_t elf_section_relocation_table_get_amount_entries(
					elf_section_relocation_table *rtab)
{
	return rtab->amount_entries;
}

elf_section_relocation_table_entry **elf_section_relocation_table_get_list_entries(
					elf_section_relocation_table *rtab)
{
	return rtab->list_entries;
}

void elf_section_relocation_table_set_section(
		elf_section_relocation_table *rtab, elf_section *section)
{
	rtab->section = section;
}

void elf_section_relocation_table_set_type(elf_section_relocation_table *rtab,
						int64_t type)
{
	rtab->type = type;
}

void elf_section_relocation_table_set_amount_entries(
		elf_section_relocation_table *rtab, uint64_t amount_entries)
{
	rtab->amount_entries = amount_entries;
}

void elf_section_relocation_table_set_list_entries(
	elf_section_relocation_table *rtab,
	elf_section_relocation_table_entry **list_entries)
{
	rtab->list_entries = list_entries;
}