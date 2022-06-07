/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_relocation_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
/*
* '_elf_section_relocation_table' represents a relocation table entry and this
*	a single relocation.
* @raw: ELF - representation of the relocation table based upon 'type'.
*/
struct _elf_section_relocation_table_entry {
	union {
		Elf64_Rel *rel;
		Elf64_Rela *rela;
	} raw;
};
typedef struct _elf_section_relocation_table_entry elf_section_relocation_table_entry;

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_relocation_table_entry *elf_section_relocation_table_entry_init(
									void)
{
	elf_section_relocation_table_entry *entry = calloc(1,
				sizeof(elf_section_relocation_table_entry));
	if (entry == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return entry;
}
void elf_section_relocation_table_entry_free(
				elf_section_relocation_table_entry *entry)
{
	if (entry != NULL)
		free(entry);
}

// Getter / Setter
Elf64_Rel *elf_section_relocation_table_entry_get_rel(
				elf_section_relocation_table_entry *entry)
{
	return entry->raw.rel;
}

Elf64_Rela *elf_section_relocation_table_entry_get_rela(
				elf_section_relocation_table_entry *entry)
{
	return entry->raw.rela;
}

void elf_section_relocation_table_entry_set_rel(
		elf_section_relocation_table_entry *entry, Elf64_Rel *rel)
{
	entry->raw.rel = rel;
}
void elf_section_relocation_table_entry_set_rela(
		elf_section_relocation_table_entry *entry, Elf64_Rela *rela)
{
	entry->raw.rela = rela;
}