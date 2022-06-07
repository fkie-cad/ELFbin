/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_dynamic_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_dynamic_entry {
	// Pointer to internal data representation.
	Elf64_Dyn *raw_entry;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_dynamic_entry *elf_section_dynamic_entry_init(void)
{
	elf_section_dynamic_entry *new_entry;
	new_entry = calloc(1, sizeof (elf_section_dynamic_entry));
	if (new_entry == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_entry;
}

void elf_section_dynamic_entry_free(elf_section_dynamic_entry *entry)
{
	if (entry != NULL)
		free(entry);
}

// Getter / Setter
Elf64_Dyn *elf_section_dynamic_entry_get_raw_entry(
					elf_section_dynamic_entry *entry)
{
	return entry->raw_entry;
}

void elf_section_dynamic_entry_set_raw_entry(
		elf_section_dynamic_entry *entry, Elf64_Dyn *raw_entry)
{
	entry->raw_entry = raw_entry;
}