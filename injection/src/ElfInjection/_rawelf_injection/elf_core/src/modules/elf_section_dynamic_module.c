/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_dynamic {
	// Abstract section view.
	elf_section *section;

	// Number of entries in '.dynamic'.
	uint64_t num_entries;

	// List of dynamic section entries.
	elf_section_dynamic_entry **list_entries;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_dynamic *elf_section_dynamic_init(void)
{
	elf_section_dynamic *new_dynamic;
	new_dynamic = calloc(1, sizeof (elf_section_dynamic));
	if (new_dynamic == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_dynamic;
}

void elf_section_dynamic_free(elf_section_dynamic *dyn_section)
{
	uint64_t i;
	if (dyn_section != NULL) {
		if (dyn_section->list_entries != NULL) {
			for (i = 0; i < dyn_section->num_entries; i++)
				elf_section_dynamic_entry_free(
					dyn_section->list_entries[i]);
			free(dyn_section->list_entries);
		}
		free(dyn_section);
	}
}

// Getter / Setter
elf_section *elf_section_dynamic_get_section(elf_section_dynamic *dyn_section)
{
	return dyn_section->section;
}

uint64_t elf_section_dynamic_get_amount_entries(
					elf_section_dynamic *dyn_section)
{
	return dyn_section->num_entries;
}

elf_section_dynamic_entry **elf_section_dynamic_get_list_entries(
					elf_section_dynamic *dyn_section)
{
	return dyn_section->list_entries;
}

void elf_section_dynamic_set_section(elf_section_dynamic *dyn_section,
					elf_section *abs_section)
{
	dyn_section->section = abs_section;
}

void elf_section_dynamic_set_amount_entries(elf_section_dynamic *dyn_section,
						uint64_t num_entries)
{
	dyn_section->num_entries = num_entries;
}

void elf_section_dynamic_set_list_entries(elf_section_dynamic *dyn_section,
				elf_section_dynamic_entry **list_entries)
{
	dyn_section->list_entries = list_entries;
}