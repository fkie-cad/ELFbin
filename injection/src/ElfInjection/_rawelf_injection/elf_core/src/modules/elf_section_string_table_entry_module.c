/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section_string_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section_string_table_entry {
	// Null - terminated string.
	char *string;

	// Offset of the string relative to the beginning of the string table.
	uint64_t offset;

	// Length of the string (null - terminator excluded, essentially strlen).
	uint64_t length;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_string_table_entry *elf_section_string_table_entry_init(void)
{
	elf_section_string_table_entry *new_entry;
	new_entry = calloc(1, sizeof (elf_section_string_table_entry));
	if (new_entry == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_entry;
}

void elf_section_string_table_entry_free(
				elf_section_string_table_entry *strtab_entry)
{
	if (strtab_entry != NULL)
		free(strtab_entry);
}

// Getter / Setter
char *elf_section_string_table_entry_get_string(
				elf_section_string_table_entry *strtab_entry)
{
	return strtab_entry->string;
}

uint64_t elf_section_string_table_entry_get_offset(
				elf_section_string_table_entry *strtab_entry)
{
	return strtab_entry->offset;
}

uint64_t elf_section_string_table_entry_get_length(
				elf_section_string_table_entry *strtab_entry)
{
	return strtab_entry->length;
}

void elf_section_string_table_entry_set_string(
		elf_section_string_table_entry *strtab_entry, char *string)
{
	strtab_entry->string = string;
}

void elf_section_string_table_entry_set_offset(
		elf_section_string_table_entry *strtab_entry, uint64_t offset)
{
	strtab_entry->offset = offset;
}

void elf_section_string_table_entry_set_length(
		elf_section_string_table_entry *strtab_entry, uint64_t length)
{
	strtab_entry->length = length;
}