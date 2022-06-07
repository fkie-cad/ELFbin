/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_STRING_TABLE_ENTRY_H_
#define _ELF_SECTION_STRING_TABLE_ENTRY_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_string_table_entry elf_section_string_table_entry;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_string_table_entry *elf_section_string_table_entry_init(void);
void elf_section_string_table_entry_free(
	elf_section_string_table_entry *strtab_entry);

// Getter / Setter
char *elf_section_string_table_entry_get_string(
	elf_section_string_table_entry *strtab_entry);
uint64_t elf_section_string_table_entry_get_offset(
	elf_section_string_table_entry *strtab_entry);
uint64_t elf_section_string_table_entry_get_length(
	elf_section_string_table_entry *strtab_entry);

void elf_section_string_table_entry_set_string(
	elf_section_string_table_entry *strtab_entry, char *string);
void elf_section_string_table_entry_set_offset(
	elf_section_string_table_entry *strtab_entry, uint64_t offset);
void elf_section_string_table_entry_set_length(
	elf_section_string_table_entry *strtab_entry, uint64_t length);

#endif