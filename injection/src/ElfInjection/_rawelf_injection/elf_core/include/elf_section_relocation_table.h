/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_RELOCATION_TABLE_H_
#define _ELF_SECTION_RELOCATION_TABLE_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_relocation_table elf_section_relocation_table;
typedef struct _elf_section_relocation_table_entry elf_section_relocation_table_entry;
typedef struct _elf_section elf_section;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_relocation_table *elf_section_relocation_table_init(void);
void elf_section_relocation_table_free(elf_section_relocation_table *rtab);

// Getter / Setter
elf_section *elf_section_relocation_table_get_section(
					elf_section_relocation_table *rtab);
uint32_t elf_section_relocation_table_get_type(
					elf_section_relocation_table *rtab);
uint64_t elf_section_relocation_table_get_amount_entries(
					elf_section_relocation_table *rtab);
elf_section_relocation_table_entry **elf_section_relocation_table_get_list_entries(
					elf_section_relocation_table *rtab);

void elf_section_relocation_table_set_section(
		elf_section_relocation_table *rtab, elf_section *section);
void elf_section_relocation_table_set_type(elf_section_relocation_table *rtab,
						int64_t type);
void elf_section_relocation_table_set_amount_entries(
		elf_section_relocation_table *rtab, uint64_t amount_entries);
void elf_section_relocation_table_set_list_entries(
	elf_section_relocation_table *rtab,
	elf_section_relocation_table_entry **list_entries);

// Utility

#endif