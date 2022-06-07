/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_RELOCATION_TABLE_ENTRY_H_
#define _ELF_SECTION_RELOCATION_TABLE_ENTRY_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_relocation_table_entry elf_section_relocation_table_entry;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_relocation_table_entry *elf_section_relocation_table_entry_init(
									void);
void elf_section_relocation_table_entry_free(
				elf_section_relocation_table_entry *entry);

// Getter / Setter
Elf64_Rel *elf_section_relocation_table_entry_get_rel(
				elf_section_relocation_table_entry *entry);
Elf64_Rela *elf_section_relocation_table_entry_get_rela(
				elf_section_relocation_table_entry *entry);

void elf_section_relocation_table_entry_set_rel(
		elf_section_relocation_table_entry *entry, Elf64_Rel *rel);
void elf_section_relocation_table_entry_set_rela(
		elf_section_relocation_table_entry *entry, Elf64_Rela *rela);

#endif