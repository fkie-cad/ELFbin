/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_SYMBOL_TABLE_ENTRY_H_
#define _ELF_SECTION_SYMBOL_TABLE_ENTRY_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_symbol_table_entry elf_section_symbol_table_entry;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_symbol_table_entry *elf_section_symbol_table_entry_init(void);
void elf_section_symbol_table_entry_free(
	elf_section_symbol_table_entry *entry);

// Getter / Setter
char *elf_section_symbol_table_entry_get_name(
	elf_section_symbol_table_entry *entry);
Elf64_Sym *elf_section_symbol_table_entry_get_raw_entry(
	elf_section_symbol_table_entry *entry);

void elf_section_symbol_table_entry_set_name(
	elf_section_symbol_table_entry *entry, char *name);
void elf_section_symbol_table_entry_set_raw_entry(
	elf_section_symbol_table_entry *entry, Elf64_Sym *raw_entry);

#endif