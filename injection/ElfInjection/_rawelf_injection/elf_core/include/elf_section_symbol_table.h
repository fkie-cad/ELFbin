/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_SYMBOL_TABLE_H_
#define _ELF_SECTION_SYMBOL_TABLE_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_symbol_table elf_section_symbol_table;
typedef struct _elf_section_symbol_table_entry elf_section_symbol_table_entry;
typedef struct _elf_section elf_section;

typedef enum elf_callback_retval(*lpfn_elf_section_symbol_table_callback)
	(elf_section_symbol_table_entry *current, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_symbol_table *elf_section_symbol_table_init(void);
void elf_section_symbol_table_free(elf_section_symbol_table *symtab);

// Getter / Setter
elf_section *elf_section_symbol_table_get_section(
	elf_section_symbol_table *symtab);
uint64_t elf_section_symbol_table_get_amount_entries(
	elf_section_symbol_table *symtab);
elf_section_symbol_table_entry **elf_section_symbol_table_get_list_entries(
	elf_section_symbol_table *symtab);

void elf_section_symbol_table_set_section(elf_section_symbol_table *symtab,
						elf_section *section);
void elf_section_symbol_table_set_amount_entries(
	elf_section_symbol_table *symtab, uint64_t num_entries);
void elf_section_symbol_table_set_list_entries(
	elf_section_symbol_table *symtab,
	elf_section_symbol_table_entry **list_entries);

// Utility
enum elf_result elf_section_symbol_table_iterate_entries(
	elf_section_symbol_table *symtab,
	lpfn_elf_section_symbol_table_callback callback, void *user_data);

#endif