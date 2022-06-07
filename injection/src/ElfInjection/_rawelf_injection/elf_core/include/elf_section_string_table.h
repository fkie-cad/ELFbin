/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_STRING_TABLE_H_
#define _ELF_SECTION_STRING_TABLE_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section elf_section;
typedef struct _elf_section_string_table elf_section_string_table;
typedef struct _elf_section_string_table_entry elf_section_string_table_entry;

// Assume ASCII encoding
typedef enum elf_callback_retval(*lpfn_elf_section_string_table_callback)
	(elf_section_string_table_entry *current, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_string_table *elf_section_string_table_init(void);
void elf_section_string_table_free(elf_section_string_table *strtab);

// Getter / Setter
elf_section *elf_section_string_table_get_section(
	elf_section_string_table *strtab);
uint64_t elf_section_string_table_get_amount_entries(
	elf_section_string_table *strtab);
elf_section_string_table_entry **elf_section_string_table_get_list_entries(
	elf_section_string_table *strtab);

void elf_section_string_table_set_section(elf_section_string_table *strtab,
						elf_section *section);
void elf_section_string_table_set_amount_entries(
	elf_section_string_table *strtab, uint64_t num_entries);
void elf_section_string_table_set_list_entries(
	elf_section_string_table *strtab,
	elf_section_string_table_entry **list_entries);

// Utility
enum elf_result elf_section_string_table_iterate_entries(
	elf_section_string_table *strtab,
	lpfn_elf_section_string_table_callback callback, void *user_data);

enum elf_result elf_section_string_table_get_size(
	elf_section_string_table *strtab, uint64_t *size);

#endif