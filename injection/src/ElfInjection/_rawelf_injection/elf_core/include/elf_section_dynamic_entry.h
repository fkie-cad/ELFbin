/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_DYNAMIC_ENTRY_H_
#define _ELF_SECTION_DYNAMIC_ENTRY_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_dynamic_entry elf_section_dynamic_entry;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_dynamic_entry *elf_section_dynamic_entry_init(void);
void elf_section_dynamic_entry_free(elf_section_dynamic_entry *entry);

// Getter / Setter
Elf64_Dyn *elf_section_dynamic_entry_get_raw_entry(
	elf_section_dynamic_entry *entry);

void elf_section_dynamic_entry_set_raw_entry(elf_section_dynamic_entry *entry,
						Elf64_Dyn *raw_entry);

#endif