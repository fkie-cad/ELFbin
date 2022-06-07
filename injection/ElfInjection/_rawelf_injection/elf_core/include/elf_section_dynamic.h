/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_DYNAMIC_H_
#define _ELF_SECTION_DYNAMIC_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section elf_section;
typedef struct _elf_section_dynamic elf_section_dynamic;
typedef struct _elf_section_dynamic_entry elf_section_dynamic_entry;
typedef enum elf_callback_retval(*lpfn_elf_section_dynamic_callback)
	(elf_section_dynamic_entry *current, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section_dynamic *elf_section_dynamic_init(void);
void elf_section_dynamic_free(elf_section_dynamic *dyn_section);

// Getter / Setter
elf_section *elf_section_dynamic_get_section(elf_section_dynamic *dyn_section);
uint64_t elf_section_dynamic_get_amount_entries(
	elf_section_dynamic *dyn_section);
elf_section_dynamic_entry **elf_section_dynamic_get_list_entries(
	elf_section_dynamic *dyn_section);

void elf_section_dynamic_set_section(elf_section_dynamic *dyn_section,
					elf_section *abs_section);
void elf_section_dynamic_set_amount_entries(elf_section_dynamic *dyn_section,
						uint64_t num_entries);
void elf_section_dynamic_set_list_entries(elf_section_dynamic *dyn_section,
				elf_section_dynamic_entry **list_entries);

// Utility
enum elf_result elf_section_dynamic_iterate_entries(
	elf_section_dynamic *dyn_section,
	lpfn_elf_section_dynamic_callback callback, void *user_data);

#endif