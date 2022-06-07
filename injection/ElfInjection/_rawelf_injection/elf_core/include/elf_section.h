/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SECTION_H_
#define _ELF_SECTION_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_section elf_section;
typedef struct _elf_binary elf_binary;

/*------------------------------------------------------------------------*/
/* Global Structure Declarations                                          */
/* NOTE: This is necessary to avoid cyclic includes!                      */
/*------------------------------------------------------------------------*/
typedef struct _elf_section_dynamic elf_section_dynamic;
typedef struct _elf_section_symbol_table elf_section_symbol_table;
typedef struct _elf_section_string_table elf_section_string_table;
typedef struct _elf_section_relocation_table elf_section_relocation_table;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section *elf_section_init(void);
void elf_section_free(elf_section *section);

// Getter / Setter
char *elf_section_get_name(elf_section *section);
Elf64_Shdr *elf_section_get_section_header(elf_section *section);
elf_binary *elf_section_get_binary(elf_section *section);

void elf_section_set_name(elf_section *section, char *name);
void elf_section_set_section_header(elf_section *section,
						Elf64_Shdr *section_header);
void elf_section_set_binary(elf_section *section, elf_binary *binary);

// Utility
enum elf_result elf_section_map_to_dynamic(elf_section *section,
					elf_section_dynamic **dyn_section);
enum elf_result elf_section_map_to_symbol_table(elf_section *section,
		uint64_t off_strtab, elf_section_symbol_table **symtab);
enum elf_result elf_section_map_to_string_table(elf_section *section,
					elf_section_string_table **strtab);
enum elf_result elf_section_map_to_reloc_table(elf_section *section,
					elf_section_relocation_table **rtab);

enum elf_result elf_section_has_symbol_table(elf_section *section,
						uint8_t *has_symtab);
enum elf_result elf_section_has_string_table(elf_section *section,
						uint8_t *has_strtab);
enum elf_result elf_section_has_reloc_table(elf_section *section,
						uint8_t *has_rtab);

#endif