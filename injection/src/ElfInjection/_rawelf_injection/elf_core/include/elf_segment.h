/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_SEGMENT_H_
#define _ELF_SEGMENT_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_segment elf_segment;
typedef struct _elf_binary elf_binary;
typedef struct _elf_section_dynamic elf_section_dynamic;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_segment *elf_segment_init(void);
void elf_segment_free(elf_segment *segment);

// Getter / Setter
Elf64_Phdr *elf_segment_get_program_header(elf_segment *segment);
elf_binary *elf_segment_get_binary(elf_segment *segment);

void elf_segment_set_program_header(elf_segment *segment,
					Elf64_Phdr *program_header);
void elf_segment_set_binary(elf_segment *segment, elf_binary *binary);

// Utility
enum elf_result elf_segment_map_to_dynamic(elf_segment *segment,
					elf_section_dynamic **dyn_section);

#endif