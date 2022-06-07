/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_MODULE_COMMON_H_
#define _ELF_MODULE_COMMON_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_debug.h"

// Standard
#include <stddef.h>
#include <stdlib.h>

#define OFFSET(base_address, amount_bytes)		\
	(((uint8_t*)base_address) + amount_bytes)

#define SECTION_ADDRESS_BY_INDEX(bin, index)\
	((Elf64_Shdr*)OFFSET(elf_binary_get_elf_header(bin), ((uint64_t)elf_binary_get_elf_header(bin)->e_shoff) + index * sizeof(Elf64_Shdr)))


#define SEGMENT_ADDRESS_BY_INDEX(bin, index)\
	((Elf64_Phdr*)OFFSET(elf_binary_get_elf_header(bin), ((uint64_t)elf_binary_get_elf_header(bin)->e_phoff) + index * sizeof(Elf64_Phdr)))


#endif