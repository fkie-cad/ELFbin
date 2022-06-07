/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_PLATFORM_H_
#define _ELF_PLATFORM_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_binary elf_binary;
typedef struct _elf_segment elf_segment;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
enum elf_result elf_platform_patch_rel(elf_binary *bin, elf_segment **segments,
			uint32_t num_segments, elf_segment **old_segments,
			uint32_t num_old_segments, Elf64_Rel *rel, uint64_t data,
			uint64_t data_size);
enum elf_result elf_platform_patch_rela(elf_binary *bin,
	elf_segment **segments, uint32_t num_segments,
	elf_segment **old_segments, uint32_t num_old_segments, Elf64_Rela *rela,
	uint64_t data, uint64_t data_size);

#endif