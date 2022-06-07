/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_segment.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_segment {
	// Pointer to the program header table entry of this segment.
	Elf64_Phdr *program_header;

	// Pointer to the binary containing this segment.
	elf_binary *binary;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_segment *elf_segment_init(void)
{
	elf_segment *new_segment = calloc(1, sizeof(elf_segment));
	if (new_segment == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_segment;
}

void elf_segment_free(elf_segment *segment)
{
	if (segment != NULL)
		free(segment);
}

// Getter / Setter
Elf64_Phdr *elf_segment_get_program_header(elf_segment *segment)
{
	return segment->program_header;
}

elf_binary *elf_segment_get_binary(elf_segment *segment)
{
	return segment->binary;
}

void elf_segment_set_program_header(elf_segment *segment,
					Elf64_Phdr *program_header)
{
	segment->program_header = program_header;
}

void elf_segment_set_binary(elf_segment *segment, elf_binary *binary)
{
	segment->binary = binary;
}