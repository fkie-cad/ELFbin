/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_section.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_section {
	// Pointer to the name of this section.
	char *name;

	// Pointer to the section header table entry of this section.
	Elf64_Shdr *section_header;

	// Pointer to the binary that contains this section.
	elf_binary *binary;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_section *elf_section_init(void)
{
	elf_section *new_section = calloc(1, sizeof (elf_section));
	if (new_section == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_section;
}

void elf_section_free(elf_section *section)
{
	if (section != NULL)
		free(section);
}

// Getter / Setter
char *elf_section_get_name(elf_section *section)
{
	return section->name;
}

Elf64_Shdr *elf_section_get_section_header(elf_section *section)
{
	return section->section_header;
}

elf_binary *elf_section_get_binary(elf_section *section)
{
	return section->binary;
}

void elf_section_set_name(elf_section *section, char *name)
{
	section->name = name;
}

void elf_section_set_section_header(elf_section *section,
						Elf64_Shdr *section_header)
{
	section->section_header = section_header;
}

void elf_section_set_binary(elf_section *section, elf_binary *binary)
{
	section->binary = binary;
}