/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framwork
#include "./internal/elf_internal.h"
#include "elf_translator.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_translator {
	// currently empty
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_translator *elf_translator_init(void)
{
	elf_translator *translator = calloc(1, sizeof(elf_translator));
	if (translator == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return translator;
}

void elf_translator_free(elf_translator *translator)
{
	if (translator != NULL)
		free(translator);
}