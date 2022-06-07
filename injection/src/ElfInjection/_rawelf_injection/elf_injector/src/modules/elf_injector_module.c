/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "../../include/internal/elf_internal.h"
#include "../../include/elf_injector.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_injector {
	// currently empty
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_injector *elf_injector_init(void)
{
	elf_injector *new_injector = calloc(1, sizeof(elf_injector));
	if (new_injector == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_injector;
}

void elf_injector_free(elf_injector *injector)
{
	if (injector != NULL)
		free(injector);
}

// Getter / Setter

