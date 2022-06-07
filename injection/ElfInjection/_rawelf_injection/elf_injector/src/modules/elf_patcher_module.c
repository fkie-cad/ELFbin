/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "./elf_patcher.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_patcher {
	// currently empty
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_patcher *elf_patcher_init(void)
{
	elf_patcher *new_patcher = calloc(1, sizeof(elf_patcher));
	if (new_patcher == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return new_patcher;
}

void elf_patcher_free(elf_patcher *patcher)
{
	if (patcher != NULL)
		free(patcher);
}

// Getter / Setter

