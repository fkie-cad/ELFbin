/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_platform.h"

#include "elf_binary.h"
#include "./platform/elf_arm64.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_platform_patch_rel(elf_binary *bin, elf_segment **segments,
			uint32_t num_segments, elf_segment **old_segments,
			uint32_t num_old_segments, Elf64_Rel *rel, uint64_t data,
			uint64_t data_size)
{
	enum elf_result result;
	Elf64_Ehdr *elf_header;

	if (bin == NULL || segments == NULL || rel == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	elf_header = elf_binary_get_elf_header(bin);

	switch (elf_header->e_machine) {
	case EM_AARCH64:
		result = elf_arm64_patch_rel(bin, segments, num_segments,
						old_segments, num_old_segments, rel,
						data, data_size);
		break;
	default:
		result = ELF_PLATFORM_NOT_SUPPORTED;
	}

	return result;
}

enum elf_result elf_platform_patch_rela(elf_binary *bin,
	elf_segment **segments, uint32_t num_segments,
	elf_segment **old_segments, uint32_t num_old_segments, Elf64_Rela *rela,
	uint64_t data, uint64_t data_size)
{
	enum elf_result result;
	Elf64_Ehdr *elf_header;

	if (bin == NULL || segments == NULL || rela == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	elf_header = elf_binary_get_elf_header(bin);
	switch (elf_header->e_machine) {
	case EM_AARCH64:
		result = elf_arm64_patch_rela(bin, segments, num_segments,
						old_segments, num_old_segments,
						rela, data, data_size);
		break;
	default:
		result = ELF_PLATFORM_NOT_SUPPORTED;
	}

	return result;
}