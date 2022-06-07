/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Injector
#include "./internal/elf_internal.h"
#include "elf_translator.h"
#include "elf_pht_tree.h"

// Core
#include "elf_segment.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_translator_vaddr_to_offset(elf_translator *translator,
		elf_segment **segments, uint32_t num_segments, uint64_t vaddr,
		uint64_t *offset)
{
	enum elf_result result;
	elf_segment *container;
	Elf64_Phdr *raw;

	// Check parameters
	if (translator == NULL || segments == NULL || vaddr == 0 ||
	    offset == NULL || num_segments == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Get segment that contains the virtual address
	result = elf_translator_get_surrounding_segment_virtual(translator,
				segments, num_segments, vaddr, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Calculate offset from vaddr. If there is no containing segment,
	// just treat the virtual address as offset.
	if (container != NULL) {
		raw = elf_segment_get_program_header(container);
		*offset = vaddr - raw->p_vaddr + raw->p_offset;

		// Check if virtual address is only valid in process image.
		if (vaddr - raw->p_vaddr >= raw->p_filesz)
			log_return(ELF_LOGLEVEL_SOFTERROR,
					ELF_TRANSLATOR_VADDR_OUT_OF_BOUNDS,
					ELF_PRINTTYPE_NONE);
	} else {
		*offset = vaddr;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_translator_offset_to_vaddr(elf_translator *translator,
		elf_segment **segments, uint32_t num_segments, uint64_t offset,
		uint64_t *vaddr)
{
	enum elf_result result;
	elf_segment *container;
	Elf64_Phdr *raw;

	// Check parameters
	if (translator == NULL || segments == NULL || vaddr == NULL ||
	    num_segments == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Get segment that contains the file offset
	result = elf_translator_get_surrounding_segment_offset(translator,
				segments, num_segments, offset, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Calculate vaddr from offset.
	if (container != NULL) {
		raw = elf_segment_get_program_header(container);
		*vaddr = offset - raw->p_offset + raw->p_vaddr;
	} else {
		*vaddr = offset;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_translator_get_surrounding_segment_virtual(
		elf_translator *translator, elf_segment **segments,
		uint32_t num_segments, uint64_t vaddr, uint8_t loadable,
		elf_segment **container)
{
	__label__ label_free_tree;
	enum elf_result result;
	elf_pht_tree *tree;
	enum elf_pht_tree_search_options option;

	// Check parameters
	if (translator == NULL || segments == NULL || container == NULL ||
	    num_segments == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*container = NULL;
	result = ELF_COMMON_SUCCESS;

	// Create pht tree object
	tree = elf_pht_tree_init();
	if (tree == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	// Construct tree from list of segments
	result = elf_pht_tree_construct(tree, segments, num_segments);
	if (result != ELF_COMMON_SUCCESS) {
		log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
		goto label_free_tree;
	}

	// Set search criteria and search for containing segment
	if (loadable)
		option = ELF_TREE_SEARCH_OPTION_VIRTUAL_LOADABLE;
	else
		option = ELF_TREE_SEARCH_OPTION_VIRTUAL;
	result = elf_pht_tree_find_container(tree, vaddr, option, container);
	if (result != ELF_COMMON_SUCCESS)
		log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

label_free_tree:
	elf_pht_tree_free(tree);

	return result;
}

enum elf_result elf_translator_get_surrounding_segment_offset(
		elf_translator *translator, elf_segment **segments,
		uint32_t num_segments, uint64_t offset, uint8_t loadable,
		elf_segment **container)
{
	__label__ label_free_tree;
	enum elf_result result;
	elf_pht_tree *tree;
	enum elf_pht_tree_search_options option;

	// Check parameters
	if (translator == NULL || segments == NULL || container == NULL ||
	    num_segments == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*container = NULL;
	result = ELF_COMMON_SUCCESS;

	// Create pht tree object
	tree = elf_pht_tree_init();
	if (tree == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	// Construct pht tree from list of segments
	result = elf_pht_tree_construct(tree, segments, num_segments);
	if (result != ELF_COMMON_SUCCESS) {
		log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
		goto label_free_tree;
	}

	// Set search criteria and search for surrounding segment
	if (loadable)
		option = ELF_TREE_SEARCH_OPTION_OFFSET_LOADABLE;
	else
		option = ELF_TREE_SEARCH_OPTION_OFFSET;
	result = elf_pht_tree_find_container(tree, offset, option, container);
	if (result != ELF_COMMON_SUCCESS)
		log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

label_free_tree:
	elf_pht_tree_free(tree);

	return result;
}