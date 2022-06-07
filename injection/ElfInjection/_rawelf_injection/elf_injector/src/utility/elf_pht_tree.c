/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Injector
#include "./internal/elf_internal.h"
#include "elf_pht_tree.h"

// Core
#include "elf_segment.h"

// Standard
#include <string.h>

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
static elf_pht_tree *_elf_get_target_parent(elf_pht_tree *tree,
						elf_segment *new);
static uint32_t *_elf_is_parent(elf_pht_tree *target, elf_segment *new,
				uint32_t *num_elements);

// Searching
static elf_segment *_elf_search_virtual(elf_pht_tree *tree, uint64_t ref);
static elf_segment *_elf_search_virtual_loadable(elf_pht_tree *tree,
							uint64_t ref);
static elf_segment *_elf_search_offset(elf_pht_tree *tree, uint64_t ref);
static elf_segment *_elf_search_offset_loadable(elf_pht_tree *tree,
							uint64_t ref);

static elf_pht_tree **_elf_find_loadable_subtrees(elf_pht_tree *tree,
						uint32_t *num_loadables);

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_pht_tree_insert(elf_pht_tree *tree, elf_segment *new)
{
	elf_pht_tree *target;
	elf_pht_tree *new_entry;
	elf_pht_tree **temp;
	uint32_t num_children;
	elf_pht_tree **children;
	uint32_t *indices;
	uint32_t num_indices;
	uint32_t i;
	uint32_t n;

	if (tree == NULL || new == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	target = _elf_get_target_parent(tree, new);
	num_children = elf_pht_tree_get_amount_children(target);
	children = elf_pht_tree_get_children(target);

	// Create new node.
	new_entry = elf_pht_tree_init();
	if (new_entry == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);
	elf_pht_tree_set_segment(new_entry, new);

	// Check if 'new' contains any child node. 'indices' is sorted in
	// ascending order!
	indices = _elf_is_parent(target, new, &num_indices);
	if (indices == NULL) {
		// Insert new node into children array.
		temp = reallocarray(children, num_children + 1,
					sizeof(elf_pht_tree*));
		if (temp == NULL) {
			elf_pht_tree_free(new_entry);
			log_return(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
		}
		elf_pht_tree_set_children(target, temp);
		elf_pht_tree_set_amount_children(target, num_children + 1);
		temp[num_children] = new_entry;
	} else {
		temp = calloc(num_indices, sizeof(elf_pht_tree*));
		if (temp == NULL) {
			elf_pht_tree_free(new_entry);
			free(indices);
			log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
					ELF_PRINTTYPE_ERRNO);
		}
		elf_pht_tree_set_children(new_entry, temp);
		elf_pht_tree_set_amount_children(new_entry, num_indices);

		for (i = 0; i < num_indices; i++)
			temp[i] = children[indices[i]];

		children[indices[0]] = new_entry;
		for (i = 1; i < num_indices; i++)
			children[indices[i]] = NULL;

		// Sort children such that values with 'num_children'
		// are at the very end. That's modified Bubblesort btw:
		// https://de.wikipedia.org/wiki/Bubblesort
		for (n = num_children; n > 1; n--) {
			for (i = 0; i < n - 1; i++) {
				if (children[i] == NULL) {
					children[i] = children[i+1];
					children[i+1] = NULL;
				}
			}
		}

		// Cut last values
		temp = reallocarray(children, num_children - (num_indices - 1),
					sizeof(elf_pht_tree*));
		if (temp == NULL) {
			elf_pht_tree_free(new_entry);
			free(indices);
			log_return(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
		}
		elf_pht_tree_set_children(target, temp);
		elf_pht_tree_set_amount_children(target,
			num_children - (num_indices - 1));

		free(indices);
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_pht_tree_construct(elf_pht_tree *tree,
				elf_segment **segments, uint32_t num_segments)
{
	enum elf_result result;
	uint32_t i;

	if (tree == NULL || segments == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	for (i = 0; i < num_segments; i++) {

		result = elf_pht_tree_insert(tree, segments[i]);
		if (result != ELF_COMMON_SUCCESS) {
			elf_pht_tree_free(tree); // kills whole tree
			tree = elf_pht_tree_init();
			log_return(ELF_LOGLEVEL_ERROR, result,
					ELF_PRINTTYPE_NONE);
		}
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_pht_tree_find_container(elf_pht_tree *tree, uint64_t ref,
	enum elf_pht_tree_search_options option, elf_segment **container)
{
	if (tree == NULL || container == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	switch (option) {

	case ELF_TREE_SEARCH_OPTION_VIRTUAL:
		*container = _elf_search_virtual(tree, ref);
		break;
	case ELF_TREE_SEARCH_OPTION_VIRTUAL_LOADABLE:
		*container = _elf_search_virtual_loadable(tree, ref);
		break;
	case ELF_TREE_SEARCH_OPTION_OFFSET:
		*container = _elf_search_offset(tree, ref);
		break;
	case ELF_TREE_SEARCH_OPTION_OFFSET_LOADABLE:
		*container = _elf_search_offset_loadable(tree, ref);
		break;
	default:
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	}
	return ELF_COMMON_SUCCESS;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
elf_pht_tree *_elf_get_target_parent(elf_pht_tree *tree, elf_segment *new)
{
	//if (elf_pht_tree_get_children(tree) == NULL)
	//	return tree;

	Elf64_Phdr *raw = elf_segment_get_program_header(new);
	elf_pht_tree **children = elf_pht_tree_get_children(tree);
	elf_segment *cur_seg;
	Elf64_Phdr *cur;
	uint32_t i;
	for (i = 0; i < elf_pht_tree_get_amount_children(tree); i++) {
		cur_seg = elf_pht_tree_get_segment(children[i]);
		cur = elf_segment_get_program_header(cur_seg);
		if (cur->p_offset <= raw->p_offset &&
		    (cur->p_offset + cur->p_filesz 
		    	>= raw->p_offset + raw->p_filesz)) {
			// Found a child that contains 'new'.
			return _elf_get_target_parent(children[i], new);
		}
	}

	return tree;
}

uint32_t *_elf_is_parent(elf_pht_tree *target, elf_segment *new,
				uint32_t *num_elements)
{
	//if (elf_pht_tree_get_children(target) == NULL)
	//	return 0;

	uint32_t *list = NULL;
	uint32_t *temp;
	uint32_t num_entries = 0;
	Elf64_Phdr *raw;
	uint32_t num_children = elf_pht_tree_get_amount_children(target);
	elf_pht_tree **children = elf_pht_tree_get_children(target);
	uint32_t i;
	elf_segment *cur_seg;
	Elf64_Phdr *cur;

	// Check if new node contains one of the other children.
	raw = elf_segment_get_program_header(new);
	for (i = 0; i < num_children; i++) {
		cur_seg = elf_pht_tree_get_segment(children[i]);
		cur = elf_segment_get_program_header(cur_seg);

		if (raw->p_offset <= cur->p_offset &&
		    (raw->p_offset + raw->p_filesz
		    	 >= cur->p_offset + cur->p_filesz)) {
			temp = reallocarray(list, num_entries + 1,
					sizeof(uint32_t));
			if (temp == NULL) {
				free(list);
				log(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
				return NULL;
			}
			list = temp;
			list[num_entries] = i;
			num_entries += 1;
		}
	}

	*num_elements = num_entries;
	return list;
}

elf_segment *_elf_search_virtual(elf_pht_tree *tree, uint64_t ref)
{
	uint32_t i;
	uint32_t num_children = elf_pht_tree_get_amount_children(tree);
	elf_pht_tree **children = elf_pht_tree_get_children(tree);
	elf_segment *segment;
	Elf64_Phdr *cur;

	for (i = 0; i < num_children; i++) {
		segment = elf_pht_tree_get_segment(children[i]);
		cur = elf_segment_get_program_header(segment);
		if (cur->p_vaddr <= ref &&
		    cur->p_vaddr + cur->p_memsz > ref)
			return _elf_search_virtual(children[i], ref);
	}

	return elf_pht_tree_get_segment(tree);
}

elf_segment *_elf_search_virtual_loadable(elf_pht_tree *tree, uint64_t ref)
{
	uint32_t i;
	uint32_t num_subtrees;
	elf_pht_tree **subtrees;
	elf_segment *segment;
	Elf64_Phdr *cur;

	subtrees = _elf_find_loadable_subtrees(tree, &num_subtrees);
	for (i = 0; i < num_subtrees; i++) {
		segment = elf_pht_tree_get_segment(subtrees[i]);
		cur = elf_segment_get_program_header(segment);

		if (cur->p_vaddr <= ref &&
		    cur->p_vaddr + cur->p_memsz > ref) {
		    	segment = _elf_search_virtual(subtrees[i], ref);
			free(subtrees);
			return segment;
		}
	}

	free(subtrees);
	return elf_pht_tree_get_segment(tree);
}

elf_segment *_elf_search_offset(elf_pht_tree *tree, uint64_t ref)
{
	uint32_t i;
	uint32_t num_children = elf_pht_tree_get_amount_children(tree);
	elf_pht_tree **children = elf_pht_tree_get_children(tree);
	elf_segment *segment;
	Elf64_Phdr *cur;

	for (i = 0; i < num_children; i++) {
		segment = elf_pht_tree_get_segment(children[i]);
		cur = elf_segment_get_program_header(segment);
		if (cur->p_offset <= ref &&
		    cur->p_offset + cur->p_filesz > ref)
			return _elf_search_offset(children[i], ref);
	}

	return elf_pht_tree_get_segment(tree);
}

elf_segment *_elf_search_offset_loadable(elf_pht_tree *tree, uint64_t ref)
{
	uint32_t i;
	uint32_t num_subtrees;
	elf_pht_tree **subtrees;
	elf_segment *segment;
	Elf64_Phdr *cur;

	subtrees = _elf_find_loadable_subtrees(tree, &num_subtrees);
	for (i = 0; i < num_subtrees; i++) {
		segment = elf_pht_tree_get_segment(subtrees[i]);
		cur = elf_segment_get_program_header(segment);

		if (cur->p_offset <= ref &&
		    cur->p_offset + cur->p_filesz > ref) {
			segment = _elf_search_offset(subtrees[i], ref);
			free(subtrees);
			return segment;
		}
	}

	free(subtrees);
	return elf_pht_tree_get_segment(tree);
}

elf_pht_tree **_elf_find_loadable_subtrees(elf_pht_tree *tree,
						uint32_t *num_loadables)
{
	elf_pht_tree **loadables = NULL;
	uint32_t amount_loadables = 0;
	elf_pht_tree **temp;
	uint32_t i;
	uint32_t num_children = elf_pht_tree_get_amount_children(tree);
	elf_pht_tree **children = elf_pht_tree_get_children(tree);
	elf_segment *segment;
	Elf64_Phdr *cur;
	elf_pht_tree **subtrees = NULL;
	uint32_t amount_subtrees = 0;

	for (i = 0; i < num_children; i++) {
		segment = elf_pht_tree_get_segment(children[i]);
		cur = elf_segment_get_program_header(segment);
		if (cur->p_type == PT_LOAD) {
			// add loadable to list
			temp = reallocarray(loadables, amount_loadables + 1,
					sizeof(elf_pht_tree*));
			if (temp == NULL) {
				free(loadables);
				log(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
				return NULL;
			}
			loadables = temp;
			loadables[amount_loadables] = children[i];
			amount_loadables += 1;

			// finally skip subtree
			continue;
		}

		// otherwise cur is not a loadable subtree
		// but can still contain such a tree
		subtrees = _elf_find_loadable_subtrees(children[i],
							&amount_subtrees);
		if (subtrees == NULL)
			continue;

		temp = reallocarray(loadables,
					amount_loadables + amount_subtrees,
					sizeof(elf_pht_tree*));
		if (temp == NULL) {
			free(subtrees);
			free(loadables);
			log(ELF_LOGLEVEL_ERROR, ELF_STD_REALLOCARRAY,
					ELF_PRINTTYPE_ERRNO);
			return NULL;
		}
		loadables = temp;
		memcpy(&loadables[amount_loadables], subtrees,
			amount_subtrees * sizeof(elf_pht_tree*));
		amount_loadables += amount_subtrees;
		free(subtrees);
	}

	*num_loadables = amount_loadables;
	return loadables;
}