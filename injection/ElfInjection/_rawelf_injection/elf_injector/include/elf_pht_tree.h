/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_PHT_TREE_H_
#define _ELF_PHT_TREE_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_pht_tree elf_pht_tree;
typedef struct _elf_segment elf_segment;

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
/*
* Describes search options. This is used in order to clarify, which fields of
*	Elf64_Phdr to use for comparison with a virtual address or file offset.
* @ELF_TREE_SEARCH_OPTION_VIRTUAL: Searches for a containing segment using
*	the fields 'p_vaddr' and 'p_memsz'. Input is expected to be a virtual
*	address.
* @ELF_TREE_SEARCH_OPTION_VIRTUAL_LOADABLE: Same as
*	'ELF_TREE_SEARCH_OPTION_VIRTUAL' except that only subtrees of loadable
*	segments are considered for comparison.
* @ELF_TREE_SEARCH_OPTION_OFFSET: Searches for a containing segment using the
*	files 'p_offset' and 'p_filesz'. Input is expected to be a file offset.
* @ELF_TREE_SEARCH_OPTION_OFFSET_LOADABLE: Same as
*	'ELF_TREE_SEARCH_OPTION_OFFSET' except that only subtrees of loadable
*	segments are considered for comparison.
*/
enum elf_pht_tree_search_options {
	ELF_TREE_SEARCH_OPTION_VIRTUAL = 0,
	ELF_TREE_SEARCH_OPTION_VIRTUAL_LOADABLE,
	ELF_TREE_SEARCH_OPTION_OFFSET,
	ELF_TREE_SEARCH_OPTION_OFFSET_LOADABLE,
	ELF_TREE_SEARCH_OPTION_MAX,
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_pht_tree *elf_pht_tree_init(void);
void elf_pht_tree_free(elf_pht_tree *tree);

// Getter / Setter
elf_segment *elf_pht_tree_get_segment(elf_pht_tree *tree);
uint32_t elf_pht_tree_get_amount_children(elf_pht_tree *tree);
elf_pht_tree **elf_pht_tree_get_children(elf_pht_tree *tree);

void elf_pht_tree_set_segment(elf_pht_tree *tree, elf_segment *segment);
void elf_pht_tree_set_amount_children(elf_pht_tree *tree,
					uint32_t num_children);
void elf_pht_tree_set_children(elf_pht_tree *tree, elf_pht_tree **children);

// Utility
/*
* 'elf_pht_tree_insert' tries to insert a new node that represents 'new' into
*	'tree'. The insertion will be based upon the containment property. I.e.
*	a segment may become a child of another segment, if, and only if, it
*	lies inside the other segment regarding 'p_offset' and 'p_filesz'.
* @tree: PHT tree that will be expanded.
* @new: Segment to insert into 'tree'.
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- calloc error
*	- reallocarray error
*/
enum elf_result elf_pht_tree_insert(elf_pht_tree *tree, elf_segment *new);

/*
* 'elf_pht_tree_construct' tries to construct a pht tree from a list of
*	segments, i.e. from a pht.
* @tree: Initialized pht tree object that will be filled with nodes from pht.
* @segments: List of segments, from which to construct a pht tree.
* @num_segments: Amount of segments in 'segments'.
* @return: Either success or one of the following:
* 	- invalid parameters
* 	- error returned by 'elf_pht_tree_insert'
*/
enum elf_result elf_pht_tree_construct(elf_pht_tree *tree,
				elf_segment **segments, uint32_t num_segments);

/*
* 'elf_pht_tree_find_container' attempts to search the whole tree for a node
*	that represents a segment that contains 'ref' based upon fields
*	requested in 'option'.
* @tree: PHT tree that will be searched in.
* @ref: Reference, for which to find a containing segment.
* @option: Search option.
* @container: On success, this will reference a container segment, if there is
*	a segment that contains 'ref'. If there is no such segment, this will
*	reference NULL.
* @return: Either success or invalid parameters.
*/
enum elf_result elf_pht_tree_find_container(elf_pht_tree *tree, uint64_t ref,
	enum elf_pht_tree_search_options option, elf_segment **container);

#endif