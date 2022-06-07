/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
#include "./internal/elf_internal.h"
#include "elf_pht_tree.h"

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
/*
* Describes a tree consisting of segments.
* @segment: Segment that this node represents.
* @num_children: Amount of entries in 'children'.
* @children: Array of node elements.
*/
struct _elf_pht_tree {
	elf_segment *segment;
	uint32_t num_children;
	elf_pht_tree **children;
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_pht_tree *elf_pht_tree_init(void)
{
	elf_pht_tree *tree = calloc(1, sizeof(elf_pht_tree));
	if (tree == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	return tree;
}

void elf_pht_tree_free(elf_pht_tree *tree)
{
	if (tree == NULL)
		return;
	uint32_t i;
	if (tree->children != NULL) {
		for (i = 0; i < tree->num_children; i++)
			elf_pht_tree_free(tree->children[i]);
		free(tree->children);
	}

	free(tree);
}

// Getter / Setter
elf_segment *elf_pht_tree_get_segment(elf_pht_tree *tree)
{
	return tree->segment;
}

uint32_t elf_pht_tree_get_amount_children(elf_pht_tree *tree)
{
	return tree->num_children;
}

elf_pht_tree **elf_pht_tree_get_children(elf_pht_tree *tree)
{
	return tree->children;
}

void elf_pht_tree_set_segment(elf_pht_tree *tree, elf_segment *segment)
{
	tree->segment = segment;
}

void elf_pht_tree_set_amount_children(elf_pht_tree *tree,
					uint32_t num_children)
{
	tree->num_children = num_children;
}

void elf_pht_tree_set_children(elf_pht_tree *tree, elf_pht_tree **children)
{
	tree->children = children;
}