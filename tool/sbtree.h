
#ifndef _SBTREE_H
#define _SBTREE_H

// a size balance tree
typedef unsigned int	sb_tree_key;
typedef union
{
	void				*ptr;
	unsigned long long	u64;
	signed long long	i64;
	double				dd;
} sb_tree_value;

#define sb_tree_cmp_fun(keyA, keyB) ((keyA) < (keyB))

struct sbtree_node
{
	sb_tree_key						key;
	sb_tree_value					value;
	struct sbtree_node				*left;
	struct sbtree_node				*right;
	unsigned int					size;
};

void								
sb_tree_clean(struct sbtree_node** proot);

const struct sbtree_node* const	
sb_tree_insert(struct sbtree_node** proot, const sb_tree_key key, const sb_tree_value value);

char								
sb_tree_delete(struct sbtree_node** proot, const sb_tree_key key);

unsigned int						
sb_tree_find_cnt(struct sbtree_node* root, const sb_tree_key key);

const struct sbtree_node* const		
sb_tree_find(struct sbtree_node* root, const sb_tree_key key);

const struct sbtree_node* const		
sb_tree_index(struct sbtree_node* root, unsigned int index);

// the cnt < key
unsigned int						
sb_tree_lt(struct sbtree_node* root, const sb_tree_key key);

unsigned int						
sb_tree_size(struct sbtree_node* root);

void								
sb_tree_print(struct sbtree_node* root);

#endif

