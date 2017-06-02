
#include <stdlib.h>
#include <string.h>
#include "sbtree.h"

#ifdef __cplusplus
extern "C" {
#endif

void sb_tree_clean(struct sbtree_node** pnode)
{
	if (!pnode || !(*pnode))
	{
		return;
	}
	sb_tree_clean(&(*pnode)->left);
	sb_tree_clean(&(*pnode)->right);
	free((*pnode));
	*pnode = 0;
}

static unsigned int _S(const struct sbtree_node* node)
{
	return node ? node->size : 0;
} 

static void left_rotate(struct sbtree_node** pnode)
{
	struct sbtree_node* node;
	struct sbtree_node* right;

	node = *pnode;
	right = node->right;
	node->right = right->left;
	right->left = node;
	right->size = node->size;
	node->size = _S(node->left) + _S(node->right) + 1;
	*pnode = right;
}

static void right_rotate(struct sbtree_node** pnode)
{
	struct sbtree_node* node;
	struct sbtree_node* left;

	node = *pnode;
	left = node->left;
	node->left = left->right;
	left->right = node;
	left->size = node->size;
	node->size = _S(node->left) + _S(node->right) + 1;
	*pnode = left;
}

static void sb_tree_main_tain(struct sbtree_node** pnode, char rightdeeper)
{
	unsigned int usize;
	struct sbtree_node* node;

	if(!pnode || !(*pnode)) return;
	node = *pnode;
	if(!rightdeeper)
	{
		if(!node->left) return;
		usize = _S(node->right);
		if(_S(node->left->left) > usize)
		{
			right_rotate(pnode);
		}
		else if(_S(node->left->right) > usize)
		{
			left_rotate(&node->left);
			right_rotate(pnode);
		}
		else
		{
			return;
		}
		sb_tree_main_tain(&node->left, 0);
	}
	else
	{
		if(!node->right) return;

		usize = _S(node->left);
		if(_S(node->right->right) > usize)
		{
			left_rotate(pnode);
		}
		else if(_S(node->right->left) > usize)
		{
			right_rotate(&node->right);
			left_rotate(pnode);
		}
		else
		{
			return;
		}
		sb_tree_main_tain(&node->right, 1);
	}
	sb_tree_main_tain(pnode, 0);
	sb_tree_main_tain(pnode, 1);
}

static void sb_tree_insert_node(struct sbtree_node** comp_node, struct sbtree_node* node)
{
	struct sbtree_node* s_node;
	char isleft;
	s_node = *comp_node;
	if(!s_node)
	{
		node->size = 1;
		(*comp_node) = node;
		return;
	}
	++s_node->size;
	isleft = sb_tree_cmp_fun(node->key, s_node->key);
	if(isleft)
	{
		sb_tree_insert_node(&s_node->left, node);
	}
	else
	{
		sb_tree_insert_node(&s_node->right, node);
	}
	sb_tree_main_tain(comp_node, (1 - (isleft & (char)1)));
}

const struct sbtree_node* const
sb_tree_insert(struct sbtree_node** proot, const sb_tree_key key, const sb_tree_value value)
{
	struct sbtree_node* node;
	node = (struct sbtree_node*)malloc(sizeof(struct sbtree_node));
	if(!node) return 0;
	memset(node, 0, sizeof(struct sbtree_node));
	node->key = key;
	node->value = value;
	sb_tree_insert_node(proot, node);
	return node;
}

static struct sbtree_node* sb_tree_delete_node(struct sbtree_node** pnode, const sb_tree_key key, char isfind)
{
	struct sbtree_node* node;
	struct sbtree_node* record;

	node = *pnode;
	if(!node) return 0;

	if(isfind && !node->right)
	{
		//  the right end node of right child tree replace the delete node
		record = node;
		*pnode = node->left;
		return record;
	}

	if(!isfind && key == node->key)
	{
		if(node->size == 1)
		{
			// leaf node, need delete
			record = node;
			*pnode = 0;
			return record;
		}
		if(node->size == 2)
		{
			// single branch node, need child node replace delete node
			record = node->left ? node->left : node->right;
			node->left = 0;
			node->right = 0;
		}
		else
		{
			// max key node of left tree replace pnode
			record = sb_tree_delete_node(&node->left, key, 1);
		}
		if(record)
		{
			node->key = record->key;
			node->value = record->value;
		}
		--node->size;
		sb_tree_main_tain(pnode, 1);
	}
	else if(!isfind && sb_tree_cmp_fun(key, node->key))
	{
		record = sb_tree_delete_node(&node->left, key, 0);
		if(record)
		{
			--node->size;
		}
	}
	else
	{
		record = sb_tree_delete_node(&node->right, key, isfind);
		if(record)
		{
			--node->size;
		}
	}
	sb_tree_main_tain(pnode, (1 - isfind) && sb_tree_cmp_fun(key, node->key) );
	return record;
}

char
sb_tree_delete(struct sbtree_node** pnode, const sb_tree_key key)
{
	struct sbtree_node* node;
	node = sb_tree_delete_node(pnode, key, 0);
	if(node)
	{
		free(node);
		return 1;
	}
	return 0;
}

unsigned int
sb_tree_find_cnt(struct sbtree_node* root, const sb_tree_key key)
{
	if(!root) return 0;
	if(sb_tree_cmp_fun(key, root->key))
	{
		return sb_tree_find_cnt(root->left, key);
	}
	else if(sb_tree_cmp_fun(root->key, key))
	{
		return sb_tree_find_cnt(root->right, key);
	}
	else
	{
		return 1 + sb_tree_find_cnt(root->left, key) + sb_tree_find_cnt(root->right, key);
	}
}

const struct sbtree_node* const
sb_tree_find(struct sbtree_node* root, const sb_tree_key key)
{
	if(!root) return 0;

	if(sb_tree_cmp_fun(key, root->key))
	{
		return sb_tree_find(root->left, key);
	}
	else if(sb_tree_cmp_fun(root->key, key))
	{
		return sb_tree_find(root->right, key);
	}
	else
	{
		return root;
	}
}

const struct sbtree_node* const
sb_tree_index(struct sbtree_node* root, unsigned int index)
{
	unsigned int usize;

	if(!root) return 0;

	if(index >= _S(root)) return 0;

	while(1)
	{
		usize = _S(root->left);
		if(index == usize)
		{
			return root;
		}
		if(index < usize)
		{
			root = root->left;
		}
		else
		{
			index -= (usize + 1);
			root = root->right;
		}
	}
	return 0;
}

unsigned int
sb_tree_lt(struct sbtree_node* node, const sb_tree_key key)
{
	if(!node) return 0;
	if(sb_tree_cmp_fun(node->key, key))
	{
		return _S(node->left) + 1 + sb_tree_lt(node->right, key);
	}
	else
	{
		return sb_tree_lt(node->left, key);
	}
}

unsigned int
sb_tree_size(struct sbtree_node* root)
{
	return _S(root);
}
//
//#include <stdio.h>
//
//void sb_tree_print_node(struct sbtree_node* node, unsigned short height, char isleft)
//{
//	unsigned short i;
//	if(!node) return;
//	sb_tree_print_node(node->left, height + 1, 1);
//	for(i = 0; i < height; ++i)
//	{
//		printf("	");
//	}
//	if(isleft)
//	{
//		printf("L");
//	}
//	else
//	{
//		printf("R");
//	}
//	printf("%ud,%ud\n", node->key, node->size);
//	sb_tree_print_node(node->right, height + 1, 0);
//}
//
//void sb_tree_print(struct sbtree_node* root)
//{
//	sb_tree_print_node(root, 0, 1);
//}


#ifdef __cplusplus
}
#endif


