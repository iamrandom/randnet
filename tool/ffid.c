/*
 * ffid.c
 *
 *  Created on: 2014-12-02
 *      Author: Random
 */

#include "ffid.h"
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ffid
{
	ffid_vtype*		ts;
	ffid_vtype		max_limit;
	ffid_vtype		first;
	unsigned short	end;
	unsigned short	cur_size;
	unsigned short	max_size;
	char			is_loop;
};

struct ffid*
ffid_create(unsigned short max_size, char is_loop)
{
	unsigned short i;
	struct ffid* ff = (struct ffid*)malloc(sizeof(struct ffid));
	if(!ff) return 0;
	ff->first = 0;
	ff->end =max_size - 1;
	ff->cur_size = 0;
	ff->max_limit = 0;
	--ff->max_limit;
	//	assert(ff->max_limit < 0);
	ff->max_size = max_size;
	ff->is_loop = is_loop;
	ff->ts =(ffid_vtype*)malloc(sizeof(ffid_vtype) * max_size);
	for(i = 0; i < ff->end; ++i)
	{
		ff->ts[i] = i + 1;
	}
	ff->ts[ff->end] = ff->max_limit;
	return ff;
}

void
ffid_release(struct ffid* ff)
{
	if(!ff) return;
	free(ff->ts);
	free(ff);
}

ffid_vtype
ffid_new_id(struct ffid* ff, unsigned short* index)
{
	unsigned short id_index;
	ffid_vtype id;
	if(!ff) return 0;
	if(ff->first >= ff->max_limit) return 0;
	id_index = ff->first % ff->max_size;
	id = ff->first;
	ff->first = ff->ts[id_index];
	ff->ts[id_index] = id;
	++ff->cur_size;
	if(index) *index = id_index;
	return id + 1;
}

char
ffid_has_id(struct ffid* ff, ffid_vtype id, unsigned short* index)
{
	unsigned short id_index;
	if(!ff) return 0;
	if(id == 0) return 0;
	--id;
	id_index = id % ff->max_size;
	if(index) *index = id_index;
	return ff->ts[id_index] == id;
}

void
ffid_del_id(struct ffid* ff, ffid_vtype id)
{
	ffid_vtype next_id;
	unsigned short id_index;
	if (!ff) return;
	if(id == 0) return;
	--id;
	id_index = id % ff->max_size;
	if(ff->max_limit <= id || (ff->max_limit  - id) <= ff->max_size )
	{
		if(!ff->is_loop)
		{
			ff->ts[id_index] = ff->max_limit;
			return;
		}
		next_id = id_index;
	}
	else
	{
		next_id = id + ff->max_size;
	}
	if(ff->first >= ff->max_limit)
	{
		ff->first = next_id;
	}
	else
	{
		ff->ts[ff->end] = next_id;
	}
	ff->end = id_index;
	ff->ts[id_index] = ff->max_limit;
	--ff->cur_size;
}

unsigned short
ffid_size(struct ffid* ff)
{
	return ff->cur_size;
}

unsigned short
ffid_index(struct ffid* ff, ffid_vtype id)
{
	return (unsigned short)((id - 1) % ff->max_size);
}

ffid_vtype
ffid_id(struct ffid* ff, unsigned short index)
{
	ffid_vtype id;
	if(!ff) return 0;
	if(index >= ff->max_size) return 0;
	id = ff->ts[index];
	if(id % ff->max_size != index)
	{
		return 0;
	}
	return id + 1;
}

#ifdef __cplusplus
}
#endif



