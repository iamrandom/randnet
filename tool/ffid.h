/*
 * ffid.h
 *
 *  Created on: 2014-12-02
 *      Author: Random
 */

#ifndef FFID_H_
#define FFID_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int ffid_vtype;

struct ffid;

struct ffid*		
ffid_create(unsigned short max_size, char is_loop);

void				
ffid_release(struct ffid* ff);

ffid_vtype			
ffid_new_id(struct ffid* ff, unsigned short* index);

char				
ffid_has_id(struct ffid* ff, ffid_vtype id, unsigned short* index);

void				
ffid_del_id(struct ffid* ff, ffid_vtype id);

unsigned short		
ffid_size(struct ffid* ff);

unsigned short		
ffid_index(struct ffid* ff, ffid_vtype id);

ffid_vtype			
ffid_id(struct ffid* ff, unsigned short index);

#ifdef __cplusplus
}
#endif

#endif /* FFID_H_ */

