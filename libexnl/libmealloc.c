/* Copyright 2020 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/


//#define DEBUGME
#include "include/libmealloc.h"

void *mealloc_init(uint32_t reserved, uint32_t generic_element_size, uint8_t color){
	void *tmp;

	DODEBUGME("mealloc.mealloc_init[%d] - arguments: reserved=%d, generic_element_size=%d\n", getpid(), reserved, generic_element_size );
	DODEBUGME("mealloc.mealloc_init[%d] - mmap for %ld of shared memory\n", getpid(), SHM_SIZE(reserved, generic_element_size, MEALLOC_CELLS_NUMBER ));
	tmp = mmap(NULL, SHM_SIZE(reserved, generic_element_size, MEALLOC_CELLS_NUMBER ), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	DODEBUGME("mealloc.mealloc_init[%d] - Zeroing %ld bytes @%p \n", getpid(), SHM_SIZE(reserved, generic_element_size, MEALLOC_CELLS_NUMBER ), tmp);
	memset(tmp, color, SHM_SIZE(reserved, generic_element_size, MEALLOC_CELLS_NUMBER ) );
	((meallocator *)tmp)->generic_element_size=generic_element_size;
	((meallocator *)tmp)->reserved=reserved;
	if (sem_init(&(((meallocator *)tmp)->semaphore), 1, 1)==-1) {
		printf("mealloc.mealloc_init[%d] - semaphore initialization error\n",  getpid());
		exit(-1);
		}
	return tmp;
}

void mealloc_destroy(void *shm){
	DODEBUGME("mealloc.mealloc_destroy[%d] - shared memory @%p is no more\n", getpid(), shm );
	sem_destroy(&(((meallocator *)shm))->semaphore);
	munmap(shm, SHM_SIZE(((meallocator *)shm)->reserved, ((meallocator *)shm)->generic_element_size, MEALLOC_CELLS_NUMBER ));
}
void *get_reserved_addr(void *shm){
	return ((void *)((char *) shm)+ sizeof(meallocator) );
}

void *mealloc(void *shm){
	int i;

	DODEBUGME("mealloc.mealloc[%d] - shm=%p\n", shm);
	sem_wait(&(((meallocator *)shm)->semaphore));
	DODEBUGME("mealloc.mealloc[%d] - find first free element\n", getpid());
	for (i=0; i<MEALLOC_CELLS_NUMBER; i++) {
		DODEBUGME("mealloc.mealloc[%d] - consider %d\n", getpid(), i );
		if (c_isfree(shm, i)==ISFREE) {
			c_occupy(shm, i);
			DODEBUGME("mealloc.mealloc[%d] - found element %d is free @%p\n", getpid(), i, ((void *)((char *) shm)+ SHM_NTH_EL_ADDR(((meallocator *)shm)->reserved, ((meallocator *)shm)->generic_element_size, i)) );
			sem_post(&(((meallocator *)shm)->semaphore));
			return ((void *)((char *) shm)+ SHM_NTH_EL_ADDR(((meallocator *)shm)->reserved, ((meallocator *)shm)->generic_element_size, i));
			}
		}
	printf("mealloc.mealloc[%d] - Failed to allocate! <<<WARNING>>>\n", getpid());
	sem_post(&(((meallocator *)shm)->semaphore));
	return NULL;
}

void mefree(meallocator *shm, void *addr, uint8_t color){
	int	tmp;

	DODEBUGME("mealloc.mefree[%d] - shm=%p, addr=%p, color=%d\n", getpid(),shm, addr, color);
	sem_wait(&(shm->semaphore));
	DODEBUGME("mealloc.mefree[%d] - request to free addr@%p, base@%p\n", getpid(), addr, shm);
	c_free(shm, addr);
	DODEBUGME("mealloc.mefree[%d] - erase content @%p\n", getpid(), addr);
	memset(addr, color, shm->generic_element_size);
	sem_post(&(shm->semaphore));
}

void c_free(meallocator *shm, void *addr){
	DODEBUGME("mealloc.c_free[%d] - request to free addr@%p, base@%p\n", getpid(), addr, shm);
	int pos=(((int) ( ((char *) addr)-((char *) shm))) - sizeof(meallocator) - shm->reserved)/shm->generic_element_size;
	DODEBUGME  ("mealloc.c_free[%d] - pos=%d, shm->map[%d]=0x%08x, &masked with 0x%08x\n", getpid(), pos, pos>>5, shm->map[pos>>5], ~(1 << (pos &0x1f)) );
	shm->map[pos>>5] &= ~(1 << (pos &0x1f));
}

int c_isfree(meallocator *shm, int pos){
	DODEBUGME("mealloc.c_isfree[%d] - request to check element %d, element is in %d uint32\n", getpid(), pos, pos>>5);
	DODEBUGME("mealloc.c_isfree[%d] - shm->map[%d]=0x%08x, &masked with 0x%08x\n", getpid(), pos>>5, shm->map[pos>>5], (1 << (pos &0x1f)));
	DODEBUGME("mealloc.c_isfree[%d] - isfree test (0x%08x & 0x%08x )=0x%08x\n", getpid(), shm->map[pos>>5], (1 << (pos &0x1f)), (shm->map[pos>>5] & (1 << (pos &0x1f))) );
	return ((shm->map[pos>>5] & (1 << (pos &0x1f)))!=0)?ISBUSY:ISFREE;
}

void c_occupy(meallocator *shm, int pos){
	DODEBUGME("mealloc.c_occupy[%d] - request to reserve element %d, element is in %d uint32\n", getpid(), pos, pos>>5);
	DODEBUGME("mealloc.c_occupy[%d] - shm->map[%d]=0x%08x, masked with 0x%08x\n", getpid(), pos>>5, shm->map[pos>>5], (1 << (pos &0x1f)));
	shm->map[pos>>5] |= (1 << (pos &0x1f)) ;
}

// HASH_BLOOM UT_hash_table UT_hash_bucket                     offset interaction
//+----------+-------------+--------------------------------+
//|          |             |#                               |   0x00	0
//|          |             | ##                             |   0x01	1
//|          |             |####                            |   0x00	2
//|          |             |    ########                    |   0x04	3
//|          |             |################                |   0x00	4
//|          |             |                ################|   0x10	5
//|          |             |################################|   0x00	6
//+----------+-------------+--------------------------------+
//                          0123456789abcdef0123456789abcdef
// this implementation assumes the bucket number to grow up to 32 times.
// it also assumes, as for current uthash implementation, that bucket_num doubles each time it expands
// given the previous assumption, strategy is to allocate staticaly a shared buffer with size sizeof(gmeallocator)+bloom_reserved_size+table_reserved_size+initial_bucket_size*MULTIPLIER

void *gmealloc_init(int bloom_reserved_size, int table_reserved_size, int initial_bucket_size, int multiplier){
	gmeallocator *b=NULL;

	DODEBUGME("bloom_reserved_size=%d, table_reserved_size=%d, initial_bucket_size=%d,  multiplier=%d\n", bloom_reserved_size, table_reserved_size, initial_bucket_size, multiplier);
	switch (multiplier) {
		case MEALLOC_UT_BUCKET_NO_GROW:
		case MEALLOC_UT_BUCKET_SMALL_GROW:
		case MEALLOC_UT_BUCKET_MEDIUM_GROW:
		case MEALLOC_UT_BUCKET_NO_MAXIMUM:
			b = (gmeallocator *) mmap(NULL, sizeof(gmeallocator)+bloom_reserved_size+table_reserved_size+initial_bucket_size*multiplier , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
			memset(b,0, sizeof(gmeallocator)+bloom_reserved_size+table_reserved_size+initial_bucket_size*multiplier );
			b->bloom_reserved = bloom_reserved_size;
			b->table_reserved = table_reserved_size;
			b->initial_bucket = initial_bucket_size;
			b->iteration = 0;
			break;
		default:
			break;
		}
	DODEBUGME("bloom_reserved = %d, table_reserved = %d, initial_bucket = %d @0x%p\n", b->bloom_reserved, b->table_reserved, b->initial_bucket, b);
	return b;
}
void *gmealloc(gmeallocator *shm, int size){

	if (size==shm->bloom_reserved) return GMEALLOC2BLOOM(shm);
	if (size==shm->table_reserved) return GMEALLOC2TABLE(shm);
	if ((size%shm->initial_bucket)==0) {
		shm->iteration++;
		return GMEALLOC2BUCKET(shm);
		}
	printf("gmealloc failed on shm=0x%p,  size=%d [bloom_reserved=%d, table_reserved=%d, initial_bucket=%d]\n", shm, size, shm->bloom_reserved, shm->table_reserved, shm->initial_bucket);
	return NULL;
}
static int pow(int base, int exp){

	if (exp==0) return 1;
	int res=base;
	while (--exp) res*=base;
	return res;
}
void gmefree(gmeallocator *shm, void *addr){

	shm->iteration--;
	memset(addr, 0, shm->initial_bucket * ( pow(2, (shm->iteration)) ) );
}
