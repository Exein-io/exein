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

#ifndef LIBMEALLOC_H
#define LIBMEALLOC_H
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <semaphore.h>

#define MEALLOC_CELLS_NUMBER 256
#define BUF_SIZE 128  // this value is not arbitrary. It have to be coherent to the kernel sent size

#define ISBUSY 0xff
#define ISFREE 0x00
#define ISOK 0xff
#define ISKO 0x00

#ifndef DODEBUG
#ifdef DEBUG
#define DODEBUG( ... ) printf( __VA_ARGS__ );
#else
#define DODEBUG( ... ) do { } while(0)
#endif
#endif

#ifndef DODEBUGME
#ifdef DEBUGME
#define DODEBUGME( ... ) printf( __VA_ARGS__ );
#else
#define DODEBUGME( ... ) do { } while(0)
#endif
#endif

#ifndef DODEBUGSB
#ifdef DEBUGSB
#define DODEBUGSB( ... ) printf( __VA_ARGS__ );
#else
#define DODEBUGSB( ... ) do { } while(0)
#endif
#endif

#define MEALLOC_UT_BUCKET_NO_GROW 0
#define MEALLOC_UT_BUCKET_SMALL_GROW 0x04
#define MEALLOC_UT_BUCKET_MEDIUM_GROW 0x10
#define MEALLOC_UT_BUCKET_NO_MAXIMUM 0x20

#define SHM_SIZE(reserved,generic_element_size,num) sizeof(meallocator)+reserved+(generic_element_size<<(num>>5))
#define SHM_NTH_EL_ADDR(reserved,generic_element_size,num) sizeof(meallocator)+reserved+(generic_element_size*num)
#define RESERVED2BASE(reserved) (void *)(((char *)reserved)-sizeof(meallocator))
#define BASE2RESERVED(base) (void *)(((char *)base)+sizeof(meallocator))

#define GMEALLOC2BLOOM(base)  (void *) (   (char *)base ) + sizeof( gmeallocator )
#define GMEALLOC2TABLE(base)  (void *) ( ( (char *)base ) + sizeof( gmeallocator ) + base->bloom_reserved )
#define GMEALLOC2BUCKET(base)															\
	(void *) 																\
	(																	\
		((char *)base) + 														\
		sizeof( gmeallocator ) +													\
		base->bloom_reserved +														\
		base->table_reserved +														\
		(																\
			(base->iteration==0)?0:													\
			(															\
				(base->iteration==1)?base->initial_bucket:									\
				(														\
					(base->iteration==2)?0:											\
					(													\
						(base->iteration==3)?base->initial_bucket*4:							\
						(												\
							(base->iteration==4)?0:									\
							(											\
								(base->iteration==5)?base->initial_bucket*0x10:0				\
							)											\
						)												\
					)													\
				)														\
			)															\
		)																\
	)

typedef struct {
	sem_t                   semaphore;
	uint32_t		map[MEALLOC_CELLS_NUMBER >>5];
	uint32_t		generic_element_size, reserved;
} meallocator;

typedef struct {
        uint32_t                bloom_reserved, table_reserved, initial_bucket, iteration;
} gmeallocator;

void *gmealloc_init(int bloom_reserved_size, int table_reserved_size, int initial_bucket_size, int multiplier);
void *gmealloc(gmeallocator *shm, int size);
void gmefree(gmeallocator *shm, void *addr);

void *mealloc_init(uint32_t reserved, uint32_t generic_element_size, uint8_t color);
void mealloc_destroy(void *shm);
void *mealloc(void *shm);
void *get_reserved_addr(void *shm);
void mefree(meallocator *shm, void *addr, uint8_t color);
void c_free(meallocator *shm, void *addr);
int c_isfree(meallocator *shm, int pos);
void c_occupy(meallocator *shm, int pos);

#endif

