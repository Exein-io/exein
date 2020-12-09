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


#ifndef LIBEXNL_H
#define LIBEXNL_H

#define _GNU_SOURCE
#include <sched.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include "uthash.h"
#include "libmealloc.h"

/*errors*/
#define EXEIN_NOERR			0
#define EXEIN_ERR_NLSOCKET		-1
#define EXEIN_ERR_NLBIND		-2
#define EXEIN_ERR_NOMEM			-3
#define EXEIN_ERR_NLCOM			-4
#define EXEIN_ERR_REGISTER		-5
#define EXEIN_ERR_NOPID			-6
#define EXEIN_CANARYERR			-7
#define EXEIN_ERR_CLOCKFAILURE		-8
#define EXEIN_ERR_TIMEOUT		-9
#define EXEIN_ERR_PTR_INV		-10
#define EXEIN_ERR_NO_NEED_TO_WORRY	-11

#define EXEIN_MSG_REG			1
#define EXEIN_MSG_KA			2
#define EXEIN_MSG_FEED			3
#define EXEIN_MSG_BK 			4
#define EXEIN_MSG_DATA_RQ		5
#define EXEIN_MSG_NEW_PID		6
#define EXEIN_MSG_DEL_PID		7
#define EXEIN_STAT_SK_ENOMEM		3
#define EXEIN_STAT_RF_ENOMEM		4
#define EXEIN_STAT_RF_ENLCOM		6
#define EXEIN_STAT_OK			0

#define EXEIN_DONT_TOUCH		1
#define EXEIN_CAN_BE_REMOVED		0

#define EXEIN_SK_STACK_SIZE		4*1024
#define EXEIN_RF_STACK_SIZE		8*1024

#define EXEIN_RCV_PKTS			256
#define EXEIN_PKT_SIZE			NLMSG_SPACE(EXEIN_BUFFES_SIZE*2+20)

#define EXEIN_TIMEOUT_SEC		5
#define EXEIN_TIMEOUT_NSEC		0
#define EXEIN_FD_TIMEOUT_SEC		0
#define EXEIN_FD_TIMEOUT_NSEC		300000000

#ifndef DODEBUG
#ifdef DEBUG
#define DODEBUG( ... ) printf( __VA_ARGS__ ); fflush(stdout);
#else
#define DODEBUG( ... ) do { } while(0)
#endif
#endif

#define EXEIN_BUFFER_MASK 0x7f
#define EXEIN_BUFFES_SIZE 0x80 // make sure this size corresponds to the kernel ringbuffer size
#define EXEIN_BUFFES_SIZE_CNT 0x07

#define EXEIN_BACKTRACE_SIZE 20
#define NETLINK_USER 31

/*macros*/
#define EX_FEED_PACKET_SIZE(data) (*(data+5)-*(data+4))+ 7

typedef struct {
	UT_hash_handle		hh;
	uint16_t		pid;
	sem_t			semaphore;
	int			safe2remove;
	uint16_t		*buffer;
} exein_pids;

typedef struct {
	uint16_t		tag;
	uint32_t		key;
	struct sockaddr_nl	*src_addr, *dest_addr;
	struct nlmsghdr		*nlh_rf, *nlh_sk;
	struct msghdr		*msg_sk, *msg_rf;
	exein_pids		*pids;
	sem_t			pids_lock __attribute__ ((aligned (8)));
	int			sock_fd;
	void			*sk_stack, *rf_stack;
	pid_t			sk_pid, rf_pid, cpid;
	int			trouble;
	void			*buffers_pool;
	void			*uthash_shm;
} exein_shandle;

typedef struct {
	exein_shandle		*uhandle;
	char			loading_done;
	void			*payload;
} proc_args;

typedef struct {
        uint32_t		key;
        uint8_t			message_id;
        uint8_t			padding;
        uint16_t		tag;
        pid_t			pid;
} exein_prot_req_t;

typedef struct {
        uint16_t		msg_type;
        uint32_t		seed;
        uint16_t		seq;
	pid_t			pid;
        uint16_t		payload[EXEIN_BUFFES_SIZE];
} exein_prot_reply_t;

void*		salloc				(size_t size);
extern void	(*exein_new_pid_notify_cb)	(uint16_t);
extern void	(*exein_delete_pid_cb)		(uint16_t);

exein_prot_req_t        keepalive,registration;

/* aux funtions */
void 		exein_print_version();
void		exein_dummy_pid_notify_cb	(uint16_t pid);
void		exein_dummy_pid_delete_cb	(uint16_t pid);


/* interface functions */
int		exein_remove_pid		(exein_shandle *uhandle, uint16_t pid);
int		exein_fetch_data		(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf, exein_pids *pid_data);
void		exein_agent_stop		(exein_shandle *uhandle);
exein_shandle	*exein_agent_start		(uint32_t key, uint16_t tag);
int		exein_block_process		(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag);
int		exein_add_pid			(exein_shandle *uhandle, uint16_t pid);
int		exein_register_callback_signal	(int signum, void (*call)(int signum, siginfo_t *si, void *ct));
exein_pids 	*exein_find_data		(exein_shandle *uhandle, uint16_t pid);

#endif
