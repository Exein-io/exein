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


//TODO: implement a fuction to free allocated resource for a deleted pid


//#define DEBUG
#define uthash_malloc(sz) gmealloc(uhandle->uthash_shm,sz)
#define uthash_free(ptr,sz) gmefree(uhandle->uthash_shm, ptr);
#define uthash_fatal(msg) printf("---------------------- [%d] %s ----------------------\n",msg,getpid());exit(-1);


#include "include/libexnl.h"
#include <time.h>


static char version[] = VERSION_STRING;
static char timestamp[] __attribute__((used)) = __DATE__ " " __TIME__;

void (*exein_new_pid_notify_cb)(uint16_t)=NULL;
void (*exein_delete_pid_cb)(uint16_t)=NULL;

void * get_pc () { return __builtin_return_address(0); }

void exein_dummy_pid_notify_cb(uint16_t pid){
	printf("libexnl.dummy_pid_notify_cb - New pid (%d) have been observed.\n",pid);
}

void exein_dummy_pid_delete_cb(uint16_t pid){
        printf("libexnl.dummy_pid_delete_cb - pid (%d) have been deleted\n",pid);
}

void exein_print_version(){
	printf("%s\n",version);
}


// this function unlink specified pid from the hash and execute a deferred deletion of the actual data.
// it's important to invalidate the current copy of pid_data by putting it at NULL to prevent it to be used again.
int exein_remove_pid(exein_shandle *uhandle, uint16_t pid){

	exein_pids              *pid_data=NULL;

	DODEBUG("libexnl.exein_remove_pid[%d] - is locking to remove %d\n",  getpid(), pid);
	sem_wait(&uhandle->pids_lock);
	HASH_FIND(hh,uhandle->pids,&pid,sizeof(uint16_t),pid_data);
	if (pid_data!=NULL){
		DODEBUG("libexnl.exein_remove_pid - Requested %d found @%p.\n", pid, pid_data);
		HASH_DEL(uhandle->pids, pid_data);
		sem_post(&uhandle->pids_lock);

		if (fork() == 0) {
			while (pid_data->safe2remove==EXEIN_DONT_TOUCH) usleep(300);
			DODEBUG("libexnl.exein_remove_pid[%d] - deferred free pid_data=%p, pid=%d\n", getpid(), pid_data, pid_data->pid);
			sem_destroy(&pid_data->semaphore);
			mefree(RESERVED2BASE(uhandle), pid_data, 0);
			}
		return EXEIN_NOERR;
		}
	sem_post(&uhandle->pids_lock);
	DODEBUG("libexnl.exein_remove_pid[%d] - pids_lock is freed FAIL Branch\n", getpid());
	return EXEIN_ERR_NOPID;

}

// exein_add_pid is called in the context of the receive_feeds thread
// the function does an early setup of the structures needed to deposit data when received from the kernel.
// this function does not initialize the exchange buffer pid_data->buffer since this action needs to be done each time a request is sent to the kernel,
// initialize it at this stage is not useful since next time the same pid will have to receive data again it will have to do the action again.
// in some weird situations though, it is like pid_data get used before passing through the exein_fetch_data, which is there to prepare a buffer and request data.
int exein_add_pid(exein_shandle *uhandle, uint16_t pid){
	exein_pids		*pid_data=NULL;
	int			ret=EXEIN_ERR_NOPID;

	DODEBUG("libexnl.exein_add_pid[%d] - getting lock\n", getpid());
	sem_wait(&uhandle->pids_lock);
	HASH_FIND(hh,uhandle->pids,&pid,sizeof(uint16_t),pid_data);

	//check what we got
	if (!pid_data){//need to initialize data structure
		DODEBUG("libexnl.exein_add_pid[%d] - since pid has not be found, needs to allocate new ringbuffer before request data\n", getpid());
		if (!(pid_data=(exein_pids *) mealloc( RESERVED2BASE(uhandle) ))){
			printf("libexnl.exein_add_pid - can't allocate mem 4 data, quit!\n");
			uhandle->trouble=EXEIN_STAT_RF_ENOMEM;
			ret=EXEIN_ERR_NOMEM;
			goto cleanup;
			}
		DODEBUG("libexnl.exein_add_pid[%d] - salloc returned pointer for pid_data=%p\n", getpid(), pid_data);
		pid_data->pid=pid;
		pid_data->buffer=mealloc(uhandle->buffers_pool); //this hack is needed to comply with weird situations
		sem_init(&pid_data->semaphore, 1, 0);
		pid_data->safe2remove=EXEIN_CAN_BE_REMOVED;
		DODEBUG("libexnl.exein_add_pid[%d] - uhandle->pids=%p, pid_data=%p pid=%d\n", getpid(), uhandle->pids, pid_data, pid);
		HASH_ADD(hh,uhandle->pids,pid,sizeof(uint16_t),pid_data);
		ret=EXEIN_NOERR;
		} else {
			printf("libexnl.exein_add_pid[%d] - pid %d is already @%p\n", getpid(), pid, pid_data);
			}
cleanup:
	sem_post(&uhandle->pids_lock);
	DODEBUG("libexnl.exein_add_pid[%d] - lock has been freed\n", getpid());
	return ret;
}

// this function is needed to find the pid_data inside the hash struct.
// because the processes using this data need to use always the same item, once the item is found once, there's no neet to be searched again.
// special attention is needed when item get deleted.
// exein_remove_pid removes pid_data and perform a deferred deallocation. once deallocation is completed, the pointer to the structure must be put at NULL to prevent to be used again.
exein_pids *exein_find_data(exein_shandle *uhandle, uint16_t pid){
	exein_pids		*pid_data=NULL;

	sem_wait(&uhandle->pids_lock);
	HASH_FIND(hh,uhandle->pids,&pid,sizeof(uint16_t),pid_data);
	DODEBUG("libexnl.exein_find_data [%d] - found pid [%d] is @%p\n", getpid(), pid, pid_data);
	sem_post(&uhandle->pids_lock);
	return pid_data;
}


// this function requires the agent handle a pid target preallocated process local buffer and a pointer to pid_data item inside the hash struct.
int exein_fetch_data(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf, exein_pids *pid_data){
        exein_prot_req_t	data_req={
				.key            = uhandle->key,
				.message_id     = EXEIN_MSG_DATA_RQ,
				.tag            = uhandle->tag,
				.padding        = 0,
				.pid            = pid,
				};
	struct timespec 	ts;
	int			found=0, tmp=EXEIN_ERR_NOPID;
        pid_t 			wp = getpid();

	// if pointer invalid, just exit
	if (!pid_data) {
		return EXEIN_ERR_PTR_INV;
		}

//critical section >>>>>>>>>>
	sem_wait(&uhandle->pids_lock);

	//check if a request is currently pending, proceed if no request.
	if (pid_data->safe2remove==EXEIN_DONT_TOUCH){
		sem_post(&uhandle->pids_lock);
		return EXEIN_ERR_NO_NEED_TO_WORRY;
		}

	//make request pending and allocate a buffer in shared memory to get the data
	pid_data->safe2remove=EXEIN_DONT_TOUCH;
	if (!pid_data->buffer) pid_data->buffer=mealloc(uhandle->buffers_pool);		// this is because in some weird situations shortly after pid_data has been created, feeds are received by receive_feeds.
											// In such situations is important to have the exchange buffer already setup. But it also means that it is possible to
											// reach this point and have the exchange buffer already set up. without the check there would be a memory leak.
	sem_post(&uhandle->pids_lock);
//<<<<<<<<<< critical section

	// Starting from here pid_data can be unlinked by the hash structure, but it can not be released
	// For having pid_data available again, its field safe2remove must be swithced to EXEIN_CAN_BE_REMOVED

	// send message to request data.
	DODEBUG("libexnl.exein_fetch_data [%d] - prepare netlink socket\n", wp);
	memcpy( NLMSG_DATA(uhandle->nlh_sk), &data_req, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	uhandle->nlh_sk->nlmsg_pid=uhandle->cpid;
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
			DODEBUG("libexnl.exein_fetch_data [%d] - netlink message on fd=%d failed @sendmsg\n", wp, uhandle->sock_fd);
			tmp=EXEIN_ERR_NLCOM;
			goto cleanup;
			}

	//wait data to get received.
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		DODEBUG("libexnl.exein_fetch_data - Clock clock_gettime error!\n");
		return EXEIN_ERR_CLOCKFAILURE;
		goto cleanup;
		}
	ts.tv_sec += EXEIN_FD_TIMEOUT_SEC;
	ts.tv_nsec += EXEIN_FD_TIMEOUT_NSEC;
	tmp = sem_timedwait(&pid_data->semaphore, &ts);

	pid_data->safe2remove=EXEIN_DONT_TOUCH;

	//eavluate the reason why this point has been reached
	if (tmp==-1) {
		// timeout: no data has been received
		tmp=EXEIN_ERR_TIMEOUT;
		} else {
			// data has been received
			// in this case, we can be sure no further requests are pending, and just copy thereceived buffer into the process local buffer and mark pid_data for being deleted.
			DODEBUG("libexnl.exein_fetch_data [%d] - data arrived, copy data on local buffer and return to caller\n", wp);
			memcpy(dstbuf, pid_data->buffer, EXEIN_BUFFES_SIZE*sizeof(uint16_t)); //EXEIN_BUFFES_SIZE*sizeof(uint16_t) constant
			tmp=EXEIN_NOERR;
			}

cleanup:
	// on cleanup, we can use uhandle->pids_lock to synchronize with receive_feeds and make sure it is not using pid_data.
	// despite the request we just made remains pending, this way we can be sure the request wont be served while deleting pid_data.
	// because exein_remove_pid immediately unlinks pid_data any other receive_feeds won't find any item where store received data and will just fail.
	// pid_data will be deleted only after receive_feeds or this branch will make it available for being purged safe2remove=EXEIN_CAN_BE_REMOVED.
	sem_wait(&uhandle->pids_lock);
	pid_data->safe2remove=EXEIN_CAN_BE_REMOVED;
	mefree(uhandle->buffers_pool, pid_data->buffer, 0);
	pid_data->buffer=NULL;
	sem_post(&uhandle->pids_lock);
	return tmp;
}

static int netlink_setup(exein_shandle *uhandle, pid_t bind_pid){

	DODEBUG("libexnl.netlink_setup - prepare netlink stuffs\n");
	uhandle->sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(uhandle->sock_fd<0) return EXEIN_ERR_NLSOCKET;
	memset(uhandle->src_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->src_addr->nl_family = AF_NETLINK;
	uhandle->src_addr->nl_pid = bind_pid;
	if (bind(uhandle->sock_fd, (struct sockaddr *)uhandle->src_addr, sizeof(struct sockaddr_nl))<0) return EXEIN_ERR_NLBIND;
	memset(uhandle->dest_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->dest_addr->nl_family = AF_NETLINK;
	uhandle->dest_addr->nl_pid = 0;
	uhandle->dest_addr->nl_groups = 0;
	return EXEIN_NOERR;
}

static int netlink_msg_init(int max_payload, pid_t bind_pid, exein_shandle *uhandle){

	DODEBUG("libexnl.netlink_msg_init - \n");
	uhandle->msg_sk->msg_iov= (struct iovec *) malloc(sizeof(struct iovec));
	if (!uhandle->msg_sk->msg_iov) return EXEIN_ERR_NOMEM;
	uhandle->msg_sk->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(max_payload));
	if (!uhandle->msg_sk->msg_iov->iov_base) return EXEIN_ERR_NOMEM;
	uhandle->nlh_sk = uhandle->msg_sk->msg_iov->iov_base;
	if (uhandle->msg_sk->msg_iov->iov_base){
		memset(uhandle->msg_sk->msg_iov->iov_base, 0, NLMSG_SPACE(max_payload));
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len	= NLMSG_SPACE(max_payload);
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_pid	= bind_pid;
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_flags	= 0;
		uhandle->msg_sk->msg_iov->iov_len	= ((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len;
		uhandle->msg_sk->msg_name		= (void *)uhandle->dest_addr;
		uhandle->msg_sk->msg_namelen	= sizeof(struct sockaddr_nl);
		uhandle->msg_sk->msg_iovlen	= 1;
		uhandle->msg_sk->msg_control	= NULL;
		uhandle->msg_sk->msg_controllen	= 0;
		uhandle->msg_sk->msg_flags		= 0;
		return EXEIN_NOERR;
		} else return EXEIN_ERR_NOMEM;
}

static int exein_nl_peer_register(exein_shandle *uhandle, exein_prot_req_t *rpacket){

	DODEBUG("libexnl.exein_nl_peer_register - send registration request\n");
	memcpy(NLMSG_DATA(uhandle->nlh_sk), rpacket, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	if (recvmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	DODEBUG("libexnl.exein_nl_peer_register - received answer\n");
	if (strncmp((char *)NLMSG_DATA(uhandle->nlh_sk), "ACK", 3)!=0) return EXEIN_ERR_REGISTER;
	DODEBUG("libexnl.exein_nl_peer_register - answer ok\n");
	return EXEIN_NOERR;
}

static void stack_trace(){
	void *trace[EXEIN_BACKTRACE_SIZE];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, EXEIN_BACKTRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace(%d) ]>>>\n", trace_size);
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);
}

static void sk_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
			printf("libexnl.sk_sigsegv_handler - Keep alive thread got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
			stack_trace();
			signal(sig, SIG_DFL);
           		kill(getpid(), sig);
           		exit(-1);
			}
		default:
		printf("libexnl.sk_sigsegv_handler - Reecived Signal :%d\n",sig);
		};
}

static void rf_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
		        printf("libexnl.rf_sigsegv_handler [pid %d , %d] got SIGSEGV at address: 0x%lx\n", getpid(), si->si_pid, (long) si->si_addr);
			stack_trace();
			signal(sig, SIG_DFL);
			kill(getpid(), sig);
			}
		default:
		printf("libexnl.rf_sigsegv_handler - Reecived Signal :%d\n",sig);
		};
}

static int send_keepalives(void *data){
	exein_shandle 		*uhandle=	((proc_args *)data)->uhandle;
	void			*payload=	((proc_args *)data)->payload;
	struct sigaction	sa = {0};
	//don't think you're smarter. those stack variables are not there by chance

	((proc_args *)data)->loading_done=1;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sk_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Keep alive can't install handler\n");
		}
	while (1){
		DODEBUG("libexnl.send_keepalives - sending keepalive\n");
		memcpy(	NLMSG_DATA(uhandle->nlh_sk), payload, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
		uhandle->nlh_sk->nlmsg_pid=uhandle->cpid;
		if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
			uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
			continue;
			}
		sleep(5);
		uhandle->trouble=EXEIN_STAT_OK;
		}
	return EXEIN_NOERR;
}

static int receive_feeds(void *data){
	uint16_t		seqn=		0x55aa; //hoping it'll never be matched by chance, I just put fake number there
	uint16_t		*rdata;
	exein_pids		*pid_data;
	exein_shandle		*uhandle=	((proc_args *)data)->uhandle;
	struct sigaction	sa = {0};
	int			err;

	//don't think you're smarter. those stack variables are not there by chance

	uhandle->msg_rf=		(struct msghdr *) malloc(sizeof(struct msghdr));
	if (!uhandle->msg_rf) exit(-1);
	memcpy(uhandle->msg_rf, uhandle->msg_sk, sizeof(struct msghdr)); //sizeof(struct msghdr) constant
	uhandle->msg_rf->msg_iov=	(struct iovec *) malloc(sizeof(struct iovec));
	if (!uhandle->msg_rf->msg_iov) exit(-1);
	memcpy(uhandle->msg_rf->msg_iov, uhandle->msg_sk->msg_iov, sizeof(struct iovec)); //sizeof(struct iovec)constant
	uhandle->msg_rf->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(EXEIN_PKT_SIZE));
	if (!uhandle->msg_rf->msg_iov->iov_base) exit(-1);
	uhandle->nlh_rf=(struct nlmsghdr *)uhandle->msg_rf->msg_iov->iov_base;
	((proc_args *) data)->loading_done=	1;

	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = rf_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Receive feeds can't install the signal handler.");
		}
	sleep(3);
	while (1){
		DODEBUG("libexnl.receive_feeds - wait for new message\n");
                memset(NLMSG_DATA(uhandle->nlh_rf), 0, EXEIN_PKT_SIZE);
		if ((err=recvmsg(uhandle->sock_fd, uhandle->msg_rf, 0))<0) {
			printf("recvmsg went wrong %d\n", err);
			uhandle->trouble=EXEIN_STAT_RF_ENLCOM;
			continue;
			}


                //printf("##### recvmsg data size=%d\n", (uint32_t *) uhandle->nlh_rf );
		rdata = (uint16_t *) NLMSG_DATA(uhandle->nlh_rf);
                //printf("##### libexnl.receive_feeds - seq no=%d [%d] \n", ((exein_prot_reply_t *) rdata)->seq, rand());
		if (((exein_prot_reply_t *) rdata)->seq!=seqn) {
			switch (((exein_prot_reply_t *) rdata)->msg_type){
				case EXEIN_MSG_DEL_PID:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_DEL_PID received\n");
					if (exein_delete_pid_cb!=NULL) {
                                                (*exein_delete_pid_cb)( ((exein_prot_reply_t *) rdata)->payload[0]);
                                                }

					break;
				case EXEIN_MSG_NEW_PID:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_NEW_PID received\n");
					if (exein_new_pid_notify_cb!=NULL) {
						(*exein_new_pid_notify_cb)( ((exein_prot_reply_t *) rdata)->payload[0]);
						}
					break;
				case EXEIN_MSG_FEED:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_FEED received {size:'%d', seed:'%d', seq:'%d', pid='%d', pl:[%d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d,  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d,  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d,  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d,  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d]}\n",
								err, ((exein_prot_reply_t *) rdata)->seed, ((exein_prot_reply_t *) rdata)->seq, ((exein_prot_reply_t *) rdata)->pid,
								((exein_prot_reply_t *) rdata)->payload[  0], ((exein_prot_reply_t *) rdata)->payload[  1], ((exein_prot_reply_t *) rdata)->payload[  2], ((exein_prot_reply_t *) rdata)->payload[  3],
								((exein_prot_reply_t *) rdata)->payload[  4], ((exein_prot_reply_t *) rdata)->payload[  5], ((exein_prot_reply_t *) rdata)->payload[  6], ((exein_prot_reply_t *) rdata)->payload[  7],
								((exein_prot_reply_t *) rdata)->payload[  8], ((exein_prot_reply_t *) rdata)->payload[  9], ((exein_prot_reply_t *) rdata)->payload[ 10], ((exein_prot_reply_t *) rdata)->payload[ 11],
								((exein_prot_reply_t *) rdata)->payload[ 12], ((exein_prot_reply_t *) rdata)->payload[ 13], ((exein_prot_reply_t *) rdata)->payload[ 14], ((exein_prot_reply_t *) rdata)->payload[ 15],
								((exein_prot_reply_t *) rdata)->payload[ 16], ((exein_prot_reply_t *) rdata)->payload[ 17], ((exein_prot_reply_t *) rdata)->payload[ 18], ((exein_prot_reply_t *) rdata)->payload[ 19],
								((exein_prot_reply_t *) rdata)->payload[ 20], ((exein_prot_reply_t *) rdata)->payload[ 21], ((exein_prot_reply_t *) rdata)->payload[ 22], ((exein_prot_reply_t *) rdata)->payload[ 23],
								((exein_prot_reply_t *) rdata)->payload[ 24], ((exein_prot_reply_t *) rdata)->payload[ 25], ((exein_prot_reply_t *) rdata)->payload[ 26], ((exein_prot_reply_t *) rdata)->payload[ 27],
								((exein_prot_reply_t *) rdata)->payload[ 28], ((exein_prot_reply_t *) rdata)->payload[ 29], ((exein_prot_reply_t *) rdata)->payload[ 30], ((exein_prot_reply_t *) rdata)->payload[ 31],

								((exein_prot_reply_t *) rdata)->payload[ 32], ((exein_prot_reply_t *) rdata)->payload[ 33], ((exein_prot_reply_t *) rdata)->payload[ 34], ((exein_prot_reply_t *) rdata)->payload[ 35],
								((exein_prot_reply_t *) rdata)->payload[ 36], ((exein_prot_reply_t *) rdata)->payload[ 37], ((exein_prot_reply_t *) rdata)->payload[ 38], ((exein_prot_reply_t *) rdata)->payload[ 39],
								((exein_prot_reply_t *) rdata)->payload[ 40], ((exein_prot_reply_t *) rdata)->payload[ 41], ((exein_prot_reply_t *) rdata)->payload[ 42], ((exein_prot_reply_t *) rdata)->payload[ 43],
								((exein_prot_reply_t *) rdata)->payload[ 44], ((exein_prot_reply_t *) rdata)->payload[ 45], ((exein_prot_reply_t *) rdata)->payload[ 46], ((exein_prot_reply_t *) rdata)->payload[ 47],
								((exein_prot_reply_t *) rdata)->payload[ 48], ((exein_prot_reply_t *) rdata)->payload[ 49], ((exein_prot_reply_t *) rdata)->payload[ 50], ((exein_prot_reply_t *) rdata)->payload[ 51],
								((exein_prot_reply_t *) rdata)->payload[ 52], ((exein_prot_reply_t *) rdata)->payload[ 53], ((exein_prot_reply_t *) rdata)->payload[ 54], ((exein_prot_reply_t *) rdata)->payload[ 55],
								((exein_prot_reply_t *) rdata)->payload[ 56], ((exein_prot_reply_t *) rdata)->payload[ 57], ((exein_prot_reply_t *) rdata)->payload[ 58], ((exein_prot_reply_t *) rdata)->payload[ 59],
								((exein_prot_reply_t *) rdata)->payload[ 60], ((exein_prot_reply_t *) rdata)->payload[ 61], ((exein_prot_reply_t *) rdata)->payload[ 62], ((exein_prot_reply_t *) rdata)->payload[ 63],

								((exein_prot_reply_t *) rdata)->payload[ 64], ((exein_prot_reply_t *) rdata)->payload[ 65], ((exein_prot_reply_t *) rdata)->payload[ 66], ((exein_prot_reply_t *) rdata)->payload[ 67],
								((exein_prot_reply_t *) rdata)->payload[ 68], ((exein_prot_reply_t *) rdata)->payload[ 69], ((exein_prot_reply_t *) rdata)->payload[ 70], ((exein_prot_reply_t *) rdata)->payload[ 71],
								((exein_prot_reply_t *) rdata)->payload[ 72], ((exein_prot_reply_t *) rdata)->payload[ 73], ((exein_prot_reply_t *) rdata)->payload[ 74], ((exein_prot_reply_t *) rdata)->payload[ 75],
								((exein_prot_reply_t *) rdata)->payload[ 76], ((exein_prot_reply_t *) rdata)->payload[ 77], ((exein_prot_reply_t *) rdata)->payload[ 78], ((exein_prot_reply_t *) rdata)->payload[ 79],
								((exein_prot_reply_t *) rdata)->payload[ 80], ((exein_prot_reply_t *) rdata)->payload[ 81], ((exein_prot_reply_t *) rdata)->payload[ 82], ((exein_prot_reply_t *) rdata)->payload[ 83],
								((exein_prot_reply_t *) rdata)->payload[ 84], ((exein_prot_reply_t *) rdata)->payload[ 85], ((exein_prot_reply_t *) rdata)->payload[ 86], ((exein_prot_reply_t *) rdata)->payload[ 87],
								((exein_prot_reply_t *) rdata)->payload[ 88], ((exein_prot_reply_t *) rdata)->payload[ 89], ((exein_prot_reply_t *) rdata)->payload[ 90], ((exein_prot_reply_t *) rdata)->payload[ 91],
								((exein_prot_reply_t *) rdata)->payload[ 92], ((exein_prot_reply_t *) rdata)->payload[ 93], ((exein_prot_reply_t *) rdata)->payload[ 94], ((exein_prot_reply_t *) rdata)->payload[ 95],

								((exein_prot_reply_t *) rdata)->payload[ 96], ((exein_prot_reply_t *) rdata)->payload[ 97], ((exein_prot_reply_t *) rdata)->payload[ 98], ((exein_prot_reply_t *) rdata)->payload[ 99],
								((exein_prot_reply_t *) rdata)->payload[100], ((exein_prot_reply_t *) rdata)->payload[101], ((exein_prot_reply_t *) rdata)->payload[102], ((exein_prot_reply_t *) rdata)->payload[103],
								((exein_prot_reply_t *) rdata)->payload[104], ((exein_prot_reply_t *) rdata)->payload[105], ((exein_prot_reply_t *) rdata)->payload[106], ((exein_prot_reply_t *) rdata)->payload[107],
								((exein_prot_reply_t *) rdata)->payload[108], ((exein_prot_reply_t *) rdata)->payload[109], ((exein_prot_reply_t *) rdata)->payload[110], ((exein_prot_reply_t *) rdata)->payload[111],
								((exein_prot_reply_t *) rdata)->payload[112], ((exein_prot_reply_t *) rdata)->payload[113], ((exein_prot_reply_t *) rdata)->payload[114], ((exein_prot_reply_t *) rdata)->payload[115],
								((exein_prot_reply_t *) rdata)->payload[116], ((exein_prot_reply_t *) rdata)->payload[117], ((exein_prot_reply_t *) rdata)->payload[118], ((exein_prot_reply_t *) rdata)->payload[119],
								((exein_prot_reply_t *) rdata)->payload[120], ((exein_prot_reply_t *) rdata)->payload[121], ((exein_prot_reply_t *) rdata)->payload[122], ((exein_prot_reply_t *) rdata)->payload[123],
								((exein_prot_reply_t *) rdata)->payload[124], ((exein_prot_reply_t *) rdata)->payload[125], ((exein_prot_reply_t *) rdata)->payload[126], ((exein_prot_reply_t *) rdata)->payload[127]);

					DODEBUG("libexnl.receive_feeds - accessing Hash @%p\n", uhandle->pids);
					DODEBUG("libexnl.receive_feeds - test read mmapped memory [%p]=%08x\n", uhandle->pids, *((uint32_t *) uhandle->pids));
					sem_wait(&uhandle->pids_lock);
					HASH_FIND(hh,uhandle->pids,&(((exein_prot_reply_t *) rdata)->pid),sizeof(uint16_t),pid_data);
					DODEBUG("libexnl.receive_feeds - suitable pid_data located @%p\n", pid_data);
					if ((pid_data)&&(pid_data->buffer)) {// there is a buffer, not first time receive this if pid_data->buffer is null, hook arrived before structure ready. Both cases can't be processed
						DODEBUG("libexnl.receive_feeds - the message we're waiting for (pid=%d) is just received, forward data to app\n", ((exein_prot_reply_t *) rdata)->pid);
						memcpy(pid_data->buffer, ( ((exein_prot_reply_t *) rdata)->payload), sizeof(uint16_t)*EXEIN_BUFFES_SIZE);//sizeof(uint16_t)*EXEIN_BUFFES_SIZE constant
						sem_post(&pid_data->semaphore);
						} else {// firs time I receive data for this pid, entry needs to be created
							if (!pid_data) printf("libexnl.receive_feeds - received feeds for unknown pid = %d or structure is not yet ready to get data.\n", ((exein_prot_reply_t *) rdata)->pid);
							}
			                if (pid_data) pid_data->safe2remove=EXEIN_CAN_BE_REMOVED;
					sem_post(&uhandle->pids_lock);
					break;
				default:
					DODEBUG("libexnl.receive_feeds - [##########] CASE DEFAULT  has been reached. Something wrong is going on!!!!\n");
					for (int i=0; i<err; i++) printf("%02x ", *(((char *) rdata)+i) );
				}

			}
		}
	return EXEIN_NOERR;
}





int exein_block_process(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag){
	exein_prot_req_t block={
        	.key            = key,
	        .message_id     = EXEIN_MSG_BK,
        	.tag            = tag,
	        .padding        = 0,
        	.pid            = pid,
	        };

	memcpy(	NLMSG_DATA(uhandle->nlh_sk), &block, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	uhandle->nlh_sk->nlmsg_pid=pid;
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
		uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
		return EXEIN_ERR_NLCOM;
		}
	return EXEIN_NOERR;

}

void exein_agent_stop(exein_shandle *uhandle){
        int i;
        exein_pids *buf;

        if (uhandle==NULL) return;
        kill(uhandle->sk_pid, SIGKILL);
        kill(uhandle->rf_pid, SIGKILL);
        close(uhandle->sock_fd);
        free(uhandle->src_addr);
        free(uhandle->dest_addr);
        free(uhandle->msg_sk->msg_iov);
        free(uhandle->msg_sk);
        free(uhandle->nlh_sk);
        free(uhandle->sk_stack);
        mealloc_destroy(uhandle);
}

exein_shandle *exein_agent_start(uint32_t key, uint16_t tag)
{
	proc_args		rf_args;
	proc_args		sk_args;
	exein_shandle		*uhandle;
	int 			err;
	pid_t			cpid=0;
	int			tmp;


	DODEBUG("libexnl.exein_agent_start - staring up\n");

	keepalive.key=key;
	keepalive.tag=tag;
	keepalive.message_id=EXEIN_MSG_KA;
	registration.key=key;
	registration.tag=tag;
	registration.message_id=EXEIN_MSG_REG;

        DODEBUG("libexnl.exein_agent_start - allocating memory structures\n");
	uhandle=                (exein_shandle *) BASE2RESERVED(mealloc_init(sizeof(exein_shandle), sizeof(exein_pids),0));
	if (!uhandle) return NULL;
	memset(uhandle, 0, sizeof(exein_shandle));


	sem_init(&uhandle->pids_lock, 1, 1);
	sem_getvalue(&uhandle->pids_lock, &tmp);


	uhandle->buffers_pool	=	mealloc_init(0, BUF_SIZE*sizeof(uint16_t), 0);
	uhandle->uthash_shm	=	(void *) gmealloc_init(HASH_BLOOM_BYTELEN, sizeof(UT_hash_table), HASH_INITIAL_NUM_BUCKETS*sizeof(struct UT_hash_bucket), MEALLOC_UT_BUCKET_MEDIUM_GROW);
	DODEBUG("libexnl.exein_agent_start - mealloc returned reserved pointer = %p for uhandle, %p for buffers_pool, uhandle->uthash_shm=%p \n", uhandle, uhandle->buffers_pool, uhandle->uthash_shm);
	uhandle->dest_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	if (!uhandle->dest_addr) {
		free(uhandle);
		return NULL;
		}
	uhandle->src_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	if (!uhandle->src_addr) {
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	uhandle->msg_sk=	(struct msghdr *) malloc(sizeof(struct msghdr));
	if (!uhandle->msg_sk) {
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	memset(uhandle->msg_sk, 0, sizeof(struct msghdr));
	cpid=getpid();
	if ((err=netlink_setup(uhandle, cpid))<0){
		printf("libexnl.exein_agent_start - netlink setup failed.");
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}

	if ((err=netlink_msg_init(EXEIN_PKT_SIZE, cpid, uhandle))<0){
		printf("libexnl.exein_agent_start - netlink message setup failed.");
		free(uhandle->msg_sk->msg_iov->iov_base); //nlh
		free(uhandle->msg_sk->msg_iov);
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	uhandle->cpid=cpid;

        DODEBUG("libexnl.exein_agent_start - starting threads\n");
	if (exein_nl_peer_register(uhandle, &registration)==EXEIN_NOERR){
		uhandle->sk_stack=	malloc(EXEIN_SK_STACK_SIZE);
		if (!uhandle->sk_stack) {
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
		sk_args.uhandle=	uhandle;
		sk_args.payload=	&keepalive;
		sk_args.loading_done=	0;
		uhandle->sk_pid=	clone(&send_keepalives, (char *) uhandle->sk_stack+EXEIN_SK_STACK_SIZE, CLONE_VM, &sk_args);
		uhandle->rf_stack=	malloc(EXEIN_RF_STACK_SIZE);
		if (!uhandle->rf_stack) {
			free(uhandle->sk_stack);
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
		rf_args.uhandle=	uhandle;
		rf_args.loading_done=	0;
		uhandle->rf_pid=	clone(&receive_feeds, (char *) uhandle->rf_stack+EXEIN_RF_STACK_SIZE, CLONE_VM, &rf_args);
		} else {
			printf("libexnl.exein_agent_start - threads setup failed.");
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
        DODEBUG("libexnl.exein_agent_start - sync with threads\n");
	while (sk_args.loading_done==0) sleep(1);
	while (rf_args.loading_done==0) sleep(1);
        DODEBUG("libexnl.exein_agent_start - setup done\n");
	uhandle->key=key;
	uhandle->tag=tag;
	printf("Agent successfully started. SockFD=%d, buffers_pool=%p, uthash_shm=%p, KeepAlive_pid=%d, ReceiveFeeds_pid=%d\n", uhandle->sock_fd, uhandle->buffers_pool, uhandle->uthash_shm, uhandle->sk_pid, uhandle->rf_pid);
	return uhandle;
}


