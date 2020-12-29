/*
 * exein Linux Security Module
 *
 * Author: Alessandro Carminati <alessandro@exein.io>
 *
 * Copyright (C) 2019 Exein, SpA.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

/********************************************************************************************************************************************/
//#define EXEIN_PRINT_DEBUG
#define EXEIN_STUFF_DEBUG
/********************************************************************************************************************************************/

#include "exein_nn_main.h"
#include "exein_struct_mappings.h"
#include "exein_nn_defs_comp.h"
#include "exein_print_level.h"
#include "exein_lsm.h"
#include "exein_trust.h"

#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/delay.h>

#if NNINPUT_SIZE ==4
 #define EXEIN_PROT_TAG_POS 4
#else
 #define EXEIN_PROT_TAG_POS 3
#endif


#define NN_DEBUG 1
#define CURRENT_PROCESS_FEATURES 1 		// Took as a duplicate from exein_struct_mappings.c as a temporal solution
#undef EXEIN_FS_CONTEXT_PARSE_PARAM_SWITCH	//this hook, newly implemented, generates some issues / not available on 4.14.151
#undef EXEIN_FS_CONTEXT_DUP_SWITCH		//not available on 4.14.151
#undef EXEIN_INODE_GETSECURITY_SWITCH

//#ifdef CONFIG_DUP_TS_FIND_IN_LSM
//extern int do_dup_td_find(int hook);
//#endif

//int	exein_debug=0;
int	exein_mode=EXEIN_ONREQUEST;
void	*exein_payload_process_ptr;
void	*exein_register_status_get_ptr, *exein_pid_status_get_ptr;
int	exein_interface_ready=0;
struct	sock *exein_nl_sk_lsm=NULL;

DEFINE_SPINLOCK(exein_pid_data_access);
DEFINE_SPINLOCK(exein_reg_data_access);

DEFINE_HASHTABLE(nl_peers,HASHTABLE_BITS);
DEFINE_HASHTABLE(pid_repo,HASHTABLE_BITS);

//EXPORT_SYMBOL(exein_debug);
EXPORT_SYMBOL(exein_mode);
EXPORT_SYMBOL(exein_payload_process_ptr);
EXPORT_SYMBOL(exein_interface_ready);
EXPORT_SYMBOL(exein_nl_sk_lsm);
EXPORT_SYMBOL(exein_pid_status_get_ptr);
EXPORT_SYMBOL(exein_register_status_get_ptr);

#ifdef EXEIN_STUFF_DEBUG
int exein_rndkey=SEEDRND;
	EXPORT_SYMBOL(exein_rndkey);
#endif

static int hash_func_4_addrs(PTRSIZE data)
{ //because the allignment, and other stuffs there's more entrophy starting from bit 5
    return (data >> 6) & ((1<<HASHTABLE_BITS)-1);
}
static int hash_func_4_pids(int data)
{
    return data & ((1<<HASHTABLE_BITS)-1);
}

// this function gets called after a grace period has elapsed to deallocate the unlinked exein_pid_data elements.
// to deallocate pids elements, the function needs to deallocate the container, ad all the buffers in the round buffer.
static void pid_data_deferred_deletion(struct rcu_head *rcu) {
	int 		i;
	exein_pid_data	*b = container_of(rcu, exein_pid_data, rcu);

	DODEBUG(KERN_INFO "ExeinLSM[%d] - pid_data_deferred_deletion: delete pid_data [%d]@0x%p\n", current->pid, b->pid, b);
	for (i=0; i<EXEIN_RINGBUFFER_SIZE; i++) kfree(b->hookdata[i]);
	kfree(b);
}

static void reg_data_deferred_deletion(struct rcu_head *rcu) {
	exein_reg_data  *b = container_of(rcu, exein_reg_data, rcu);
	kfree(b);
}

int exein_register_status_get(char *buf, int size){ // TODO: Replace sprintf with snprintf. Use the size argument
	int pos=0;
        int bkt_cursor;
        exein_reg_data *reg_data;

	pos+=sprintf( (buf+pos),"pid, tag, time\n");
	rcu_read_lock();
	hash_for_each(nl_peers, bkt_cursor, reg_data, next)
	pos+=sprintf( (buf+pos),"%d,%d,%llu\n", reg_data->pid, reg_data->tag, reg_data->timestamp);
	rcu_read_unlock();
	return pos;
}

int exein_pid_status_get(char *buf, int size){ // TODO: Replace sprintf with snprintf. Use the size argument
	int pos=0, peerpid=0;
	int bkt_cursor, pid_cursor;
	exein_reg_data *reg_data;
	exein_pid_data *pid_data;

	pos+=sprintf( (buf+pos),"pid, tag, ts_addr, peer_pid\n");
	rcu_read_lock();
	hash_for_each(pid_repo, pid_cursor, pid_data, next){
		hash_for_each(nl_peers, bkt_cursor, reg_data, next) if (reg_data->tag==pid_data->tag) peerpid=reg_data->pid;
		pos+=sprintf( (buf+pos),"%d,%d,%x,%d\n", pid_data->pid, pid_data->tag, pid_data->task_struct_addr, peerpid);
		}
	rcu_read_unlock();
	return pos;
}



// each time this function is triggered it scans the registration hash and select the first expired item if any.
// if more than one exein agent is registered, and more than one expires, for example during the shutdown, it could be
// too much delete everything in a single hook slot.
void exein_delete_expired_regs(void){
	int			bkt_cursor, pid_cursor;
	exein_reg_data		*reg_data;
	exein_pid_data          *pid_data;
	int 			reg_2del_found=0;

	// scans registration hashes and find first expired item
	rcu_read_lock();
	hash_for_each_rcu(nl_peers, bkt_cursor, reg_data, next){
		if (jiffies_64-reg_data->timestamp>EXEIN_REG_DURATION){
			reg_2del_found=1;
			break;
			}
		}
	rcu_read_unlock();

	if (reg_2del_found){				// if one is found, it is possible to start a critical section with locks.
							// in this critical section is mandatory to search for the expired regs again,with locks, just to be sure that in
							// the meantime nothing has changed.
		spin_lock_bh(&exein_reg_data_access);
		hash_for_each_rcu(nl_peers, bkt_cursor, reg_data, next){
			if (jiffies_64-reg_data->timestamp>EXEIN_REG_DURATION){
				reg_2del_found=1;
				break;
				}
			}
		if (reg_data){				// if still there, just delete the expired reg, and schedule the function for free the memory.
			hash_del_rcu(&reg_data->next);
			call_rcu(&reg_data->rcu, reg_data_deferred_deletion);
			}
		spin_unlock_bh(&exein_reg_data_access);	//unlock the data structure either case, and do it asap.
		if (reg_data){				// if needed, deal with the unlinking of each pid_data element, associated with the previously selected
							// reg item.
			spin_lock_bh(&exein_pid_data_access);
			DODEBUG(KERN_INFO "ExeinLSM - PeerID: %d Tag: %d is expired.\n", reg_data->pid, reg_data->tag, reg_data->timestamp);
			hash_for_each_rcu(pid_repo, pid_cursor, pid_data, next){ // look at the PIDs we have, if found update the ring buffer
				DODEBUG(KERN_INFO "ExeinLSM - exein_delete_expired_regs: delete pid_data [%d]@0x%p\n", pid_data->pid,  pid_data);
				hash_del_rcu(&pid_data->next);
				call_rcu(&pid_data->rcu, pid_data_deferred_deletion);
				}
			spin_unlock_bh(&exein_pid_data_access);
			}

		}
}

int exein_send_nl_msg(void *pl, int plsize, pid_t dst_pid){
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
	int err;

	DODEBUG(KERN_INFO "ExeinLSM - exein_send_nl_msg pl=%p, size=%d, PID=%d\n", pl, plsize, dst_pid);
	skb_out = nlmsg_new(sizeof(exein_prot_reply),0); //message to notify new pid.
	if(!skb_out) {
		printk(KERN_INFO "ExeinLSM - Failed to allocate new skb\n");
		return -ENOBUFS; //if this goes wrong, there's no mean in collecting data. MLE won't ask for them
		}
	nlh=nlmsg_put(skb_out, 0, 0, NLMSG_DONE, plsize,0);
	if (!nlh) {
		nlmsg_free(skb_out);
		printk(KERN_INFO "ExeinLSM - Failed to nlmsg_put\n");
		return -ENOBUFS; //if this goes wrong, there's no mean in collecting data. MLE won't ask for them
		}
	NETLINK_CB(skb_out).dst_group = 0;

	memcpy(nlmsg_data(nlh), pl, plsize); //TODO: Does not check for buffer overflows when copying to destination (CWE-120). Make sure destination can always hold the source data.
	err = netlink_unicast(exein_nl_sk_lsm, skb_out, dst_pid, MSG_DONTWAIT); // MSG_DONTWAIT=0x40  //err=nlmsg_unicast(exein_nl_sk_lsm, skb_out, reg_data->pid);
	if (err<0) {
		printk(KERN_INFO "ExeinLSM - Failed to send unicast netlink message p=%d, err=%d\n", dst_pid,  err);
		} else {
			DODEBUG(KERN_INFO "ExeinLSM - Complete to send unicast netlink message p=%d\n", dst_pid);
			}
	return err;
}

/*return value
	=0 indicates no answer is needed
	=1 indicates module must provide ok answer
	=2 indicates module must provide ko answer
*/
static int exein_payload_process(void *data, pid_t pid){
	int retval=2;
	int bkt_cursor, pidfound;
	exein_reg_data *reg_data, *curr_data;
	u16 curr_tag;


	DODEBUG(KERN_INFO "ExeinLSM - exein_payload_process data@%p, from pid=%d\n", data, pid);
	if ((((exein_prot_req_t *)data)->key == SEEDRND)){
		switch (((exein_prot_req_t *)data)->message_id){
		case EXEIN_PROT_REGISTRATION_ID:
			curr_tag = ((exein_prot_req_t *)data)->tag;
			DODEBUG(KERN_INFO "ExeinLSM - Registration request for tag [%d] from MLE (PID %d)\n", curr_tag, pid);
			rcu_read_lock();
			hash_for_each_rcu(nl_peers, bkt_cursor, curr_data, next){
				if (curr_data->tag == curr_tag){
					DODEBUG(KERN_INFO "ExeinLSM - Tag [%d] exists!\n", curr_tag);
					retval=2;
					rcu_read_unlock();
					return retval;
					}
				}
			rcu_read_unlock();
			reg_data=kmalloc(sizeof(exein_reg_data),GFP_ATOMIC);
			reg_data->pid=pid;
			reg_data->tag=((exein_prot_req_t *)data)->tag;
			reg_data->timestamp=jiffies_64;
			reg_data->seqn=0;
			spin_lock_bh(&exein_reg_data_access);
			hash_add_rcu(nl_peers, &reg_data->next, hash_func_4_pids(reg_data->pid) );
			spin_unlock_bh(&exein_reg_data_access);
#ifdef EXEIN_PRINT_DEBUG
			rcu_read_lock();
			hash_for_each(nl_peers, bkt_cursor, reg_data, next) printk(KERN_INFO "ExeinLSM - PeerID: %d Tag: %d @time=%llu\n", reg_data->pid, reg_data->tag, reg_data->timestamp);
			rcu_read_unlock();
#endif
			retval=1;
			break;
		case EXEIN_PROT_KEEPALIVE_ID: //in this section, the "curr_data->timestamp" is actually written, but considering that modern processors are able to write int64 atomically, this should not concur with any race.
			rcu_read_lock();
			hash_for_each_possible(nl_peers, curr_data, next, hash_func_4_pids(pid) ) {
				if ((curr_data->tag==((exein_prot_req_t *)data)->tag)){
					curr_data->timestamp=jiffies_64;
					DODEBUG(KERN_INFO "ExeinLSM - MLE (PID %d) for tag [%d] registration updated\n", pid, ((exein_prot_req_t *)data)->tag);
					retval=0;
					rcu_read_unlock();
					return retval;
					}
				}
			rcu_read_unlock();
			DODEBUG(KERN_INFO "ExeinLSM - Unknown MLE received: (PID %d) for tag [%d]\n", pid, ((exein_prot_req_t *)data)->tag);
			retval=0;
			break;
		case EXEIN_PROT_BLOCK_ID:
			DODEBUG(KERN_INFO "ExeinLSM - Block process (%d) request for tag [%d] from MLE (PID %d)\n", ((exein_prot_req_t *)data)->pid, ((exein_prot_req_t *)data)->tag, pid);
			exein_mark_not_trusted(((exein_prot_req_t *)data)->tag, ((exein_prot_req_t *)data)->pid);
			retval=0;
			break;
		case EXEIN_PROT_DATA_REQ:
			DODEBUG(KERN_INFO "ExeinLSM - data request from MLE (MLE_PID %d, Requested_PID=%d)\n", pid,((exein_prot_req_t *)data)->pid);
			//look4 data in the "storage" and send it back
			pidfound=0;
			//for each request a message have to be send back.
			rcu_read_lock();
			hash_for_each(nl_peers, bkt_cursor, reg_data, next){
				if (((exein_prot_req_t *)data)->tag==reg_data->tag) {
					reg_data->pending_request=1;
					}
				}
			rcu_read_unlock();
			retval=0;
			break;
		default:
			DODEBUG(KERN_INFO "ExeinLSM - Request about tag [%d] from MLE (PID %d) payload pid %d padding %d", ((exein_prot_req_t *)data)->tag, pid, ((exein_prot_req_t *)data)->pid, ((exein_prot_req_t *)data)->padding);
			retval=0;
		}
	} else printk(KERN_INFO "ExeinLSM - Wrong key, request discarded\n");

return retval;
}

static void commit_data(exein_feature_t *data, int size, uint16_t *NNInput){
	int bkt_cursor, err, pid_cursor, i, pid_found, reg_found, pl_cursor, buf_cursor;
	exein_reg_data *reg_data;
	exein_pid_data *pid_data;
	exein_prot_reply msg_rpy;

#ifdef EXEIN_PRINT_DEBUG_EXTREME
	if (data[EXEIN_PROT_TAG_POS]!=0) printk(KERN_INFO "ExeinLSM - Commit data for tag %d\n", data[5]);
#endif
	if (data[EXEIN_PROT_TAG_POS]!=0){
		switch (exein_mode){
			case EXEIN_ONREQUEST:
				pid_found=0;
				reg_found=0;
				rcu_read_lock();
				hash_for_each_rcu(nl_peers, bkt_cursor, reg_data, next){
					if ((data[EXEIN_PROT_TAG_POS]==reg_data->tag)) {
						reg_found=1;
						hash_for_each_rcu(pid_repo, pid_cursor, pid_data, next){	// look at the PIDs we have, if found update the ring buffer
							if (CURRENT_ADDR==pid_data->task_struct_addr){		//check if current is hash item corresponds to the target
								pid_found=1;
								break;
								}
							}
						break;
						}
					}
				rcu_read_unlock();
				if (reg_found) {
					if (pid_found) {
						if (pid_data->in_use==1) {
							DODEBUG(KERN_INFO "ExeinLSM[TS=%llu] - pid[%d] pid_data@0x%p produced %d hook while in use!!!!!!!!!!\n", jiffies_64, current->pid, pid_data, NNInput[EXEIN_HOOK_ID_ARG1_POS]);
							return;
							}
						data[EXEIN_PROT_TAG_POS]=NNInput[EXEIN_HOOK_ID_ARG1_POS];
						spin_lock_bh(&pid_data->ring_buffer_lock); //TODO: verifythe short period between the rcu_read_unlock and the spinlock do ot generates races
						pid_data->in_use=1;
						pid_data->index++;
						pid_data->index&=0x7f;
						memcpy(pid_data->hookdata[pid_data->index], data, size*sizeof(exein_feature_t));
						spin_unlock_bh(&pid_data->ring_buffer_lock);
						if (reg_data->pending_request==1){
							DODEBUG(KERN_INFO "ExeinLSM - since data feed has been requested, prepare payload to send data back to registered peer\n");
							msg_rpy.msg_type = EXEIN_PROT_FEED_ID;
							msg_rpy.seed = SEEDRND;
							msg_rpy.seq=(u16) reg_data->seqn++;
							msg_rpy.pid = pid_data->pid;
							DODEBUG(KERN_INFO "ExeinLSM - Header details: Type=%d, seed=%d, seqn=%d, objpid=%d\n", msg_rpy.msg_type, msg_rpy.seed, msg_rpy.seq, msg_rpy.pid);
							pl_cursor=0;
							buf_cursor=pid_data->index;
							buf_cursor=(buf_cursor+1)&0x7f;

							for (pl_cursor=0; pl_cursor<EXEIN_RINGBUFFER_SIZE; pl_cursor++){
								*((u16 *) msg_rpy.payload+pl_cursor)=pid_data->hookdata[buf_cursor]->features[3]; //hookid
								DODEBUG(KERN_INFO "ExeinLSM - @buf[%d]<-rbuf[%d]=%04x\n", pl_cursor, buf_cursor, pid_data->hookdata[buf_cursor]->features[3]);
								buf_cursor=(buf_cursor+1)&0x7f;
								}
							err=exein_send_nl_msg(&msg_rpy, sizeof(exein_prot_reply), reg_data->pid); //sending message to userspace that feeds hookIDs for specified PID on Registered TAG.
							if (err<0) printk(KERN_INFO "ExeinLSM - Failed to send unicast FEED netlink message p=%d, t=%d, seq=%d err=%d\n", reg_data->pid, reg_data->tag, msg_rpy.seq, err);
								else {
								reg_data->pending_request=0;
								DODEBUG(KERN_INFO "ExeinLSM - Feed sent!\n");
								}
							}
						pid_data->in_use=0;
						} else {//the PID is not found, add a buffer for it and send netlink message about the event.
							//Setup a netlink packet and send it on the netlink connection.
							DODEBUG(KERN_INFO "ExeinLSM - <****> the pid %d is not there it's necessary to insert it. (index=0) <- hookid=%d\n", data[2], data[3]); //to be removed.
							//add buffer for the new pid
							data[EXEIN_PROT_TAG_POS]=NNInput[EXEIN_HOOK_ID_ARG1_POS];
							pid_data=kmalloc(sizeof(exein_pid_data), GFP_ATOMIC); // TODO: consider include this into while loop to be sure memory is allocated
							pid_data->pid=data[2];
							pid_data->tag=reg_data->tag;
							pid_data->index=0;
							pid_data->task_struct_addr= CURRENT_ADDR;
							pid_data->in_use=1;
							spin_lock_init(&pid_data->ring_buffer_lock);
							for (i=0; i<EXEIN_RINGBUFFER_SIZE; i++) { //allocate all buffers
								if (!(pid_data->hookdata[i] = kzalloc(sizeof(exein_pid_data_cell), GFP_ATOMIC))){
									panic("no memory for pid_data ring buffer target_pid=%d, pid_data=%p", data[2], pid_data);
									}
								}
							memcpy(pid_data->hookdata[0], data, size*sizeof(exein_feature_t));//TODO:Does not check for buffer overflows when copying to destination (CWE-120). Make sure destination can always hold the source data.

							spin_lock_bh(&exein_pid_data_access);
							hash_add_rcu(pid_repo, &pid_data->next, hash_func_4_addrs(pid_data->task_struct_addr) );
							spin_unlock_bh(&exein_pid_data_access);
							DODEBUG(KERN_INFO "ExeinLSM[TS=%llu] - pid[%d] just spawned! hookpid_data@0x%p hookNo=%d\n", jiffies_64, current->pid, pid_data, NNInput[EXEIN_HOOK_ID_ARG1_POS]);
							msg_rpy.msg_type = EXEIN_PROT_NEW_PID;
							msg_rpy.seed = SEEDRND;
							msg_rpy.seq=(u16) reg_data->seqn++;
							msg_rpy.pid=data[2];
							*((pid_t *) msg_rpy.payload) = data[2];
							DODEBUG(KERN_INFO "*** ExeinLSM - EXEIN_PROT_NEW_PID p=%d\n", pid_data->pid);
							err=exein_send_nl_msg(&msg_rpy, sizeof(exein_prot_reply), reg_data->pid); //sending message to userspace that new pid appeared for specified tag.
							if (err<0) printk(KERN_INFO "ExeinLSM - Failed to send unicast NEW_PID netlink message p=%d, t=%d, seq=%d err=%d\n", reg_data->pid, reg_data->tag, msg_rpy.seq, err);
								else DODEBUG(KERN_INFO "ExeinLSM - NEW_PID Message sent\n");
							pid_data->in_use=0;
							}
					}
				break;
			case EXEIN_LIVE:
				rcu_read_lock();
				hash_for_each(nl_peers, bkt_cursor, reg_data, next){
					if ((data[EXEIN_PROT_TAG_POS]==reg_data->tag)) {
						data[EXEIN_PROT_TAG_POS]=NNInput[EXEIN_HOOK_ID_ARG1_POS]; //tag is used no more
						data[size++]=(u16) reg_data->seqn++;
						err=exein_send_nl_msg(data, size<<1, reg_data->pid);
						}
					}
				rcu_read_unlock();
				break;
			default:
				printk(KERN_ERR "ExeinLSM - LSM is working in an unknown mode!\n");
			}
		}
//#ifdef CONFIG_DUP_TS_FIND_IN_LSM
//	do_dup_td_find(NNInput[EXEIN_HOOK_ID_ARG1_POS]);
//#endif
}

static void exein_prepare_send_data(size_t start_index, size_t end_index, uint16_t *NNInput){
	exein_feature_t *buffer;
	int i, pos=0;

	buffer=kmalloc(1024,GFP_ATOMIC);
	*(buffer+(pos++))=0x7845;							//[0]           Magic Number "Ex"
	*(buffer+(pos++))=(u16) EXEIN_NN_INPUT_SIZE;					//[1]           Size of the big input array
	*(buffer+(pos++))=(u16) NNInput[EXEIN_HOOK_CURRENT_PROCESS_ARG1_POS];		//[2]           Current PID
	*(buffer+(pos++))=(u16) NNInput[EXEIN_HOOK_CURRENT_PROCESS_TAG_ARG1_POS];	//[3]           Current HookID  temporary TAG
	*(buffer+(pos++))=(u16) start_index;						//[4]           Feature data start position within the array
	*(buffer+(pos++))=(u16) end_index;						//[5]           Feature data end position within the array
	for (i=2; i<end_index-start_index+2;i++){					//[6]~[n - n-1] Features
		*(buffer+(pos++))=(u16) *(NNInput+i);
		}									//[last]            sequence number

        if (NNInput[EXEIN_HOOK_ID_ARG1_POS]==0) {
		printk(KERN_INFO "ExeinLSM - hookid=0, start=%d, end=%d, pid=[%d]\n", start_index, end_index, NNInput[EXEIN_HOOK_CURRENT_PROCESS_ARG1_POS]);
		//dump_stack();
		}
	commit_data(buffer, pos, NNInput);
	kfree(buffer);
}

void exein_delete_pids(void){ //this function is called inside /kernel/exit.c:do_exit()
	int			err,i, bkt_cursor;
	exein_pid_data		*pid_data;
	exein_reg_data		*reg_data;
	exein_prot_reply	msg_rpy;

	DODEBUG(KERN_INFO "ExeinLSM[TS=%llu] - exein_delete_pids: delete pid_data [%d] l4 %x(%d)\n", jiffies_64, current->pid, CURRENT_ADDR, sizeof(CURRENT_ADDR) );
	if ((exein_mode==EXEIN_ONREQUEST)&&(current->process_tag!=0)){
		rcu_read_lock();
		hash_for_each_possible_rcu(pid_repo, pid_data, next, hash_func_4_addrs(CURRENT_ADDR) ){ // look at the PIDs we have, if found update the ring buffer
			if (CURRENT_ADDR==pid_data->task_struct_addr){
				hash_for_each_rcu(nl_peers, bkt_cursor, reg_data, next){
					if (pid_data->tag==reg_data->tag) {
						DODEBUG(KERN_INFO "ExeinLSM[TS=%llu] - exein_delete_pids: PID[%d] found @0x%p owned by %d at 0x%p\n", jiffies_64, current->pid, pid_data, reg_data->pid, reg_data);
						break;
						}
					}
				break;
				}
			}
		rcu_read_unlock();
		if ( pid_data && reg_data){
			DODEBUG(KERN_INFO "ExeinLSM - pid=%d is no more. Send a message back to tell it pid_data=%px, reg_data=%px\n",current->pid, pid_data, reg_data);
			pid_data->in_use=1;
			msg_rpy.msg_type = EXEIN_PROT_DEL_PID;
			msg_rpy.seed = SEEDRND;
			msg_rpy.seq=(u16) reg_data->seqn++;
			msg_rpy.pid=reg_data->pid;
			*((pid_t *) msg_rpy.payload) = current->pid;
			err=exein_send_nl_msg(&msg_rpy, sizeof(exein_prot_reply), reg_data->pid);
			if (err<0) printk(KERN_INFO "ExeinLSM - Failed to send unicast DEL_PID netlink message p=%d, t=%d, seq=%d err=%d\n", reg_data->pid, reg_data->tag, msg_rpy.seq, err);
			DODEBUG("ExeinLSM - pid %d removed from storage\n", current->pid);
			spin_lock_bh(&exein_pid_data_access);
			hash_del_rcu(&pid_data->next);
			spin_unlock_bh(&exein_pid_data_access);
			call_rcu(&pid_data->rcu, pid_data_deferred_deletion);
			DODEBUG(KERN_INFO "ExeinLSM[TS=%llu] - exein_delete_pids: delete pid_data [%d]@0x%p<\n", jiffies_64, pid_data->pid, pid_data);
			}
		}
}

/**********************************************************************************************************************/
#ifdef EXEIN_CAPGET_SWITCH
static int exein_capget(struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_CAPGET_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_CAPGET_ARG1_POS;
    size_t feature_index = 3;

    exein_map_task_struct_to_features(target, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(effective, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(inheritable, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(permitted, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_CAPGET_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_CAPSET_SWITCH
static int exein_capset(struct cred *new, const struct cred *old, const kernel_cap_t *effective, const kernel_cap_t *inheritable, const kernel_cap_t *permitted )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_CAPSET_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_CAPSET_ARG1_POS;
    size_t feature_index = 3;

    exein_map_cred_to_features(new, &feature_index, NNInput);
    exein_map_cred_to_features(old, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(effective, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(inheritable, &feature_index, NNInput);
    exein_map_kernel_cap_t_to_features(permitted, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_CAPSET_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_CAPABLE_SWITCH
//4.14.151
static int exein_capable(const struct cred *cred, struct user_namespace *ns, int cap, int opts )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_CAPABLE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_CAPABLE_ARG1_POS;
    size_t feature_index = 3;

    exein_map_cred_to_features(cred, &feature_index, NNInput);
    exein_map_user_namespace_to_features(ns, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) cap;
    NNInput[feature_index++] = (exein_feature_t) opts;
    feature_index=arg1_pos+EXEIN_CAPABLE_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPRM_SET_CREDS_SWITCH
static int exein_bprm_set_creds(struct linux_binprm *bprm )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPRM_SET_CREDS_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPRM_SET_CREDS_ARG1_POS;
    size_t feature_index = 3;

    exein_map_linux_binprm_to_features(bprm, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_BPRM_SET_CREDS_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPRM_CHECK_SECURITY_SWITCH
static int exein_bprm_check_security(struct linux_binprm *bprm )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPRM_CHECK_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPRM_CHECK_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_linux_binprm_to_features(bprm, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_BPRM_CHECK_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPRM_COMMITTING_CREDS_SWITCH
static void exein_bprm_committing_creds(struct linux_binprm *bprm )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPRM_COMMITTING_CREDS_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPRM_COMMITTING_CREDS_ARG1_POS;
    size_t feature_index = 3;

    exein_map_linux_binprm_to_features(bprm, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_BPRM_COMMITTING_CREDS_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_BPRM_COMMITTED_CREDS_SWITCH
static void exein_bprm_committed_creds(struct linux_binprm *bprm )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPRM_COMMITTED_CREDS_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPRM_COMMITTED_CREDS_ARG1_POS;
    size_t feature_index = 3;

    exein_map_linux_binprm_to_features(bprm, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_BPRM_COMMITTED_CREDS_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_FS_CONTEXT_DUP_SWITCH
static int exein_fs_context_dup(struct fs_context *fc, struct fs_context *src_sc )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FS_CONTEXT_DUP_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FS_CONTEXT_DUP_ARG1_POS;
    size_t feature_index = 3;

    exein_map_fs_context_to_features(fc, &feature_index, NNInput);
    exein_map_fs_context_to_features(src_sc, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FS_CONTEXT_DUP_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FS_CONTEXT_PARSE_PARAM_SWITCH
static int exein_fs_context_parse_param(struct fs_context *fc, struct fs_parameter *param )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FS_CONTEXT_PARSE_PARAM_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FS_CONTEXT_PARSE_PARAM_ARG1_POS;
    size_t feature_index = 3;

    exein_map_fs_context_to_features(fc, &feature_index, NNInput);
    exein_map_fs_parameter_to_features(param, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FS_CONTEXT_PARSE_PARAM_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_UNLINK_SWITCH
static int exein_path_unlink(const struct path *dir, struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_UNLINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_UNLINK_ARG1_POS;
    size_t feature_index = 3;

//    exein_map_path_to_features(dir, &feature_index, NNInput);
//    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_UNLINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_MKDIR_SWITCH
static int exein_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_MKDIR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_MKDIR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    feature_index=arg1_pos+EXEIN_PATH_MKDIR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_RMDIR_SWITCH
static int exein_path_rmdir(const struct path *dir, struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_RMDIR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_RMDIR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_RMDIR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_MKNOD_SWITCH
static int exein_path_mknod(const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_MKNOD_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_MKNOD_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    NNInput[feature_index++] = (exein_feature_t) dev;
    feature_index=arg1_pos+EXEIN_PATH_MKNOD_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_TRUNCATE_SWITCH
static int exein_path_truncate(const struct path *path )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_TRUNCATE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_TRUNCATE_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(path, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_TRUNCATE_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_SYMLINK_SWITCH
static int exein_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_SYMLINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_SYMLINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(old_name, DUMMY_STRING_MAX_LENGTH ,&feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_SYMLINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_LINK_SWITCH
static int exein_path_link(struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_LINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_LINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(old_dentry, &feature_index, NNInput);
    exein_map_path_to_features(new_dir, &feature_index, NNInput);
    exein_map_dentry_to_features(new_dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_LINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_RENAME_SWITCH
static int exein_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_RENAME_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_RENAME_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(old_dir, &feature_index, NNInput);
    exein_map_dentry_to_features(old_dentry, &feature_index, NNInput);
    exein_map_path_to_features(new_dir, &feature_index, NNInput);
    exein_map_dentry_to_features(new_dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_RENAME_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_CHMOD_SWITCH
static int exein_path_chmod(const struct path *path, umode_t mode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_CHMOD_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_CHMOD_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(path, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    feature_index=arg1_pos+EXEIN_PATH_CHMOD_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_CHOWN_SWITCH
static int exein_path_chown(const struct path *path, kuid_t uid, kgid_t gid )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_CHOWN_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_CHOWN_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(path, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) uid.val;
    NNInput[feature_index++] = (exein_feature_t) gid.val;
    feature_index=arg1_pos+EXEIN_PATH_CHOWN_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_PATH_CHROOT_SWITCH
static int exein_path_chroot(const struct path *path )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_PATH_CHROOT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_PATH_CHROOT_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(path, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_PATH_CHROOT_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_ALLOC_SECURITY_SWITCH
static int exein_inode_alloc_security(struct inode *inode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_ALLOC_SECURITY_ID;
//    printk(KERN_INFO "EXEIN_INODE_ALLOC_SECURITY hookid=%d, pid=%d\n", NNInput[EXEIN_HOOK_ID_ARG1_POS], NNInput[EXEIN_HOOK_CURRENT_PROCESS_ARG1_POS]);
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_ALLOC_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_ALLOC_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_FREE_SECURITY_SWITCH
static void exein_inode_free_security(struct inode *inode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_FREE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_FREE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_FREE_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_INIT_SECURITY_SWITCH
static int exein_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_INIT_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_INIT_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_qstr_to_features(qstr, &feature_index, NNInput);
    exein_map_string_to_features(*name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) *len;
    feature_index=arg1_pos+EXEIN_INODE_INIT_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_CREATE_SWITCH
static int exein_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_CREATE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_CREATE_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    feature_index=arg1_pos+EXEIN_INODE_CREATE_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_LINK_SWITCH
static int exein_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_LINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_LINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(old_dentry, &feature_index, NNInput);
    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(new_dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_LINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_UNLINK_SWITCH
static int exein_inode_unlink(struct inode *dir, struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_UNLINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_UNLINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_UNLINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_SYMLINK_SWITCH
static int exein_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_SYMLINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_SYMLINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(old_name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_SYMLINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_MKDIR_SWITCH
static int exein_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_MKDIR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_MKDIR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    feature_index=arg1_pos+EXEIN_INODE_MKDIR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_RMDIR_SWITCH
static int exein_inode_rmdir(struct inode *dir, struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_RMDIR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_RMDIR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_RMDIR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_MKNOD_SWITCH
static int exein_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_MKNOD_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_MKNOD_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(dir, &feature_index, NNInput);
    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mode;
    NNInput[feature_index++] = (exein_feature_t) dev;
    feature_index=arg1_pos+EXEIN_INODE_MKNOD_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_RENAME_SWITCH
static int exein_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_RENAME_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_RENAME_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(old_dir, &feature_index, NNInput);
    exein_map_dentry_to_features(old_dentry, &feature_index, NNInput);
    exein_map_inode_to_features(new_dir, &feature_index, NNInput);
    exein_map_dentry_to_features(new_dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_RENAME_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_READLINK_SWITCH
static int exein_inode_readlink(struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_READLINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_READLINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_READLINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_FOLLOW_LINK_SWITCH
static int exein_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_FOLLOW_LINK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_FOLLOW_LINK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_inode_to_features(inode, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) rcu;
    feature_index=arg1_pos+EXEIN_INODE_FOLLOW_LINK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_PERMISSION_SWITCH
static int exein_inode_permission(struct inode *inode, int mask )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_PERMISSION_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_PERMISSION_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mask;
    feature_index=arg1_pos+EXEIN_INODE_PERMISSION_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_SETATTR_SWITCH
static int exein_inode_setattr(struct dentry *dentry, struct iattr *attr )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_SETATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_SETATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_iattr_to_features(attr, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_SETATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_GETATTR_SWITCH
static int exein_inode_getattr(const struct path *path )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_GETATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_GETATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_path_to_features(path, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_GETATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_SETATTR_SWITCH
static int exein_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_SETATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_SETATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) size;
    NNInput[feature_index++] = (exein_feature_t) flags;
    feature_index=arg1_pos+EXEIN_INODE_SETATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_POST_SETXATTR_SWITCH
static void exein_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_POST_SETXATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_POST_SETXATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) size;
    NNInput[feature_index++] = (exein_feature_t) flags;
    feature_index=arg1_pos+EXEIN_INODE_POST_SETXATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_GETATTR_SWITCH
static int exein_inode_getxattr(struct dentry *dentry, const char *name )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_GETATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_GETATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_GETATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_LISTXATTR_SWITCH
static int exein_inode_listxattr(struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_LISTXATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_LISTXATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_LISTXATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_REMOVEXATTR_SWITCH
static int exein_inode_removexattr(struct dentry *dentry, const char *name )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_REMOVEXATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_REMOVEXATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_REMOVEXATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_NEED_KILLPRIV_SWITCH
static int exein_inode_need_killpriv(struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_NEED_KILLPRIV_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_NEED_KILLPRIV_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_NEED_KILLPRIV_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_KILLPRIV_SWITCH
static int exein_inode_killpriv(struct dentry *dentry )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_KILLPRIV_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_KILLPRIV_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_KILLPRIV_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_GETSECURITY_SWITCH
static int exein_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_GETSECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_GETSECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) alloc;
    feature_index=arg1_pos+EXEIN_INODE_GETSECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_SETSECURITY_SWITCH
static int exein_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_SETSECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_SETSECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) size;
    NNInput[feature_index++] = (exein_feature_t) flags;
    feature_index=arg1_pos+EXEIN_INODE_SETSECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_LISTSECURITY_SWITCH
static int exein_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_LISTSECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_LISTSECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    exein_map_string_to_features(buffer, buffer_size, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_LISTSECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_GETSECID_SWITCH
static void exein_inode_getsecid(struct inode *inode, u32 *secid )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_GETSECID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_GETSECID_ID;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) *secid;
    feature_index=arg1_pos+EXEIN_INODE_GETSECID_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_COPY_UP_SWITCH
static int exein_inode_copy_up(struct dentry *src, struct cred **new )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_COPY_UP_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_COPY_UP_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(src, &feature_index, NNInput);
    exein_map_cred_to_features(*new, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_COPY_UP_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_COPY_UP_XATTR_SWITCH
static int exein_inode_copy_up_xattr(const char *name )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_COPY_UP_XATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_COPY_UP_XATTR_ARG1_POS;
    size_t feature_index = 3;

    exein_map_string_to_features(name, DUMMY_STRING_MAX_LENGTH, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_COPY_UP_XATTR_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif
/**
 * exein_file_open - validate file_open calls
 * @file: descriptor of the file
 *
 * stores the filename counter in the rbtree
 * Returns 0 .
 */
#ifdef EXEIN_FILE_OPEN_SWITCH
//4.14.151
static int exein_file_open(struct file *file)
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_OPEN_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_OPEN_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FILE_OPEN_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_PERMISSION_SWITCH
static int exein_file_permission(struct file *file, int mask)
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_PERMISSION_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_PERMISSION_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) mask;
    feature_index=arg1_pos+EXEIN_FILE_PERMISSION_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_ALLOC_SECURITY_SWITCH
static int exein_file_alloc_security(struct file *file )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_ALLOC_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_ALLOC_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FILE_ALLOC_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_FREE_SECURITY_SWITCH
static void exein_file_free_security(struct file *file )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_FREE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_FREE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FILE_FREE_SECURITY_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_IOCTL_SWITCH
static int exein_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_IOCTL_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_IOCTL_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) cmd;
    NNInput[feature_index++] = (exein_feature_t) arg;
    feature_index=arg1_pos+EXEIN_FILE_IOCTL_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_MPROTECT_SWITCH
static int exein_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_MPROTECT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_MPROTECT_ARG1_POS;
    size_t feature_index = 3;

    exein_map_vm_area_struct_to_features(vma, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) reqprot;
    NNInput[feature_index++] = (exein_feature_t) prot;
    feature_index=arg1_pos+EXEIN_FILE_MPROTECT_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_LOCK_SWITCH
static int exein_file_lock(struct file *file, unsigned int cmd )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_LOCK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_LOCK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) cmd;
    feature_index=arg1_pos+EXEIN_FILE_LOCK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_FCNTL_SWITCH
static int exein_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_FCNTL_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_FCNTL_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) cmd;
    NNInput[feature_index++] = (exein_feature_t) arg;
    feature_index=arg1_pos+EXEIN_FILE_FCNTL_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_SET_FOWNER_SWITCH
static void exein_file_set_fowner(struct file *file )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_SET_FOWNER_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_SET_FOWNER_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FILE_SET_FOWNER_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_SEND_SIGIOTASK_SWITCH
static int exein_file_send_sigiotask(struct task_struct *tsk, struct fown_struct *fown, int sig )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_SEND_SIGIOTASK_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_SEND_SIGIOTASK_ARG1_POS;
    size_t feature_index = 3;

    exein_map_task_struct_to_features(tsk, &feature_index, NNInput);
    exein_map_fown_struct_to_features(fown, &feature_index, NNInput);
    NNInput[feature_index++] = (exein_feature_t) sig;
    feature_index=arg1_pos+EXEIN_FILE_SEND_SIGIOTASK_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_FILE_RECEIVE_SWITCH
static int exein_file_receive(struct file *file )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_FILE_RECEIVE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_FILE_RECEIVE_ARG1_POS;
    size_t feature_index = 3;

    exein_map_file_to_features(file, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_FILE_RECEIVE_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_INVALIDATE_SECCTX_SWITCH
static void exein_inode_invalidate_secctx(struct inode *inode )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_INVALIDATE_SECCTX_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_INVALIDATE_SECCTX_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_INVALIDATE_SECCTX_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_NOTIFYSECCTX_SWITCH
static int exein_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_NOTIFYSECCTX_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_NOTIFYSECCTX_ARG1_POS;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_NOTIFYSECCTX_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_SETSECCTX_SWITCH
static int exein_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_SETSECCTX_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_SETSECCTX_ARG1_POS;
    size_t feature_index = 3;

    exein_map_dentry_to_features(dentry, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_SETSECCTX_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_INODE_GETSECCTX_SWITCH
static int exein_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_INODE_GETSECCTX_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_INODE_GETSECCTX_ID;
    size_t feature_index = 3;

    exein_map_inode_to_features(inode, &feature_index, NNInput);
    feature_index=arg1_pos+EXEIN_INODE_GETSECCTX_SIZE;

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

/********************************************************************************************/

#ifdef EXEIN_SOCKET_POST_CREATE_SWITCH
static int exein_socket_post_create(struct socket * arg1, int arg2, int arg3, int arg4, int arg5 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_POST_CREATE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_POST_CREATE_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_POST_CREATE_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_SOCKETPAIR_SWITCH
static int exein_socket_socketpair(struct socket * arg1, struct socket * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_SOCKETPAIR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_SOCKETPAIR_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_SOCKETPAIR_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_BIND_SWITCH
static int exein_socket_bind(struct socket * arg1, struct sockaddr * arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_BIND_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_BIND_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_BIND_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_CONNECT_SWITCH
static int exein_socket_connect(struct socket * arg1, struct sockaddr * arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_CONNECT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_CONNECT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_CONNECT_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_LISTEN_SWITCH
static int exein_socket_listen(struct socket * arg1, int arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_LISTEN_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_LISTEN_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_LISTEN_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_ACCEPT_SWITCH
static int exein_socket_accept(struct socket * arg1, struct socket * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_ACCEPT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_ACCEPT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_ACCEPT_SIZE;
/* end ---- specific mappings*/


    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_SENDMSG_SWITCH
static int exein_socket_sendmsg(struct socket * arg1, struct msghdr * arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_SENDMSG_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_SENDMSG_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_SENDMSG_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_RECVMSG_SWITCH
static int exein_socket_recvmsg(struct socket * arg1, struct msghdr * arg2, int arg3, int arg4 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_RECVMSG_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_RECVMSG_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_RECVMSG_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_GETSOCKNAME_SWITCH
static int exein_socket_getsockname(struct socket * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_GETSOCKNAME_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_GETSOCKNAME_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_GETSOCKNAME_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_GETPEERNAME_SWITCH
static int exein_socket_getpeername(struct socket * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_GETPEERNAME_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_GETPEERNAME_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_GETPEERNAME_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_GETSOCKOPT_SWITCH
static int exein_socket_getsockopt(struct socket * arg1, int arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_GETSOCKOPT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_GETSOCKOPT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_GETSOCKOPT_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_SETSOCKOPT_SWITCH
static int exein_socket_setsockopt(struct socket * arg1, int arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_SETSOCKOPT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_SETSOCKOPT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_SETSOCKOPT_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_SHUTDOWN_SWITCH
static int exein_socket_shutdown(struct socket * arg1, int arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_SHUTDOWN_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_SHUTDOWN_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_SHUTDOWN_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_SOCK_RCV_SKB_SWITCH
static int exein_socket_sock_rcv_skb(struct sock * arg1, struct sk_buff * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_SOCK_RCV_SKB_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_SOCK_RCV_SKB_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_SOCK_RCV_SKB_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_GETPEERSEC_STREAM_SWITCH
static int exein_socket_getpeersec_stream(struct socket * arg1, char * arg2, int * arg3, unsigned arg4 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_GETPEERSEC_STREAM_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_GETPEERSEC_STREAM_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_GETPEERSEC_STREAM_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SOCKET_GETPEERSEC_DGRAM_SWITCH
static int exein_socket_getpeersec_dgram(struct socket * arg1, struct sk_buff * arg2, u32 * arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SOCKET_GETPEERSEC_DGRAM_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SOCKET_GETPEERSEC_DGRAM_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SOCKET_GETPEERSEC_DGRAM_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SK_ALLOC_SECURITY_SWITCH
static int exein_sk_alloc_security(struct sock * arg1, int arg2, gfp_t arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SK_ALLOC_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SK_ALLOC_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SK_ALLOC_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SK_FREE_SECURITY_SWITCH
static void exein_sk_free_security(struct sock * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SK_FREE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SK_FREE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SK_FREE_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_SK_CLONE_SECURITY_SWITCH
static void exein_sk_clone_security(const struct sock * arg1, struct sock * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SK_CLONE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SK_CLONE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SK_CLONE_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_SK_GETSECID_SWITCH
static void exein_sk_getsecid(struct sock * arg1, u32 * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SK_GETSECID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SK_GETSECID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SK_GETSECID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_SWITCH
static int exein_bpf(int arg1, union bpf_attr * arg2, unsigned int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_MAP_SWITCH
static int exein_bpf_map(struct bpf_map * arg1, fmode_t arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_MAP_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_MAP_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_MAP_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_PROG_SWITCH
static int exein_bpf_prog(struct bpf_prog * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_PROG_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_PROG_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_PROG_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_MAP_ALLOC_SECURITY_SWITCH
static int exein_bpf_map_alloc_security(struct bpf_map * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_MAP_ALLOC_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_MAP_ALLOC_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_MAP_ALLOC_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_MAP_FREE_SECURITY_SWITCH
static void exein_bpf_map_free_security(struct bpf_map * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_MAP_FREE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_MAP_FREE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_MAP_FREE_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_PROG_ALLOC_SECURITY_SWITCH
static int exein_bpf_prog_alloc_security(struct bpf_prog_aux * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_PROG_ALLOC_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_PROG_ALLOC_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_PROG_ALLOC_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_BPF_PROG_FREE_SECURITY_SWITCH
static void exein_bpf_prog_free_security(struct bpf_prog_aux * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_BPF_PROG_FREE_SECURITY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_BPF_PROG_FREE_SECURITY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_BPF_PROG_FREE_SECURITY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_ALLOC_SWITCH
static int exein_task_alloc(struct task_struct * arg1, unsigned long arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_ALLOC_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_ALLOC_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_ALLOC_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_FREE_SWITCH
static void exein_task_free(struct task_struct * arg1 )
{
	exein_feature_t		NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
	NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_FREE_ID;
	exein_map_current_to_features(NNInput);
	size_t arg1_pos = EXEIN_TASK_FREE_ARG1_POS;
	size_t feature_index = 3;
/* start -- specific mappings*/ 
	NNInput[3] = task_struct_get_pid(arg1);
	feature_index=arg1_pos+EXEIN_TASK_FREE_SIZE;
/* end ---- specific mappings*/
	exein_prepare_send_data(arg1_pos, feature_index, NNInput);
	playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_FIX_SETUID_SWITCH
static int exein_task_fix_setuid(struct cred * arg1, const struct cred * arg2, int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_FIX_SETUID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_FIX_SETUID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_FIX_SETUID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_SETPGID_SWITCH
static int exein_task_setpgid(struct task_struct * arg1, pid_t arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_SETPGID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_SETPGID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_SETPGID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_GETPGID_SWITCH
static int exein_task_getpgid(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_GETPGID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_GETPGID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_GETPGID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_GETSID_SWITCH
static int exein_task_getsid(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_GETSID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_GETSID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_GETSID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_GETSECID_SWITCH
static void exein_task_getsecid(struct task_struct * arg1, u32 * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_GETSECID_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_GETSECID_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_GETSECID_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_SETNICE_SWITCH
static int exein_task_setnice(struct task_struct * arg1, int arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_SETNICE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_SETNICE_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_SETNICE_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_SETIOPRIO_SWITCH
static int exein_task_setioprio(struct task_struct * arg1, int arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_SETIOPRIO_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_SETIOPRIO_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_SETIOPRIO_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_GETIOPRIO_SWITCH
static int exein_task_getioprio(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_GETIOPRIO_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_GETIOPRIO_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_GETIOPRIO_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_PRLIMIT_SWITCH
static int exein_task_prlimit(const struct cred * arg1, const struct cred * arg2, unsigned int arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_PRLIMIT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_PRLIMIT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_PRLIMIT_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_SETRLIMIT_SWITCH
static int exein_task_setrlimit(struct task_struct * arg1, unsigned int arg2, struct rlimit * arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_SETRLIMIT_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_SETRLIMIT_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_SETRLIMIT_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_SETSCHEDULER_SWITCH
static int exein_task_setscheduler(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_SETSCHEDULER_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_SETSCHEDULER_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_SETSCHEDULER_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_GETSCHEDULER_SWITCH
static int exein_task_getscheduler(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_GETSCHEDULER_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_GETSCHEDULER_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_GETSCHEDULER_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_MOVEMEMORY_SWITCH
static int exein_task_movememory(struct task_struct * arg1 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_MOVEMEMORY_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_MOVEMEMORY_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_MOVEMEMORY_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_KILL_SWITCH
//4.14.151
static int exein_task_kill(struct task_struct * arg1, struct siginfo * arg2, int arg3, const struct cred *cred)
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_KILL_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_KILL_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_KILL_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_PRCTL_SWITCH
static int exein_task_prctl(int arg1, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_PRCTL_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_PRCTL_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_PRCTL_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_TASK_TO_INODE_SWITCH
static void exein_task_to_inode(struct task_struct * arg1, struct inode * arg2 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_TASK_TO_INODE_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_TASK_TO_INODE_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_TASK_TO_INODE_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    playnn(NNInput);
}
#endif

#ifdef EXEIN_GETPROCATTR_SWITCH
static int exein_getprocattr(struct task_struct * arg1, char * arg2, char ** arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_GETPROCATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_GETPROCATTR_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_GETPROCATTR_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif

#ifdef EXEIN_SETPROCATTR_SWITCH
static int exein_setprocattr(const char * arg1, void * arg2, size_t arg3 )
{
	exein_feature_t NNInput[EXEIN_NN_MAX_SIZE];

#ifdef EXEIN_PRINT_DEBUG
#endif
    NNInput[EXEIN_HOOK_ID_ARG1_POS] = EXEIN_SETPROCATTR_ID;
    exein_map_current_to_features(NNInput);
    size_t arg1_pos = EXEIN_SETPROCATTR_ARG1_POS;
    size_t feature_index = 3;

/* start -- specific mappings*/
    feature_index=arg1_pos+EXEIN_SETPROCATTR_SIZE;
/* end ---- specific mappings*/

    exein_prepare_send_data(arg1_pos, feature_index, NNInput);
    return playnn(NNInput);
}
#endif



/* Hooks setup */ static struct security_hook_list exein_hooks[] __lsm_ro_after_init = {
#ifdef EXEIN_CAPGET_SWITCH
     LSM_HOOK_INIT(capget,                                exein_capget ),
#endif
#ifdef EXEIN_CAPSET_SWITCH
     LSM_HOOK_INIT(capset,                                exein_capset ),
#endif
#ifdef EXEIN_CAPABLE_SWITCH
     LSM_HOOK_INIT(capable,                               exein_capable ),
#endif
#ifdef EXEIN_BPRM_SET_CREDS_SWITCH
     LSM_HOOK_INIT(bprm_set_creds,                        exein_bprm_set_creds ),
#endif
#ifdef EXEIN_BPRM_CHECK_SECURITY_SWITCH
     LSM_HOOK_INIT(bprm_check_security,                   exein_bprm_check_security ),
#endif
#ifdef EXEIN_BPRM_COMMITTING_CREDS_SWITCH
     LSM_HOOK_INIT(bprm_committing_creds,                 exein_bprm_committing_creds ),
#endif
#ifdef EXEIN_BPRM_COMMITTED_CREDS_SWITCH
     LSM_HOOK_INIT(bprm_committed_creds,                  exein_bprm_committed_creds ),
#endif
#ifdef EXEIN_FS_CONTEXT_DUP_SWITCH
     LSM_HOOK_INIT(fs_context_dup,                        exein_fs_context_dup ),
#endif
#ifdef EXEIN_FS_CONTEXT_PARSE_PARAM_SWITCH
   LSM_HOOK_INIT(fs_context_parse_param,                  exein_fs_context_parse_param ),
#endif
#ifdef EXEIN_PATH_UNLINK_SWITCH
     LSM_HOOK_INIT(path_unlink,                           exein_path_unlink ),
#endif
#ifdef EXEIN_PATH_MKDIR_SWITCH
     LSM_HOOK_INIT(path_mkdir,                            exein_path_mkdir ),
#endif
#ifdef EXEIN_PATH_RMDIR_SWITCH
     LSM_HOOK_INIT(path_rmdir,                            exein_path_rmdir ),
#endif
#ifdef EXEIN_PATH_MKNOD_SWITCH
     LSM_HOOK_INIT(path_mknod,                            exein_path_mknod ),
#endif
#ifdef EXEIN_PATH_TRUNCATE_SWITCH
     LSM_HOOK_INIT(path_truncate,                         exein_path_truncate ),
#endif
#ifdef EXEIN_PATH_SYMLINK_SWITCH
     LSM_HOOK_INIT(path_symlink,                          exein_path_symlink ),
#endif
#ifdef EXEIN_PATH_LINK_SWITCH
     LSM_HOOK_INIT(path_link,                             exein_path_link ),
#endif
#ifdef EXEIN_PATH_RENAME_SWITCH
     LSM_HOOK_INIT(path_rename,                           exein_path_rename ),
#endif
#ifdef EXEIN_PATH_CHMOD_SWITCH
     LSM_HOOK_INIT(path_chmod,                            exein_path_chmod ),
#endif
#ifdef EXEIN_PATH_CHOWN_SWITCH
     LSM_HOOK_INIT(path_chown,                            exein_path_chown ),
#endif
#ifdef EXEIN_PATH_CHROOT_SWITCH
     LSM_HOOK_INIT(path_chroot,                           exein_path_chroot ),
#endif
#ifdef EXEIN_INODE_ALLOC_SECURITY_SWITCH
     LSM_HOOK_INIT(inode_alloc_security,                  exein_inode_alloc_security ),
#endif
#ifdef EXEIN_INODE_FREE_SECURITY_SWITCH
     LSM_HOOK_INIT(inode_free_security,                   exein_inode_free_security ),
#endif
#ifdef EXEIN_INODE_INIT_SECURITY_SWITCH
     LSM_HOOK_INIT(inode_init_security,                   exein_inode_init_security ),
#endif
#ifdef EXEIN_INODE_CREATE_SWITCH
     LSM_HOOK_INIT(inode_create,                          exein_inode_create ),
#endif
#ifdef EXEIN_INODE_LINK_SWITCH
     LSM_HOOK_INIT(inode_link,                            exein_inode_link ),
#endif
#ifdef EXEIN_INODE_UNLINK_SWITCH
     LSM_HOOK_INIT(inode_unlink,                          exein_inode_unlink ),
#endif
#ifdef EXEIN_INODE_SYMLINK_SWITCH
     LSM_HOOK_INIT(inode_symlink,                         exein_inode_symlink ),
#endif
#ifdef EXEIN_INODE_MKDIR_SWITCH
     LSM_HOOK_INIT(inode_mkdir,                           exein_inode_mkdir ),
#endif
#ifdef EXEIN_INODE_RMDIR_SWITCH
     LSM_HOOK_INIT(inode_rmdir,                           exein_inode_rmdir ),
#endif
#ifdef EXEIN_INODE_MKNOD_SWITCH
     LSM_HOOK_INIT(inode_mknod,                           exein_inode_mknod ),
#endif
#ifdef EXEIN_INODE_RENAME_SWITCH
     LSM_HOOK_INIT(inode_rename,                          exein_inode_rename ),
#endif
#ifdef EXEIN_INODE_READLINK_SWITCH
     LSM_HOOK_INIT(inode_readlink,                        exein_inode_readlink ),
#endif
#ifdef EXEIN_INODE_FOLLOW_LINK_SWITCH
     LSM_HOOK_INIT(inode_follow_link,                     exein_inode_follow_link ),
#endif
#ifdef EXEIN_INODE_PERMISSION_SWITCH
     LSM_HOOK_INIT(inode_permission,                      exein_inode_permission ),
#endif
#ifdef EXEIN_INODE_SETATTR_SWITCH
     LSM_HOOK_INIT(inode_setattr,                         exein_inode_setattr ),
#endif
#ifdef EXEIN_INODE_GETATTR_SWITCH
     LSM_HOOK_INIT(inode_getattr,                         exein_inode_getattr ),
#endif
#ifdef EXEIN_INODE_SETXATTR_SWITCH
     LSM_HOOK_INIT(inode_setxattr,                        exein_inode_setxattr ),
#endif
#ifdef EXEIN_INODE_POST_SETXATTR_SWITCH
     LSM_HOOK_INIT(inode_post_setxattr,                   exein_inode_post_setxattr ),
#endif
#ifdef EXEIN_INODE_GETXATTR_SWITCH
     LSM_HOOK_INIT(inode_getxattr,                        exein_inode_getxattr ),
#endif
#ifdef EXEIN_INODE_LISTXATTR_SWITCH
     LSM_HOOK_INIT(inode_listxattr,                       exein_inode_listxattr ),
#endif
#ifdef EXEIN_INODE_REMOVEXATTR_SWITCH
     LSM_HOOK_INIT(inode_removexattr,                     exein_inode_removexattr ),
#endif
#ifdef EXEIN_INODE_NEED_KILLPRIV_SWITCH
     LSM_HOOK_INIT(inode_need_killpriv,                   exein_inode_need_killpriv ),
#endif
#ifdef EXEIN_INODE_KILLPRIV_SWITCH
     LSM_HOOK_INIT(inode_killpriv,                        exein_inode_killpriv ),
#endif
#ifdef EXEIN_INODE_GETSECURITY_SWITCH
     LSM_HOOK_INIT(inode_getsecurity,                     exein_inode_getsecurity ),
#endif
#ifdef EXEIN_INODE_SETSECURITY_SWITCH
     LSM_HOOK_INIT(inode_setsecurity,                     exein_inode_setsecurity ),
#endif
#ifdef EXEIN_INODE_LISTSECURITY_SWITCH
     LSM_HOOK_INIT(inode_listsecurity,                    exein_inode_listsecurity ),
#endif
#ifdef EXEIN_INODE_GETSECID_SWITCH
     LSM_HOOK_INIT(inode_getsecid,                        exein_inode_getsecid ),
#endif
#ifdef EXEIN_INODE_COPY_UP_SWITCH
     LSM_HOOK_INIT(inode_copy_up,                         exein_inode_copy_up ),
#endif
#ifdef EXEIN_INODE_COPY_UP_XATTR_SWITCH
     LSM_HOOK_INIT(inode_copy_up_xattr,                   exein_inode_copy_up_xattr ),
#endif
#ifdef EXEIN_FILE_PERMISSION_SWITCH
     LSM_HOOK_INIT(file_permission,                       exein_file_permission ),
#endif
#ifdef EXEIN_FILE_ALLOC_SECURITY_SWITCH
     LSM_HOOK_INIT(file_alloc_security,                   exein_file_alloc_security ),
#endif
#ifdef EXEIN_FILE_FREE_SECURITY_SWITCH
     LSM_HOOK_INIT(file_free_security,                    exein_file_free_security ),
#endif
#ifdef EXEIN_FILE_IOCTL_SWITCH
     LSM_HOOK_INIT(file_ioctl,                            exein_file_ioctl ),
#endif
#ifdef EXEIN_FILE_MPROTECT_SWITCH
     LSM_HOOK_INIT(file_mprotect,                         exein_file_mprotect ),
#endif
#ifdef EXEIN_FILE_LOCK_SWITCH
     LSM_HOOK_INIT(file_lock,                             exein_file_lock ),
#endif
#ifdef EXEIN_FILE_FCNTL_SWITCH
     LSM_HOOK_INIT(file_fcntl,                            exein_file_fcntl ),
#endif
#ifdef EXEIN_FILE_SET_FOWNER_SWITCH
     LSM_HOOK_INIT(file_set_fowner,                       exein_file_set_fowner ),
#endif
#ifdef EXEIN_FILE_SEND_SIGIOTASK_SWITCH
     LSM_HOOK_INIT(file_send_sigiotask,                   exein_file_send_sigiotask ),
#endif
#ifdef EXEIN_FILE_RECEIVE_SWITCH
     LSM_HOOK_INIT(file_receive,                          exein_file_receive ),
#endif
#ifdef EXEIN_FILE_OPEN_SWITCH
     LSM_HOOK_INIT(file_open,                             exein_file_open ),
#endif
#ifdef EXEIN_INODE_INVALIDATE_SECCTX_SWITCH
     LSM_HOOK_INIT(inode_invalidate_secctx,               exein_inode_invalidate_secctx ),
#endif
#ifdef EXEIN_INODE_NOTIFYSECCTX_SWITCH
     LSM_HOOK_INIT(inode_notifysecctx,                    exein_inode_notifysecctx ),
#endif
#ifdef EXEIN_INODE_SETSECCTX_SWITCH
     LSM_HOOK_INIT(inode_setsecctx,                       exein_inode_setsecctx ),
#endif
#ifdef EXEIN_INODE_GETSECCTX_SWITCH
     LSM_HOOK_INIT(inode_getsecctx,                       exein_inode_getsecctx ),
#endif
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#ifdef EXEIN_SOCKET_POST_CREATE_SWITCH
    LSM_HOOK_INIT(socket_post_create,	exein_socket_post_create ),
#endif

#ifdef EXEIN_SOCKET_SOCKETPAIR_SWITCH
    LSM_HOOK_INIT(socket_socketpair,	exein_socket_socketpair ),
#endif

#ifdef EXEIN_SOCKET_BIND_SWITCH
    LSM_HOOK_INIT(socket_bind,	exein_socket_bind ),
#endif

#ifdef EXEIN_SOCKET_CONNECT_SWITCH
    LSM_HOOK_INIT(socket_connect,	exein_socket_connect ),
#endif

#ifdef EXEIN_SOCKET_LISTEN_SWITCH
    LSM_HOOK_INIT(socket_listen,	exein_socket_listen ),
#endif

#ifdef EXEIN_SOCKET_ACCEPT_SWITCH
    LSM_HOOK_INIT(socket_accept,	exein_socket_accept ),
#endif

#ifdef EXEIN_SOCKET_SENDMSG_SWITCH
    LSM_HOOK_INIT(socket_sendmsg,	exein_socket_sendmsg ),
#endif

#ifdef EXEIN_SOCKET_RECVMSG_SWITCH
    LSM_HOOK_INIT(socket_recvmsg,	exein_socket_recvmsg ),
#endif

#ifdef EXEIN_SOCKET_GETSOCKNAME_SWITCH
    LSM_HOOK_INIT(socket_getsockname,	exein_socket_getsockname ),
#endif

#ifdef EXEIN_SOCKET_GETPEERNAME_SWITCH
    LSM_HOOK_INIT(socket_getpeername,	exein_socket_getpeername ),
#endif

#ifdef EXEIN_SOCKET_GETSOCKOPT_SWITCH
    LSM_HOOK_INIT(socket_getsockopt,	exein_socket_getsockopt ),
#endif

#ifdef EXEIN_SOCKET_SETSOCKOPT_SWITCH
    LSM_HOOK_INIT(socket_setsockopt,	exein_socket_setsockopt ),
#endif

#ifdef EXEIN_SOCKET_SHUTDOWN_SWITCH
    LSM_HOOK_INIT(socket_shutdown,	exein_socket_shutdown ),
#endif

#ifdef EXEIN_SOCKET_SOCK_RCV_SKB_SWITCH
    LSM_HOOK_INIT(socket_sock_rcv_skb,	exein_socket_sock_rcv_skb ),
#endif

#ifdef EXEIN_SOCKET_GETPEERSEC_STREAM_SWITCH
    LSM_HOOK_INIT(socket_getpeersec_stream,	exein_socket_getpeersec_stream ),
#endif

#ifdef EXEIN_SOCKET_GETPEERSEC_DGRAM_SWITCH
    LSM_HOOK_INIT(socket_getpeersec_dgram,	exein_socket_getpeersec_dgram ),
#endif

#ifdef EXEIN_SK_ALLOC_SECURITY_SWITCH
    LSM_HOOK_INIT(sk_alloc_security,	exein_sk_alloc_security ),
#endif

#ifdef EXEIN_SK_FREE_SECURITY_SWITCH
    LSM_HOOK_INIT(sk_free_security,	exein_sk_free_security ),
#endif

#ifdef EXEIN_SK_CLONE_SECURITY_SWITCH
    LSM_HOOK_INIT(sk_clone_security,	exein_sk_clone_security ),
#endif

#ifdef EXEIN_SK_GETSECID_SWITCH
    LSM_HOOK_INIT(sk_getsecid,	exein_sk_getsecid ),
#endif

#ifdef EXEIN_BPF_SWITCH
    LSM_HOOK_INIT(bpf,	exein_bpf ),
#endif

#ifdef EXEIN_BPF_MAP_SWITCH
    LSM_HOOK_INIT(bpf_map,	exein_bpf_map ),
#endif

#ifdef EXEIN_BPF_PROG_SWITCH
    LSM_HOOK_INIT(bpf_prog,	exein_bpf_prog ),
#endif

#ifdef EXEIN_BPF_MAP_ALLOC_SECURITY_SWITCH
    LSM_HOOK_INIT(bpf_map_alloc_security,	exein_bpf_map_alloc_security ),
#endif

#ifdef EXEIN_BPF_MAP_FREE_SECURITY_SWITCH
    LSM_HOOK_INIT(bpf_map_free_security,	exein_bpf_map_free_security ),
#endif

#ifdef EXEIN_BPF_PROG_ALLOC_SECURITY_SWITCH
    LSM_HOOK_INIT(bpf_prog_alloc_security,	exein_bpf_prog_alloc_security ),
#endif

#ifdef EXEIN_BPF_PROG_FREE_SECURITY_SWITCH
    LSM_HOOK_INIT(bpf_prog_free_security,	exein_bpf_prog_free_security ),
#endif

#ifdef EXEIN_TASK_ALLOC_SWITCH
    LSM_HOOK_INIT(task_alloc,	exein_task_alloc ),
#endif

#ifdef EXEIN_TASK_FREE_SWITCH
    LSM_HOOK_INIT(task_free,	exein_task_free ),
#endif

#ifdef EXEIN_TASK_FIX_SETUID_SWITCH
    LSM_HOOK_INIT(task_fix_setuid,	exein_task_fix_setuid ),
#endif

#ifdef EXEIN_TASK_SETPGID_SWITCH
    LSM_HOOK_INIT(task_setpgid,	exein_task_setpgid ),
#endif

#ifdef EXEIN_TASK_GETPGID_SWITCH
    LSM_HOOK_INIT(task_getpgid,	exein_task_getpgid ),
#endif

#ifdef EXEIN_TASK_GETSID_SWITCH
    LSM_HOOK_INIT(task_getsid,	exein_task_getsid ),
#endif

#ifdef EXEIN_TASK_GETSECID_SWITCH
    LSM_HOOK_INIT(task_getsecid,	exein_task_getsecid ),
#endif

#ifdef EXEIN_TASK_SETNICE_SWITCH
    LSM_HOOK_INIT(task_setnice,	exein_task_setnice ),
#endif

#ifdef EXEIN_TASK_SETIOPRIO_SWITCH
    LSM_HOOK_INIT(task_setioprio,	exein_task_setioprio ),
#endif

#ifdef EXEIN_TASK_GETIOPRIO_SWITCH
    LSM_HOOK_INIT(task_getioprio,	exein_task_getioprio ),
#endif

#ifdef EXEIN_TASK_PRLIMIT_SWITCH
    LSM_HOOK_INIT(task_prlimit,	exein_task_prlimit ),
#endif

#ifdef EXEIN_TASK_SETRLIMIT_SWITCH
    LSM_HOOK_INIT(task_setrlimit,	exein_task_setrlimit ),
#endif

#ifdef EXEIN_TASK_SETSCHEDULER_SWITCH
    LSM_HOOK_INIT(task_setscheduler,	exein_task_setscheduler ),
#endif

#ifdef EXEIN_TASK_GETSCHEDULER_SWITCH
    LSM_HOOK_INIT(task_getscheduler,	exein_task_getscheduler ),
#endif

#ifdef EXEIN_TASK_MOVEMEMORY_SWITCH
    LSM_HOOK_INIT(task_movememory,	exein_task_movememory ),
#endif

#ifdef EXEIN_TASK_KILL_SWITCH
    LSM_HOOK_INIT(task_kill,	exein_task_kill ),
#endif

#ifdef EXEIN_TASK_PRCTL_SWITCH
    LSM_HOOK_INIT(task_prctl,	exein_task_prctl ),
#endif

#ifdef EXEIN_TASK_TO_INODE_SWITCH
    LSM_HOOK_INIT(task_to_inode,	exein_task_to_inode ),
#endif

#ifdef EXEIN_GETPROCATTR_SWITCH
    LSM_HOOK_INIT(getprocattr,	exein_getprocattr ),
#endif

#ifdef EXEIN_SETPROCATTR_SWITCH
    LSM_HOOK_INIT(setprocattr,	exein_setprocattr ),
#endif
};

static int __init exein_init(void)
{
	pr_info("ExeinLSM - lsm is active: seed [%d]\n",SEEDRND);
        exein_payload_process_ptr	=	&exein_payload_process;
	exein_register_status_get_ptr	=	&exein_register_status_get;
	exein_pid_status_get_ptr	=	&exein_pid_status_get;
	security_add_hooks(exein_hooks, ARRAY_SIZE(exein_hooks), "exein");
	hash_init(nl_peers);
	hash_init(pid_repo);
	return 0;
}

//4.14.151
security_initcall(exein_init);

//5.1.11
// DEFINE_LSM(exein) = {
// 	.name = "exein",
// 	.init = exein_init,
// };
