#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock_types.h>
#define EXEIN_REG_DURATION		2500
#define EXEIN_PROT_REGISTRATION_ID	1
#define EXEIN_PROT_KEEPALIVE_ID		2
#define EXEIN_PROT_FEED_ID		3
#define EXEIN_PROT_BLOCK_ID		4
#define EXEIN_PROT_DATA_REQ		5
#define EXEIN_PROT_NEW_PID		6
#define EXEIN_PROT_DEL_PID		7
#define EXEIN_PID_POS			1
#define EXEIN_NN_MAX_SIZE		50
#define EXEIN_RINGBUFFER_SIZE		(1<<7)
#define EXEIN_FEATURE_NUM_MAX		35
#define HASHTABLE_BITS			5

#define EXEIN_ONREQUEST			0x80
#define EXEIN_LIVE			0x81

#ifdef EXEIN_PRINT_DEBUG
#define DODEBUG( ... ) printk( __VA_ARGS__ );
#else
#define DODEBUG( ... ) do { } while(0)
#endif

#ifdef __LP64__
#define CURRENT_ADDR ((u64) current)
#define PTRSIZE u64
#else
#define CURRENT_ADDR ((u32) current)
#define PTRSIZE u32
#endif

typedef struct {
        u32			key;
        u8			message_id;
        u8			padding;
        u16			tag;
        pid_t			pid;
} exein_prot_req_t;

typedef struct {
	u16			tag;
	u64			timestamp;
	pid_t			pid;
	uint16_t		pending_request;
	u16			seqn;
	struct hlist_node	next;
	struct rcu_head         rcu;
} exein_reg_data;

void exein_delete_expired_regs(void);

typedef struct {
	u16			features[EXEIN_FEATURE_NUM_MAX];
} exein_pid_data_cell;

typedef struct {
	pid_t			pid;
#ifdef __LP64__
	u64			task_struct_addr;
#else
	u32			task_struct_addr;
#endif
	u16			tag;
	exein_pid_data_cell	*hookdata[EXEIN_RINGBUFFER_SIZE];
	spinlock_t 		ring_buffer_lock;
	int			index;
	int			in_use;
	struct hlist_node	next;
	struct rcu_head		rcu;
} exein_pid_data;

typedef struct {
	u16			msg_type;
	u32			seed;
	u16			seq;
	pid_t			pid;
	u16			payload[EXEIN_RINGBUFFER_SIZE];
} exein_prot_reply;


