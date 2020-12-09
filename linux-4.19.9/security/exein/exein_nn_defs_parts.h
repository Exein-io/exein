/*
   ------
  / *    *
 /   *  *  *
(------     *
 \   *  *  *
  \ *    *
   ------
Exein
*/
#include <uapi/linux/capability.h>

#define	DUMMY_STRING_MAX_LENGTH     0

#define CURRENT_PROCESS_FEATURES    1
#define BOOL                        1
#define CHAR                        1
#define CONST_CHAR                  CHAR
#define CONST_STRUCT_CRED           STRUCT_CRED
#define CONST_STRUCT_KERNEL_CAP_T   KERNEL_CAP_T
#define CONST_STRUCT_PATH           1 //temporary
#define CONST_STRUCT_QSTR           STRUCT_QSTR
#define CONST_STRUCT_SUPER_BLOCK    1 //temporary
#define CONST_STRUCT_TIMESPEC64     1 //temporary
#define CONST_STRUCT_TIMEZONE       1 //temporary
#define CONST_VOID                  1 //temporary
#define CONST_STRUCT_REQUEST_SOCK   STRUCT_REQUEST_SOCK
#define CONST_STRUCT_FLOWI          STRUCT_FLOWI
#define CONST_STRUCT_SOCK           STRUCT_SOCK
#define UNION_BPF_ATTR              1 //temporary
#define DEV_T                       1 //temporary
#define ENUM_KERNEL_LOAD_DATA_ID    1 //temporary
#define ENUM_KERNEL_READ_FILE_ID    1 //temporary
#define GFP_T                       1 //temporary
#define INT                         1
#define KERNEL_CAP_T                2 //_KERNEL_CAPABILITY_U32S
#define KGID_T                      1 //temporary
#define KUID_T                      1 //temporary
#define LOFF_T                      1 //temporary
#define LONG                        1 //temporary
#define PID_T                       1 //temporary
#define SHORT                       1 //temporary
#define SIZE_T                      1 //temporary
#define KEY_REF_T                   1 //temporary
#define FMODE_T                     1 //temporary
#define STRUCT_CRED                 9
#define STRUCT_DENTRY               1 //temporary was 0
#define STRUCT_FILE                 STRUCT_DENTRY + STRUCT_INODE + STRUCT_FOWN_STRUCT + 1
#define STRUCT_FOWN_STRUCT          1
#define STRUCT_FS_CONTEXT           DUMMY_STRING_MAX_LENGTH + STRUCT_DENTRY + STRUCT_USER_NAMESPACE + STRUCT_CRED + DUMMY_STRING_MAX_LENGTH + DUMMY_STRING_MAX_LENGTH + 6
#define STRUCT_FS_PARAMETER         1 //temporary was 0
#define STRUCT_IATTR                5
#define STRUCT_INODE                7
//4.14.151
#define STRUCT_SIGINFO       1 //temporary
#define STRUCT_KERN_IPC_PERM        1 //temporary
#define STRUCT_LINUX_BINPRM         1 //temporary was 0
#define STRUCT_MM_STRUCT            1 //temporary
#define STRUCT_MSG_MSG              1 //temporary
#define STRUCT_QSTR                 1 //temporary was 0
#define STRUCT_RLIMIT               1 //temporary
#define STRUCT_SEQ_FILE             1 //temporary
#define STRUCT_SUPER_BLOCK          1 //temporary
#define STRUCT_TASK_STRUCT         10
#define STRUCT_USER_NAMESPACE       3
#define STRUCT_VFSMOUNT             1 //temporary
#define STRUCT_VM_AREA_STRUCT      20
#define STRUCT_AUDIT_KRULE          1 //temporary
//4.14.151
#define STRUCT_AUDIT_CONTEXT        1 //temporary
#define STRUCT_XFRM_STATE           1 //temporary
#define STRUCT_XFRM_USER_SEC_CTX    1 //temporary
#define STRUCT_XFRM_SEC_CTX         1 //temporary
#define STRUCT_SOCK                 1 //temporary
#define STRUCT_XFRM_POLICY          1 //temporary
#define STRUCT_MSGHDR               1 //temporary
#define STRUCT_SOCKADDR             1 //temporary
#define STRUCT_SOCKET               1 //temporary
#define STRUCT_KEY                  1 //temporary
#define STRUCT_SK_BUFF              1 //temporary
#define STRUCT_REQUEST_SOCK         1 //temporary
#define STRUCT_SEMBUF               1 //temporary
#define STRUCT_BPF_PROG_AUX         1 //temporary
#define STRUCT_BPF_PROG             1 //temporary
#define STRUCT_BPF_MAP              1 //temporary
#define STRUCT_SCTP_ENDPOINT        1 //temporary
#define STRUCT_FLOWI                1 //temporary
#define UMODE_T                     1 //temporary
#define UNSIGNED_INT                1
#define UNSIGNED_LONG               1 //temporary
#define VOID                        1 //temporary
#define UNSIGNED                    1 //temporary
#define U8                          1 //temporary
#define U16                         1 //temporary
#define U32                         1 //temporary
#define U64                         1 //temporary
//4.14.151
#define STRUCT_SECURITY_MNT_OPTS    1 //temporary
#define STRUCT_SEM_ARRAY            1 //temporary
#define STRUCT_MSG_QUEUE            1 //temporary
#define STRUCT_SHMID_KERNEL         1 //temporary
