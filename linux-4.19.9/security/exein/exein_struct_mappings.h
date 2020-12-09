#include <linux/types.h>
#include <linux/cred.h>             // cred
#include <linux/fs.h>               // fown_struct, iattr,
#include <linux/binfmts.h>          // linux_binprm
#include <linux/user_namespace.h>
#include <linux/mount.h>            // vfsmount
#include <linux/sched.h>
//5.1.11
//#include <linux/fs_context.h>       // fs_context, fs_parameter
#include <linux/capability.h>       //  kernel_cap_struct
#include <linux/path.h>             // path
#include <linux/uidgid.h>           // kuid_t

//4.14.151
#include <linux/sem.h>           // sem_array
#include "../../kernel/audit.h"

#include "exein_types.h"
#include "exein_nn_defs.h"
#include "exein_print_level.h"

#define PARSE_STRINGS 0
#define DUMMY_STRING_MAX_LENGTH 10

uint16_t task_struct_get_pid(struct task_struct *arg1);
void exein_map_current_to_features(exein_feature_t* features_arr);

void exein_map_string_to_features(const char* string,   size_t string_max_length,   size_t* index_p,   exein_feature_t* features_arr);

void exein_map_cred_to_features(            const struct cred* input,               size_t* index_p,   exein_feature_t* features_arr);
void exein_map_fown_struct_to_features(     const struct fown_struct* input,        size_t* index_p,   exein_feature_t* features_arr);
void exein_map_iattr_to_features(           const struct iattr* input,              size_t* index_p,   exein_feature_t* features_arr);
void exein_map_user_namespace_to_features(  const struct user_namespace* input,     size_t* index_p,   exein_feature_t* features_arr);
void exein_map_vm_area_struct_to_features(  const struct vm_area_struct* input,     size_t* index_p,   exein_feature_t* features_arr);
void exein_map_task_struct_to_features(     const struct task_struct* input,        size_t* index_p,   exein_feature_t* features_arr);
//void exein_map_fs_context_to_features(      const struct fs_context* input,         size_t* index_p,   exein_feature_t* features_arr);
void exein_map_inode_to_features(           const struct inode* input,              size_t* index_p,   exein_feature_t* features_arr);
void exein_map_dentry_to_features(          const struct dentry* input,             size_t* index_p,   exein_feature_t* features_arr);
void exein_map_file_to_features(            const struct file* input,               size_t* index_p,   exein_feature_t* features_arr);
void exein_map_kernel_cap_t_to_features(    const struct kernel_cap_struct* input,  size_t* index_p,   exein_feature_t* features_arr);
void exein_map_linux_binprm_to_features(    const struct linux_binprm* input,       size_t* index_p,   exein_feature_t* features_arr);
//void exein_map_fs_parameter_to_features(    const struct fs_parameter* input,       size_t* index_p,   exein_feature_t* features_arr);
void exein_map_path_to_features(            const struct path* input,               size_t* index_p,   exein_feature_t* features_arr);
void exein_map_qstr_to_features(            const struct qstr* input,               size_t* index_p,   exein_feature_t* features_arr);
