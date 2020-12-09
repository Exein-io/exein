#include "exein_struct_mappings.h"
#include "exein_nn_defs_parts.h"



uint16_t task_struct_get_pid(struct task_struct *arg1){
	return arg1->pid;
}

void exein_map_string_to_features(const char * input, size_t string_length, size_t* index_p, exein_feature_t* features_arr){
    if(input == NULL){
        (*index_p)+=string_length;
        return;
    }

    #if PARSE_STRINGS > 0
        size_t i;
        for (i = 0; i < string_length; i++)
        {
            features_arr[(*index_p)++] = input[i];
        }
    #endif
}


void exein_map_cred_to_features(const struct cred* input, size_t* index_p, exein_feature_t* features_arr){
    /* Cred structure */
    if(input == NULL){
        (*index_p)+=STRUCT_CRED;
        return;
    }

    features_arr[(*index_p)++] = (exein_feature_t) (*input).uid.val;       /* real UID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).gid.val;       /* real GID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).suid.val;      /* saved UID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).sgid.val;      /* saved GID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).euid.val;      /* effective UID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).egid.val;      /* effective GID of the task */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).fsuid.val;     /* UID for VFS ops */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).fsgid.val;     /* GID for VFS ops */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).securebits;    /* SUID-less security management */
}


void exein_map_fown_struct_to_features(const struct fown_struct* input, size_t* index_p, exein_feature_t* features_arr){
    /* Fown structure */
    if(input == NULL){
        (*index_p)+=STRUCT_FOWN_STRUCT;
        return;
    }
    features_arr[(*index_p)++] = (exein_feature_t) (*input).euid.val;
}


void exein_map_iattr_to_features(const struct iattr* input, size_t* index_p, exein_feature_t* features_arr){
    /* Inode Attributes structure */
    if(input == NULL){
        (*index_p)+=STRUCT_IATTR;
        return;
    }
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ia_valid;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ia_mode;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ia_uid.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ia_gid.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ia_size;
}


void exein_map_user_namespace_to_features(const struct user_namespace* input, size_t* index_p, exein_feature_t* features_arr){
    /* User Namespace structure */
    if(input == NULL){
        (*index_p)+=STRUCT_USER_NAMESPACE;
        return;
    }

    features_arr[(*index_p)++] = (exein_feature_t) (*input).owner.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).group.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).flags;
}


void exein_map_vm_area_struct_to_features(const struct vm_area_struct * input, size_t* index_p, exein_feature_t* features_arr){
    /* VM Area structure */
    if(input == NULL){
        (*index_p)+=STRUCT_VM_AREA_STRUCT;
        return;
    }
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_start;                  /* Start address within vm_mm. */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_end;                    /* The first byte after the end address within vm_mm. */
    //features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_page_prot.pgprot;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_flags;                  /* Flags: https://elixir.bootlin.com/linux/v5.1.11/source/include/linux/mm.h#L197 */

    if(input->vm_mm == NULL){
        (*index_p)+=STRUCT_VM_AREA_STRUCT-4;
        return;
    }
    //features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->pgd->pgd;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->mm_users.counter;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->data_vm;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->exec_vm;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->stack_vm;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->def_flags;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->start_code;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->start_data;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->end_data;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->start_brk;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->brk;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->start_stack;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->arg_end;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->env_start;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->env_end;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).vm_mm->def_flags;
}

void exein_map_task_struct_to_features(const struct task_struct* input, size_t* index_p, exein_feature_t* features_arr){
    /* Task structure */

    /*
        This is one of the most complex structures
        Deeper analysis is needed
    */

    if(input == NULL){
        (*index_p)+=STRUCT_TASK_STRUCT;
        return;
    }
    features_arr[(*index_p)++] = (exein_feature_t) (*input).flags;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).ptrace;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).pdeath_signal;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).in_execve;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).pid;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).tgid;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).stack;
    //4.14.151
    features_arr[(*index_p)++] = (exein_feature_t) (*input).usage.counter;    /* indicates how many object are referencing this task */
	  features_arr[(*index_p)++] = (exein_feature_t) (*input).static_prio;           /* static_prio is the starting priority which is not affected by the scheduler dynamics */
    //features_arr[(*index_p)++] = (exein_feature_t) (*input).thread_pid->count.counter;

    // TODO: Map the whole path?
    // target->nameidata->path

    // TODO: Map the whole inode struct?
    // target->nameidata->inode

    // TODO: Map the whole cred struct?
    // input->cred->euid.val         /* effective process uid */

}


void exein_map_current_to_features(exein_feature_t* features_arr){
    /* Identify current process */
    /* Current is just an instance of strcut task_struct */
    /* How to get the process name : https://stackoverflow.com/questions/5406942/linux-get-process-name-from-pid-within-kernel */
    int index = EXEIN_HOOK_CURRENT_PROCESS_ARG1_POS;
    features_arr[index++]  = (exein_feature_t) current->pid;
    features_arr[index]  = (exein_feature_t) current->process_tag;

}


void exein_map_inode_to_features(const struct inode *input, size_t* index_p, exein_feature_t* features_arr){
    /* Inode structure */
    if(input == NULL){
        (*index_p)+=STRUCT_INODE;
        return;
    }

    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_mode;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_opflags;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_uid.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_gid.val;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_flags;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_size;        /* Filesize */
    features_arr[(*index_p)++] = (exein_feature_t) (*input).i_ino;         /* Inode number */
}


void exein_map_dentry_to_features(const struct dentry *input, size_t* index_p, exein_feature_t* features_arr){
    /* Dentry structure */
    if(input == NULL){
        (*index_p)+=STRUCT_DENTRY;
        return;
    }

    //printk(EXEIN_PRINT_LEVEL "MAP dentry to features disabled\n");

    // TODO:  Map the d_name qstr to features
    // input->d_name;  // this is a struct qstr (quickstring)
                    // it contains not only the dentry name but also the hash. Which is better in our case
    // In case we use the full name : exein_map_string_to_features(fullname, 768, index_p, features_arr);

    exein_map_inode_to_features((*input).d_inode, index_p, features_arr);
}


void exein_map_file_to_features(const struct file *input, size_t* index_p, exein_feature_t* features_arr){
    /* File structure */
    if(input == NULL){
        (*index_p)+=STRUCT_FILE;
        return;
    }

    exein_map_dentry_to_features((*input).f_path.dentry, index_p, features_arr);

    exein_map_inode_to_features((*input).f_inode, index_p, features_arr);

    exein_map_fown_struct_to_features(&(*input).f_owner, index_p, features_arr);

    u_int32_t trustworthiness = 0;

    // Check if the file has a mnt
    if (input->f_path.mnt != NULL)
    {
        // trustworthiness
        char buffer[150];
        char *path;

        //printk(EXEIN_PRINT_LEVEL "MAP dentry path is not implemented [!]\n");
        // path = dentry_path_raw(input->f_path.mnt->mnt_root, buffer, 150);
        // if (strcmp("/", path) == 0 ) trustworthiness+=10;
        // if (strcmp("squashfs",  input->f_path.mnt->mnt_sb->s_type->name) == 0 ) trustworthiness+=5;
        // if (strcmp("rootfs",    input->f_path.mnt->mnt_sb->s_type->name) == 0 ) trustworthiness+=5;
        // if (strcmp("cramfs",    input->f_path.mnt->mnt_sb->s_type->name) == 0 ) trustworthiness+=5;
    }

    features_arr[(*index_p)++] = (exein_feature_t) trustworthiness;

    // features_arr[(*index_p)++] = (exein_feature_t) djb2(input); // Simple hash of the name

    features_arr[(*index_p)++] = (exein_feature_t) (*input).f_flags;
    features_arr[(*index_p)++] = (exein_feature_t) (*input).f_mode;
}


void exein_map_kernel_cap_t_to_features(const struct kernel_cap_struct* input, size_t* index_p, exein_feature_t* features_arr){
    if(input == NULL){
        (*index_p)+=KERNEL_CAP_T;
        return;
    }

    size_t i;
    for (i = 0; i < KERNEL_CAP_T; i++)
    {
        features_arr[(*index_p)++] = (exein_feature_t) (*input).cap[i];
    }
}


void exein_map_linux_binprm_to_features(const struct linux_binprm *input, size_t* index_p, exein_feature_t* features_arr){
    //printk(EXEIN_PRINT_LEVEL "MAP linux_binprm to features not implemented\n");
}

//4.14.151
// void exein_map_fs_parameter_to_features(const struct fs_parameter *input, size_t* index_p, exein_feature_t* features_arr){
//     printk(EXEIN_PRINT_LEVEL "MAP fs_parameter to features not implemented\n");
// }


void exein_map_path_to_features(const struct path *input, size_t* index_p, exein_feature_t* features_arr){
    //printk(EXEIN_PRINT_LEVEL "MAP path to features not implemented\n");
}


void exein_map_qstr_to_features(const struct qstr *input, size_t* index_p, exein_feature_t* features_arr){
    //printk(EXEIN_PRINT_LEVEL "MAP qstr to features not implemented\n");
}

//4.14.151
//void exein_map_fs_context_to_features(const struct fs_context * input, size_t* index_p, exein_feature_t* features_arr){}
