
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/user.h>
#include <linux/regset.h>

#include "mapper.h"
#include "parseElf.h"
#include "utils_stack.h"


Stack rstack, pstack; //stacks to check the invocation of register/unregister and encrypt/decrypt


int symbol_table_init = 0;
item_t *mapper = NULL;
char *path_to_exe = "/home/qi/stackvault-from-zehra/mini-example/a.out";

// Register the boundaries (user_rbp, user_rsp) of a stack
long jsys_register_stack(void) {
	printk(KERN_INFO "jsys_register_stack is called\n");
	reg_stack *r = NULL;
	
	register unsigned long kernel_rbp asm("rbp");
	unsigned long user_rbp = *((unsigned long*)kernel_rbp);

	const struct pt_regs *regs = task_pt_regs(current);
	unsigned long user_rsp = regs->sp + 0x10; //0x10 is a result of stackvault.c from libstackvault.a
	//unsigned long user_rsp = kernel_rbp;

	// the function name check is not necessary when register() has not parameter
	#ifdef REG_WITH_PARAMETER
	char *func_name;
	unsigned long user_ip = *((unsigned long *)kernel_rbp + 12);
	if(mapper == NULL) {
		printk(KERN_ERR "symbol table has not been not ready\n");
		jprobe_return();
		return -1;
	}

	func_name = get_func_name(mapper, user_ip);

	if(func_name == NULL) {
		printk(KERN_ERR "func_name is NULL");
		jprobe_return();
		return -1;
	}
	#endif

	
	printk(KERN_INFO "jsys_register_stack: user_rbp is %p, user_rsp is %p\n", user_rbp, user_rsp);



	r = (reg_stack *)kmalloc(sizeof(reg_stack), GFP_KERNEL);
	r->user_rsp = user_rsp;
	r->user_rbp = user_rbp;

	Stack_Push(&rstack, (void *)r);
	jprobe_return();
	return 0;
}


// Unregister the boundaries of a stack
long jsys_unregister_stack(void) {
	printk(KERN_INFO "jsys_unregister_stack is called\n");

	reg_stack *r = (reg_stack *)Stack_Pop(&rstack);
	printk(KERN_INFO "jsys_unregister_stack: user_rbp = %p, user_rsp = %p\n", r->user_rbp, r->user_rsp);
	if(r == NULL) {
		printk(KERN_ERR "jsys_unregister_stack: cannot pop from an empty stack\n");
		jprobe_return();
		return -1;
	}

	kfree(r);
	
	jprobe_return();
	return 0;
}

// Encrypt the registered stack
long jsys_encrypt_stack(void) {
	printk(KERN_INFO "jsys_encrypt_stack is called\n");

	protected_stack *p = NULL;
	unsigned long user_rbp, user_rsp;
	char *func_name;
	

	register unsigned long kernel_rbp asm("rbp");
	const struct pt_regs *regs = task_pt_regs(current);
	unsigned long user_ip = regs->ip;
	//unsigned long user_ip = *((unsigned long *)kernel_rbp + 12);

	//No stack is registered
	if (Stack_Empty(&rstack)) {
		printk(KERN_ERR "jsys_encrypt_stack: no stack has been registered\n");
		jprobe_return();
		return -1;
	}

	if(mapper == NULL) {
		printk(KERN_ERR "symbol table has not been not ready\n");
		jprobe_return();
		return -1;
	}

	func_name = get_func_name(mapper, user_ip);
	printk(KERN_INFO "jsys_encrypt_stack: func_name is %s, user_ip is %lx\n", func_name, user_ip);

	if(func_name == NULL) {
		printk(KERN_ERR "func_name is NULL\n");
		jprobe_return();
		return -1;
	}

	/*
	// Protect the stack: copy the function stack into kernel
	p = (protected_stack *)kmalloc(sizeof(protected_stack), GFP_KERNEL);
	
	p->buf = (char *)p->user_rsp;
	p->user_rsp = user_rsp;
	p->user_rbp = user_rbp;

	p->buf = (char *)kmalloc(sizeof(char)*(p->user_rbp - p->user_rsp), GFP_KERNEL);
	if(p->buf) {
		memcpy(p->buf, (char *)p->user_rsp, p->user_rbp - p->user_rsp);
		memset((char *)p->user_rsp, '0', p->user_rbp - p->user_rsp);
	}else{
		printk(KERN_ERR "jsys_encrypt_stack: kernel buffer allocation failed");
	}


	if(user_rbp < user_rsp) {
        printk(KERN_ERR "rbp should not be smaller than rsp\n");
		jprobe_return();
        return -1;
    }

	Stack_Push(&pstack, (void *)p);
	kfree(p);
	*/
	jprobe_return();
	return 0;
}

long jsys_decrypt_stack(void){
	printk(KERN_INFO "jsys_decrypt_stack is called\n");
	/*
	protected_stack *p = NULL;

	//No stack is registered
	if (Stack_Empty(&rstack)) {
		printk(KERN_ERR "jsys_encrypt_stack: no stack has been registered\n");
		jprobe_return();
		return -1;
	}

	// Unprotect the stack: restore the function stack
	p = (protected_stack *)Stack_Pop(&pstack);

	if(p == NULL) {
		printk(KERN_ERR "jsys_decrypt_stack: cannot pop from an empty stack\n");
		jprobe_return();
		return -1;
	}

	memcpy((char *)p->user_rsp, p->buf, p->user_rbp - p->user_rsp);
	kfree(p->buf);
	kfree(p);
	*/
	jprobe_return();
	return 0;
}

static struct jprobe jsys_register_stack_probe = {
	.entry			= jsys_register_stack,
	.kp = {
		.symbol_name	= "sys_register_stack",
	},
};

static struct jprobe jsys_unregister_stack_probe = {
	.entry			= jsys_unregister_stack,
	.kp = {
		.symbol_name	= "sys_unregister_stack",
	},
};

static struct jprobe jsys_encrypt_stack_probe = {
	.entry			= jsys_encrypt_stack,
	.kp = {
		.symbol_name	= "sys_encrypt_stack",
	},
};
static struct jprobe jsys_decrypt_stack_probe = {
	.entry			= jsys_decrypt_stack,
	.kp = {
		.symbol_name	= "sys_decrypt_stack",
	},
};
static int __init jprobe_init(void)
{
	int ret;
    
	ret = register_jprobe(&jsys_register_stack_probe);
	if (ret < 0) {
		printk(KERN_INFO "register_jsys_register_stack_probe failed, returned %d\n", ret);
		return -1;
	}

	ret = register_jprobe(&jsys_unregister_stack_probe);
	if (ret < 0) {
		printk(KERN_INFO "register_jsys_unregister_stack_probe failed, returned %d\n", ret);
		return -1;
	}

	ret = register_jprobe(&jsys_encrypt_stack_probe);
	if (ret < 0) {
		printk(KERN_INFO "register_jsys_encrypt_stack_probe failed, returned %d\n", ret);
		return -1;
	}

	ret = register_jprobe(&jsys_decrypt_stack_probe);
	if (ret < 0) {
		printk(KERN_INFO "register_jsys_decrypt_stack_probe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted handlers successfully\n");

	Stack_Init(&rstack, REG_STACK);
	Stack_Init(&pstack, PROTECTED_STACK);

	if (symbol_table_init == 0) {
		mapper = init_mapper(8);
		parse(path_to_exe, &mapper);
		symbol_table_init = 1;
	}

	return 0;
}

static void __exit jprobe_exit(void)
{
	unregister_jprobe(&jsys_register_stack_probe);
	unregister_jprobe(&jsys_unregister_stack_probe);
	unregister_jprobe(&jsys_encrypt_stack_probe);
	unregister_jprobe(&jsys_decrypt_stack_probe);
	printk(KERN_INFO "handlers unregistered\n");
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
