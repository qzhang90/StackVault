
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/user.h>
#include <linux/regset.h>
#include <linux/time.h>
#include <linux/jiffies.h>

#include "mapper.h"
#include "parseElf.h"
#include "utils_stack.h"


unsigned long register_time = 0;
unsigned long register_witharg_time = 0;
unsigned long encrypt_time = 0;
unsigned long encrypt_withexception_time = 0;
unsigned long decrypt_time = 0;
unsigned long unregister_time = 0;


/*
 * rstack: stack data structure to maintain the stack areas and the heap areas registered by jsys_register_stack()
 * pstack: stack data structure to maintain the stack areas and the heap areas protected by jsys_encrypt_stack()
 * pestack: stack data structure to maintain the stack exception areas registered by jsys_encrypt_stack_exception()
 */
Stack rstack, pstack, pestack; 


int symbol_table_init = 0;
item_t *mapper = NULL;

//char *path_to_exe = "/home/qi/stackvault-from-zehra/examples/minizip-example/minizip";
char *path_to_exe = "/home/qi/stackvault-from-zehra/examples/libcurl-example-xmlstream/a.out";

int protect_exception_flag = 0;

/* 
 * Register the stack of a sensitive function and push the (rsp, rbp) pair into rstack.
 * This needs to be done when a sensitive function starts.
 * The registered stack will be protected if an untrusted function is called by the sensitive function.
 */
long jsys_register_stack(void) {
	//printk(KERN_INFO "jsys_register_stack\n");
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);
	
	reg_stack *r = NULL;
	
	register unsigned long kernel_rbp asm("rbp");
	unsigned long user_rbp = *((unsigned long*)kernel_rbp);

	const struct pt_regs *regs = task_pt_regs(current);
	unsigned long user_rsp = regs->sp;

	/*
	#ifdef REG_WITH_PARAMETER
		char *func_name;
		unsigned long user_ip = regs->ip;
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
	*/

	r = (reg_stack *)kmalloc(sizeof(reg_stack), GFP_KERNEL);
	r->data1.user_rsp = user_rsp;
	r->data2.user_rbp = user_rbp;
	r->is_arg = 0;

	//printk(KERN_INFO "registered stack size is %ld\n", r->data2.user_rbp - r->data1.user_rsp);
	Stack_Push(&rstack, (void *)r);
	
	getnstimeofday(&end_time);
	register_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;

	jprobe_return();
	return 0;
}

/*
 * Register the heap area pointed by a pointer on the stack of a sensitive function.
 * The registered heap area will be protected when an untrusted function is called by the sensitive function.
 */
long jsys_register_stack_withargs(unsigned long base, unsigned long len) {
	//printk(KERN_INFO "jsys_register_stack_withargs: base = %p, len = %ld\n", base, len);
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);
	
	reg_stack *r = NULL;

	r = (reg_stack *)kmalloc(sizeof(reg_stack), GFP_KERNEL);
	r->data1.base = base;
	r->data2.len = len;
	r->is_arg = 1;

	Stack_Push(&rstack, (void *)r);

	getnstimeofday(&end_time);
	register_witharg_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;
	
	jprobe_return();
	return 0;
}


/*
 * From rstack, pop out the most recently registered stack areas as well as its associated heap areas.
 * This needs to be done when a sensitive function finishes.
 */
long jsys_unregister_stack(void) {
	//printk(KERN_INFO "jsys_unregister_stack\n");
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);

	reg_stack *r;
	

	/*
	 * Pop out the most recently registered area.
	 * This area could be either a stack area(r->is_arg == 0) or a heap area(r->is_arg == 1).
	 */
	r = (reg_stack *)Stack_Pop(&rstack);
	if(r == NULL) {
		printk(KERN_ERR "jsys_unregister_stack: cannot pop from an empty stack\n");
		jprobe_return();
		return -1;
	}

	/*
	 * If the above area is a heap area, keeping popping out from rstack, until reaching a stack area.
	 * This stack area is associate with all the heap areas poped out previously.
	 * When this while loop exists, r points to the most recent registered stack area.
	 */
	while (r->is_arg){
		if(r == NULL) {
			printk(KERN_ERR "jsys_unregister_stack: cannot pop from an empty stack\n");
			jprobe_return();
			return -1;
		}
		
		r = (reg_stack *)Stack_Pop(&rstack);

	}

	/* 
	 * Clear the stack before the sensitive function returns.
	 * Do not clear the registered heap, since it may be needed by other processes.
	 */
	clear_user(r->data1.user_rsp, r->data2.user_rbp - r->data1.user_rsp);

	if(r == NULL) {
		printk(KERN_ERR "jsys_unregister_stack: cannot pop from an empty stack\n");
		jprobe_return();
		return -1;
	}

	kfree(r);

	getnstimeofday(&end_time);
	unregister_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;
	
	jprobe_return();
	return 0;
}


/*
 * Protect the registered stack and heap areas by copying them into the kernel, and then clearing the user space area.
 */ 
long jsys_encrypt_stack(void) {
	//printk(KERN_INFO "+++++jsys_encrypt_stack\n");
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);
	
	protected_stack *p = NULL;
	reg_stack *q = NULL;
	char *func_name;
	int bytes = 0;
	int reg_stack_idx = 0;
	

	register unsigned long kernel_rbp asm("rbp");
	const struct pt_regs *regs = task_pt_regs(current);
	unsigned long user_ip = regs->ip;

	if(mapper == NULL) {
		printk(KERN_ERR "symbol table has not been not ready\n");
		jprobe_return();
		return -1;
	}

	func_name = get_func_name(mapper, user_ip);
	

	if(func_name == NULL) {
		printk(KERN_ERR "func_name is NULL\n");
		jprobe_return();
		return -1;
	}
	//TODO: check whether func_name is in white list

	reg_stack_idx = rstack.size;
	
	if(reg_stack_idx == 0) {
		printk(KERN_ERR "jsys_encrypt_stack: no stack has been registered\n");
		jprobe_return();
		return -1;
	}

	// encrypt all the registered stacks
	while(reg_stack_idx > 0) {
		q = (reg_stack *)(rstack.data[reg_stack_idx - 1]);

		/*
		 * Hit a boundary on rstack, stop encryption.
		 */
		if(q->data1.user_rsp == 0){
			break;
		}

		p = (protected_stack *)kmalloc(sizeof(protected_stack), GFP_KERNEL);
		if(!p){
			printk(KERN_ERR "encrypt stack: kernel allocation failed\n");
			jprobe_return();
			return -1;
		}

		// The registered stack could be either a stack area(q->is_arg == 0) or a heap area(q->is_arg == 1)
		if (q->is_arg) {
			p->data1.base = q->data1.base;
			p->data2.len = q->data2.len;
			
			p->buf = (char *)kmalloc(sizeof(char)*p->data2.len, GFP_KERNEL);
			if(p->buf){
				bytes = copy_from_user(p->buf, (char *)p->data1.base, p->data2.len);
				if(bytes){
					printk(KERN_ERR "encrypt_stack: failed to copy user stack data to the kernel\n");
				}
			}else{
				printk(KERN_ERR "jsys_encrypt_stack: kernel buffer allocation failed");
			}

			p->is_arg = 1;
		}else{
			p->data1.user_rsp = q->data1.user_rsp;
			p->data2.user_rbp = q->data2.user_rbp;

			if(p->data2.user_rbp < p->data1.user_rsp) {
				printk(KERN_ERR "rbp should not be smaller than rsp\n");
				jprobe_return();
				return -1;
			}

			p->buf = (char *)kmalloc(sizeof(char)*(p->data2.user_rbp - p->data1.user_rsp), GFP_KERNEL);
			
			if(p->buf) {
				bytes = copy_from_user(p->buf, (char *)p->data1.user_rsp, p->data2.user_rbp - p->data1.user_rsp);
				if(bytes){
					printk(KERN_ERR "encrypt_stack: failed to copy user stack data to the kernel\n");
				}
				
				bytes = clear_user((char *)p->data1.user_rsp, p->data2.user_rbp - p->data1.user_rsp);
				if(bytes){
					printk(KERN_ERR "encrypt_stack: failed to clear the user stack, size = %ld, bytes = %ld\n", p->data2.user_rbp - p->data1.user_rsp, bytes);
				}
				
			}else{
				printk(KERN_ERR "jsys_encrypt_stack: kernel buffer allocation failed");
			}

			p->is_arg = 0;
		}
		
		Stack_Push(&pstack, (void *)p);
		reg_stack_idx--;
	}

	/*
	 * Add a boundary to the top of rstack, so that the encrypt_stack() knows where to stop.
	 */
	q = (reg_stack *)kmalloc(sizeof(reg_stack), GFP_KERNEL);
	q->data1.user_rsp = 0;
	Stack_Push(&rstack, (void *)q);
	
	/*
	 * Add a boundary to the top of pstack, so that the decrypt_stack() knows where to stop.
	 */
	p = (protected_stack *)kmalloc(sizeof(protected_stack), GFP_KERNEL);
	p->data1.user_rsp = 0;
	p->func_name = func_name;
	Stack_Push(&pstack, (void *)p);
	
	/*
	 * Add a boundary in the pestack, so that the decrypt_stack() knows where to stop
	 */
	p = (protected_stack *)kmalloc(sizeof(protected_stack), GFP_KERNEL);
	p->data1.base = 0;
	Stack_Push(&pestack, (void *)p);

	// Restore the exception areas so that the untrusted function can read
	if(protect_exception_flag == 1){
		int pe_stack_idx = pestack.size - 1; // The top entry will be a boundary
		while(pe_stack_idx > 0) {
			p = (protected_stack *)(pestack.data[pe_stack_idx - 1]); 
			if(p->data1.base == 0)
				break;
			
			copy_to_user((char *)p->data1.base, p->buf, p->data2.len);
			pe_stack_idx--;
		}
	}
	protect_exception_flag = 0;

	getnstimeofday(&end_time);
	encrypt_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;

	jprobe_return();
	return 0;
}

/*
 * Some of the variables on the stack of a sensitive function will be modified by the untrusted function. 
 * Usually, the address of such variables are passed to the untrusted functions as paramenters.
 * These variables will be exceptions, which should not be protected.
 * Allocate temporary buffers to store the values of the exception variables produced by the untrusted funcions.
 */ 
long jsys_encrypt_stack_exception(unsigned long base, unsigned long len) {
	//printk(KERN_INFO "jsys_encrypt_stack_exception, base = %p, len =%ld\n", base, len);
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);

	protect_exception_flag = 1;

	protected_stack *p = NULL;

	p = (protected_stack *)kmalloc(sizeof(protected_stack), GFP_KERNEL);
	if(p == NULL) {
		printk(KERN_ERR "jsys_encrypt_stack_exception: protected_stack allocation failed\n");
		jprobe_return();
		return 0;
	}

	p->data1.base = base;
	p->data2.len = len;

	p->buf = kmalloc(len, GFP_KERNEL);
	if(p->buf == NULL){
		printk(KERN_ERR "jsys_encrypt_stack_exception: buffer allocation failed\n");
		jprobe_return();
		return 0;
	}

	copy_from_user(p->buf, p->data1.base, p->data2.len);

	Stack_Push(&pestack, (void *)p);

	getnstimeofday(&end_time);
	encrypt_withexception_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;

	jprobe_return();
	return 0;
}

/*
 * Temporarily save current value of the protect exceptions. These values were produced by the untrusted functions.
 */
bool save_exceptions(void){
	//printk(KERN_INFO "save_exceptions\n");
	protected_stack *p = NULL;
	int bytes = 0;
	int pestack_idx;

	if(pestack.size > 1)
	{
		pestack_idx = pestack.size - 1; // The top entry will be a boundary
		while(pestack_idx > 0) {
			p = (protected_stack *)(pestack.data[pestack_idx - 1]); 
			if(p->data1.base == 0)
				break;
			//printk("save exceptions: base = %p, len = %ld\n", (char *)p->data1.base, p->data2.len);
			bytes = copy_from_user(p->buf, (char *)p->data1.base, p->data2.len);
			if(bytes){
				printk(KERN_ERR "save_exceptions: data copy failed\n");
				return false;
			}

			pestack_idx--;
		}
	}
	return true;
}

/*
 * Overwrite the protect exceptions on the stack with the values saved by 'save_exceptions()'
 */
bool restore_exceptions(void){
	//printk(KERN_INFO "restore_exceptions\n");
	protected_stack *p = NULL;
	int bytes = 0;

	Stack_Pop(&pestack); // Pop out the top entry, which is a boundary

	while(true){
		p = (protected_stack *)Stack_Pop(&pestack);
		if(p == NULL || p->data1.base == 0){
			break;
		}

		//printk("restore exceptions: base = %p, len = %ld\n", (char *)p->data1.base, p->data2.len);
		bytes = copy_to_user((char *)p->data1.base, p->buf, p->data2.len);
		if(bytes){
			printk(KERN_ERR "restore_exceptions: data copy failed\n");
			return false;
		}
	}

	return true;
}

/*
 * Restore the stack of the sensitive function.
 * Save the values of the exception variables produced by the untrusted functions.
 * Copy the whole stack of the sensitive function from the protected kernel buffer to the user space.
 * Overwrite the exceptoin variables using the previously saved values.
 */ 
long jsys_decrypt_stack(void){
	//printk(KERN_INFO "-----jsys_decrypt_stack\n");
	struct timespec start_time, end_time;
	getnstimeofday(&start_time);
	
	protected_stack *p = NULL;
	int bytes = 0;

	char *func_name = NULL;
	register unsigned long kernel_rbp asm("rbp");
	const struct pt_regs *regs = task_pt_regs(current);
	unsigned long user_ip = regs->ip;

	if(mapper == NULL) {
		printk(KERN_ERR "symbol table has not been not ready\n");
		jprobe_return();
		return -1;
	}
	
	func_name = get_func_name(mapper, user_ip);

	if(func_name == NULL) {
		printk(KERN_ERR "func_name is NULL\n");
		jprobe_return();
		return -1;
	}

	if (Stack_Empty(&rstack)) {
		printk(KERN_ERR "jsys_encrypt_stack: no stack has been registered\n");
		jprobe_return();
		return -1;
	}
	
	if (false == save_exceptions()) {
		printk(KERN_ERR "save_exceptions() failed\n");
		jprobe_return();
		return 0;
	}
	
	// The top entry should be a boundary, thus remove it.
	p = (protected_stack *)Stack_Pop(&pstack);
	if(p == NULL || p->data1.user_rsp){
		printk(KERN_ERR "The top entry of the pstack should be a boundary\n");
		jprobe_return();
		return 0;
	}else{
		if(strcmp(p->func_name, func_name)) {
			printk(KERN_ERR "Illegal invocation of stop_protect(): it is not invoked by the same function that issues start_protect()\n");
			jprobe_return();
			return 0;
		}
	}
	
	
	while(true){
		// Continue poping from the pstack until reaching the next boundary
		p = (protected_stack *)Stack_Pop(&pstack);

		if(p == NULL) {
			break;
		}

		// Put the p back if it is a boundary on pstack, this boundary will be popped out by the next invocation of jsys_decrypt_stack()
		if (p->data1.user_rsp == 0){
			Stack_Push(&pstack, (void *)p);
			break;
		}

		if (p->is_arg){
			//printk(KERN_INFO "jsys_decrypt_stack arg: base = %p, len = %p, p->buf = %p\n", p->data1.base, p->data2.len, p->buf);
			bytes = copy_to_user((char *)p->data1.base, p->buf, p->data2.len);
			if(bytes){
				printk(KERN_ERR "decrypt stack: failed to restore the user stack\n");
			}
		}else{
			//printk(KERN_INFO "jsys_decrypt_stack stack: rsp = %p, rbp = %p, p->buf = %p\n", p->data1.user_rsp, p->data2.user_rbp, p->buf);
			bytes = copy_to_user((char *)p->data1.user_rsp, p->buf, p->data2.user_rbp - p->data1.user_rsp);
			if(bytes){
				printk(KERN_ERR "decrypt stack: failed to restore the user stack\n");
			}
		}
		kfree(p->buf);
		kfree(p);
	}
	
	if(false == restore_exceptions()) {
		printk(KERN_ERR "restore_exceptions() failed\n");
	}
	
	getnstimeofday(&end_time);
	decrypt_time += (end_time.tv_sec - start_time.tv_sec)*1000000000 + end_time.tv_nsec - start_time.tv_nsec;

	jprobe_return();
	return 0;
}

static struct jprobe jsys_register_stack_probe = {
	.entry			= jsys_register_stack,
	.kp = {
		.symbol_name	= "sys_register_stack",
	},
};

static struct jprobe jsys_register_stack_withargs_probe = {
	.entry			= jsys_register_stack_withargs,
	.kp = {
		.symbol_name	= "sys_register_stack_withargs",
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

static struct jprobe jsys_encrypt_stack_exception_probe = {
	.entry			= jsys_encrypt_stack_exception,
	.kp = {
		.symbol_name	= "sys_encrypt_stack_exception",
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

	ret = register_jprobe(&jsys_register_stack_withargs_probe);
	if (ret < 0) {
		printk(KERN_INFO "register_jsys_register_stack_withargs_probe failed, returned %d\n", ret);
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

	ret = register_jprobe(&jsys_encrypt_stack_exception_probe);
	if (ret < 0) {
		printk(KERN_INFO "register jsys_encrypt_stack_exception_probe failed, returned %d\n", ret);
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
	Stack_Init(&pestack, PROTECTED_EXCEPTION_STACK);

	if (symbol_table_init == 0) {
		mapper = init_mapper(16);
		if(parse(path_to_exe, &mapper) == 0){
			symbol_table_init = 1;
		}else{
			printk(KERN_ERR "parse the ELF failed, please try again\n");
		}
		
	}

	return 0;
}

static void __exit jprobe_exit(void)
{
	printk(KERN_INFO "=========== Elapsed time  ============\n");
	printk(KERN_INFO "Stackvault_register: %ld\t", register_time);
	printk(KERN_INFO "Stackvault_register_withargs: %ld\t", register_witharg_time);
	printk(KERN_INFO "Stackvault_encrypt: %ld\t", encrypt_time);
	printk(KERN_INFO "Stackvault_encrypt_withexception: %ld\t", encrypt_withexception_time);
	printk(KERN_INFO "Stackvault_decrypt: %ld\t", decrypt_time);
	printk(KERN_INFO "Stackvault_unregister: %ld\t", unregister_time);
	printk(KERN_INFO "=======================================\n");

	unregister_jprobe(&jsys_register_stack_probe);
	unregister_jprobe(&jsys_register_stack_withargs_probe);
	unregister_jprobe(&jsys_unregister_stack_probe);
	unregister_jprobe(&jsys_encrypt_stack_probe);
	unregister_jprobe(&jsys_encrypt_stack_exception_probe);
	unregister_jprobe(&jsys_decrypt_stack_probe);
	printk(KERN_INFO "handlers unregistered\n");
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
