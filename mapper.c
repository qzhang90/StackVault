#include <linux/slab.h>
#include "mapper.h"

//unsigned long cur = 0;
//unsigned long cap = 0;

item_t *init_mapper(size_t size){

	item_t *mapper = kmalloc(size*sizeof(item_t), GFP_KERNEL);
	
	if(mapper == NULL){
		printk(KERN_ERR "mapper initialization fails\n");
	}else{
		mapper->cur = 0;
		mapper->cap = size;
	}
	return mapper;
}

int insert_mapper(item_t **mapper, char *func_name, unsigned long ip, unsigned long size){
	unsigned long tmp_cap;
	item_t *tmp_mapper, *t1, *t2;
	int i, len;

	unsigned long cur = (*mapper)->cur;
	unsigned long cap = (*mapper)->cap;
	if(cur == cap){
		/*mapper is full, realloc before insert*/
		tmp_cap = 2*cap;
		tmp_mapper = kmalloc(tmp_cap*sizeof(item_t), GFP_KERNEL);
	
		if(tmp_mapper == NULL){
			printk(KERN_ERR "mapper realloc fails\n");
			return -1;
		}	

		tmp_mapper->cap = tmp_cap;
		tmp_mapper->cur = cur;

		for(i = 0; i < cur; i++){
			t1 = *mapper + i;
			t2 = tmp_mapper + i;
			
			len = strlen(t1->func_name);
			t2->func_name = kmalloc(len+ 1, GFP_KERNEL);
			strncpy(t2->func_name, t1->func_name, len);
			*(t2->func_name + len) = '\0';

			kfree(t1->func_name);
			t2->ip = t1->ip;
			t2->size = t1->size;
		}

		kfree(*mapper);
		*mapper = tmp_mapper;
	}

	//Insert the new item
	tmp_mapper = *mapper + cur;

	len = strlen(func_name);
	tmp_mapper->func_name = kmalloc(len + 1, GFP_KERNEL);
	strncpy(tmp_mapper->func_name, func_name, len);
	*(tmp_mapper->func_name + len) = '\0';

	tmp_mapper->ip = ip;
	tmp_mapper->size = size;

	(*mapper)->cur++;

	//printk("insert cur = %ld\n", (*mapper)->cur);
	return 0;
}

int destroy_mapper(item_t *mapper){
	int i;
	item_t *tmp;

	for(i = 0; i < mapper->cap; i++){
		tmp = mapper + i;
		kfree(tmp->func_name);
	}

	kfree(mapper);
	return 0;
}

char *get_func_name(item_t *mapper, unsigned long ip){
	int i;
	item_t *tmp;

	for(i = 0; i < mapper->cur; i++){
		tmp = mapper + i;
		
		//printk("get_func_name: %-30s, %-30ld, %-30ld\n", tmp->func_name, tmp->ip, tmp->size);
		if((ip >= tmp->ip) && (ip < (tmp->ip + tmp->size))){
			return tmp->func_name;
		}
	}

	return NULL;
	
}