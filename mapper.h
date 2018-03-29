#ifndef __MAPPER_H__
#define __MAPPER_H__

typedef struct item{
    char *func_name;
	unsigned long ip;
    unsigned long size;

	unsigned long cur;
	unsigned long cap;
}item_t;

item_t *init_mapper(size_t size);
int insert_mapper(item_t **mapper, char *func_name, unsigned long ip, unsigned long size);
char *get_func_name(item_t *mapper, unsigned long ip);

#endif