#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#define STACK_MAX 100
#define REG_STACK 0
#define PROTECTED_STACK 1

struct reg_stack {
    unsigned long user_rsp;
    unsigned long user_rbp;
};

struct protected_stack{
	char *buf;
	unsigned long user_rsp;
	unsigned long user_rbp;
};


typedef struct reg_stack reg_stack;
typedef struct protected_stack protected_stack;

struct Stack {
    int     type; // 0 - this stack contains reg_stack, 1 - this stack contains protected_stack
    void*   data[STACK_MAX];
    int     size;
};

typedef struct Stack Stack;

void Stack_Init(Stack *S, int type);

void* Stack_Top(Stack *S);

void Stack_Push(Stack *S, void *d);

void* Stack_Pop(Stack *S);

bool Stack_Empty(Stack *S);