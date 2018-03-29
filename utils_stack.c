#include "utils_stack.h"

void Stack_Init(Stack *S, int type)
{
    S->size = 0;
    S->type = type;
}

void* Stack_Top(Stack *S)
{
    if (S->size == 0) {
        printk(KERN_WARNING, "Error: stack empty\n");
        return NULL;
    } 

    return S->data[S->size - 1];
}

void Stack_Push(Stack *S, void *d)
{
    if (S->size < STACK_MAX){
        S->data[S->size++] = d;   
    }else{
        printk(KERN_WARNING, "Error: stack full\n");
    }
}

void* Stack_Pop(Stack *S)
{
    if (S->size == 0){
        printk(KERN_WARNING, "Stack empty when trying to pop\n");
        return NULL;
    }else{
        void *p = Stack_Top(S);
        S->size--;
        return p;
    }
}

bool Stack_Empty(Stack *S) {
    if(S->size == 0)
        return true;
    else
        return false;
}