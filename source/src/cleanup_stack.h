#ifndef __HAVE_CLEANUP_STACK_H__
#define __HAVE_CLEANUP_STACK_H__

struct __cleanup_stack_entry {
        void (*f)(void *);
        void *a;
};

#define __MAX_CLEANUP_STACK_SIZE 64
#define cleanup_stack_init struct __cleanup_stack_entry __CLEANUP_STACK[__MAX_CLEANUP_STACK_SIZE]; \
                           int __CLEANUP_STACK_COUNTER = -1;

#define cleanup_stack_push(func, arg) { \
        __CLEANUP_STACK_COUNTER++; \
        assert(__CLEANUP_STACK_COUNTER < __MAX_CLEANUP_STACK_SIZE); \
        __CLEANUP_STACK[__CLEANUP_STACK_COUNTER].f = (void(*)(void *)) func; \
        __CLEANUP_STACK[__CLEANUP_STACK_COUNTER].a = arg;\
        }

#define cleanup_stack_pop() { \
        __CLEANUP_STACK[__CLEANUP_STACK_COUNTER].f(__CLEANUP_STACK[__CLEANUP_STACK_COUNTER].a); \
        __CLEANUP_STACK_COUNTER--; \
        }

#define cleanup_stack_free_all() { \
        while (__CLEANUP_STACK_COUNTER >= 0) { \
                cleanup_stack_pop() \
        } \
        }

#define cleanup_stack_save_bottom(save) { \
        while (__CLEANUP_STACK_COUNTER >= save) { \
                cleanup_stack_pop() \
        } \
        }

#endif
