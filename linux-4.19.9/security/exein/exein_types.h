#include <linux/types.h>
#include <linux/list.h>

#ifndef EXEIN_TYPES_INCLUDED
#define EXEIN_TYPES_INCLUDED

#define NNINPUT_SIZE 2
typedef u16 exein_feature_t;


// define struct
typedef struct {
    uint16_t tag;
    pid_t pid;
    int val;
    struct list_head list;
} exein_trust_t;

#endif
