#ifndef _QOS_H
#define _QOS_H

#include <stdint.h>

int qos_start(uint8_t dscp);
void qos_stop(void);

#endif
