#ifndef _EASYBT_CONFIG_H_
#define _EASYBT_CONFIG_H_

#include "autoconfig.h"

typedef int ebt_base_t;
extern ebt_base_t ebt_hw_interrupt_disable(void);
extern void ebt_hw_interrupt_enable(ebt_base_t level);

#define __ebt_disable_isr() ebt_base_t _ebt_isr_level = ebt_hw_interrupt_disable()
#define __ebt_enable_isr() ebt_hw_interrupt_enable(_ebt_isr_level)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EASYBT_CONFIG_H_ */