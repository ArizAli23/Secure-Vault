
#ifndef VAULT_H
#define VAULT_H

#include <linux/ioctl.h>   

#define VAULT_BUF_SIZE   4096       
#define DEFAULT_XOR_KEY  0xAB       

#define VAULT_IOC_MAGIC  'V'

#define VAULT_SET_KEY    _IOW(VAULT_IOC_MAGIC, 1, unsigned char)
#define VAULT_GET_KEY    _IOR(VAULT_IOC_MAGIC, 2, unsigned char)
#define VAULT_CLEAR      _IO (VAULT_IOC_MAGIC, 3)
#define VAULT_GET_SIZE   _IOR(VAULT_IOC_MAGIC, 4, size_t)

#endif 
