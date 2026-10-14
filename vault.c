
#include <linux/module.h>       /* MODULE_* macros, module_init/exit         */
#include <linux/kernel.h>       /* printk, KERN_* log levels                 */
#include <linux/fs.h>           /* file_operations, register_chrdev_region   */
#include <linux/cdev.h>         /* cdev_init, cdev_add, cdev_del             */
#include <linux/device.h>       /* class_create, device_create               */
#include <linux/uaccess.h>      /* copy_to_user, copy_from_user copying the data             */
#include <linux/slab.h>         /* kmalloc, kfree                            */
#include <linux/string.h>       /* memset, memcpy                            */
#include <linux/mutex.h>        /* mutex_lock, mutex_unlock also lock_interruptible                  */
#include <linux/ioctl.h>        /* _IOW, _IOR commands*/


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rehan Siddiqui, Abdullah Razzaq, Ariz Ali");
MODULE_DESCRIPTION("Secure Vault: Virtual Encrypted Character Device Driver");
MODULE_VERSION("1.0");


#define DEVICE_NAME     "vault"         
#define CLASS_NAME      "vault_class"   
#define VAULT_BUF_SIZE  4096            
#define DEFAULT_XOR_KEY 0xAB
#define VAULT_IOC_MAGIC  'V'
#define VAULT_SET_KEY    _IOW(VAULT_IOC_MAGIC, 1, unsigned char)
#define VAULT_GET_KEY    _IOR(VAULT_IOC_MAGIC, 2, unsigned char)
#define VAULT_CLEAR      _IO (VAULT_IOC_MAGIC, 3)
#define VAULT_GET_SIZE   _IOR(VAULT_IOC_MAGIC, 4, size_t)


static int            vault_major;          
static struct class  *vault_class  = NULL;  
static struct device *vault_device = NULL;  
static struct cdev    vault_cdev;           
static dev_t          vault_devno;          

static unsigned char *vault_buffer = NULL;  
static size_t         vault_data_len = 0;   
static unsigned char  xor_key = DEFAULT_XOR_KEY; 
static DEFINE_MUTEX(vault_mutex);


static void vault_xor_transform(unsigned char *buf, size_t len, unsigned char key)
{
    size_t i;
    for (i = 0; i < len; i++)
        buf[i] ^= key;
}

static inline void vault_encrypt(unsigned char *buf, size_t len)
{
    vault_xor_transform(buf, len, xor_key);
}

static inline void vault_decrypt(unsigned char *buf, size_t len)
{
    vault_xor_transform(buf, len, xor_key);
}

static int vault_open(struct inode *inode, struct file *filp)
{
    pr_info("vault: device opened by PID %d\n", current->pid);
    return 0;   /* success */
}
static int vault_release(struct inode *inode, struct file *filp)
{
    pr_info("vault: device closed by PID %d\n", current->pid);
    return 0;
}
static ssize_t vault_write(struct file *filp, const char __user *user_buf,
                           size_t count, loff_t *offset)
{
    unsigned char *tmp;
    ssize_t ret;

    if (count == 0)
        return 0;

    if (count > VAULT_BUF_SIZE) {
        pr_warn("vault: write rejected — data too large (%zu > %d)\n",
                count, VAULT_BUF_SIZE);
        return -EINVAL;
    }

    tmp = kmalloc(count, GFP_KERNEL);
    if (!tmp) {
        pr_err("vault: kmalloc failed for write buffer\n");
        return -ENOMEM;
    }

    if (copy_from_user(tmp, user_buf, count)) {
        pr_err("vault: copy_from_user failed\n");
        kfree(tmp);
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&vault_mutex)) {
        kfree(tmp);
        return -ERESTARTSYS;
    }

    vault_encrypt(tmp, count);

    memcpy(vault_buffer, tmp, count);
    vault_data_len = count;

    mutex_unlock(&vault_mutex);
    kfree(tmp);

    ret = (ssize_t)count;
    pr_info("vault: encrypted and stored %zu byte(s) from PID %d\n",
            count, current->pid);
    return ret;
}

static ssize_t vault_read(struct file *filp, char __user *user_buf,
                          size_t count, loff_t *offset)
{
    unsigned char *tmp;
    ssize_t ret;
    size_t to_read;

    if (mutex_lock_interruptible(&vault_mutex))
        return -ERESTARTSYS;

    if (vault_data_len == 0) {
        mutex_unlock(&vault_mutex);
        pr_info("vault: read called but vault is empty\n");
        return 0;   
    }

    to_read = min(count, vault_data_len);

    tmp = kmalloc(to_read, GFP_KERNEL);
    if (!tmp) {
        mutex_unlock(&vault_mutex);
        pr_err("vault: kmalloc failed for read buffer\n");
        return -ENOMEM;
    }

    memcpy(tmp, vault_buffer, to_read);
    vault_decrypt(tmp, to_read);

    mutex_unlock(&vault_mutex);

    if (copy_to_user(user_buf, tmp, to_read)) {
        kfree(tmp);
        pr_err("vault: copy_to_user failed\n");
        return -EFAULT;
    }

    kfree(tmp);
    ret = (ssize_t)to_read;
    pr_info("vault: decrypted and sent %zu byte(s) to PID %d\n",
            to_read, current->pid);
    return ret;
}

static long vault_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    unsigned char key;
    size_t size;

    switch (cmd) {

    case VAULT_SET_KEY:
        if (copy_from_user(&key, (unsigned char __user *)arg, sizeof(key)))
            return -EFAULT;
        if (mutex_lock_interruptible(&vault_mutex))
            return -ERESTARTSYS;
        if (vault_data_len > 0) {
            vault_decrypt(vault_buffer, vault_data_len);
            xor_key = key;
            vault_encrypt(vault_buffer, vault_data_len);
        } else {
            xor_key = key;
        }
        mutex_unlock(&vault_mutex);
        pr_info("vault: XOR key updated to 0x%02X\n", key);
        return 0;

    case VAULT_GET_KEY:
        if (mutex_lock_interruptible(&vault_mutex))
            return -ERESTARTSYS;
        key = xor_key;
        mutex_unlock(&vault_mutex);
        if (copy_to_user((unsigned char __user *)arg, &key, sizeof(key)))
            return -EFAULT;
        return 0;

    case VAULT_CLEAR:
        if (mutex_lock_interruptible(&vault_mutex))
            return -ERESTARTSYS;
        memset(vault_buffer, 0, VAULT_BUF_SIZE);
        vault_data_len = 0;
        mutex_unlock(&vault_mutex);
        pr_info("vault: buffer cleared by PID %d\n", current->pid);
        return 0;

    case VAULT_GET_SIZE:
        if (mutex_lock_interruptible(&vault_mutex))
            return -ERESTARTSYS;
        size = vault_data_len;
        mutex_unlock(&vault_mutex);
        if (copy_to_user((size_t __user *)arg, &size, sizeof(size)))
            return -EFAULT;
        return 0;

    default:
        pr_warn("vault: unknown ioctl command 0x%08X\n", cmd);
        return -ENOTTY;
    }
}


static const struct file_operations vault_fops = {
    .owner          = THIS_MODULE,
    .open           = vault_open,
    .release        = vault_release,
    .read           = vault_read,
    .write          = vault_write,
    .unlocked_ioctl = vault_ioctl,
};

static int __init vault_init(void)
{
    int ret;

    pr_info("vault: loading Secure Vault kernel module...\n");

    ret = alloc_chrdev_region(&vault_devno, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("vault: alloc_chrdev_region failed (%d)\n", ret);
        return ret;
    }
    vault_major = MAJOR(vault_devno);
    pr_info("vault: registered with major number %d\n", vault_major);

    cdev_init(&vault_cdev, &vault_fops);
    vault_cdev.owner = THIS_MODULE;
    ret = cdev_add(&vault_cdev, vault_devno, 1);
    if (ret < 0) {
        pr_err("vault: cdev_add failed (%d)\n", ret);
        unregister_chrdev_region(vault_devno, 1);
        return ret;
    }

    vault_class = class_create(CLASS_NAME);
    if (IS_ERR(vault_class)) {
        pr_err("vault: class_create failed\n");
        cdev_del(&vault_cdev);
        unregister_chrdev_region(vault_devno, 1);
        return PTR_ERR(vault_class);
    }

    vault_device = device_create(vault_class, NULL, vault_devno, NULL, DEVICE_NAME);
    if (IS_ERR(vault_device)) {
        pr_err("vault: device_create failed\n");
        class_destroy(vault_class);
        cdev_del(&vault_cdev);
        unregister_chrdev_region(vault_devno, 1);
        return PTR_ERR(vault_device);
    }

    vault_buffer = kmalloc(VAULT_BUF_SIZE, GFP_KERNEL);
    if (!vault_buffer) {
        pr_err("vault: kmalloc for vault_buffer failed\n");
        device_destroy(vault_class, vault_devno);
        class_destroy(vault_class);
        cdev_del(&vault_cdev);
        unregister_chrdev_region(vault_devno, 1);
        return -ENOMEM;
    }
    memset(vault_buffer, 0, VAULT_BUF_SIZE);

    pr_info("vault: /dev/%s created successfully (major=%d, key=0x%02X, buf=%d bytes)\n",
            DEVICE_NAME, vault_major, xor_key, VAULT_BUF_SIZE);
    return 0;
}

static void __exit vault_exit(void)
{
    pr_info("vault: unloading Secure Vault kernel module...\n");

    if (vault_buffer) {
        memset(vault_buffer, 0, VAULT_BUF_SIZE);
        kfree(vault_buffer);
        vault_buffer = NULL;
    }

    device_destroy(vault_class, vault_devno);
    class_destroy(vault_class);
    cdev_del(&vault_cdev);
    unregister_chrdev_region(vault_devno, 1);

    pr_info("vault: module unloaded cleanly\n");
}

module_init(vault_init);
module_exit(vault_exit);
