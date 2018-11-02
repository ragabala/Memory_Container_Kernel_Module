//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/list.h>


struct Memory_list
 {
    __u64 oid;
    __u64 size;
    __u64 pfn; 
    struct list_head list;
 };

struct Task_list
{
    struct task_struct *data;
    struct list_head list;
};

struct Container_list
{
    __u64 cid;
    struct Memory_list memory_head;
    struct Task_list task_head;
    struct list_head list;
    struct mutex lock;
};

extern struct Container_list container_head;
extern struct mutex list_lock;

// get_container: return the container with the given _cid
// This iterates through the container list and returns the
// container matching the given cid
struct Container_list *get_container(__u64 cid){
    struct Container_list *temp;
    struct list_head *pos, *q;
    list_for_each_safe(pos, q, &container_head.list) {
        temp = list_entry(pos, struct Container_list, list);
        if( cid == temp->cid) {
            return temp;
        }
    }
    return NULL;
}

//create_container: Return a container with the given cid
// if the cid exists already return the same container
// if its a new cid, create a container, set the container
// with cid and initialize the task list and returh self.
struct Container_list *create_container(__u64 cid){
    struct Container_list *temp = get_container(cid);
    if(temp == NULL )
    {
        printk("Creating a new container with Cid: %llu\n", cid);
        temp = (struct Container_list*)kmalloc(sizeof(struct Container_list),GFP_KERNEL);
        memset(temp, 0, sizeof(struct Container_list));
        temp->cid = cid;
        INIT_LIST_HEAD(&temp->task_head.list);
        INIT_LIST_HEAD(&temp->memory_head.list);
        mutex_init(&temp->lock);
        mutex_lock(&list_lock);
        list_add(&(temp->list), &(container_head.list));
        mutex_unlock(&list_lock);
    }
    return temp;
}


// This iterates through the container list and returns the
// task matching the given tid.
struct Task_list *get_task(struct Container_list* container, pid_t tid){
    struct Task_list *temp;
    struct list_head *pos, *q;
    list_for_each_safe(pos, q, &((container->task_head).list)) {
        temp = list_entry(pos, struct Task_list, list);
        if( tid == temp->data->pid) {
            return temp;
        }
    }
    return NULL;
}

// task: Return the current task in the given container.
// if the current task exists already return the task
// if its a new task, put it in the container and returh self.
struct Task_list *create_task(struct Container_list* container){
    struct Task_list *temp = get_task(container, current->pid);
    if(temp == NULL)
    {
        printk("Creating a new Task with Tid: %d in container %llu \n", current->pid, container->cid);
        temp = (struct Task_list*)kmalloc(sizeof(struct Task_list),GFP_KERNEL);
        memset(temp, 0, sizeof(struct Task_list));
        temp->data = current;
        mutex_lock(&list_lock);
        list_add(&(temp->list), &((container->task_head).list));
        mutex_unlock(&list_lock);
    }
    return temp;
}


struct Container_list *get_task_container(void){
    struct Container_list *temp;
    struct list_head *pos, *q, *pos1, *q1;
    struct Task_list *temp_task;
    list_for_each_safe(pos, q, &container_head.list) {
        temp = list_entry(pos, struct Container_list, list);
        list_for_each_safe(pos1, q1, &(temp->task_head.list)) {
            temp_task = list_entry(pos1, struct Task_list, list);
            if( current->pid == temp_task->data->pid) {
                // return the container holding this task
                return temp; 
            }
        }
    }
    return NULL;
}

// This iterates through the container list and returns the
// task matching the given tid.
struct Memory_list *get_memory_object(struct Container_list* container, __u64 oid){
    struct Memory_list *temp;
    struct list_head *pos, *q;
    list_for_each_safe(pos, q, &container->memory_head.list) {
        temp = list_entry(pos, struct Memory_list, list);
        if( oid == temp->oid) {
            return temp;
        }
    }
    return NULL;
}

// memory
struct Memory_list *create_memory_object(struct Container_list* container, __u64 oid){
    struct Memory_list *temp = get_memory_object(container, oid);
    // If a memory object is not existing
    if(temp == NULL)
    {
        temp = (struct Memory_list*)kmalloc(sizeof(struct Memory_list),GFP_KERNEL);
        memset(temp, 0, sizeof(struct Memory_list));
        temp->oid = oid;
        temp->size=0; // The actuall size will be set in mmap
        temp->pfn=0;
        mutex_lock(&list_lock);
        list_add(&(temp->list), &((container->memory_head).list));
        mutex_unlock(&list_lock);
    }
    return temp;
}


/*
* Delete and free the current thread from given thread list
*/
void delete_current_task(struct Task_list *current_task){
    mutex_lock(&list_lock);
    list_del(&current_task->list);
    kfree(current_task);
    mutex_unlock(&list_lock);
}

/*
* Delete and free the container container from given container list
*/
void delete_current_container(struct Container_list *current_container){
    mutex_lock(&list_lock);
    list_del(&current_container->list);
    kfree(current_container);
    mutex_unlock(&list_lock);
}

/*
* Delete the current task
* If all task are deleted then delete the container
*/

void delete_task_and_container(struct Container_list *container, struct Task_list* task ){
    delete_current_task(task);
    // checking if the task list is empty
    if(list_empty(&container->task_head.list) && list_empty(&container->memory_head.list))
    {
        delete_current_container(container);
    }
}

/*
* Delete the passed memory object 
*/

void delete_memory_object(struct Memory_list *memory_object){
    if(memory_object != NULL){
        mutex_lock(&list_lock);
        list_del(&(memory_object->list));
        kfree(memory_object);
        mutex_unlock(&list_lock);
    }
}



/*********************************************************************************************/



int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    // get the container holding the current task
    struct Container_list *current_container = get_task_container();
    if(current_container != NULL)
    {
        struct Memory_list *memory_object = create_memory_object(current_container, vma->vm_pgoff);
        int rc;
        if(!memory_object->size){
            int size = vma->vm_end - vma->vm_start;
            void *kernel_memory = kmalloc(size, GFP_KERNEL);
            // Physical Address is PFN offseted by the page
            // Thus to get back pfn we unset physical address by the bits for page size. 
            __u64 pfn = (unsigned long)virt_to_phys((void*)kernel_memory) >> PAGE_SHIFT; 
            rc = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
            memory_object->size = size;
            memory_object->pfn = pfn;
        }
        else{ // If Memory Object already is allocated
            rc = remap_pfn_range(vma, vma->vm_start, memory_object->pfn, memory_object->size, vma->vm_page_prot);
        }
        return rc;
    }
    return 0;

}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    struct Container_list *current_container = get_task_container();
    if(current_container!=NULL){
        mutex_lock(&current_container->lock);
    }
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    struct Container_list *current_container = get_task_container();
    if(current_container!=NULL){
        mutex_unlock(&current_container->lock);
    }
    return 0;
}


int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    struct Container_list* container = get_task_container();
    if(container!=NULL)
    {
        struct Task_list* task = get_task(container, current->pid);
        delete_task_and_container(container, task);
    }
    return 0;
}


int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    struct Container_list *container =  NULL;
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user *) user_cmd, sizeof(struct memory_container_cmd));
    container = create_container(kernel_cmd.cid);
    create_task(container);
    return 0;
}


int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    struct Container_list* container = NULL;
    struct Memory_list* memory_object = NULL;
    struct memory_container_cmd kernel_cmd;
    copy_from_user(&kernel_cmd, (void __user *) user_cmd, sizeof(struct memory_container_cmd));
    container = get_task_container();
    if(container != NULL){
        memory_object = get_memory_object(container, kernel_cmd.oid);
        delete_memory_object(memory_object);
    }
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
