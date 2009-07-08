/******************************************************************************
 Copyright 2009, Philipp Schmidt, Freie Universitaet Berlin (FUB).
 All rights reserved.
 
 These sources were originally developed by Philipp Schmidt
 at Freie Universitaet Berlin (http://www.fu-berlin.de/), 
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group 
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)
 ------------------------------------------------------------------------------
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 
 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .
 ------------------------------------------------------------------------------
 For further information and questions please use the web site
        http://www.des-testbed.net/
*******************************************************************************/

#include "dessert.h"

/* data storage */
dessert_periodic_t *_tasklist = NULL;
pthread_mutex_t _dessert_periodic_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t _dessert_periodic_changed = PTHREAD_COND_INITIALIZER;
pthread_t _dessert_periodic_worker;
int _dessert_periodic_worker_running = 0;

/* internal task list modifier - only call while holding _dessert_periodic_mutex */
int _dessert_periodic_add_periodic_t(dessert_periodic_t *task) 
{
    
    dessert_periodic_t *i;
    
    /* first task? */
    if (_tasklist == task)
    {
        dessert_err("infinite loop in periodic tasklist requested - aborting!");
        return(-1);
    }
    else if (_tasklist == NULL) 
    {
        _tasklist = task;
        pthread_cond_broadcast(&_dessert_periodic_changed);
    }
    /* is next task.... */
    else if (_tasklist->scheduled.tv_sec > task->scheduled.tv_sec && 
             _tasklist->scheduled.tv_usec > task->scheduled.tv_usec )
    {
        task->next = _tasklist;
        _tasklist = task;
        pthread_cond_broadcast(&_dessert_periodic_changed);
    }    
    /* search right place */    
    else 
    {
        i = _tasklist;
        while(i->next != NULL && 
               ( i->scheduled.tv_sec < task->scheduled.tv_sec ||
                 (i->scheduled.tv_sec == task->scheduled.tv_sec &&
                  i->scheduled.tv_usec <= task->scheduled.tv_usec )))
        {
            i = i->next;
            if (i->next == task) {
                dessert_err("infinite loop in periodic tasklist requested - aborting!");
                return(-1);
            }
        }
        /* last or right place */
        task->next = i->next;
        i->next = task;
        /* no need to tell periodic thread to check 
           again - next task has not changed */
    }
    
    return(0);
    
}


/** add a delayed/periodic task to the task list 
  * @arg c callback to call when task is scheduled
  * @arg data data to give to the callback
  * @arg scheduled when should the callback be called the first time
  * @arg interval how often should it be called (set to NULL if only once)
  */
dessert_periodic_t *dessert_periodic_add(dessert_periodiccallback_t* c, void *data, const struct timeval *scheduled, const struct timeval *interval)
{
    struct timeval now;
    dessert_periodic_t *task;
    
    gettimeofday(&now, NULL);
    
    if(scheduled == NULL) {
        scheduled = &now;
    }
    
    /* sanity checks */
    if(c == NULL) {
        return(NULL);
    }
    
    /* get task memory */
    task = malloc(sizeof(dessert_periodic_t));
    if(task == NULL) {
        return NULL;
    }
    
    /* copy data */
    task->c = c;
    task->data = data;
    memcpy(&(task->scheduled), scheduled, sizeof(struct timeval));
    if(interval == NULL) {
        task->interval.tv_sec = 0;
        task->interval.tv_usec = 0;
    } else {
        memcpy(&(task->interval), interval, sizeof(struct timeval));
    }
    task->next = NULL;
    
    pthread_mutex_lock(&_dessert_periodic_mutex);
    _dessert_periodic_add_periodic_t(task);
    pthread_mutex_unlock(&_dessert_periodic_mutex);
 
    
    return(task);
}

/** add a delayed task to the task list 
  * this is an easier version of dessert_periodic_add taking a single delay as parameter
  * @arg c callback to call when task is scheduled
  * @arg data data to give to the callback
  * @arg scheduled when should the callback be called the first time
  * @arg interval how often should it be called (set to NULL if only once)
  */
dessert_periodic_t *dessert_periodic_add_delayed(dessert_periodiccallback_t* c, void *data, int delay)
{
    struct timeval at;
    gettimeofday(&at, NULL);
    
    at.tv_sec += delay;
    return(dessert_periodic_add(c, data, &at, NULL));
    
}

/** remove a delayed/periodic task from the task list 
 * @arg p pointer to task description
 * @returns -1 on failure, 0 if the task was removed 
 */
int dessert_periodic_del(dessert_periodic_t *p)
{
    dessert_periodic_t *i;
    int x = -1; 
    
	assert(p != NULL);

    pthread_mutex_lock(&_dessert_periodic_mutex);
    

    if(p == _tasklist) {
        _tasklist = _tasklist->next;
        x++;
    }	

    i = _tasklist;
    while(i != NULL ){
        if(i->next == p ) {
            i->next = p->next;
            x++;
        }
		i = i->next;
    }
    
    pthread_mutex_unlock(&_dessert_periodic_mutex);
    
	assert(x < 2);

    free(p);
    return(x);
    
}

/* internal worker for the task list */
void *_dessert_periodic_thread(void* arg)
{
    dessert_periodic_t *next_task;
    dessert_periodic_t task;
    struct timeval now;
    struct timespec ts;
    
    pthread_mutex_lock(&_dessert_periodic_mutex);
    
    while(1) {
                
        gettimeofday(&now, NULL);
        
        if( _tasklist == NULL) {
            if(pthread_cond_wait(&_dessert_periodic_changed,
                &_dessert_periodic_mutex) == EINVAL) {
                dessert_err("sleeping failed in periodic scheduler - scheduler died");
                break;
            }
            continue;
        } 
        else if( now.tv_sec < _tasklist->scheduled.tv_sec ||
                (now.tv_sec == _tasklist->scheduled.tv_sec &&
                 now.tv_usec < _tasklist->scheduled.tv_usec  ))
        {
            ts.tv_sec =  _tasklist->scheduled.tv_sec;
            ts.tv_nsec =  _tasklist->scheduled.tv_usec*1000;
            if(pthread_cond_timedwait(&_dessert_periodic_changed,
                &_dessert_periodic_mutex, &ts) == EINVAL) {
                dessert_err("sleeping failed in periodic scheduler - scheduler died");
                break;
            }
            continue;
        }
        
        /* run next task */
        next_task = _tasklist;
        _tasklist = next_task->next;
        
        /* safe task to local variable */
        memcpy(&task, next_task, sizeof(dessert_periodic_t));
                
        /* periodic task - re-add */
        if(next_task->interval.tv_sec != 0 || next_task->interval.tv_usec != 0) 
        {
            next_task->scheduled.tv_sec += next_task->interval.tv_sec;
            next_task->scheduled.tv_usec += next_task->interval.tv_usec;
            _dessert_periodic_add_periodic_t(next_task);
        }
        /* otherwise free memory */
        else 
        {
            free(next_task);
        }

        /* run the callback */
        pthread_mutex_unlock(&_dessert_periodic_mutex);
        /* call the callback - remove it from list if exits with nonzero code */
        if(task.c(task.data, &(task.scheduled), &(task.interval))) {
            dessert_periodic_del(next_task);
        }
        pthread_mutex_lock(&_dessert_periodic_mutex);
    }
    
    pthread_mutex_unlock(&_dessert_periodic_mutex);
    _dessert_periodic_worker_running = 0;
    
    return;
}


/** internal function to start periodic worker */
void _desp2_periodic_init() {
    if(_dessert_periodic_worker_running == 0 ) {
        _dessert_periodic_worker_running = 1;
        pthread_create(&_dessert_periodic_worker, NULL, _dessert_periodic_thread, NULL);
    }
}
