
#ifndef __CYGHEAP_H_
#define __CYGHEAP_H_

void *sh_create_pool(size_t size);
void sh_free_poll(void *ptr);

void *sh_malloc(size_t size);
void sh_free(void *ptr);
void *sh_calloc(size_t nmemb, size_t size);
void *sh_realloc(void *ptr, size_t size);

#endif
