#ifndef MM_H
#define MM_H
#include <stddef.h>
#define PAGE_SIZE       4096
#define FLOOR(addr)     ((addr) / PAGE_SIZE * PAGE_SIZE)
#define CEIL(addr)      (((addr) / PAGE_SIZE + ((addr) % PAGE_SIZE != 0)) * PAGE_SIZE)
#define MEM_START       0x80000000
#define MEM_END         0x88000000
#define SIB_START       0x80000000
#define SBI_END         0x82000000
#define HIGH_MEM        FLOOR(0x87FF0000)
#define LOW_MEM         CEIL(0x83000000)
#define PAGING_MEMORY   (1024 * 1024 * 128)
#define PAGING_PAGES    (PAGING_MEMORY>>12)
#define MAP_NR(addr)    (((addr)-MEM_START)>>12)

#define USED 100
#define PAGE_DIRTY	    0x80
#define PAGE_ACCESSED	0x40
// TODO
#define PAGE_USER	    0x04 
// TODO
#define PAGE_RW		    0x02
#define PAGE_PRESENT	0x01

#define invalidate() __asm__ __volatile__("sfence.vma\n\t"::)

#define GET_VPN1(addr) (((addr) >> 30) & 0x1FF)
#define GET_VPN2(addr) (((addr) >> 21) & 0x1FF)
#define GET_VPN3(addr) (((addr) >> 12) & 0x1FF)
#define GET_PPN(addr)  ((addr) >> 12)

extern unsigned char mem_map [ PAGING_PAGES ];
extern uint64_t pg_dir[512];
void mem_test();
void show_mem();
void mem_init(uint64_t start_mem, uint64_t end_mem);
void free_page(uint64_t addr);
uint64_t get_free_page(void);
void get_empty_page(uint64_t addr);
uint64_t put_page(uint64_t page, uint64_t addr);
uint64_t put_dirty_page(uint64_t page, uint64_t addr);
void enable_rv39_pagging();

#endif