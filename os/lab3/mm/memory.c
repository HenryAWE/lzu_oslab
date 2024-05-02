/**
 * @file memory.c
 * @brief 实现物理内存管理
 */
#include <assert.h>
#include <kdebug.h>
#include <mm.h>
#include <stddef.h>

/** 内存页表，跟踪系统的全部内存 */
unsigned char mem_map[PAGING_PAGES] = { 0 };

/**
 * @brief 初始化内存管理模块
 *
 * 该函数初始化 mem_map[] 数组，将物理地址空间 [MEM_START, HIGH_MEM) 纳入到
 * 内核的管理中。SBI 和内核部分被设置为`USED`，其余内存被设置为`UNUSED`
 */
void mem_init()
{
    size_t i = MAP_NR(HIGH_MEM);
    /** 设用户内存空间[LOW_MEM, HIGH_MEM)为可用 */
    while (i > MAP_NR(LOW_MEM))
        mem_map[--i] = UNUSED;
    /** 设SBI与内核内存空间[MEM_START, LOW_MEM)的内存空间为不可用 */
    while (i > MAP_NR(MEM_START))
        mem_map[--i] = USED;
}

/**
 * @brief 从地址 from 拷贝一页数据到地址 to
 *
 * @param from 源地址
 * @param to 目标地址
 */
static inline void copy_page(uint64_t from, uint64_t to)
{
    for (size_t i = 0; i < PAGE_SIZE / 8; ++i) {
        *(uint64_t *)to = *(uint64_t *)(from);
        to += 8;
        from += 8;
    }
}

/**
 * @brief 释放指定的物理地址所在的页
 *
 * @param addr 物理地址
 */
void free_page(uint64_t addr)
{
    if (addr < LOW_MEM)
        return;
    if (addr >= HIGH_MEM)
        panic("free_page(): trying to free nonexistent page");
    assert(mem_map[MAP_NR(addr)] != 0,
           "free_page(): trying to free free page");

    // 打印释放的地址
    kprintf("Page freed at %p\n", (void *)addr);

    --mem_map[MAP_NR(addr)];
}

/**
 * @brief 获取空物理页
 *
 * @return 成功则物理页的物理地址,失败返回 0
 */
uint64_t get_free_page(void)
{
    size_t i = MAP_NR(HIGH_MEM) - 1;
    for (; i >= MAP_NR(LOW_MEM); --i) {
        if (mem_map[i] == 0) {
            mem_map[i] = 1;
            uint64_t ret = MEM_START + i * PAGE_SIZE;
            memset((void *)ret, 0, PAGE_SIZE);

            // 打印分配的地址
            kprintf("Page allocated at %p\n", (void *)ret);

            return ret;
        }
    }
    return 0;
}

/**
 * @brief 测试物理内存分配/回收函数是否正确
 */
void mem_test()
{
    /** 测试 mem_map[] 是否正确 */
    size_t i;
    for (i = 0; i < MAP_NR(LOW_MEM); ++i)
        assert(mem_map[i] == USED, "Reference counter goes wrong");
    for (; i < MAP_NR(HIGH_MEM); ++i)
        assert(mem_map[i] == UNUSED, "Reference counter goes wrong");

    /** 测试物理页分配是否正常 */
    uint64_t page1, old_page1;
    page1 = old_page1 = get_free_page();
    assert(page1, "Memory exhausts");
    assert(page1 != 0, "page1 equal to zero");
    assert(page1 == HIGH_MEM - PAGE_SIZE,
           "Error in address return by get_free_page()");
    for (i = 0; i < 512; ++i) {
        assert(*(uint64_t *)old_page1 == 0, "page1 is dirty");
        old_page1 = old_page1 + 8;
    }

    uint64_t page2, old_page2;
        assert(page2 = old_page2 = get_free_page(), "Memory exhausts");
    assert(page2 != 0, "page2 equal to zero");
    assert(page2 == HIGH_MEM - 2 * PAGE_SIZE,
           "page2 is not equal to HIGH_MEM - 2 * PAGE_SIZE");
    assert(page1 != page2, "page1 equal to page2");
    for (i = 0; i < 512; ++i) {
        assert(*(uint64_t *)old_page2 == 0, "page2 is dirty");
        old_page2 = old_page2 + 8;
    }

    uint64_t page3, old_page3;
    assert(page3 = old_page3 = get_free_page(), "Memory exhausts");
    assert(page3 != 0, "page3 equal to zero");
    assert(page3 == HIGH_MEM - 3 * PAGE_SIZE,
           "page3 is not equal to HIGH_MEM - 3 * PAGE_SIZE");
    for (i = 0; i < 512; ++i) {
        assert(*(uint64_t *)old_page3 == 0, "page3 is dirty");
        old_page3 = old_page3 + 8;
    }

    /** 测试返回地址是否正常 */
    assert(page1 != page2, "page1 equal to page2");
    assert(page1 != page3, "page1 equal to page3");
    assert(page2 != page3, "page2 equal to page3");

    /** 测试 mem_map[] 引用计数是否正常 */
    assert(mem_map[MAP_NR(page2)] == 1, "Reference counter goes wrong");
    free_page(page2);
    assert(mem_map[MAP_NR(page2)] == 0, "Reference counter goes wrong");
    assert(page2 == get_free_page(),
           "get_free_page() don't return the highest empty page");
    assert(mem_map[MAP_NR(page1)] == 1, "Reference counter goes wrong");
    assert(mem_map[MAP_NR(page2)] == 1, "Reference counter goes wrong");
    assert(mem_map[MAP_NR(page2)] == 1, "Reference counter goes wrong");

    ++mem_map[MAP_NR(page2)];
    free_page(page2);
    assert(mem_map[MAP_NR(page2)] == 1, "Reference counter goes wrong");
    free_page(page2);
    assert(mem_map[MAP_NR(page2)] == 0, "Reference counter goes wrong");

    /* 通过测试 */
    free_page(page1);
    assert(mem_map[MAP_NR(page1)] == 0, "Reference counter goes wrong");
    free_page(page3);
    assert(mem_map[MAP_NR(page3)] == 0, "Reference counter goes wrong");
    kputs("mem_test(): Passed");
}

struct page_bulk_info {
        uint64_t addr; // 物理地址
        size_t size; // 页框数
};
typedef struct page_bulk_info page_bulk_info_t;

#define PAGE_BULK_COUNT 11

static page_bulk_info_t bulk_lists[PAGE_BULK_COUNT];

void setup_page_bulk(uint64_t start_addr)
{
        // 连续页框
        const size_t size_list[] = {
                1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1
        };

        for (size_t i = 0; i < PAGE_BULK_COUNT; ++i) {
                bulk_lists[i].addr = start_addr;
                bulk_lists[i].size = size_list[i];

                // 确保起始地址是大小的整数倍
                assert(start_addr % (bulk_lists[i].size * PAGE_SIZE) == 0,
                       "Invalid address");
                kprintf("Bulk %u, size %u, address %p\n", i, size_list[i],
                        (void *)start_addr);

                start_addr += size_list[i] * PAGE_SIZE;
        }
}

void page_alloc_init(void)
{
        // 初始化内存
        mem_init();

        setup_page_bulk(LOW_MEM);
}

static uint64_t search_contiguous_pages(const page_bulk_info_t *p_info, size_t count)
{
        uint64_t i = 0;
        while (1) {
                if (i >= p_info->size)
                        return 0;

                uint64_t current = p_info->addr + i * PAGE_SIZE;
                if (mem_map[MAP_NR(current)] != UNUSED) {
                        ++i;
                        continue;
                }

                for (size_t j = 1; j < count; ++j) {
                        if (i + j >= p_info->size)
                                return 0;
                        if (mem_map[MAP_NR(current + j)] != UNUSED) {
                                i += j;
                                goto try_next; // 尝试搜寻下一个连续内存块
                        }
                }

                return current;

        try_next:;
        }
}

static void *alloc_in_bulk(const page_bulk_info_t *p_info, size_t count)
{
        if (count > p_info->size) // 请求的页面数大于当前内存块总页框数
                return NULL;

        uint64_t found = search_contiguous_pages(p_info, count);
        if (found != 0) {
                for (size_t i = 0; i < count; ++i) {
                        // 标记内存为已使用
                        mem_map[MAP_NR(found + i * PAGE_SIZE)] = 1;
                }

                kprintf("Allocated %u page(s) at %p in bulk %u\n", count,
                        (void *)found, (uint64_t)(p_info - bulk_lists));
                return (void *)found;
        }

        kprintf("Bulk %u: out of memory\n", (uint64_t)(p_info - bulk_lists));
        return NULL; // 该块没有足够的内存，告知上层代码尝试下一块
}

void *page_alloc(size_t count)
{
        if (count == 0) // 请求分配 0 页，直接返回空指针
                return NULL;
        if (count > 1024) // 超过上限，直接返回空指针
                return NULL;

        // 反向遍历，优先使用小块的内存
        for (size_t i = PAGE_BULK_COUNT; i != 0; --i) {
                const page_bulk_info_t *p_info = &bulk_lists[i - 1];
                void *allocated = alloc_in_bulk(p_info, count);
                if (allocated != NULL) {
                        return allocated;
                }
        }

        kputs("page_alloc(): out of memory");
        return NULL;
}

void page_free(void *p, size_t count)
{
        if (p == NULL) // 忽略空指针
                return;

        uint64_t start_addr = (uint64_t)p;
        if (start_addr < LOW_MEM || start_addr >= HIGH_MEM)
                panic("page_free(): Invalid address");
        for (size_t i = 0; i < count; ++i) {
                uint64_t addr = start_addr + i * PAGE_SIZE;
                // 防止重复调用 free
                assert(mem_map[MAP_NR(addr)] != UNUSED,
                       "page_free(): Detected double-free");

                mem_map[MAP_NR(addr)] = UNUSED;
        }

        kprintf("Freed %u page(s) at %p\n", count, p);
}

// 用来测试的辅助函数
static const page_bulk_info_t *locate_bulk(void *p)
{
        uint64_t addr = (uint64_t)p;
        for (size_t i = 0; i < PAGE_BULK_COUNT; ++i) {
                const page_bulk_info_t *p_info = &bulk_lists[i];
                if (p_info->addr > addr)
                        continue;
                if (addr < p_info->addr + p_info->size * PAGE_SIZE)
                        return p_info;
        }

        return NULL;
}
static int check_bulk_id(const page_bulk_info_t *p_info, size_t id)
{
        if (p_info == NULL)
                return 0;

        return id == p_info - bulk_lists;
}

void test_page_alloc(void)
{
        kputs("Test buddy system");

        kputs("TEST CASE 1: Basic allocation");
        {
                const size_t size_list[] = { 1,  2,   4,   8,   16,  32,
                                             64, 128, 256, 512, 1024 };

                for (size_t i = 0; i < PAGE_BULK_COUNT; ++i) {
                        void *p = page_alloc(size_list[i]);
                        assert(check_bulk_id(locate_bulk(p),
                                             PAGE_BULK_COUNT - i - 1),
                               "Failed");
                        free_page(p);
                        p = NULL;
                }
        }

        kputs("TEST CASE 2: Reuse freed pages");
        {
                void *p1 = page_alloc(2);
                assert(check_bulk_id(locate_bulk(p1), 9), "Failed");
                void *p2 = page_alloc(2);
                assert(check_bulk_id(locate_bulk(p2), 8), "Failed");

                page_free(p1, 2);
                p1 = NULL;

                void *p3 = page_alloc(2);
                assert(check_bulk_id(locate_bulk(p3), 9), "Failed");

                page_free(p2, 2);
                p2 = NULL;
                page_free(p3, 2);
                p3 = NULL;
        }

        kputs("TEST CASE 3: Avoid memory fragmentation");
        {
                void *p1 = page_alloc(1);
                assert(check_bulk_id(locate_bulk(p1), 10), "Failed");
                void *p2 = page_alloc(1024);
                assert(check_bulk_id(locate_bulk(p2), 0), "Failed");
                void *p3 = page_alloc(512);
                assert(check_bulk_id(locate_bulk(p3), 1), "Failed");

                page_free(p2, 1024);
                p2 = NULL;

                void *p4 = page_alloc(1);
                assert(check_bulk_id(locate_bulk(p4), 9), "Failed");

                void *p5 = page_alloc(1024);
                assert(check_bulk_id(locate_bulk(p5), 0), "Failed");

                page_free(p1, 1);
                p1 = NULL;
                page_free(p3, 512);
                p3 = NULL;
                page_free(p4, 1);
                p4 = NULL;
                page_free(p5, 1024);
                p5 = NULL;
        }

        kputs("TEST CASE 4: Check behavior when out of memory");
        {
                void *p1 = page_alloc(1024);
                assert(check_bulk_id(locate_bulk(p1), 0), "Failed");

                void *p2 = page_alloc(1024); // 内存不足，应返回空指针
                assert(p2 == NULL, "Failed");

                free_page(p1);
                p1 = NULL;
        }

        kputs("Buddy system test passed");
}
