#include <sbi.h>
#include <kdebug.h>
#include <mm.h>
int main()
{
    kputs("\nLZU OS STARTING....................");
    print_system_infomation();
    // mem_init();
    // mem_test();
    page_alloc_init();
    test_page_alloc();
    kputs("Hello LZU OS");
    while (1)
        ; /* infinite loop */
    return 0;
}
