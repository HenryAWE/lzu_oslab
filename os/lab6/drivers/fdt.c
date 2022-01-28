#include <device/fdt.h>
#include <device.h>
#include <kdebug.h>
#include <mm.h>

struct driver_resource fdt_mem = {
    .resource_type = DRIVER_RESOURCE_MEM
};

void fdt_match_drivers_by_node(const struct fdt_header *fdt, struct fdt_node_header *node, struct device_driver *driver_list[]) {
    struct fdt_property *prop = fdt_get_prop(fdt, node, "compatible");
    if (!prop) return;
    if (!driver_list) return;
    uint32_t prop_used_len = 0;
    while (prop_used_len < fdt_get_prop_value_len(prop)) {
        const char *device_compatible = fdt_get_prop_str_value(prop, prop_used_len);
        uint64_t is_device_matched = 0;
        for (uint64_t driver_idx = 0; driver_list[driver_idx]; driver_idx += 1) {
            struct device_driver *driver = driver_list[driver_idx];
            for (uint64_t driver_match = 0; ; driver_match += 1){
                struct driver_match_table match_table = driver->match_table[driver_match];
                const char * driver_match_str = match_table.compatible;
                if (!driver_match_str) break;
                if (!strcmp(driver_match_str, device_compatible)) {
                    struct device *dev = kmalloc(sizeof(struct device));
                    dev->match_data = match_table.match_data;
                    dev->fdt_node = node;
                    driver->device_probe(dev);
                    is_device_matched = 1;
                    kprintf("load device %s\n\tdriver: %s\n", device_compatible, driver->driver_name);
                    break;
                }
            }
            if (is_device_matched) break;
        }
        prop_used_len += strlen(device_compatible) + 1;
    }
}

void fdt_loader(const struct fdt_header *fdt, struct device_driver *driver_list[]) {
    struct device *dev = kmalloc(sizeof(struct device));
    device_init(dev);
    fdt_mem.resource_start = (uint64_t)fdt;
    fdt_mem.resource_end = fdt_mem.resource_start + 2 * PAGE_SIZE;
    device_add_resource(dev, &fdt_mem);

    fdt = (const struct fdt_header *)fdt_mem.map_address;
    union fdt_walk_pointer pointer = { .address = (uint64_t)fdt };
    pointer.address += fdt32_to_cpu(fdt->off_dt_struct);

    while (pointer.address) {
        if (pointer.node->tag == FDT_BEGIN_NODE) {
            fdt_match_drivers_by_node(fdt, pointer.node, driver_list);
        }
        fdt_walk_node(&pointer);
    }
}
