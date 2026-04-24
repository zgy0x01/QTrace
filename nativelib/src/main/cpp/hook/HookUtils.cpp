//
// Created by fang on 2024/1/3.
//
#include <climits>
#include <cstring>
#include <cstdio>
#include <asm-generic/unistd.h>
#include <unistd.h>
#include <dlfcn.h>
#include <vector>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <sys/mman.h>

// 修复Android NDK中_Unwind_Word未定义的问题
#ifndef _Unwind_Word
#if defined(__aarch64__)
typedef uint64_t _Unwind_Word;
#elif defined(__arm__)
typedef uint32_t _Unwind_Word;
#else
typedef uintptr_t _Unwind_Word;
#endif
#endif
#include"logger.h"
#include "HookUtils.h"
#include "elf.h"
#include <fcntl.h>

char* bytes_to_hex_string(char* bytes, size_t len) {
    if (bytes == NULL || len == 0) {
        return NULL;
    }
    // 每个字节对应2个16进制字符，加1用于存储字符串结束符'\0'
    char* hex_str = (char*)malloc(len * 2 + 1);
    if (hex_str == NULL) {
        return NULL; // 内存分配失败
    }
    // 16进制字符映射表（0-15对应'0'-'9','a'-'f'）
    const char hex_chars[] = "0123456789abcdef";
    // 遍历每个字节，转换为两位16进制字符
    for (size_t i = 0; i < len; i++) {
        unsigned char byte = bytes[i];
        // 高4位转换（右移4位取高半字节）
        hex_str[2 * i] = hex_chars[(byte >> 4) & 0x0F];
        // 低4位转换（直接取低半字节）
        hex_str[2 * i + 1] = hex_chars[byte & 0x0F];
    }
    hex_str[2 * len] = '\0'; // 字符串结束符
    return hex_str;
}
size_t getLibRXsize(const char * soname)
{
    int fd = -1;
    struct stat st = {0};
    void* mapped_addr = MAP_FAILED;
    size_t rx_size = -1;
    LOGE("open %s",soname);
    fd = open(soname, O_RDONLY);
    if (fd < 0) {
        LOGE("open failed");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        LOGE("fstat failed");
        close(fd);
        return -1;
    }

    mapped_addr = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped_addr == MAP_FAILED) {
        LOGE("mmap failed");
        close(fd);
        return -1;
    }
    Elf64_Ehdr* elf64_hdr = (Elf64_Ehdr*)mapped_addr;
    Elf64_Phdr* phdr = (Elf64_Phdr*)((uint8_t*)mapped_addr + elf64_hdr->e_phoff);
    for (int i = 0; i < elf64_hdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD &&
            (phdr[i].p_flags & (PF_R | PF_X)) == (PF_R | PF_X) &&
            !(phdr[i].p_flags & PF_W)) {
            rx_size = phdr[i].p_memsz + phdr[i].p_vaddr;
            break;
        }
    }
    close(fd);
    munmap(mapped_addr, st.st_size);
    LOGE("lib:%s,rx size:%lx",soname,rx_size);
    return rx_size;
}
uintptr_t get_current_x0() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x0" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x1() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x1" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x2() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x2" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x3() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x3" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x4() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x4" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x5() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x5" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x6() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x6" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x7() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x7" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x8() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x8" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x9() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x9" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x10() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x10" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x11() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x11" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x12() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x12" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x13() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x13" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x14() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x14" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x15() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x15" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x16() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x16" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x17() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x17" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x18() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x18" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x19() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x19" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x20() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x20" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x21() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x21" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x22() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x22" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x23() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x23" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x24() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x24" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x25() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x25" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x26() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x26" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x27() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x27" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x28() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x28" : "=r"(reg));
    return reg;
}
uintptr_t get_current_x29() {
    uintptr_t reg;
    __asm__ __volatile__("mov %0, x29" : "=r"(reg));
    return reg;
}

size_t findSymbolInLibArt(const char * soname,const char * symname)
{
    size_t start = 0;
    size_t end = 0;
    size_t len = 0;
    char buffer[PATH_MAX];
    memset(buffer, 0, PATH_MAX);
    char prop[10];
    memset(prop, 0, 10);
    //找不到用原始文件
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        LOGD("open maps error");
    }
    FILE *raw = fopen("/apex/com.android.art/lib64/libart.so","r");
    if (raw == nullptr) {
        LOGD("open /apex/com.android.art/lib64/libart.so error");
        return -1;
    }
    char header[HEADSIZE];
    size_t read = fread(header,sizeof(char),HEADSIZE,raw);
    if(read != HEADSIZE)
    {
        LOGD("read raw file error,size should > 0x100.");
        fclose(raw);
        return -1;
    }
    char *line = nullptr;
    bool findart = false;
    while (getline(&line, &len, fp) != -1) {
        if (line != nullptr && strstr(line,"libart")) {
            sscanf(line, "%lx-%lx", &start, &end);
            if(memcmp((void*)start,header,HEADSIZE) == 0)
            {
                findart = true;
                break;
            }
        }
    }
    if(start == 0 || !findart)
    {
        return -1;
    }
    Elf64_Ehdr * elf = (Elf64_Ehdr*)start;
    Elf64_Phdr * phdrstart = (Elf64_Phdr *)((size_t)elf + (size_t)(elf->e_phoff));
    Elf64_Phdr * phdr = nullptr;
    bool find = false;
    for(int i=0;i<elf->e_phnum;i++)
    {
        phdr = (Elf64_Phdr *)((size_t)phdrstart + (size_t)(i*elf->e_phentsize));
        if(phdr->p_type == PT_DYNAMIC)
        {
            find = true;
            break;
        }
    }
    if(!find)
    {
        LOGD("PT_DYNAMIC not found ");
        return -1;
    }
    Elf64_Dyn * dynstart = (Elf64_Dyn *)((Elf64_Phdr *)((size_t)elf + (size_t)(phdr->p_vaddr)));
    Elf64_Dyn * strtab = nullptr;
    Elf64_Dyn * symtab = nullptr;
    for(int i =0;i<(phdr->p_memsz / 0x10);i++)
    {
        Elf64_Dyn * curr = (Elf64_Dyn *)((size_t)dynstart + i*0x10);
        if(curr->d_tag == DT_STRTAB)
        {
            strtab = curr;
        }

        if(curr->d_tag == DT_SYMTAB)
        {
            symtab = curr;
        }
    }

    if(strtab == nullptr || symtab == nullptr)
    {
        LOGE("strtab or symtab not found ");
        return -1;
    }
    Elf64_Sym * symstart = (Elf64_Sym *)((Elf64_Phdr *)((size_t)elf + (size_t)(symtab->d_un.d_val)));
    size_t addr = -1;
    int maxcount = 0x10000;
    int idx = 0;
    Elf64_Sym * sym;
    while (true)
    {
        idx = idx + 1;
        if(idx >= maxcount)
        {
            LOGE("not found sym %s",soname);
            break;
        }
        sym = (Elf64_Sym *)((size_t)symstart + idx * 0x18);
        char* sname = (char*)((size_t)elf + strtab->d_un.d_val + sym->st_name);
        if(!strcmp(sname,symname))
        {
            addr = start + sym->st_value;
            LOGE("find %s,%lx",soname,addr);
            break;
        }
    }
    fclose(fp);
    return addr;
}

static const char *TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* 编码：每 3 字节 → 合并为 24bit → 拆成 4 个 6bit 索引查表 */
size_t base64_encode(char *out, const uint8_t *data, size_t len) {
    char *p = out;
    for (size_t i = 0; i < len; i += 3) {
        int remain = len - i;  // 剩余字节数

        /* 3 字节合并为 24 位整数 */
        uint32_t val = data[i] << 16
                       | (remain > 1 ? data[i + 1] : 0) << 8
                       | (remain > 2 ? data[i + 2] : 0);

        /* 拆为 4 组 6bit，不足部分填 '=' */
        *p++ = TABLE[(val >> 18) & 0x3F];
        *p++ = TABLE[(val >> 12) & 0x3F];
        *p++ = remain > 1 ? TABLE[(val >> 6) & 0x3F] : '=';
        *p++ = remain > 2 ? TABLE[ val       & 0x3F] : '=';
    }
    *p = '\0';
    return p - out;
}

MapItemInfo getSoBaseAddress(const char *libpath, const char *name) {
    MapItemInfo info{0};
    if (name == nullptr) {
        return info;
    }
    size_t start = 0;
    size_t end = 0;
    size_t len = 0;
    char buffer[PATH_MAX];
    memset(buffer, 0, PATH_MAX);
    char prop[10];
    memset(prop, 0, 10);

    info.size = getLibRXsize(libpath);
    FILE *raw = fopen(libpath,"r");
    if (raw == nullptr) {
        LOGD("open raw file error,please set libpath to your target lib.");
        return info;
    }
    char header[HEADSIZE];
    size_t read = fread(header,sizeof(char),HEADSIZE,raw);
    if(read != HEADSIZE)
    {
        LOGD("read raw file error,size should > 0x100.");
        fclose(raw);
        return info;
    }

    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) {
        LOGD("open maps error");
        return info;
    }

    char *line = nullptr;
    while (getline(&line, &len, fp) != -1) {
        if (line != nullptr && strstr(line,"r") && strstr(line,"x")) {
            sscanf(line, "%lx-%lx", &start, &end);
            if(memcmp((void*)start,header,HEADSIZE) == 0)
            {
                info.start = start;
                info.end = end;
                if(info.size == -1)
                {
                    LOGD("use end - start as size");
                    info.size = end - start;
                }
                break;
            }
        }
    }
    fclose(fp);
    return info;
}

MapItemInfo getSoBaseAddressFromAddress(void* address) {
    MapItemInfo soinfo = {0,0};
    size_t addr = reinterpret_cast<size_t>(address);
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Can't open /proc/self/maps");
        return soinfo;
    }
    
    char *line = nullptr;
    size_t len = 0;
    std::string target_so_path;
    size_t min_start = SIZE_MAX, max_end = 0;
    
    // 第一遍：找到包含目标地址的段，获取so路径
    while (getline(&line, &len, fp) != -1) {
        size_t start = 0, end = 0;
        char perms[16], offset[16], dev[16], inode[32];
        char pathname[PATH_MAX] = {0};
        
        // 解析 /proc/self/maps 格式: address perms offset dev inode pathname
        int fields = sscanf(line, "%lx-%lx %15s %15s %15s %31s %[^\n]", 
                           &start, &end, perms, offset, dev, inode, pathname);
                
        if (fields >= 6 && addr >= start && addr < end) {
            target_so_path = pathname;
          
            break;
        }
    }
    
    // 如果找到了so路径，第二遍找该so的所有段
    if (!target_so_path.empty()) {
        rewind(fp);
        while (getline(&line, &len, fp) != -1) {
            if (strstr(line, target_so_path.c_str())) {
                size_t start = 0, end = 0;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    if (start < min_start) min_start = start;
                    if (end > max_end) max_end = end;
                }
            }
        }
    } else {
        LOGE("No so path found for address 0x%lx", addr);
    }
    
    fclose(fp);
    if (line) free(line);
    
    if (min_start != SIZE_MAX && max_end != 0) {
        soinfo.start = min_start;
        soinfo.end = max_end;
    } else {
        LOGE("Failed to find so range for address %p", address);
    }
    
    return soinfo;
}
// 检查一个字符串是否包含任何过滤字符串
static bool containsFilterString(const char* text, const char** filter_strings, size_t filter_count) {
    if (!text || !filter_strings || filter_count == 0) {
        return false;
    }
    
    for (size_t i = 0; i < filter_count; i++) {
        if (filter_strings[i] && strstr(text, filter_strings[i])) {
            return true;
        }
    }
    return false;
}
char* appName = nullptr;
char* getAppName(){
    if (appName != NULL){
        //LOGD("get appName %s",appName);
        return appName;
    }
    FILE* f = fopen("/proc/self/cmdline","r");
    size_t len;
    char* line = nullptr;
    if(getline(&line,&len,f)==-1){
        perror("can't get app name");
    }
    appName = line;
    //LOGD("get appName %s",appName);
    return appName;
}

char privatePath[PATH_MAX];
char* getPrivatePath(){
    if (privatePath[0] != 0 ){
        return privatePath;
    }
    // 使用应用私有files目录，避免权限问题
    sprintf(privatePath,"%s%s%s","/storage/emulated/0/Android/data/",getAppName(),"/files/");
    LOGI("Using private path: %s", privatePath);
    return privatePath;
}

bool isString(const char*s,int len)
{
    bool isString = true;
    for(int i=0;i<len;i++)
    {
        if(*(s+i)>=0x20 && *(s+i)<=0x7e)
        {
            continue;
        }
        return false;
    }
    return true;
}

const char* getAddressInfo(void* address, char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 32 || !address) {
        return nullptr;
    }
    
    Dl_info info;
    if (dladdr(address, &info)) {
        // 提取SO文件名（去掉路径）
        const char* so_name = strrchr(info.dli_fname, '/');
        if (so_name) {
            so_name++; // 跳过'/'
        } else {
            so_name = info.dli_fname;
        }
        
        // 计算偏移
        size_t offset = (char*)address - (char*)info.dli_fbase;
        snprintf(buffer, buffer_size, "%s+0x%zx", so_name, offset);
    } else {
        // 如果dladdr失败，使用简单格式
        snprintf(buffer, buffer_size, "unknown+0x%lx", (uintptr_t)address);
    }
    
    return buffer;
}