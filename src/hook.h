#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#undef PAGE_START
#define PAGE_START(addr, size) ~((size)-1) & (addr)

#ifdef __cplusplus
extern "C" {
#endif

uint64_t get_module_base(const char* module_path) {
  FILE* fp = NULL;
  char* pch = NULL;
  char filename[32];
  char line[512];
  uint64_t addr = 0;

  snprintf(filename, sizeof(filename), "/proc/self/maps");
  LOG(INFO) << "ch filename = " << filename;
  if ((fp = fopen(filename, "r")) == NULL) {
    LOG(INFO) << "ch open failed! " << filename;
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, module_path)) {
      pch = strtok(line, "-");
      if (strlen(pch) > 8 && strlen(pch) <= 12) {  // cpu 64
        addr = strtoul(pch, NULL, 16);
        LOG(INFO) << "module_path addre:" << addr;
      } else {
        LOG(INFO) << "64bit address:" << pch;
      }
      break;
    }
  }

  fclose(fp);
  return addr;
}

uint64_t find_got_entry_address(const char* module_path,
                                const char* symbol_name) {
  LOG(INFO) << "find_got_entry_address1";
  uint64_t module_base = get_module_base(module_path);

  if (module_base == 0) {
    LOG(INFO) << "ch it seems that process " << getpid()
              << " does not dependent on " << module_path;
    return 0;
  }

  LOG(INFO) << "ch base address of " << module_path << "0x" << module_base;

  int fd = open(module_path, O_RDONLY);
  if (fd == -1) {
    LOG(INFO) << "ch open error! " << module_path;
    return 0;
  }

  Elf64_Ehdr* elf_header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));

  int sizet = read(fd, elf_header, sizeof(Elf64_Ehdr));
  if (sizet != sizeof(Elf64_Ehdr)) {
    LOG(INFO) << "read %s error! in %s at line %d, size:%d, expect:%d, fd:%d, "
                 "errorno: %d, addr:%p"
              << module_path << " , " << __FILE__ << "," << __LINE__ << ", "
              << sizet << "," << sizeof(Elf64_Ehdr) << "," << fd << "," << errno
              << "," << elf_header;
    return 0;
  }

  uint64_t sh_base = elf_header->e_shoff;
  uint64_t ndx = elf_header->e_shstrndx;
  uint64_t shstr_base = sh_base + ndx * sizeof(Elf64_Shdr);
  LOG(INFO) << "ch start of section headers: 0x%x" << sh_base;
  LOG(INFO) << "ch section header string table index: %d" << ndx;
  LOG(INFO) << "ch section header string table offset: 0x%x" << shstr_base;

  lseek(fd, shstr_base, SEEK_SET);
  Elf64_Shdr* shstr_shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
  if (read(fd, shstr_shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
    LOG(INFO) << "ch read %s error! in %s at line %d<< module_path , "
              << __FILE__ << "," << __LINE__;
    return 0;
  }
  LOG(INFO) << "ch section header string table offset: 0x%x"
            << shstr_shdr->sh_offset;

  char* shstrtab = (char*)malloc(sizeof(char) * shstr_shdr->sh_size);
  lseek(fd, shstr_shdr->sh_offset, SEEK_SET);
  if (read(fd, shstrtab, shstr_shdr->sh_size) != shstr_shdr->sh_size) {
    LOG(INFO) << "ch read %s error! in %s at line %d" << module_path << ","
              << __FILE__ << "," << __LINE__;
    return 0;
  }

  Elf64_Shdr* shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
  Elf64_Shdr* relplt_shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
  Elf64_Shdr* dynsym_shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
  Elf64_Shdr* dynstr_shdr = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));

  lseek(fd, sh_base, SEEK_SET);
  if (read(fd, shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
    LOG(INFO) << "ch read %s error! in %s at line %d" << module_path << ","
              << __FILE__ << "," << __LINE__;
    perror("Error");
    return 0;
  }
  int i = 1;
  char* s = NULL;
  for (; i < elf_header->e_shnum; i++) {
    s = shstrtab + shdr->sh_name;
    if (strcmp(s, ".rela.plt") == 0) {
      memcpy(relplt_shdr, shdr, sizeof(Elf64_Shdr));
    } else if (strcmp(s, ".dynsym") == 0) {
      memcpy(dynsym_shdr, shdr, sizeof(Elf64_Shdr));
    } else if (strcmp(s, ".dynstr") == 0) {
      memcpy(dynstr_shdr, shdr, sizeof(Elf64_Shdr));
    }

    if (read(fd, shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
      LOG(INFO) << "ch read %s error! i = %d, in %s at line %d" << module_path
                << i << __FILE__ << __LINE__;
      return 0;
    }
  }

  LOG(INFO) << "ch offset of .rela.plt section: 0x%x" << relplt_shdr->sh_offset;

  // read dynmaic symbol string table
  char* dynstr = (char*)malloc(sizeof(char) * dynstr_shdr->sh_size);
  lseek(fd, dynstr_shdr->sh_offset, SEEK_SET);
  if (read(fd, dynstr, dynstr_shdr->sh_size) != dynstr_shdr->sh_size) {
    LOG(INFO) << "ch read %s error!" << module_path;
    return 0;
  }

  // read dynamic symbol table
  Elf64_Sym* dynsymtab = (Elf64_Sym*)malloc(dynsym_shdr->sh_size);
  lseek(fd, dynsym_shdr->sh_offset, SEEK_SET);
  if (read(fd, dynsymtab, dynsym_shdr->sh_size) != dynsym_shdr->sh_size) {
    LOG(INFO) << "ch read %s error!" << module_path;
    return 0;
  }

  // read each entry of relocation table
  Elf64_Rela* rel_ent = (Elf64_Rela*)malloc(sizeof(Elf64_Rela));
  lseek(fd, relplt_shdr->sh_offset, SEEK_SET);
  if (read(fd, rel_ent, sizeof(Elf64_Rela)) != sizeof(Elf64_Rela)) {
    LOG(INFO) << "ch read %s error!" << module_path;
    return 0;
  }

  uint64_t offset;

  LOG(INFO) << "ch relplt_shdr->sh_size = "
            << relplt_shdr->sh_size / sizeof(Elf64_Rela);

  for (i = 0; i < relplt_shdr->sh_size / sizeof(Elf64_Rela); i++) {
    ndx = ELF64_R_SYM(rel_ent->r_info);
    LOG(INFO) << "ch name " << dynstr + dynsymtab[ndx].st_name << ", "
              << symbol_name;

    if (strcmp(dynstr + dynsymtab[ndx].st_name, symbol_name) == 0) {
      LOG(INFO) << "ch got entry offset of %s: 0x%x" << symbol_name << ", "
                << rel_ent->r_offset;
      offset = rel_ent->r_offset;
      break;
    }
    if (read(fd, rel_ent, sizeof(Elf64_Rela)) != sizeof(Elf64_Rela)) {
      LOG(INFO) << "ch read %s error!" << module_path;
      return 0;
    }
  }

  //  uint64_t offset = rel_ent->r_offset;
  Elf64_Half type = elf_header->e_type;  // ET_EXEC or ET_DYN

  free(elf_header);
  free(shstr_shdr);
  free(shstrtab);
  free(shdr);
  free(relplt_shdr);
  free(dynsym_shdr);
  free(dynstr_shdr);
  free(dynstr);
  free(dynsymtab);
  free(rel_ent);

  if (type == ET_EXEC) {
    return offset;
  } else if (type == ET_DYN) {
    LOG(INFO) << "found api address = " << offset;
    return offset + module_base;
  }

  return 0;
}

uint64_t do_hook(const char* module_path,
                 uint64_t hook_func,
                 const char* symbol_name) {
  uint64_t entry_addr = find_got_entry_address(module_path, symbol_name);

  if (entry_addr == 0) {
    LOG(INFO) << "find got entry address failed!";
    return 0;
  }

  uint64_t original_addr = 0;

  memcpy(&original_addr, (uint64_t*)entry_addr, sizeof(uint64_t));

  uint64_t page_size = getpagesize();
  uint64_t entry_page_start = PAGE_START(entry_addr, page_size);

  int res =
      mprotect((uint64_t*)entry_page_start, page_size, PROT_READ | PROT_WRITE);
  if (res != 0) {
    LOG(INFO) << "mprotect failed! ";
    return 0;
  }

  memcpy((uint64_t*)entry_addr, &hook_func, sizeof(uint64_t));
  return original_addr;
}

typedef void* (*NEW_TYPE)(size_t);

NEW_TYPE g_new;

uint64_t h_new(size_t s) {
  LOG(INFO) << "ch my new " << s << ", global operator new=" << (uint64_t)g_new;
  uint64_t value = (uint64_t)g_new(s);
  return value;
}

void hook_malloc() {
  const char* library = "/lib/libtest.so";
  g_new = (NEW_TYPE)do_hook(library, (uint64_t)h_new, "_Znwm");

  if (!g_new) {
    LOG(INFO) << "hook operator new failed";
  }
}

typedef void* (*DELETE_TYPE)(void*);

DELETE_TYPE g_delete;

uint64_t h_delete(void* s) {
  LOG(INFO) << "ch my operator delete " << s
            << ", global operator delete=" << (uint64_t)g_delete;
  uint64_t value = (uint64_t)g_delete(s);
  return value;
}

void hook_delete() {
  const char* library = "/lib/libtest.so";
  g_delete = (TYPE)do_hook(library, (uint64_t)h_delete, "_ZdlPv");

  if (!g_delete) {
    LOG(INFO) << "hook operator delete failed";
  }
}

#ifdef __cplusplus
}
#endif
