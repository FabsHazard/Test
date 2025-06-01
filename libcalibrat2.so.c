typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long double    longdouble;
typedef long long    longlong;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined3;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined5;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef int    wchar_t;
typedef unsigned short    word;
typedef pointer pointer __((offset(0x8)));

typedef void _IO_lock_t;

typedef struct _IO_marker _IO_marker, *P_IO_marker;

typedef struct _IO_FILE _IO_FILE, *P_IO_FILE;

typedef long __off_t;

typedef longlong __quad_t;

typedef __quad_t __off64_t;

typedef ulong size_t;

struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    ushort _cur_column;
    char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    void *__pad1;
    void *__pad2;
    void *__pad3;
    void *__pad4;
    size_t __pad5;
    int _mode;
    char _unused2[40];
};

struct _IO_marker {
    struct _IO_marker *_next;
    struct _IO_FILE *_sbuf;
    int _pos;
};

typedef struct stat stat, *Pstat;

typedef ulonglong __u_quad_t;

typedef __u_quad_t __dev_t;

typedef ulong __ino_t;

typedef uint __mode_t;

typedef uint __nlink_t;

typedef uint __uid_t;

typedef uint __gid_t;

typedef long __blksize_t;

typedef long __blkcnt_t;

typedef struct timespec timespec, *Ptimespec;

typedef long __time_t;

struct timespec {
    __time_t tv_sec;
    long tv_nsec;
};

struct stat {
    __dev_t st_dev;
    ushort __pad1;
    __ino_t st_ino;
    __mode_t st_mode;
    __nlink_t st_nlink;
    __uid_t st_uid;
    __gid_t st_gid;
    __dev_t st_rdev;
    ushort __pad2;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    ulong __unused4;
    ulong __unused5;
};

typedef struct _IO_FILE FILE;

typedef int __jmp_buf[6];

typedef int __ssize_t;

typedef __ssize_t ssize_t;

typedef int __pid_t;

typedef union pthread_mutex_t pthread_mutex_t, *Ppthread_mutex_t;

typedef struct __pthread_mutex_s __pthread_mutex_s, *P__pthread_mutex_s;

typedef union _union_13 _union_13, *P_union_13;

typedef struct __pthread_internal_slist __pthread_internal_slist, *P__pthread_internal_slist;

typedef struct __pthread_internal_slist __pthread_slist_t;

struct __pthread_internal_slist {
    struct __pthread_internal_slist *__next;
};

union _union_13 {
    int __spins;
    __pthread_slist_t __list;
};

struct __pthread_mutex_s {
    int __lock;
    uint __count;
    int __owner;
    int __kind;
    uint __nusers;
    union _union_13 field5_0x14;
};

union pthread_mutex_t {
    struct __pthread_mutex_s __data;
    char __size[24];
    long __align;
};

typedef union pthread_mutexattr_t pthread_mutexattr_t, *Ppthread_mutexattr_t;

union pthread_mutexattr_t {
    char __size[4];
    int __align;
};

typedef int pthread_once_t;

typedef union pthread_cond_t pthread_cond_t, *Ppthread_cond_t;

typedef struct _struct_16 _struct_16, *P_struct_16;

struct _struct_16 {
    int __lock;
    uint __futex;
    ulonglong __total_seq;
    ulonglong __wakeup_seq;
    ulonglong __woken_seq;
    void *__mutex;
    uint __nwaiters;
    uint __broadcast_seq;
};

union pthread_cond_t {
    struct _struct_16 __data;
    char __size[48];
    longlong __align;
};

typedef ulong pthread_t;

typedef uint pthread_key_t;

typedef union pthread_attr_t pthread_attr_t, *Ppthread_attr_t;

union pthread_attr_t {
    char __size[36];
    long __align;
};

typedef struct __ndk1 __ndk1, *P__ndk1;

struct __ndk1 { // PlaceHolder Class Structure
};

typedef struct char_traits<wchar_t> char_traits<wchar_t>, *Pchar_traits<wchar_t>;

struct char_traits<wchar_t> { // PlaceHolder Class Structure
};

typedef struct __itoa __itoa, *P__itoa;

struct __itoa { // PlaceHolder Class Structure
};

typedef void *__gnuc_va_list;

typedef struct __jmp_buf_tag __jmp_buf_tag, *P__jmp_buf_tag;

typedef struct __sigset_t __sigset_t, *P__sigset_t;

struct __sigset_t {
    ulong __val[32];
};

struct __jmp_buf_tag {
    __jmp_buf __jmpbuf;
    int __mask_was_saved;
    struct __sigset_t __saved_mask;
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct out_of_range out_of_range, *Pout_of_range;

struct out_of_range { // PlaceHolder Structure
};

typedef struct bad_cast bad_cast, *Pbad_cast;

struct bad_cast { // PlaceHolder Structure
};

typedef struct logic_error logic_error, *Plogic_error;

struct logic_error { // PlaceHolder Structure
};

typedef struct nothrow_t nothrow_t, *Pnothrow_t;

struct nothrow_t { // PlaceHolder Structure
};

typedef struct invalid_argument invalid_argument, *Pinvalid_argument;

struct invalid_argument { // PlaceHolder Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Structure
};

typedef struct bad_typeid bad_typeid, *Pbad_typeid;

struct bad_typeid { // PlaceHolder Structure
};

typedef struct underflow_error underflow_error, *Punderflow_error;

struct underflow_error { // PlaceHolder Structure
};

typedef undefined align_val_t;

typedef struct length_error length_error, *Plength_error;

struct length_error { // PlaceHolder Structure
};

typedef struct runtime_error runtime_error, *Pruntime_error;

struct runtime_error { // PlaceHolder Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
};

typedef struct overflow_error overflow_error, *Poverflow_error;

struct overflow_error { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct range_error range_error, *Prange_error;

struct range_error { // PlaceHolder Structure
};

typedef struct domain_error domain_error, *Pdomain_error;

struct domain_error { // PlaceHolder Structure
};

typedef struct bad_array_new_length bad_array_new_length, *Pbad_array_new_length;

struct bad_array_new_length { // PlaceHolder Structure
};

typedef undefined random_access_iterator_tag;

typedef struct basic_string basic_string, *Pbasic_string;

struct basic_string { // PlaceHolder Structure
};

typedef struct allocator allocator, *Pallocator;

struct allocator { // PlaceHolder Structure
};

typedef struct __less __less, *P__less;

struct __less { // PlaceHolder Structure
};

typedef struct basic_string_view basic_string_view, *Pbasic_string_view;

struct basic_string_view { // PlaceHolder Structure
};

typedef struct basic_string<wchar_t,std::__ndk1::char_traits<wchar_t>,std::__ndk1::allocator<wchar_t>> basic_string<wchar_t,std::__ndk1::char_traits<wchar_t>,std::__ndk1::allocator<wchar_t>>, *Pbasic_string<wchar_t,std::__ndk1::char_traits<wchar_t>,std::__ndk1::allocator<wchar_t>>;

struct basic_string<wchar_t,std::__ndk1::char_traits<wchar_t>,std::__ndk1::allocator<wchar_t>> { // PlaceHolder Structure
};

typedef struct basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>> basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>, *Pbasic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>>;

struct basic_string<char,std::__ndk1::char_traits<char>,std::__ndk1::allocator<char>> { // PlaceHolder Structure
};

typedef undefined __wrap_iter;

typedef undefined _EnableIfImpl;

typedef int (*__compar_fn_t)(void *, void *);

typedef struct Elf32_Sym Elf32_Sym, *PElf32_Sym;

struct Elf32_Sym {
    dword st_name;
    dword st_value;
    dword st_size;
    byte st_info;
    byte st_other;
    word st_shndx;
};

typedef struct Elf32_Rel Elf32_Rel, *PElf32_Rel;

struct Elf32_Rel {
    dword r_offset; // location to apply the relocation action
    dword r_info; // the symbol table index and the type of relocation
};

typedef struct Elf32_Phdr Elf32_Phdr, *PElf32_Phdr;

typedef enum Elf_ProgramHeaderType_ARM {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482,
    PT_ARM_EXIDX=1879048192
} Elf_ProgramHeaderType_ARM;

struct Elf32_Phdr {
    enum Elf_ProgramHeaderType_ARM p_type;
    dword p_offset;
    dword p_vaddr;
    dword p_paddr;
    dword p_filesz;
    dword p_memsz;
    dword p_flags;
    dword p_align;
};

typedef enum Elf32_DynTag_ARM {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf32_DynTag_ARM;

typedef struct GnuBuildId GnuBuildId, *PGnuBuildId;

struct GnuBuildId {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[4]; // Vendor name
    byte hash[20];
};

typedef struct Elf32_Dyn_ARM Elf32_Dyn_ARM, *PElf32_Dyn_ARM;

struct Elf32_Dyn_ARM {
    enum Elf32_DynTag_ARM d_tag;
    dword d_val;
};

typedef enum Elf_SectionHeaderType_ARM {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_ARM_EXIDX=1879048193,
    SHT_ARM_PREEMPTMAP=1879048194,
    SHT_ARM_ATTRIBUTES=1879048195,
    SHT_ARM_DEBUGOVERLAY=1879048196,
    SHT_ARM_OVERLAYSECTION=1879048197
} Elf_SectionHeaderType_ARM;

typedef struct Elf32_Shdr Elf32_Shdr, *PElf32_Shdr;

struct Elf32_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_ARM sh_type;
    dword sh_flags;
    dword sh_addr;
    dword sh_offset;
    dword sh_size;
    dword sh_link;
    dword sh_info;
    dword sh_addralign;
    dword sh_entsize;
};

typedef struct ElfNote_8_132 ElfNote_8_132, *PElfNote_8_132;

struct ElfNote_8_132 {
    dword namesz; // Length of name field
    dword descsz; // Length of description field
    dword type; // Vendor specific type
    char name[8]; // Vendor name
    byte description[132]; // Blob value
};

typedef struct Elf32_Ehdr Elf32_Ehdr, *PElf32_Ehdr;

struct Elf32_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    dword e_entry;
    dword e_phoff;
    dword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef ulonglong uintmax_t;

typedef longlong intmax_t;




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x000ef760) overlaps instruction at (ram,0x000ef75e)
// 
// WARNING: Removing unreachable block (ram,0x000ef7fc)
// WARNING: Removing unreachable block (ram,0x000ef804)
// WARNING: Removing unreachable block (ram,0x000ef7c0)
// WARNING: Removing unreachable block (ram,0x000ef39c)
// WARNING: Removing unreachable block (ram,0x000ef3ac)
// WARNING: Removing unreachable block (ram,0x000ef3d2)
// WARNING: Removing unreachable block (ram,0x000ef418)
// WARNING: Removing unreachable block (ram,0x000efbd6)
// WARNING: Removing unreachable block (ram,0x000efbf6)
// WARNING: Removing unreachable block (ram,0x000efc08)
// WARNING: Removing unreachable block (ram,0x000efc14)
// WARNING: Removing unreachable block (ram,0x000efc1e)
// WARNING: Removing unreachable block (ram,0x000ef6cc)
// WARNING: Removing unreachable block (ram,0x000ef6ce)
// WARNING: Removing unreachable block (ram,0x000ef642)
// WARNING: Removing unreachable block (ram,0x000ef666)
// WARNING: Removing unreachable block (ram,0x000ef670)
// WARNING: Removing unreachable block (ram,0x000ef6ee)
// WARNING: Removing unreachable block (ram,0x000ef700)
// WARNING: Removing unreachable block (ram,0x000ef704)
// WARNING: Removing unreachable block (ram,0x000ef70e)
// WARNING: Removing unreachable block (ram,0x000ef71a)
// WARNING: Removing unreachable block (ram,0x000ef722)
// WARNING: Removing unreachable block (ram,0x000ef738)
// WARNING: Removing unreachable block (ram,0x000ef760)
// WARNING: Removing unreachable block (ram,0x000ef746)
// WARNING: Removing unreachable block (ram,0x000ef76a)
// WARNING: Removing unreachable block (ram,0x000ef76c)
// WARNING: Removing unreachable block (ram,0x000ef828)
// WARNING: Removing unreachable block (ram,0x000ef832)
// WARNING: Removing unreachable block (ram,0x000ef8a6)
// WARNING: Removing unreachable block (ram,0x000ef79a)
// WARNING: Removing unreachable block (ram,0x000ef7f6)
// WARNING: Removing unreachable block (ram,0x000ef7ae)
// WARNING: Removing unreachable block (ram,0x000ef3e8)

undefined8
FUN_000ef876(undefined4 param_1,int param_2,undefined2 param_3,undefined4 param_4,undefined4 param_5
            )

{
  int unaff_r4;
  undefined1 unaff_r5;
  uint unaff_r6;
  undefined4 unaff_r11;
  char in_CY;
  undefined4 in_cr1;
  
  if (in_CY == '\0') {
    *(undefined1 *)(unaff_r4 + 9) = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((unaff_r6 >> 3 & 1) == 0 || unaff_r6 >> 4 == 0) {
    coprocessor_storelong(8,in_cr1,unaff_r11);
    *(undefined2 *)((unaff_r6 >> 4) + 0x26) = param_3;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(*(int *)(param_2 + 0x3e) << 9,param_5);
}



// WARNING: Control flow encountered bad instruction data

void thunk_EXT_FUN_ff2fc578(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void processEntry _FINI_1(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)FUN_001473ac();
                    // WARNING: Could not recover jumptable at 0x0014724c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void processEntry entry(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)FUN_001473ac();
                    // WARNING: Could not recover jumptable at 0x0014724c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void _FINI_0(undefined1 *param_1,undefined1 *param_2,int param_3)

{
  if (param_3 != 0) {
    do {
      param_3 = param_3 + -1;
      *param_1 = *param_2;
      param_2 = param_2 + 1;
      param_1 = param_1 + 1;
    } while (param_3 != 0);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00147408)

undefined8 FUN_001473ac(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  int unaff_r5;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  int unaff_r9;
  undefined4 *unaff_r10;
  undefined4 in_r12;
  uint *in_lr;
  undefined4 *local_32c;
  uint *local_310;
  undefined *local_30c;
  int local_2fc;
  int local_2f8;
  int local_2f4;
  uint local_2e8;
  uint local_2e4;
  uint local_2d4;
  uint local_2d0;
  int local_2c0;
  uint local_2b4;
  uint auStack_2b0 [12];
  byte abStack_280 [256];
  int local_180;
  byte abStack_14c [256];
  uint local_4c;
  uint local_48;
  uint local_44;
  undefined4 local_40;
  uint local_3c [4];
  int local_2c;
  
  local_40 = 0x469ee221;
  local_44 = 0xfd673333;
  local_48 = 0x16a3c230;
  local_4c = 0x5c3dee4;
  uVar6 = 0x24;
  do {
    uVar5 = local_4c;
    if (0x31 < uVar6) goto LAB_001488d4;
                    // WARNING: Could not find normalized switch variable to match jumptable
    switch(uVar6) {
    case 0:
      local_310 = &local_2b4;
      uVar6 = 0x21;
      break;
    case 2:
      uVar6 = 0x1a;
      uVar5 = local_48 * 4 + 0xce44dbce;
      uVar10 = uVar5 ^ 0x12ede385;
      local_48 = uVar10 * uVar5 + 0x98ceb4aa;
      local_44 = uVar10 * uVar5;
      local_4c = local_48 + uVar10;
      break;
    case 4:
      local_32c = unaff_r10 + -0xb9e0;
      local_3c[3] = local_32c[unaff_r10[9] + 3] ^ unaff_r10[3];
      uVar5 = 0xb54cda56;
      puVar4 = local_30c;
      puVar7 = in_lr;
      uVar6 = local_2e4;
      if (local_2e4 == 0) {
        uVar6 = 0xffffffff;
      }
      else {
        do {
          uVar6 = uVar6 - 1;
          *(undefined *)puVar7 = *puVar4;
          puVar4 = puVar4 + 1;
          puVar7 = (uint *)((int)puVar7 + 1);
        } while (uVar6 != 0);
        uVar6 = (local_2e4 >> 2) - 1;
        if (uVar6 < 0x34) {
          uVar10 = local_2e4 >> 2;
          if (uVar10 == 8) {
            uVar6 = 7;
            uVar5 = 0x6a99b4ac;
          }
          else if (uVar10 == 10) {
            uVar6 = 9;
            uVar5 = 0xcc623af3;
          }
          else if (uVar10 == 0x10) {
            uVar6 = 0xf;
            uVar5 = 0x8ff34781;
          }
          else {
            uVar12 = LZCOUNT(uVar10) | 0xffffffe0;
            if (0xfffffff9 < uVar12) {
              iVar14 = uVar12 + 7;
              uVar5 = 1 << (uVar12 + 6 & 0xff);
              uVar10 = uVar10 << (uVar12 + 6 & 0xff);
              uVar12 = 0x34;
              iVar2 = 0;
              do {
                iVar14 = iVar14 + -1;
                if (uVar10 <= uVar12) {
                  iVar2 = iVar2 + uVar5;
                  uVar12 = uVar12 - uVar10;
                }
                uVar5 = uVar5 >> 1;
                uVar10 = uVar10 >> 1;
              } while (0 < iVar14);
              uVar5 = iVar2 * -0x61c88647 + 0xb54cda56;
            }
          }
        }
      }
      uVar10 = *in_lr;
      do {
        uVar9 = (uVar5 << 0x1c) >> 0x1e;
        uVar12 = uVar10;
        uVar13 = uVar6;
        if (0 < (int)uVar6) {
          uVar12 = in_lr[uVar6];
          uVar3 = uVar6;
          do {
            uVar11 = in_lr[uVar3 - 1];
            uVar10 = uVar12 - ((uVar11 >> 5 ^ uVar10 << 2) + (uVar11 << 4 ^ uVar10 >> 3) ^
                              (local_3c[uVar3 & 3 ^ uVar9] ^ uVar11) + (uVar10 ^ uVar5));
            in_lr[uVar3] = uVar10;
            uVar13 = uVar3 - 1;
            bVar1 = 0 < (int)uVar3;
            uVar12 = uVar11;
            uVar3 = uVar13;
          } while (uVar13 != 0 && bVar1);
          uVar12 = *in_lr;
        }
        uVar3 = in_lr[uVar6];
        uVar10 = uVar12 - ((uVar3 >> 5 ^ uVar10 << 2) + (uVar3 << 4 ^ uVar10 >> 3) ^
                          (local_3c[uVar13 & 3 ^ uVar9] ^ uVar3) + (uVar10 ^ uVar5));
        uVar5 = uVar5 + 0x61c88647;
        *in_lr = uVar10;
      } while (uVar5 != 0);
      do {
        software_interrupt(0);
      } while (in_lr == (uint *)0xfffffffc);
      uVar6 = 0x19;
      break;
    case 6:
      uVar6 = 0x21;
      local_2b4 = (local_310[local_2d4] ^ local_4c ^ 0x9b6f48e8) + local_2b4;
      local_310[local_2d4] = local_2b4 >> (local_4c + 0xede3 & 0xff);
      local_2d4 = local_2d4 + 1;
      break;
    case 8:
      return CONCAT44((&switchD_00147430::switchdataD_00147434)[uVar6],local_32c);
    case 10:
      uVar6 = (uint)(local_2c0 * -0x639f079f) >> 0x11;
      uVar5 = local_4c + ((uint)(local_2c0 * -0x639f079f) >> 0x11) + 0x35a9e21;
      uVar5 = uVar5 + local_4c ^ uVar5;
      do {
        software_interrupt(0);
      } while (local_2fc == -4);
      local_4c = uVar5 * 2 + 0xd31442d0;
      local_44 = uVar5 << 1;
      local_48 = (uVar5 * 2 - uVar6) + 0xd9800176;
      uVar6 = 0x37 - uVar6 & 0x3f;
      break;
    case 0xc:
      local_44 = local_44 & (local_48 ^ 0xd53a9c23);
      local_48 = local_44 ^ local_48;
      local_4c = local_48 - local_44;
      local_2d0 = local_44 ^ 0x80d04615;
      goto LAB_00147ab0;
    case 0xe:
      iVar2 = 0x6b8 - ((uint)(local_2c0 * -0x31e5da95) >> 0x11);
      local_2c = iVar2;
      uVar6 = (uint)(local_2c0 * -0x31e5da95) >> 0x11;
      if (iVar2 != 0) {
        uVar5 = (0x75d61869 - uVar6) * -0x1a082c53;
        puVar7 = &DAT_001489c4;
        puVar8 = auStack_2b0;
        do {
          uVar12 = *puVar7;
          iVar2 = iVar2 + -1;
          uVar10 = uVar12 ^ uVar5;
          *puVar8 = uVar10;
          uVar5 = uVar10 * uVar12 + uVar5;
          puVar7 = puVar7 + 1;
          puVar8 = puVar8 + 1;
        } while (iVar2 != 0);
      }
      local_4c = (local_48 * local_4c ^ local_4c) - local_48 * local_4c;
      uVar6 = 0x2e - uVar6 & 0x3f;
      local_44 = local_4c + 0x32401aec;
      local_48 = local_4c + 0x32401aec ^ local_4c;
      break;
    case 0x10:
      local_2d0 = local_2d0 + local_48 + 0x4ac74b16;
LAB_00147ab0:
      uVar6 = 0x14;
      break;
    case 0x12:
      uVar6 = 0xb;
      if (unaff_r5 < (int)((local_2f8 + 0x1d2b1b41) - local_4c)) {
        uVar6 = 0x2a;
      }
      break;
    case 0x14:
      uVar6 = 0x20;
      local_2c0 = 0x16d444d8;
      if ((int)local_2d0 < (int)((local_2f4 + 0x34686ecb) - local_4c)) {
        uVar6 = 0x17;
      }
      break;
    case 0x16:
      do {
        software_interrupt(0);
      } while (unaff_r9 == -4);
      uVar6 = 0x28;
      local_48 = local_44 * 4 + 0x90072dc2;
      local_4c = local_48 ^ 0xbf139508;
      iVar2 = 0x5ff69124;
      local_2f4 = unaff_r9;
      goto LAB_00148088;
    case 0x18:
      local_48 = local_44 + 0x6ef5dbc5;
      local_4c = local_44 + 0x6ef5dbc5 & local_44;
      uVar6 = 0x2c;
      local_2c0 = 0x5c53601b;
      if (local_2e8 == (local_44 & 0xff ^ 0x5f)) {
        uVar6 = 0x1e;
      }
      break;
    case 0x1a:
      unaff_r9 = local_4c + 0xa51977ee;
      local_44 = local_48 + local_4c;
      do {
        software_interrupt(0);
      } while (unaff_r9 == -4);
      uVar6 = 0x15;
      break;
    case 0x1c:
      uVar6 = 0xf;
      local_48 = (local_4c ^ local_48 ^ 0xb777a522) + 0xf7dec70b ^ 0x6c247ca7;
      local_4c = local_48 << 1;
      local_2c0 = 0x20a540e4;
      local_44 = local_48 * 2 + 0xd2b51701;
      break;
    case 0x1e:
      unaff_r10 = &DAT_00147f44;
      in_r12 = 0x10000;
      local_30c = &DAT_003069a4;
      uVar6 = 4 - ((uint)(local_2c0 * 0xae6401) >> 0x11) & 0x3f;
      break;
    case 0x20:
      uVar6 = 0x18;
      iVar2 = (local_4c - local_48) + 0x1d2b373f;
      local_4c = iVar2 * 2 + 0x891352aa;
      local_48 = local_4c + iVar2;
      local_4c = local_48 ^ local_4c;
      iVar2 = 0x6e6b8799;
LAB_00148088:
      local_44 = local_4c + iVar2;
      break;
    case 0x22:
      uVar6 = 0x25;
      local_4c = 0xe3d991a;
      local_44 = 0xc6d2a9d4;
      local_48 = uVar5 + 0xa3a5f462;
      break;
    case 0x24:
      local_40 = 0xf332df54;
      uVar6 = 0xe;
      local_48 = 0x64213af8;
      local_44 = 0xa95d1603;
      local_4c = 0x7437d9cc;
      local_2e8 = 0xb4b65f2e;
      local_2c0 = 0x4a3e7629;
      break;
    case 0x26:
      uVar6 = 0x13;
      if (local_180 == 0) {
        uVar6 = 0x2e;
      }
      break;
    case 0x28:
      local_44 = local_44 * local_44;
      do {
        software_interrupt(0);
      } while (unaff_r9 == -4);
      uVar6 = 0x11;
      local_48 = local_44 ^ local_44 * local_44 + 0x7c16ac9f;
      local_4c = local_48 & 0x71f370cc;
      local_44 = local_4c + 0xdd1444b1;
      break;
    case 0x2a:
      if (((((uint)abStack_14c[(local_44 ^ 0xc6d2a9d6) + unaff_r5] == (local_4c + 0x15 & 0xff)) &&
           ((uint)(byte)(&stack0x392d54e4)[unaff_r5 + local_44] == (local_48 + 0x46 & 0xff))) &&
          ((uint)(byte)(&stack0x4974089d)[unaff_r5 + local_48] == (local_44 - 0x70 & 0xff))) &&
         ((((uint)abStack_14c[(local_44 ^ 0xc6d2a9d2) + unaff_r5] == (local_48 + 0x31 & 0xff) &&
           ((local_48 & 0xff ^ 0x76) == (uint)(byte)(&stack0xe2d4e36f)[unaff_r5 + local_4c])) &&
          ((local_48 & 0xff ^ 0x4b) == (uint)abStack_14c[unaff_r5])))) {
        uVar6 = 0x23;
        if ((uint)abStack_14c[(local_4c ^ 0x1d2b1b45) + unaff_r5] != (local_4c - 0x12 & 0xff)) {
          uVar6 = 0x2d;
        }
      }
      else {
        uVar6 = 0x2d;
      }
      break;
    case 0x2c:
      uVar6 = 0;
      local_2b4 = local_2d0 * local_2f4;
      local_2d4 = local_44 ^ 0xe589a6f;
      break;
    case 0x2e:
      uVar6 = 0x31;
      local_3c[0] = unaff_r10[unaff_r10[9] + -0xb9df] ^ unaff_r10[1];
      break;
    case 0x30:
      local_2e8 = (uint)abStack_280[(local_44 ^ 0x80d0461e) + local_2d0];
      uVar6 = 2 - ((uint)(local_2c0 * 0x75d0b205) >> 0x11) & 0x3f;
    }
LAB_001488d4:
    if (uVar6 == 0x32) {
      return CONCAT44(in_r12,in_lr);
    }
  } while( true );
}



// WARNING: Control flow encountered bad instruction data

void JNI_OnLoad(undefined4 param_1,undefined2 param_2,int param_3)

{
  ushort uVar1;
  char cVar2;
  int extraout_r1;
  int unaff_r4;
  int unaff_r6;
  undefined4 unaff_r9;
  undefined4 unaff_r10;
  undefined4 in_cr4;
  undefined4 in_cr5;
  undefined4 in_stack_0000002c;
  
  *(undefined2 *)(unaff_r4 + 0x3e) = param_2;
  thunk_EXT_FUN_ff2fc578();
  uVar1 = *(ushort *)(extraout_r1 + param_3);
  *(int *)(uVar1 + 0x28) = unaff_r6;
  if (uVar1 >> 0xb != 0 && !SBORROW4(unaff_r6,2)) {
    coprocessor_load(6,in_cr4,unaff_r9);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar2 = *(char *)((uint)*(byte *)(unaff_r4 + 0xe) + unaff_r6 + -2);
  *(undefined1 *)(unaff_r6 + 0x10) = *(undefined1 *)(unaff_r6 + -1);
  coprocessor_loadlong(0xd,in_cr5,unaff_r10);
                    // WARNING: Could not recover jumptable at 0x002c08e0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)((int)cVar2 & ~(uint)&stack0x000003f4))(in_stack_0000002c,*(undefined2 *)(uVar1 + 0x16))
  ;
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_001aa684(undefined1 *param_1,undefined4 param_2)

{
  int unaff_r5;
  undefined1 unaff_r8;
  int unaff_r10;
  int *in_lr;
  char in_NG;
  undefined1 in_ZR;
  undefined1 in_OV;
  undefined4 in_cr7;
  
  if ((bool)in_NG) {
    in_OV = SCARRY4(unaff_r5,0x8600);
    in_NG = unaff_r5 + 0x8600 < 0;
    in_ZR = unaff_r5 == -0x8600;
  }
  if ((bool)in_ZR || in_NG != in_OV) {
    *param_1 = unaff_r8;
  }
  *in_lr = (int)in_lr - (unaff_r10 >> 0x18);
  if (!(bool)in_ZR) {
    if ((bool)in_ZR) {
      coprocessor_storelong(8,in_cr7,param_2);
    }
    if (!(bool)in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_001b77cc(undefined4 param_1,undefined4 param_2,int *param_3)

{
  int unaff_r4;
  undefined1 unaff_r5;
  int unaff_r7;
  
  *(undefined1 *)(unaff_r7 + 0x1f) = unaff_r5;
  *(int *)(*param_3 + 0x58) = param_3[2];
  param_3[0x13] = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void _INIT_2(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 unaff_r4;
  undefined4 unaff_r6;
  uint unaff_r7;
  undefined4 unaff_r8;
  undefined4 unaff_r9;
  undefined4 *unaff_r10;
  undefined4 unaff_r11;
  uint in_r12;
  char in_NG;
  undefined1 in_ZR;
  undefined1 in_CY;
  char in_OV;
  undefined4 in_cr5;
  
                    // WARNING: Read-only address (ram,0x001fcdfc) is written
                    // WARNING: Read-only address (ram,0x001fce00) is written
                    // WARNING: Read-only address (ram,0x001fce04) is written
                    // WARNING: Read-only address (ram,0x001fce08) is written
  DAT_001fce20 = 0x1fcdfc;
  uRam001fcdfc = param_2;
  uRam001fce00 = param_3;
  uRam001fce04 = unaff_r4;
  uRam001fce08 = unaff_r6;
  DAT_001fce0c = unaff_r9;
  DAT_001fce10 = unaff_r10;
  DAT_001fce14 = unaff_r11;
  DAT_001fce18 = in_r12;
  DAT_001fce1c = (undefined1 *)register0x00000054;
  if ((bool)in_OV) {
    *unaff_r10 = param_1;
    unaff_r10[1] = param_3;
    unaff_r10[2] = unaff_r4;
    unaff_r10[3] = unaff_r6;
    unaff_r10[4] = unaff_r8;
    unaff_r10[5] = in_r12;
    unaff_r10[6] = 0x1fce00;
  }
  else {
    in_CY = 0xfffd17ff < in_r12;
    in_OV = SCARRY4(in_r12,0x2e800);
    in_NG = (int)(&UNK_0002e800 + in_r12) < 0;
    in_ZR = in_r12 == 0xfffd1800;
  }
  if ((bool)in_NG) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!(bool)in_CY || (bool)in_ZR) {
    in_NG = (int)(unaff_r7 | 0x69) < 0;
  }
  if (in_NG == in_OV) {
    coprocessor_load(2,in_cr5,unaff_r8);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_00227e38(undefined4 param_1,undefined4 param_2)

{
  undefined4 unaff_r5;
  undefined4 unaff_r6;
  undefined4 unaff_r7;
  undefined4 unaff_r8;
  undefined4 unaff_r9;
  int unaff_r11;
  undefined4 in_r12;
  undefined4 in_lr;
  char in_NG;
  char in_OV;
  
  if (in_NG != in_OV) {
    *(undefined **)(unaff_r11 + -4) = &UNK_00227e40;
    *(undefined4 *)(unaff_r11 + -8) = in_lr;
    *(BADSPACEBASE **)(unaff_r11 + -0xc) = register0x00000054;
    *(undefined4 *)(unaff_r11 + -0x10) = in_r12;
    *(undefined4 *)(unaff_r11 + -0x14) = unaff_r9;
    *(undefined4 *)(unaff_r11 + -0x18) = unaff_r8;
    *(undefined4 *)(unaff_r11 + -0x1c) = unaff_r7;
    *(undefined4 *)(unaff_r11 + -0x20) = unaff_r6;
    *(undefined4 *)(unaff_r11 + -0x24) = unaff_r5;
    *(undefined4 *)(unaff_r11 + -0x28) = param_2;
    *(undefined4 *)(unaff_r11 + -0x2c) = param_1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_002b6260(void)

{
  int in_r3;
  int unaff_r6;
  int unaff_r7;
  char in_NG;
  bool in_ZR;
  char in_OV;
  
  *(undefined1 *)(unaff_r7 + 5) = 0xb0;
  if (in_ZR || in_NG != in_OV) {
    DAT_002b62cc = (short)&stack0x00000148;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r6 + 0x32) = (short)unaff_r6;
  *(short *)((in_r3 >> 5) + 0x28) = (short)*(undefined4 *)(in_r3 + 4);
  *(char *)((unaff_r6 >> 5) + 0x16) = (char)unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void _INIT_3(void)

{
  undefined4 unaff_r6;
  bool in_NG;
  undefined4 in_cr9;
  undefined4 in_cr15;
  
  if (in_NG) {
    coprocessor_moveto(6,1,1,unaff_r6,in_cr15,in_cr9);
    FUN_00227e38();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::__next_prime(unsigned int)

void std::__ndk1::__next_prime(uint param_1)

{
  undefined2 uVar1;
  int in_r1;
  int iVar2;
  int in_r3;
  int unaff_r4;
  int unaff_r6;
  int unaff_r7;
  
  uVar1 = *(undefined2 *)(unaff_r4 + in_r1);
  iVar2 = 0x689ce828;
  func_0x004dbf70(unaff_r6 << 0x18);
  *(int *)(unaff_r7 + iVar2 + 6) = unaff_r7;
  *(char *)(in_r3 + 0xe) = (char)uVar1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_002c52c2(void)

{
  undefined4 in_cr6;
  
  coprocessor_loadlong(0xc,in_cr6,0x95883746);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5350)
// WARNING: Removing unreachable block (ram,0x0033b5d0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// unsigned int const* std::__ndk1::__lower_bound<std::__ndk1::__less<unsigned int, unsigned int>&,
// unsigned int const*, unsigned int>(unsigned int const*, unsigned int const*, unsigned int const&,
// std::__ndk1::__less<unsigned int, unsigned int>&)

uint * std::__ndk1::__lower_bound<>(uint *param_1,uint *param_2,uint *param_3,__less *param_4)

{
  undefined1 uVar1;
  ushort uVar2;
  uint *puVar3;
  undefined4 *puVar4;
  code *UNRECOVERED_JUMPTABLE;
  int *piVar5;
  undefined1 *unaff_r4;
  undefined4 unaff_r5;
  undefined4 uVar6;
  int iVar7;
  int unaff_r6;
  undefined4 *unaff_r7;
  int in_stack_000000e0;
  int in_stack_000001f8;
  undefined4 in_stack_000001fc;
  uint *in_stack_000002e0;
  
  *unaff_r7 = param_2;
  unaff_r7[1] = param_3;
  unaff_r7[2] = param_4;
  unaff_r7[3] = unaff_r5;
  unaff_r7[4] = unaff_r7;
  puVar4 = (undefined4 *)&DAT_f6ca0091;
  puVar3 = param_1;
  uVar6 = unaff_r5;
  if (param_4 == (__less *)0x0) {
    unaff_r7 = (undefined4 *)0x0;
    unaff_r4 = &stack0x00000168;
    _DAT_f6ca00a1 = 0;
    uVar6 = 0;
    _DAT_f6ca00d9 = SUB42(in_stack_000002e0,0);
    param_4 = (__less *)0x2c5358;
    puVar4 = (undefined4 *)&DAT_f6ca0164;
    _DAT_f6ca0095 = 0;
    puVar3 = in_stack_000002e0;
    _DAT_f6ca0091 = param_1;
    _DAT_f6ca0099 = unaff_r5;
    _DAT_f6ca009d = unaff_r6;
  }
  *(undefined4 **)((int)puVar4 + (int)unaff_r7) = unaff_r7;
  *(uint **)(param_4 + unaff_r6) = puVar3;
  *puVar4 = puVar3;
  puVar4[1] = in_stack_000001fc;
  puVar4[2] = param_4;
  puVar4[3] = unaff_r4;
  puVar4[4] = uVar6;
  *(char *)((int)puVar3 + unaff_r6) = (char)unaff_r7;
  iVar7 = _DAT_0000006f >> 6;
  if (in_stack_000000e0 < 0x74) {
    if (SBORROW4(in_stack_000000e0,0x73)) {
      uVar2 = *(ushort *)(in_stack_000001f8 + 0x16);
      uVar6 = *unaff_r7;
      UNRECOVERED_JUMPTABLE = (code *)unaff_r7[2];
      uVar1 = *(undefined1 *)(uVar2 + 5);
      *(short *)(unaff_r7[1] + 0xe) = (short)uVar6;
                    // WARNING: Could not recover jumptable at 0x002c46d4. Too many branches
                    // WARNING: Treating indirect jump as call
      puVar3 = (uint *)(*UNRECOVERED_JUMPTABLE)(uVar6,(uint)uVar2,uVar1);
      return puVar3;
    }
    *(short *)(in_stack_000000e0 * 0x2000 + 0x18) = (short)in_stack_000000e0;
    piVar5 = (int *)(int)*(char *)((int)unaff_r7 * 2);
    do {
      *piVar5 = (int)&stack0x000001c4;
      piVar5[1] = in_stack_000000e0;
      piVar5[2] = (int)unaff_r7;
      piVar5 = piVar5 + 3;
    } while( true );
  }
  software_interrupt(0x1a);
  *(char *)(*(int *)(param_4 + 0x40) + 0xe) = (char)in_stack_000001f8;
  *(char *)(in_stack_000000e0 + 0x15) = (char)iVar7 + -0x1a;
  DAT_002c5241 = 0xd3;
  DAT_00000055 = (undefined1)*(undefined4 *)(((uint)param_4 >> 0xd) + 8);
  *(undefined2 *)(((uint)param_4 >> 0xd) + 0x10) = 0;
  _DAT_1fd071a8 = &stack0x000003c8;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::__throw_bad_alloc()

undefined4 std::__throw_bad_alloc(void)

{
  int in_r0;
  undefined2 in_r3;
  int unaff_r5;
  undefined4 in_stack_00000000;
  
  *(undefined2 *)(in_r0 + unaff_r5) = in_r3;
  return in_stack_00000000;
}



// WARNING: Control flow encountered bad instruction data
// operator new(unsigned int)

void * operator_new(uint param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// operator new[](unsigned int)

void * operator_new__(uint param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined1 *extraout_r1;
  int extraout_r1_00;
  int *piVar5;
  undefined1 *in_r3;
  undefined1 *unaff_r4;
  int unaff_r5;
  int unaff_r6;
  byte unaff_r10;
  byte unaff_00000049;
  byte unaff_0000004a;
  byte unaff_0000004b;
  uint uVar6;
  int in_pc;
  bool bVar7;
  undefined4 in_cr2;
  undefined4 in_cr4;
  undefined4 in_cr8;
  
  uVar6 = 0x2c542f;
  func_0xff33be00();
  bVar7 = unaff_r4 < in_r3;
  piVar5 = (int *)(unaff_r4 + -(int)in_r3);
  coprocessor_storelong(0xf,in_cr4,&stack0x00000000);
  *(short *)(extraout_r1_00 + (unaff_r5 >> 8)) = (short)in_r3;
  iVar3 = _DAT_69b4930e;
  iVar2 = _DAT_69b4930a;
  puVar4 = &DAT_69b4930a;
  if (SBORROW4((int)unaff_r4,(int)in_r3)) {
    unaff_r4 = &stack0x000001fc;
    Absolute((uVar6 & 0xff) - (uint)unaff_r10);
    Absolute((uVar6 >> 8 & 0xff) - (uint)unaff_00000049);
    Absolute((uVar6 >> 0x10 & 0xff) - (uint)unaff_0000004a);
    Absolute((uVar6 >> 0x18) - (uint)unaff_0000004b);
    if (bVar7 || piVar5 == (int *)0x0) {
      *(undefined1 *)(unaff_r5 + unaff_r6) = 0x12;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(short *)(_DAT_69b4930a * 2) = (short)piVar5;
    uVar1 = *(ushort *)(iVar3 + unaff_r6);
    *piVar5 = iVar2;
    piVar5[1] = (int)unaff_r4;
    piVar5[2] = unaff_r5;
    piVar5[3] = (uint)uVar1;
    in_r3 = (undefined1 *)coprocessor_movefromRt(0,0,in_cr8);
    coprocessor_movefromRt2(0,0,in_cr8);
    coprocessor_loadlong(2,in_cr2,*(int *)(((in_pc >> 9) - unaff_r6) + 0x68) + 0x28c);
    func_0xff6a354e(*(undefined4 *)(in_r3 + 0x44));
    puVar4 = extraout_r1;
  }
  unaff_r4[0xc] = (char)in_r3;
  puVar4[7] = (char)puVar4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// operator new[](unsigned int, std::nothrow_t const&)

void * operator_new__(uint param_1,nothrow_t *param_2)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined1 *extraout_r1;
  int *piVar5;
  undefined1 *in_r3;
  undefined1 *unaff_r4;
  int unaff_r5;
  int unaff_r6;
  byte unaff_r10;
  byte unaff_00000049;
  byte unaff_0000004a;
  byte unaff_0000004b;
  uint in_lr;
  int in_pc;
  bool bVar6;
  undefined4 in_cr2;
  undefined4 in_cr4;
  undefined4 in_cr8;
  
  bVar6 = unaff_r4 < in_r3;
  piVar5 = (int *)(unaff_r4 + -(int)in_r3);
  coprocessor_storelong(0xf,in_cr4,&stack0x00000000);
  *(short *)(param_2 + (unaff_r5 >> 8)) = (short)in_r3;
  iVar3 = _DAT_69b4930e;
  iVar2 = _DAT_69b4930a;
  puVar4 = &DAT_69b4930a;
  if (SBORROW4((int)unaff_r4,(int)in_r3)) {
    unaff_r4 = &stack0x000001fc;
    Absolute((in_lr & 0xff) - (uint)unaff_r10);
    Absolute((in_lr >> 8 & 0xff) - (uint)unaff_00000049);
    Absolute((in_lr >> 0x10 & 0xff) - (uint)unaff_0000004a);
    Absolute((in_lr >> 0x18) - (uint)unaff_0000004b);
    if (bVar6 || piVar5 == (int *)0x0) {
      *(undefined1 *)(unaff_r5 + unaff_r6) = 0x12;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(short *)(_DAT_69b4930a * 2) = (short)piVar5;
    uVar1 = *(ushort *)(iVar3 + unaff_r6);
    *piVar5 = iVar2;
    piVar5[1] = (int)unaff_r4;
    piVar5[2] = unaff_r5;
    piVar5[3] = (uint)uVar1;
    in_r3 = (undefined1 *)coprocessor_movefromRt(0,0,in_cr8);
    coprocessor_movefromRt2(0,0,in_cr8);
    coprocessor_loadlong(2,in_cr2,*(int *)(((in_pc >> 9) - unaff_r6) + 0x68) + 0x28c);
    func_0xff6a354e(*(undefined4 *)(in_r3 + 0x44));
    puVar4 = extraout_r1;
  }
  unaff_r4[0xc] = (char)in_r3;
  puVar4[7] = (char)puVar4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete(void*)

void operator_delete(void *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete(void*, unsigned int)

void operator_delete(void *param_1,uint param_2)

{
  undefined4 in_cr6;
  
  coprocessor_loadlong(0xc,in_cr6,0x95883746);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete[](void*)

void operator_delete__(void *param_1)

{
  undefined4 in_cr6;
  
  coprocessor_loadlong(0xc,in_cr6,0x95883746);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete[](void*, std::nothrow_t const&)

void operator_delete__(void *param_1,nothrow_t *param_2)

{
  undefined4 in_cr6;
  
  coprocessor_loadlong(0xc,in_cr6,0x95883746);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete[](void*, unsigned int)

void operator_delete__(void *param_1,uint param_2)

{
  int unaff_r6;
  
  *(int *)(unaff_r6 + param_2) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator new(unsigned int, std::align_val_t)

void * operator_new(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0033b5d0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// operator new(unsigned int, std::align_val_t, std::nothrow_t const&)

void * operator_new(undefined4 param_1,int param_2,int param_3)

{
  undefined1 uVar1;
  byte bVar2;
  ushort uVar3;
  undefined4 uVar4;
  void *pvVar5;
  int iVar6;
  int *piVar7;
  int unaff_r4;
  int unaff_r5;
  code *UNRECOVERED_JUMPTABLE_00;
  int unaff_r6;
  uint unaff_r7;
  undefined4 *puVar8;
  undefined4 in_r12;
  bool bVar9;
  bool bVar10;
  undefined4 in_cr12;
  int *in_stack_00000234;
  int in_stack_000002b8;
  
  bVar9 = SCARRY4(unaff_r7,0xdb);
  puVar8 = (undefined4 *)(unaff_r7 + 0xdb);
  if (bVar9) {
    bVar10 = false;
    bVar9 = unaff_r5 == 0x1ea00000;
    coprocessor_load(7,in_cr12,in_r12);
    iVar6 = func_0x010c4938();
    bVar2 = *(byte *)(param_3 + 4);
    *(char *)(unaff_r5 + iVar6) = (char)unaff_r5;
    if (!bVar10 || bVar9) {
      *(ushort *)(*(ushort *)((uint)bVar2 + unaff_r5) + 4) = (ushort)bVar2;
      func_0x00e6f93c();
      software_bkpt(0xed);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (puVar8 == (undefined4 *)0x0 || (int)puVar8 < 0 != bVar9) {
    *(undefined4 *)(unaff_r7 + 0x123) = 0x5e;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(param_2 + 8) = (char)param_1;
  if (bVar9) {
    *in_stack_00000234 = param_3;
    in_stack_00000234[1] = unaff_r6;
    in_stack_00000234[2] = in_stack_000002b8;
    *(int *)(unaff_r4 + 0x78) = unaff_r4;
    puVar8 = (undefined4 *)(int)*(short *)(param_2 + param_3);
    *puVar8 = param_1;
    puVar8[1] = param_2;
    puVar8[2] = param_3;
    puVar8[3] = in_stack_00000234 + 3;
    puVar8[4] = puVar8;
    puVar8[5] = 0xa4;
    *(undefined4 *)(_DAT_000000ac + 0x44) = 0xb6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(unaff_r5 + 8) = (char)puVar8;
  if (0xffffff24 < unaff_r7) {
    if (0x73 < param_3) {
      software_interrupt(0x1a);
      *(char *)(in_stack_00000234[0x10] + 0xe) = (char)unaff_r4;
      *(char *)(param_3 + 0x15) = (char)unaff_r5 + -0x1a;
      DAT_002c5241 = 0xd3;
      DAT_00000055 = (undefined1)*(undefined4 *)(((uint)in_stack_00000234 >> 0xd) + 8);
      *(undefined2 *)(((uint)in_stack_00000234 >> 0xd) + 0x10) = 0;
      _DAT_1fd071a8 = &stack0x000003dc;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (!SBORROW4(param_3,0x73)) {
      *(short *)(param_3 * 0x2000 + 0x18) = (short)param_3;
      piVar7 = (int *)(int)*(char *)((int)puVar8 * 2);
      do {
        *piVar7 = param_2;
        piVar7[1] = param_3;
        piVar7[2] = (int)puVar8;
        piVar7 = piVar7 + 3;
      } while( true );
    }
    uVar3 = *(ushort *)(unaff_r4 + 0x16);
    uVar4 = *puVar8;
    UNRECOVERED_JUMPTABLE_00 = *(code **)(unaff_r7 + 0xe3);
    uVar1 = *(undefined1 *)(uVar3 + 5);
    *(short *)(*(int *)(unaff_r7 + 0xdf) + 0xe) = (short)uVar4;
                    // WARNING: Could not recover jumptable at 0x002c46d4. Too many branches
                    // WARNING: Treating indirect jump as call
    pvVar5 = (void *)(*UNRECOVERED_JUMPTABLE_00)(uVar4,(uint)uVar3,uVar1);
    return pvVar5;
  }
  *(short *)((int)in_stack_00000234 + 0x36) = (short)param_1;
  UNRECOVERED_JUMPTABLE_00 = (code *)(unaff_r6 + 0x18);
  if (unaff_r4 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar3 = *(ushort *)(unaff_r4 + param_3);
  *(code **)(unaff_r6 + 0x30) = UNRECOVERED_JUMPTABLE_00;
                    // WARNING: Could not recover jumptable at 0x002c4d66. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar5 = (void *)(*UNRECOVERED_JUMPTABLE_00)
                             ((uint)uVar3,
                              (int)*(short *)(((int)UNRECOVERED_JUMPTABLE_00 >> 9) + (uint)uVar3));
  return pvVar5;
}



// WARNING: Control flow encountered bad instruction data
// operator new[](unsigned int, std::align_val_t)

void * operator_new__(void)

{
  int unaff_r4;
  int unaff_r5;
  bool in_ZR;
  bool in_CY;
  
  if (in_CY && !in_ZR) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(*(ushort *)(unaff_r4 + unaff_r5) + 4) = (short)unaff_r4;
  func_0x00e6f93c();
  software_bkpt(0xed);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator new[](unsigned int, std::align_val_t, std::nothrow_t const&)

void * operator_new__(void)

{
  undefined2 unaff_r4;
  int unaff_r7;
  bool in_ZR;
  bool in_CY;
  
  if (in_CY && !in_ZR) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined2 *)(unaff_r7 + 4) = unaff_r4;
  func_0x00e6f93c();
  software_bkpt(0xed);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// operator delete(void*, std::align_val_t)

void operator_delete(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *in_r3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 in_cr3;
  
  iVar1 = std::__ndk1::__basic_string_common<true>::__throw_length_error;
  iVar2 = *in_r3;
  iVar3 = in_r3[1];
  iVar5 = in_r3[3];
  iVar6 = in_r3[4];
  iVar7 = in_r3[5];
  *(char *)((int)in_r3 + 0x2e) = (char)iVar7;
  piVar4 = (int *)(iVar1 >> 0xc);
  *piVar4 = iVar1;
  piVar4[1] = iVar2;
  piVar4[2] = iVar3;
  piVar4[3] = (int)piVar4;
  piVar4[4] = iVar5;
  piVar4[5] = iVar7;
  coprocessor_loadlong(0,in_cr3,iVar2 + 0x50);
  *piVar4 = iVar3;
  piVar4[1] = (int)piVar4;
  piVar4[2] = iVar5;
  piVar4[3] = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete(void*, std::align_val_t, std::nothrow_t const&)

void operator_delete(int param_1,undefined4 param_2,undefined4 param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 in_cr3;
  
  iVar1 = *param_4;
  iVar2 = param_4[1];
  iVar4 = param_4[3];
  iVar5 = param_4[4];
  iVar6 = param_4[5];
  *(char *)((int)param_4 + 0x2e) = (char)iVar6;
  piVar3 = (int *)(param_1 >> 0xc);
  *piVar3 = param_1;
  piVar3[1] = iVar1;
  piVar3[2] = iVar2;
  piVar3[3] = (int)piVar3;
  piVar3[4] = iVar4;
  piVar3[5] = iVar6;
  coprocessor_loadlong(0,in_cr3,iVar1 + 0x50);
  *piVar3 = iVar2;
  piVar3[1] = (int)piVar3;
  piVar3[2] = iVar4;
  piVar3[3] = iVar5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete(void*, unsigned int, std::align_val_t)

void operator_delete(int param_1,int param_2,int param_3,int param_4)

{
  int *piVar1;
  int unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_cr3;
  
  *(char *)(param_4 + 0x16) = (char)unaff_r7;
  piVar1 = (int *)(param_1 >> 0xc);
  *piVar1 = param_1;
  piVar1[1] = param_2;
  piVar1[2] = param_3;
  piVar1[3] = (int)piVar1;
  piVar1[4] = unaff_r5;
  piVar1[5] = unaff_r7;
  coprocessor_loadlong(0,in_cr3,param_2 + 0x50);
  *piVar1 = param_3;
  piVar1[1] = (int)piVar1;
  piVar1[2] = unaff_r5;
  piVar1[3] = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete[](void*, std::align_val_t)

void operator_delete__(int param_1,int param_2,int param_3)

{
  int *piVar1;
  int unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_cr3;
  
  piVar1 = (int *)(param_1 >> 0xc);
  *piVar1 = param_1;
  piVar1[1] = param_2;
  piVar1[2] = param_3;
  piVar1[3] = (int)piVar1;
  piVar1[4] = unaff_r5;
  piVar1[5] = unaff_r7;
  coprocessor_loadlong(0,in_cr3,param_2 + 0x50);
  *piVar1 = param_3;
  piVar1[1] = (int)piVar1;
  piVar1[2] = unaff_r5;
  piVar1[3] = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// operator delete[](void*, std::align_val_t, std::nothrow_t const&)

void operator_delete__(undefined4 param_1,int param_2,undefined4 param_3,undefined4 *param_4)

{
  undefined4 unaff_r5;
  undefined4 unaff_r6;
  undefined4 in_cr3;
  
  coprocessor_loadlong(0,in_cr3,param_2 + 0x50);
  *param_4 = param_3;
  param_4[1] = param_4;
  param_4[2] = unaff_r5;
  param_4[3] = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::logic_error::logic_error(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&)

void __thiscall std::logic_error::logic_error(logic_error *this,basic_string *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::logic_error::logic_error(char const*)

void __thiscall std::logic_error::logic_error(logic_error *this,char *param_1)

{
  int unaff_r4;
  
  *(char **)(unaff_r4 + 0x30) = param_1;
  return;
}



// std::logic_error::logic_error(std::logic_error const&)

void __thiscall std::logic_error::logic_error(logic_error *this,logic_error *param_1)

{
  undefined4 uVar1;
  int *unaff_r4;
  undefined1 unaff_r5;
  int unaff_r6;
  int unaff_r7;
  
  *unaff_r4 = unaff_r6;
  unaff_r4[1] = unaff_r7;
  *(undefined1 *)(unaff_r6 + 2) = unaff_r5;
  uVar1 = uRam000000ba;
  *(uint *)(unaff_r6 + 0x40) = (uint)(unaff_r4 + 2) >> 0x1f;
  operator_delete(uVar1);
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::logic_error::TEMPNAMEPLACEHOLDERVALUE(std::logic_error const&)

void __thiscall std::logic_error::operator=(logic_error *this,logic_error *param_1)

{
  uint uVar1;
  uint in_r3;
  uint uVar2;
  int unaff_r5;
  int unaff_r7;
  uint *puVar3;
  undefined4 unaff_r11;
  bool in_ZR;
  bool in_CY;
  undefined4 in_cr7;
  undefined4 in_cr8;
  undefined8 unaff_d8;
  undefined1 in_q12 [16];
  
  software_bkpt(0x80);
  if (!in_CY || in_ZR) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (*(ushort *)(unaff_r7 + 0x30) != 0) {
    uVar1 = (int)(in_r3 << 0x1b) >> 0x1e;
    puVar3 = *(uint **)(unaff_r5 + 0x24);
    uVar2 = *(ushort *)(unaff_r7 + 0x30) + 0x23c;
    coprocessor_store(0xb,in_cr8,uVar2);
    *(short *)((int)puVar3 + uVar1 + 3) = (short)uVar2;
    *(uint *)(this + 0x104) = uVar2;
    *puVar3 = (uint)*(byte *)(in_r3 + 0x17);
    puVar3[1] = uVar1;
    puVar3[2] = in_r3;
    puVar3[3] = uVar2;
    puVar3[4] = (uint)puVar3;
    software_hlt(4);
    coprocessor_moveto2(1,10,unaff_r11,uVar1,in_cr7);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  VectorSignedUnsignedDotProduct(in_q12,unaff_d8,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::runtime_error::runtime_error(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&)

void __thiscall std::runtime_error::runtime_error(runtime_error *this,basic_string *param_1)

{
  uint uVar1;
  int unaff_r7;
  int unaff_r11;
  int in_stack_00000000;
  undefined4 in_stack_00000004;
  
  uVar1 = *(uint *)((unaff_r7 >> 3) + 8);
  software_interrupt(0xb8);
  *(char *)((uVar1 >> 0x10) + 9) = (char)uVar1;
                    // WARNING: Could not recover jumptable at 0x002c568c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)(&UNK_002c5690 + unaff_r11))(in_stack_00000000 << 0x1c,0,in_stack_00000004,0x2c5908);
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::runtime_error::runtime_error(char const*)

void __thiscall std::runtime_error::runtime_error(runtime_error *this,char *param_1)

{
  int in_r3;
  undefined4 unaff_r6;
  
  *(int *)((int)this * 2) = (int)this << 0x1a;
  *(undefined4 *)(this + in_r3) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::runtime_error::runtime_error(std::runtime_error const&)

undefined4 __thiscall std::runtime_error::runtime_error(runtime_error *this,runtime_error *param_1)

{
  undefined4 uVar1;
  undefined4 in_r3;
  char in_NG;
  bool in_ZR;
  char in_OV;
  undefined8 in_d2;
  undefined8 uVar2;
  undefined8 in_d19;
  undefined4 in_stack_00000000;
  
  if (!in_ZR && in_NG == in_OV) {
    uVar2 = VectorAdd(in_d19,in_d2,2,1);
    SatQ(uVar2,2,1);
    prRam002c5b34 = (runtime_error *)0x56346a79;
    return in_stack_00000000;
  }
  prRam002c5b34 = param_1;
                    // WARNING (jumptable): Read-only address (ram,0x002c5b34) is written
                    // WARNING: Read-only address (ram,0x002c5b34) is written
  *(runtime_error **)param_1 = param_1;
  *(undefined4 *)(param_1 + 4) = in_r3;
  *(undefined **)(param_1 + 8) = &UNK_002c5b24;
                    // WARNING: Could not recover jumptable at 0x002c5a60. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*(code *)this)();
  return uVar1;
}



// WARNING: Control flow encountered bad instruction data
// std::runtime_error::TEMPNAMEPLACEHOLDERVALUE(std::runtime_error const&)

void __thiscall std::runtime_error::operator=(runtime_error *this,runtime_error *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::__basic_string_common<true>::__throw_length_error() const

void std::__ndk1::__basic_string_common<true>::__throw_length_error(void)

{
  int in_r0;
  int in_r1;
  int in_r2;
  undefined4 in_r3;
  undefined1 unaff_r5;
  undefined1 unaff_r6;
  
  *(undefined1 *)(in_r2 + 8) = unaff_r6;
  *(undefined4 *)(in_r1 + 0xc) = in_r3;
  *(undefined1 *)(in_r0 + in_r1) = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::__basic_string_common<true>::__throw_out_of_range() const

void std::__ndk1::__basic_string_common<true>::__throw_out_of_range(void)

{
  code *UNRECOVERED_JUMPTABLE;
  int in_r1;
  undefined4 in_r3;
  undefined4 unaff_r4;
  
  *(int *)in_r1 = in_r1;
  *(undefined4 *)(in_r1 + 4) = in_r3;
  *(undefined4 *)(in_r1 + 8) = unaff_r4;
                    // WARNING: Could not recover jumptable at 0x002c5a60. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::replace(unsigned int, unsigned int, char const*, unsigned int)

void std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,char *param_3,uint param_4)

{
  int unaff_r4;
  int unaff_r7;
  
  _DAT_00000030 = param_3;
  *(int *)param_2 = (int)param_1 >> 0x17;
  *(undefined4 *)(param_2 + 4) = 0x20;
  *(uint *)(param_2 + 8) = param_2 + 8;
  *(char **)(param_2 + 0xc) = param_3;
  *(uint *)(param_2 + 0x10) = param_4;
  *(int *)(param_2 + 0x14) = unaff_r4;
  *(undefined4 *)(param_2 + 0x18) = 0x20;
  *(int *)(param_2 + 0x1c) = unaff_r7;
  *(char *)(unaff_r4 + 0x1e) = (char)param_3;
  *(int *)(unaff_r7 * 2) = (int)param_1 >> 0x17;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__grow_by_and_replace(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int,
// unsigned int, char const*)

void std::__ndk1::basic_string<>::__grow_by_and_replace
               (uint param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint param_6,
               char *param_7)

{
  int unaff_r4;
  char in_OV;
  undefined4 in_cr11;
  undefined8 in_d6;
  
  coprocessor_movefromRt(10,2,in_cr11);
  coprocessor_movefromRt2(10,2,in_cr11);
  if (in_OV != '\0') {
    *(undefined1 *)(param_4 + 0x11) = 0x38;
    VectorShiftLeft(in_d6,1,0x10,1);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r4 * 2) = (short)unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c58f8) overlaps instruction at (ram,0x002c58f6)
// 
// WARNING: Removing unreachable block (ram,0x002c598c)
// WARNING: Removing unreachable block (ram,0x002c598e)
// WARNING: Removing unreachable block (ram,0x002c5906)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::rfind(char const*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::rfind(char *param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  byte bVar2;
  short sVar3;
  int iVar4;
  undefined2 uVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  uint uVar10;
  int iVar11;
  int unaff_r5;
  int unaff_r6;
  int iVar12;
  int unaff_r7;
  uint uVar13;
  uint unaff_r8;
  int unaff_r10;
  undefined2 in_r12;
  undefined4 *puVar14;
  undefined4 *puVar15;
  char cVar16;
  bool bVar17;
  char cVar18;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr11;
  undefined4 in_cr12;
  undefined8 uVar19;
  int in_stack_00000000;
  uint in_stack_00000004;
  int in_stack_00000008;
  undefined4 in_stack_0000000c;
  undefined4 in_stack_00000010;
  int iStack000000fc;
  int in_stack_00000180;
  
  uVar13 = unaff_r7 - 0x4f;
  *(short *)(unaff_r5 + 4) = (short)unaff_r5;
  if (*(ushort *)(unaff_r6 + 0x32) < 0x61) {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x88,0x2c59d6);
    (*pcVar1)();
  }
  uVar10 = DAT_37636d25 + 0xa3;
  cVar18 = SCARRY4(uVar13,0x97);
  cVar16 = unaff_r7 + 0x48 < 0;
  bVar17 = uVar13 == 0xffffff69;
  if ((bool)cVar16) {
    iVar7 = (int)(param_3 - 0x22) >> 0x1c;
    puVar14 = (undefined4 *)register0x00000054;
    uVar5 = DAT_002c5bf2;
    sVar3 = DAT_002c5c12;
    if (0xffffff69 < uVar13) goto LAB_002c5874;
  }
  else {
    uVar19 = func_0xff958d7c();
    iVar7 = (int)((ulonglong)uVar19 >> 0x20);
    param_1 = (char *)uVar19;
    bVar2 = *(byte *)(iVar7 + 0x18);
    uVar13 = (uint)bVar2;
    coprocessor_function(8,6,7,in_cr9,in_cr4,in_cr12);
    uVar5 = *(undefined2 *)(iVar7 + 8);
    sVar3 = (short)param_2 + -1;
    if (bVar17 || cVar16 != cVar18) {
      sVar3 = *(short *)(param_1 + *(ushort *)(param_1 + 0x1a));
      func_0x00e6c164();
      coprocessor_moveto2(10,0xc,uVar13,uVar13,in_cr1);
      DAT_5ecd8c4f = *(undefined1 *)(unaff_r7 + 0x49);
      _DAT_08d51b37 = 0x521f9727;
      _DAT_08d51b3b = 0x29e1a81e;
      _DAT_08d51b3f = &DAT_8f049e83;
      _DAT_08d51b43 = &DAT_08d51b37;
      _DAT_08d51b47 = 0;
      puVar15 = (undefined4 *)coprocessor_movefromRt(4,6,5,in_cr8,in_cr4);
      _DAT_a43f2e4e = (undefined4 *)(uVar13 - 0x1b);
      _DAT_8f049e93 = puVar15[0xa8];
      *_DAT_a43f2e4e = 0x521f9727;
      *(undefined4 *)(uVar13 - 0x17) = 0x29e1a81e;
      *(undefined1 **)(uVar13 - 0x13) = &DAT_8f049e83;
      *(undefined1 **)(uVar13 - 0xf) = &DAT_08d51b37;
      _DAT_8f049ecd = bVar2 - 0xb;
      _DAT_8f049e8f = (uint)DAT_8f049ea2;
      _DAT_8f049e83 = 0x2c5c18;
      _DAT_8f049e87 = 0x521f9727;
      _DAT_8f049e8b = 0x29e1a81e;
      uVar6 = *puVar15;
      uVar8 = puVar15[1];
      uVar9 = puVar15[2];
      *(undefined4 *)(_DAT_8f049e8f + 0x40) = 1;
      iStack000000fc = (int)sVar3;
      operator_delete(uVar6,uVar8,uVar9,puVar15 + 0xe5);
      return;
    }
  }
  DAT_002c5c12 = sVar3;
  DAT_002c5bf2 = uVar5;
  iVar7 = in_stack_00000004;
  in_stack_00000004 = *(uint *)(param_1 + 4);
  *(undefined2 *)(unaff_r8 + 0x71c) = in_r12;
  uVar10 = (uint)*(ushort *)(in_stack_00000008 + 0x14);
  puVar14 = &stack0x00000004;
  *(char *)((uint)*(ushort *)(((int)in_stack_00000004 >> 0x1e) + 8) + iVar7) = (char)iVar7;
  iVar7 = in_stack_00000000;
  if ((in_stack_00000004 >> 0x1a & 1) == 0 || in_stack_00000004 >> 0x1b == 0) {
    uVar10 = *(uint *)((in_stack_00000004 >> 0x1b) + 0x48);
    *(short *)(in_stack_00000004 + in_stack_00000180) = (short)in_stack_00000180;
    puVar14 = (undefined4 *)&stack0x00000018;
    if (SBORROW4(unaff_r10,unaff_r10)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
LAB_002c5874:
  iVar11 = puVar14[1];
  iVar12 = puVar14[3];
  *(int *)(uVar10 + 0x54) = iVar12;
  iVar4 = -(unaff_r8 >> 0x1d | unaff_r8 << 3);
  coprocessor_movefromRt(10,2,in_cr11);
  coprocessor_movefromRt2(10,2,in_cr11);
  *(short *)(iVar11 * 2) = (short)iVar11;
  *(int *)(iVar12 + iVar4 + 0x2a0) = iVar7;
  *(int *)(iVar12 + iVar4 + 0x248) = (iVar12 << 0x14) >> 7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__init(char const*, unsigned int, unsigned int)

undefined4 std::__ndk1::basic_string<>::__init(char *param_1,uint param_2,uint param_3)

{
  int iVar1;
  int *unaff_r7;
  undefined4 in_cr6;
  undefined4 in_cr12;
  undefined4 in_stack_00000104;
  undefined4 uStack_1b4;
  
  software_bkpt(0x2b);
  iVar1 = coprocessor_movefromRt(4,0,4,in_cr12,in_cr6);
  *(char *)(iVar1 + param_3) = (char)param_1;
  *(undefined4 *)(param_3 + 4) = in_stack_00000104;
  software_interrupt(0x25);
  *(char *)(param_3 + 0x18) = (char)param_3;
  *unaff_r7 = param_3 + 0x79;
  unaff_r7[1] = (int)unaff_r7;
  return uStack_1b4;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::basic_string(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&)

void std::__ndk1::basic_string<>::basic_string(basic_string *param_1)

{
  int in_r1;
  int in_r3;
  int unaff_r5;
  undefined1 unaff_r7;
  
  *(int *)(in_r3 + 100) = in_r1;
  *(short *)(unaff_r5 + 0x32) = (short)unaff_r5;
  *(undefined1 *)(*(int *)(in_r1 + 4) + 3) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5b7c)
// WARNING: Removing unreachable block (ram,0x002c5b7e)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::replace(unsigned int, unsigned int, char const*)

undefined8 std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,char *param_3)

{
  bool bVar1;
  code *pcVar2;
  byte bVar3;
  int *piVar4;
  uint in_r3;
  uint *unaff_r4;
  uint *puVar5;
  uint unaff_r5;
  int iVar6;
  int iVar7;
  uint *puVar8;
  int iVar9;
  char unaff_r8;
  undefined4 in_lr;
  bool bVar10;
  undefined4 in_cr4;
  undefined4 in_cr13;
  undefined4 in_stack_00000000;
  int in_stack_00000100;
  int in_stack_00000114;
  int in_stack_00000134;
  
  *unaff_r4 = param_2;
  unaff_r4[1] = (uint)param_3;
  unaff_r4[2] = in_r3;
  unaff_r4[3] = unaff_r5;
  puVar8 = (uint *)(in_stack_00000134 - 5);
  bVar3 = *(byte *)(in_stack_00000134 + 0xd);
  *(char *)(*(char *)(in_r3 * 2) + 10) = *(char *)(in_r3 * 2);
  puVar5 = (uint *)(int)*(char *)(in_stack_00000134 + (uint)bVar3);
  bVar1 = ((int)param_2 >> 0x17 & 1U) != 0;
  piVar4 = (int *)((int)param_2 >> 0x18);
  bVar10 = piVar4 != (int *)0x0;
  if (param_1 == 0) {
    if (bVar1 && bVar10) {
      *puVar5 = in_r3;
      puVar5[1] = (uint)puVar5;
      puVar5[2] = (uint)puVar8;
      piVar4 = *(int **)(in_stack_00000134 + 0x1f);
      if (bVar10) {
        iVar7 = *(int *)(*(char *)(in_stack_00000134 + _operator_) + 0x50);
        *(int *)(*(int *)(iVar7 + 0xc) + 0x1c) = _operator_;
        if (!bVar1) {
          coprocessor_load(9,in_cr13,iVar7 + -0x1e8);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      software_interrupt(0x25);
      find_first_not_of = 0xa8;
      *puVar8 = in_r3;
      *(uint **)(in_stack_00000134 + -1) = puVar8;
    }
    return CONCAT44(piVar4,in_stack_00000000);
  }
  iVar7 = in_stack_00000134 + 0x57;
  if (bVar3 == 0) {
    puVar8 = (uint *)(in_stack_00000134 + 0x68);
    iVar6 = 0;
  }
  else {
    in_r3 = (in_r3 >> 0x1d) + 0x66;
    iVar6 = (int)puVar5 + 5;
    if (puVar5 < (uint *)0xfffffffb) {
                    // WARNING: Does not return
      pcVar2 = (code *)software_udf(0x49,0x2c5b7a);
      (*pcVar2)();
    }
  }
  iVar9 = (int)puVar8 + -0x91;
  if (puVar8 < (uint *)0x91 || iVar9 == 0) {
    *(short *)(in_stack_00000100 + in_stack_00000114) = (short)in_stack_00000114;
    *(char *)((int)puVar5 + 10) = (char)*(undefined4 *)(iVar6 + 4);
    coprocessor_loadlong(7,in_cr4,in_lr);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *piVar4 = iVar6;
  piVar4[1] = iVar7;
  piVar4[2] = (int)(piVar4 + 2);
  piVar4[3] = in_stack_00000100;
  piVar4[4] = in_r3;
  piVar4[5] = (int)puVar5;
  piVar4[6] = iVar7;
  piVar4[7] = iVar9;
  *(char *)((int)puVar5 + 0x1e) = (char)((uint)iVar7 >> 0x10) * unaff_r8 + (char)in_stack_00000100;
  *(int *)(iVar9 * 2) = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::basic_string(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, std::__ndk1::allocator<char> const&)

undefined8 std::__ndk1::basic_string<>::basic_string(basic_string *param_1,allocator *param_2)

{
  int in_r2;
  undefined4 in_r3;
  undefined4 *unaff_r4;
  int iVar1;
  undefined4 *unaff_r7;
  bool in_ZR;
  bool in_CY;
  char in_OV;
  undefined4 in_cr13;
  undefined4 in_stack_000001a0;
  
  iVar1 = *(int *)(param_2 + (int)param_1);
  if (in_OV != '\0') {
    *(char *)(in_r2 + 3) = (char)unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (in_CY && !in_ZR) {
    *unaff_r4 = in_r3;
    unaff_r4[1] = unaff_r4;
    unaff_r4[2] = unaff_r7;
    param_2 = (allocator *)unaff_r7[9];
    if (in_ZR == false) {
      iVar1 = *(int *)(*(char *)(iVar1 + _operator_) + 0x50);
      *(int *)(*(int *)(iVar1 + 0xc) + 0x1c) = _operator_;
      if (in_CY != false) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      coprocessor_load(9,in_cr13,iVar1 + -0x1e8);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    software_interrupt(0x25);
    *(char *)(in_r2 + 0x18) = (char)in_r2;
    *unaff_r7 = in_r3;
    unaff_r7[1] = unaff_r7;
  }
  return CONCAT44(param_2,in_stack_000001a0);
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find_last_not_of(char const*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::find_last_not_of(char *param_1,uint param_2,uint param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::~basic_string()

void __thiscall std::__ndk1::basic_string<>::~basic_string(basic_string<> *this)

{
  int *in_r2;
  int in_r3;
  undefined1 unaff_r4;
  int iVar1;
  int iVar2;
  char unaff_r11;
  char cVar3;
  
  *(short *)(in_r3 + 0x32) = (short)in_r2;
  iVar1 = *in_r2;
  iVar2 = in_r2[1];
  cVar3 = (char)in_r2 + '\f';
  func_0xff52c60a(unaff_r4);
  *(char *)(iVar1 + 0x1c) = cVar3;
  *(char *)(iVar2 + 0xe) = (char)iVar1 + unaff_r11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find_first_not_of(char const*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::find_first_not_of(char *param_1,uint param_2,uint param_3)

{
  char unaff_r4;
  int unaff_r5;
  char unaff_r11;
  
  *(char *)(unaff_r5 + 0xe) = unaff_r4 + unaff_r11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::insert(unsigned int, unsigned int, char)

void std::__ndk1::basic_string<>::insert(uint param_1,uint param_2,char param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__grow_by(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int)

undefined8
std::__ndk1::basic_string<>::__grow_by
          (uint param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint param_6)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  char cVar4;
  
  iVar3 = *(int *)(param_3 + param_1);
  bVar2 = *(byte *)(iVar3 * 0x4000080);
  cVar4 = '\0';
  func_0x01261246();
  if (cVar4 != '\0') {
    *(ushort *)(iVar3 + 0x36) = (ushort)bVar2;
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xa8,0x2c5ce8);
    (*pcVar1)();
  }
  return CONCAT44(param_6,param_5);
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5d6e)
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::TEMPNAMEPLACEHOLDERVALUE(char)

void __thiscall std::__ndk1::basic_string<>::operator=(basic_string<> *this,char param_1)

{
  char in_r2;
  undefined1 in_r3;
  int unaff_r4;
  uint unaff_r5;
  int unaff_r6;
  char in_NG;
  bool in_ZR;
  char in_OV;
  
  if (this == (basic_string<> *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!in_ZR && in_NG == in_OV) {
    *(undefined1 *)(unaff_r4 + 0xf) = in_r3;
    *(char *)(unaff_r6 + 0x17) = in_r2 + -0x2e;
    *(short *)(unaff_r6 + 0x10) = (short)this;
    if (unaff_r5 < 0xdb) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(char *)(unaff_r5 + 0x15) = in_r2 + -0x2e;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r5 + 0x2c) = (short)unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__init(char const*, unsigned int)

void std::__ndk1::basic_string<>::__init(char *param_1,uint param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::insert(unsigned int, char const*, unsigned int)

void __thiscall
std::__ndk1::basic_string<>::insert(basic_string<> *this,uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *unaff_r5;
  int iVar5;
  undefined4 unaff_r6;
  int iVar6;
  int iVar7;
  int unaff_r10;
  undefined4 unaff_r11;
  uint in_r12;
  int in_pc;
  undefined4 in_cr7;
  undefined4 in_cr10;
  undefined4 in_cr12;
  undefined4 in_cr14;
  int *in_stack_000003a0;
  
  uVar2 = *unaff_r5;
  iVar4 = unaff_r5[1];
  iVar6 = unaff_r5[2];
  *(undefined4 *)(iVar6 + 0x28) = unaff_r6;
  if (unaff_r5 == (undefined4 *)0xfffffff4) {
    coprocessor_function2(3,2,3,in_cr14,in_cr12,in_cr7);
    *(uint *)param_1 = param_1;
    *(undefined4 *)(param_1 + 4) = uVar2;
    *(uint *)(param_1 + 8) = param_3;
    *(undefined4 *)(param_1 + 0xc) = unaff_r6;
    uVar2 = uRam00000008;
    iVar5 = iRam00000004;
    puVar3 = puRam00000000;
    *(char *)(in_pc + 0x7ca) = (char)iVar6;
    *(int *)iVar5 = iVar5;
    *(int *)(iVar5 + 4) = iVar4;
    *(undefined4 *)(iVar5 + 8) = uVar2;
    *(undefined4 *)(iVar5 + 0xc) = unaff_r6;
    *puVar3 = 0x6ed17e6f;
    puVar3[1] = iVar5;
    puVar3[2] = iVar4 << 0xf;
    puVar3[3] = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  coprocessor_load(6,in_cr10,unaff_r11);
  in_stack_000003a0[0xb] = param_3;
  in_stack_000003a0[0x58] = unaff_r10;
  in_stack_000003a0[0x59] = (int)in_stack_000003a0 >> 3;
  iVar4 = *in_stack_000003a0;
  puVar3 = (undefined4 *)in_stack_000003a0[1];
  iVar6 = in_stack_000003a0[2];
  iVar5 = in_stack_000003a0[3];
  software_interrupt(0x51);
  if ((int)(in_r12 | 0x10600000) < 0) {
    *(undefined2 *)puVar3 = *(undefined2 *)(param_3 + iVar5);
    *(int *)(iVar4 + 0x60) = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar1 = (int *)*puVar3;
  iVar6 = puVar3[1];
  iVar7 = puVar3[3];
  *piVar1 = iVar4;
  piVar1[1] = (int)piVar1;
  piVar1[2] = (int)&stack0x000002ec;
  piVar1[3] = iVar6;
  piVar1[4] = iVar5;
  piVar1[5] = iVar7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_002c5e2c(int param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4)

{
  int *piVar1;
  int iVar2;
  int unaff_r4;
  int unaff_r5;
  undefined4 unaff_r6;
  int iVar3;
  undefined1 in_q0 [16];
  undefined1 in_q7 [16];
  undefined1 in_q9 [16];
  
  *(int *)param_1 = param_1;
  *(undefined4 **)(param_1 + 4) = param_3;
  *(undefined4 *)(param_1 + 8) = param_4;
  *(int *)(param_1 + 0xc) = unaff_r4;
  *(int *)(param_1 + 0x10) = unaff_r5;
  *(undefined4 *)(param_1 + 0x14) = unaff_r6;
  software_bkpt(0x4e);
  VectorComplexMultiplyAccumulateByElement(in_q7,in_q9,in_q0,0x5a,4);
  if (-1 < unaff_r4 >> 0x20) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar1 = (int *)*param_3;
  iVar2 = param_3[1];
  iVar3 = param_3[3];
  *piVar1 = param_1;
  piVar1[1] = (int)piVar1;
  piVar1[2] = (int)&stack0x000002ec;
  piVar1[3] = iVar2;
  piVar1[4] = unaff_r5;
  piVar1[5] = iVar3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find_first_of(char const*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::find_first_of(char *param_1,uint param_2,uint param_3)

{
  undefined2 in_r3;
  int unaff_r7;
  
  *(undefined2 *)(unaff_r7 + 0x1c) = in_r3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::replace(unsigned int, unsigned int, unsigned int, char)

void std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,uint param_3,char param_4)

{
  uint uVar1;
  uint uVar2;
  uint *unaff_r4;
  uint *puVar3;
  uint *puVar4;
  uint unaff_r6;
  uint uVar5;
  uint unaff_r7;
  int unaff_r8;
  int unaff_r11;
  
  puVar3 = (uint *)(int)param_4;
  do {
    *(short *)(param_3 + 6) = (short)unaff_r6;
    uVar5 = *(uint *)(param_2 + 0x74);
    *(uint *)((int)register0x00000054 + -4) = unaff_r7;
    *(uint *)((int)register0x00000054 + -8) = uVar5;
    *(uint **)((int)register0x00000054 + -0xc) = unaff_r4;
    *(uint *)((int)register0x00000054 + -0x10) = param_3;
    *(uint *)((int)register0x00000054 + -0x14) = param_2;
    *(uint *)((int)register0x00000054 + -0x18) = param_1;
    *(short *)((int)unaff_r4 * 2) = (short)puVar3;
    *(uint *)param_1 = param_2;
    *(uint **)(param_1 + 4) = puVar3;
    *(uint **)(param_1 + 8) = unaff_r4;
    *(uint *)(param_1 + 0xc) = unaff_r7;
    param_1 = param_1 + 0x10;
    while( true ) {
      uVar1 = puVar3[1];
      uVar2 = puVar3[2];
      unaff_r6 = *(uint *)((int)register0x00000054 + 0xdc);
      puVar4 = (uint *)(uint)*(ushort *)(*puVar3 - 0x52);
      *(uint *)(param_1 + unaff_r11 + 0x3c) = *puVar3 - 0x78;
      software_interrupt(0xa0);
      uVar5 = *(uint *)((int)register0x00000054 + 0x3b0);
      puVar3 = *(uint **)(uVar5 + 0x48);
      *puVar4 = uVar5;
      puVar4[1] = uVar2;
      puVar4[2] = (uint)puVar4;
      puVar4[3] = unaff_r6;
      puVar4[4] = uVar1 >> 0x12;
      *(uint *)(unaff_r6 + (uVar1 >> 0x12)) = uVar5;
      if (SBORROW4((int)puVar4,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar3[0x14] = uVar5;
      if (!SBORROW4((int)puVar4,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      param_3 = puVar3[1];
      uVar5 = puVar3[2];
      unaff_r4 = puVar3 + 3;
      param_1 = (uint)(short)uVar5;
      param_2 = *puVar3 + 8;
      if (*puVar3 < 0xfffffff8) break;
      puVar3 = (uint *)(uint)_DAT_0058c480;
      *(uint *)((int)register0x00000054 + 0x134) = *(uint *)((int)register0x00000054 + 0x340);
      *puVar3 = param_3;
      puVar3[1] = uVar5;
      puVar3[2] = 0x2c6240;
      puVar3 = puVar3 + 3;
      if (!SCARRY4((int)unaff_r4,0x2c6240)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    puVar3 = (uint *)(param_1 << 0x18);
    unaff_r7 = (uVar2 - 0x3b4000) - (uint)(puVar4 < (uint *)0xb6) ^ unaff_r8 >> 6;
    register0x00000054 = (BADSPACEBASE *)((int)register0x00000054 + -0x18);
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::assign(char const*, unsigned int)

undefined8 std::__ndk1::basic_string<>::assign(char *param_1,uint param_2)

{
  int *piVar1;
  uint *puVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  uint in_r2;
  uint *puVar7;
  uint uVar8;
  int in_r3;
  uint *puVar9;
  undefined2 *puVar10;
  int *unaff_r5;
  uint uVar11;
  int iVar12;
  int unaff_r6;
  int iVar13;
  uint uVar14;
  int iVar15;
  int unaff_r8;
  int unaff_r9;
  int unaff_r11;
  int *piVar16;
  uint in_pc;
  undefined8 in_stack_00000000;
  int in_stack_000000f4;
  
  if (in_r3 + 0x2d == 0) {
    puVar3 = (undefined4 *)*unaff_r5;
    puVar10 = (undefined2 *)(unaff_r6 * 0x100);
    uVar4 = *puVar3;
    iVar12 = puVar3[3];
    iVar13 = puVar3[4];
    *(char *)(iVar12 + 6) = (char)puVar3[2];
    func_0xff810cb4(uVar4,*(undefined4 *)(in_r2 + 0x6c));
    iVar15 = (int)(short)*(int *)((int)puVar10 + iVar12 + -0x60);
    if (!SBORROW4(iVar12,0x60)) {
      iVar5 = *(int *)(iVar12 + -0x60);
      puVar3 = *(undefined4 **)(iVar12 + -0x5c);
      uVar4 = *(undefined4 *)(iVar12 + -0x54);
      if (iVar5 == 0) {
        SignedSaturate(unaff_r9 >> 0xd,0x10);
        SignedDoesSaturate(unaff_r9 >> 0xd,0x10);
        *puVar3 = *(undefined4 *)(iVar12 + -0x58);
        puVar3[1] = uVar4;
        puVar3[2] = iVar13;
        puVar3[3] = iVar15;
        *(short *)((int)puVar3 + 0x4a) = (short)uVar4;
        *(char *)(puVar3 + 10) = (char)puVar3 + '\x10';
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (puVar10 != (undefined2 *)0xffffffe0 &&
          (int)(puVar10 + 0x10) < 0 == SCARRY4((int)puVar10,0x20)) {
        *(char *)(iVar15 + iVar5) = (char)*puVar10;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(iVar13 + 0x1d) = (char)*puVar10;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar9 = (uint *)&DAT_00000080;
  if (in_r3 - 0x97U < 0xffffff3c) {
    return in_stack_00000000;
  }
  _DAT_00000088 = 0x80;
  _DAT_0000008c = in_stack_000000f4;
  uVar11 = *(uint *)(in_stack_000000f4 + 0x5c);
  puVar2 = (uint *)(int)param_1[in_stack_000000f4];
  piVar1 = (int *)register0x00000054;
  _DAT_00000080 = in_r2;
  _DAT_00000084 = in_r3 + 0x2d;
  do {
    piVar16 = piVar1;
    puVar7 = (uint *)((int)puVar2 << 0x18);
    uVar14 = in_pc ^ unaff_r8 >> 6;
    *(short *)(in_r2 + 6) = (short)uVar11;
    iVar12 = *(int *)(param_2 + 0x74);
    piVar16[-1] = uVar14;
    piVar16[-2] = iVar12;
    piVar16[-3] = (int)puVar9;
    piVar16[-4] = in_r2;
    piVar16[-5] = param_2;
    piVar16[-6] = (int)puVar2;
    *(undefined2 *)((int)puVar9 * 2) = 0;
    *puVar2 = param_2;
    puVar2[1] = (uint)puVar7;
    puVar2[2] = (uint)puVar9;
    puVar2[3] = uVar14;
    puVar2 = puVar2 + 4;
    while( true ) {
      uVar6 = puVar7[1];
      uVar8 = puVar7[2];
      uVar11 = piVar16[0x37];
      puVar9 = (uint *)(uint)*(ushort *)(*puVar7 - 0x52);
      *(uint *)((int)puVar2 + unaff_r11 + 0x3c) = *puVar7 - 0x78;
      software_interrupt(0xa0);
      uVar14 = piVar16[0xec];
      puVar7 = *(uint **)(uVar14 + 0x48);
      *puVar9 = uVar14;
      puVar9[1] = uVar8;
      puVar9[2] = (uint)puVar9;
      puVar9[3] = uVar11;
      puVar9[4] = uVar6 >> 0x12;
      *(uint *)(uVar11 + (uVar6 >> 0x12)) = uVar14;
      in_pc = (uVar8 - 0x3b4000) - (uint)(puVar9 < (uint *)0xb6);
      if (SBORROW4((int)puVar9,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar7[0x14] = uVar14;
      if (!SBORROW4((int)puVar9,0xb6)) {
        halt_baddata();
      }
      in_r2 = puVar7[1];
      uVar14 = puVar7[2];
      puVar9 = puVar7 + 3;
      puVar2 = (uint *)(int)(short)uVar14;
      param_2 = *puVar7 + 8;
      piVar1 = piVar16 + -6;
      if (*puVar7 < 0xfffffff8) break;
      puVar7 = (uint *)(uint)_DAT_0058c480;
      piVar16[0x4d] = piVar16[0xd0];
      *puVar7 = in_r2;
      puVar7[1] = uVar14;
      puVar7[2] = 0x2c6240;
      puVar7 = puVar7 + 3;
      if (!SCARRY4((int)puVar9,0x2c6240)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::reserve(unsigned int)

void std::__ndk1::basic_string<>::reserve(uint param_1)

{
  undefined2 in_r3;
  int unaff_r7;
  char in_NG;
  char in_OV;
  
  *(undefined2 *)(unaff_r7 + 0x1a) = in_r3;
  if (in_NG != in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uRam0000000a = 0xd4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::append(char const*, unsigned int)

void std::__ndk1::basic_string<>::append(char *param_1,uint param_2)

{
  undefined4 *puVar1;
  undefined4 *in_r2;
  undefined4 uVar2;
  undefined4 in_r3;
  int unaff_r4;
  undefined4 unaff_r5;
  undefined4 unaff_r6;
  undefined4 uVar3;
  undefined1 in_q0 [16];
  undefined1 in_q7 [16];
  undefined1 in_q9 [16];
  
  *(char **)param_1 = param_1;
  *(undefined4 **)(param_1 + 4) = in_r2;
  *(undefined4 *)(param_1 + 8) = in_r3;
  *(int *)(param_1 + 0xc) = unaff_r4;
  *(undefined4 *)(param_1 + 0x10) = unaff_r5;
  *(undefined4 *)(param_1 + 0x14) = unaff_r6;
  software_bkpt(0x4e);
  VectorComplexMultiplyAccumulateByElement(in_q7,in_q9,in_q0,0x5a,4);
  if (-1 < unaff_r4 >> 0x20) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar1 = (undefined4 *)*in_r2;
  uVar2 = in_r2[1];
  uVar3 = in_r2[3];
  *puVar1 = param_1;
  puVar1[1] = puVar1;
  puVar1[2] = &stack0x000002ec;
  puVar1[3] = uVar2;
  puVar1[4] = unaff_r5;
  puVar1[5] = uVar3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5ea4)
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::assign(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int, unsigned int)

void __thiscall
std::__ndk1::basic_string<>::assign
          (basic_string<> *this,basic_string *param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  ushort uVar2;
  undefined1 uVar3;
  int iVar4;
  int extraout_r1;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *unaff_r4;
  int unaff_r5;
  undefined4 unaff_r6;
  undefined8 *unaff_r8;
  char in_NG;
  bool in_ZR;
  char in_OV;
  undefined8 extraout_d0;
  undefined8 extraout_d1;
  undefined1 in_q7 [16];
  undefined1 in_q9 [16];
  undefined8 in_d23;
  undefined1 auVar7 [16];
  
  if (in_ZR || in_NG != in_OV) {
    *unaff_r4 = this;
    unaff_r4[1] = 0x53ee4e2a;
    unaff_r4[2] = unaff_r4;
    unaff_r4[3] = unaff_r6;
    *(char *)(param_2 + 8) = (char)unaff_r5;
    uVar5 = 0x2c6338;
    uVar3 = func_0xff6479e0();
    auVar7._8_8_ = extraout_d1;
    auVar7._0_8_ = extraout_d0;
    *unaff_r8 = in_d23;
    uVar6 = param_3 >> 0x1a;
    *(short *)(extraout_r1 * 2) = (short)param_3;
    *(char *)(uVar6 + 0x1d) = (char)unaff_r6;
    uVar2 = *(ushort *)(uVar6 + 4);
    *(undefined1 *)(extraout_r1 + 0x1e) = uVar3;
    iVar4 = extraout_r1 - unaff_r5;
    *(int *)iVar4 = iVar4;
    *(undefined4 *)(iVar4 + 4) = uVar5;
    *(uint *)(iVar4 + 8) = param_3;
    *(uint *)(iVar4 + 0xc) = uVar6;
    *(int *)(iVar4 + 0x10) = unaff_r5;
    *(uint *)(iVar4 + 0x14) = (uint)uVar2;
    software_bkpt(0x4e);
    VectorComplexMultiplyAccumulateByElement(in_q7,in_q9,auVar7,0x5a,4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xcb,0x2c61c6);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::copy(char*, unsigned int, unsigned int) const

void __thiscall
std::__ndk1::basic_string<>::copy(basic_string<> *this,char *param_1,uint param_2,uint param_3)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  int *piVar8;
  uint *puVar9;
  uint unaff_r4;
  uint *puVar10;
  uint *puVar11;
  int unaff_r5;
  int iVar12;
  undefined4 uVar13;
  uint uVar14;
  int unaff_r6;
  int iVar15;
  uint uVar16;
  int unaff_r8;
  undefined4 *unaff_r9;
  int unaff_r11;
  int in_r12;
  undefined4 in_lr;
  bool bVar17;
  undefined4 in_cr0;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined4 in_cr14;
  undefined1 in_q0 [16];
  undefined8 in_d3;
  undefined1 in_q7 [16];
  undefined1 in_q9 [16];
  undefined8 in_d31;
  int in_stack_00000080;
  
  VectorMultiply(in_d31,in_d3,4);
  *(short *)(unaff_r5 + param_3) = (short)unaff_r5;
  uVar1 = *(ushort *)(this + 0x30);
  puVar4 = (undefined4 *)(uint)uVar1;
  *(char **)(param_3 + 0x30) = param_1;
  piVar8 = (int *)((int)(unaff_r4 >> 0x16) >> 5);
  *(ushort *)(puVar4 + 5) = uVar1;
  bVar17 = SCARRY4(in_stack_00000080,0x46);
  iVar12 = in_stack_00000080 + 0x46;
  puVar10 = (uint *)(int)(char)this[unaff_r4];
  if (unaff_r6 == 0) {
    if (bVar17) {
      *(undefined4 *)((int)unaff_r9 + -4) = in_lr;
      *(undefined1 **)((int)unaff_r9 + -8) = &stack0x00000020;
      *(undefined4 *)((int)unaff_r9 + -0xc) = 0;
      *(int *)((int)unaff_r9 + -0x10) = (int)this >> 0x13;
      *(uint **)((int)unaff_r9 + -0x14) = puVar10;
      *(int **)((int)unaff_r9 + -0x18) = piVar8;
      *(undefined4 **)((int)unaff_r9 + -0x1c) = puVar4;
      if ((int)this >> 0x13 == 0) {
        *(char *)((int)puVar10 + 0xb) = (char)&stack0x00000020;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(ushort *)(*piVar8 + 0x30) = uVar1;
      coprocessor_storelong(9,in_cr9,in_r12 + 0x140);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(char *)(in_stack_00000080 + 0x5f) = (char)&stack0x00000010;
    *puVar4 = puVar4;
    puVar4[1] = piVar8;
    puVar4[2] = puVar10;
    puVar4[3] = iVar12;
    uVar16 = (uint)(char)this[(int)param_1];
    piVar8 = (int *)(uint)*(byte *)(in_stack_00000080 + 0x48);
    coprocessor_function(6,10,7,in_cr14,in_cr13,in_cr11);
    do {
      uVar13 = *(undefined4 *)(param_1 + 0x74);
      unaff_r9[-1] = uVar16;
      unaff_r9[-2] = uVar13;
      unaff_r9[-3] = puVar10;
      unaff_r9[-4] = puVar4;
      unaff_r9[-5] = param_1;
      unaff_r9[-6] = this;
      *(short *)((int)puVar10 * 2) = (short)piVar8;
      *(char **)this = param_1;
      *(int **)(this + 4) = piVar8;
      *(uint **)(this + 8) = puVar10;
      *(uint *)(this + 0xc) = uVar16;
      this = this + 0x10;
      while( true ) {
        uVar3 = piVar8[1];
        uVar6 = piVar8[2];
        uVar14 = unaff_r9[0x37];
        puVar11 = (uint *)(uint)*(ushort *)(*piVar8 + -0x52);
        *(int *)(this + unaff_r11 + 0x3c) = *piVar8 + -0x78;
        software_interrupt(0xa0);
        uVar16 = unaff_r9[0xec];
        puVar9 = *(uint **)(uVar16 + 0x48);
        *puVar11 = uVar16;
        puVar11[1] = uVar6;
        puVar11[2] = (uint)puVar11;
        puVar11[3] = uVar14;
        puVar11[4] = uVar3 >> 0x12;
        *(uint *)(uVar14 + (uVar3 >> 0x12)) = uVar16;
        if (SBORROW4((int)puVar11,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar9[0x14] = uVar16;
        if (!SBORROW4((int)puVar11,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar4 = (undefined4 *)puVar9[1];
        uVar16 = puVar9[2];
        puVar10 = puVar9 + 3;
        this = (basic_string<> *)(int)(short)uVar16;
        param_1 = (char *)(*puVar9 + 8);
        if (*puVar9 < 0xfffffff8) break;
        puVar7 = (undefined4 *)(uint)_DAT_0058c480;
        unaff_r9[0x4d] = unaff_r9[0xd0];
        *puVar7 = puVar4;
        puVar7[1] = uVar16;
        puVar7[2] = 0x2c6240;
        piVar8 = puVar7 + 3;
        if (!SCARRY4((int)puVar10,0x2c6240)) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      piVar8 = (int *)((int)this << 0x18);
      uVar16 = (uVar6 - 0x3b4000) - (uint)(puVar11 < (uint *)0xb6) ^ unaff_r8 >> 6;
      *(short *)((int)puVar4 + 6) = (short)uVar14;
      unaff_r9 = unaff_r9 + -6;
    } while( true );
  }
  if (bVar17) {
    *(char *)((int)puVar10 + 0x1d) = (char)unaff_r6;
    uVar16 = puVar10[1];
    param_1[0x1e] = (char)this;
    iVar2 = (int)param_1 - iVar12;
    *(int *)iVar2 = iVar2;
    *(undefined4 **)(iVar2 + 4) = puVar4;
    *(int **)(iVar2 + 8) = piVar8;
    *(uint **)(iVar2 + 0xc) = puVar10;
    *(int *)(iVar2 + 0x10) = iVar12;
    *(uint *)(iVar2 + 0x14) = (uint)(ushort)uVar16;
    software_bkpt(0x4e);
    VectorComplexMultiplyAccumulateByElement(in_q7,in_q9,in_q0,0x5a,4);
    if (-1 < (int)puVar10 >> 0x20) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    piVar8 = (int *)*puVar4;
    iVar5 = puVar4[1];
    iVar15 = puVar4[3];
    *piVar8 = iVar2;
    piVar8[1] = (int)piVar8;
    piVar8[2] = (int)((int)unaff_r9 + 0x2ec);
    piVar8[3] = iVar5;
    piVar8[4] = iVar12;
    piVar8[5] = iVar15;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char **)((int)unaff_r9 + 0x3c4) = param_1;
  iVar12 = (int)param_1 >> 0x19;
  *(short *)((int)piVar8 + 2) = (short)param_1;
  if (((int)param_1 >> 0x18 & 1U) != 0 && iVar12 != 0) {
    *(uint *)((int)unaff_r9 + 0x98) = *(uint *)((int)unaff_r9 + 0x328);
    coprocessor_function2(5,5,6,in_cr14,in_cr0,in_cr13);
    *(char *)((*(int *)((int)unaff_r9 + 0x33c) >> (*(uint *)((int)unaff_r9 + 0x328) & 0xff)) + 0xb6)
         = (char)*(undefined4 *)((int)unaff_r9 + 0x334);
    *(undefined1 **)((int)unaff_r9 + 500) = (undefined1 *)((int)unaff_r9 + 0x1dc);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (iVar12 == 0 || iVar12 < 0 != bVar17) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar10[0x19] = (uint)param_1;
  coprocessor_function2(0xc,1,0,in_cr10,in_cr6,in_cr5);
  (*(code *)&DAT_00000076)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::basic_string(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int, unsigned int, std::__ndk1::allocator<char>
// const&)

void std::__ndk1::basic_string<>::basic_string
               (basic_string *param_1,uint param_2,uint param_3,allocator *param_4)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find(char, unsigned int) const

void std::__ndk1::basic_string<>::find(char param_1,uint param_2)

{
  uint *puVar1;
  uint uVar2;
  uint in_r2;
  uint uVar3;
  uint *puVar4;
  int *in_r3;
  uint *unaff_r4;
  uint *puVar5;
  int unaff_r5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int *unaff_r7;
  int unaff_r8;
  int unaff_r11;
  int in_r12;
  int *piVar9;
  undefined4 in_cr9;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined4 in_cr14;
  
  puVar1 = (uint *)(int)param_1;
  iVar6 = unaff_r5 + -0x5f;
  *unaff_r7 = (int)puVar1;
  unaff_r7[1] = (int)in_r3;
  unaff_r7[2] = (int)unaff_r4;
  unaff_r7[3] = iVar6;
  if (SBORROW4(unaff_r5,0x5f)) {
    unaff_r7[4] = param_2;
    unaff_r7[5] = in_r2;
    unaff_r7[6] = (int)in_r3;
    unaff_r7[7] = iVar6;
    if ((int)puVar1 >> 0x13 == 0) {
      *(char *)((int)unaff_r4 + 0xb) = (char)unaff_r7 + ' ';
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(short *)(*in_r3 + 0x30) = (short)in_r2;
    coprocessor_storelong(9,in_cr9,in_r12 + 0x140);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(unaff_r5 + -0x46) = (char)(unaff_r7 + 4);
  *(uint *)in_r2 = in_r2;
  *(int **)(in_r2 + 4) = in_r3;
  *(uint **)(in_r2 + 8) = unaff_r4;
  *(int *)(in_r2 + 0xc) = iVar6;
  uVar8 = (uint)*(char *)((int)puVar1 + param_2);
  puVar4 = (uint *)(uint)*(byte *)(unaff_r5 + -0x5d);
  coprocessor_function(6,10,7,in_cr14,in_cr13,in_cr11);
  piVar9 = (int *)register0x00000054;
  do {
    iVar6 = *(int *)(param_2 + 0x74);
    piVar9[-1] = uVar8;
    piVar9[-2] = iVar6;
    piVar9[-3] = (int)unaff_r4;
    piVar9[-4] = in_r2;
    piVar9[-5] = param_2;
    piVar9[-6] = (int)puVar1;
    *(short *)((int)unaff_r4 * 2) = (short)puVar4;
    *puVar1 = param_2;
    puVar1[1] = (uint)puVar4;
    puVar1[2] = (uint)unaff_r4;
    puVar1[3] = uVar8;
    puVar1 = puVar1 + 4;
    while( true ) {
      uVar2 = puVar4[1];
      uVar3 = puVar4[2];
      uVar7 = piVar9[0x37];
      puVar5 = (uint *)(uint)*(ushort *)(*puVar4 - 0x52);
      *(uint *)((int)puVar1 + unaff_r11 + 0x3c) = *puVar4 - 0x78;
      software_interrupt(0xa0);
      uVar8 = piVar9[0xec];
      puVar4 = *(uint **)(uVar8 + 0x48);
      *puVar5 = uVar8;
      puVar5[1] = uVar3;
      puVar5[2] = (uint)puVar5;
      puVar5[3] = uVar7;
      puVar5[4] = uVar2 >> 0x12;
      *(uint *)(uVar7 + (uVar2 >> 0x12)) = uVar8;
      if (SBORROW4((int)puVar5,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar4[0x14] = uVar8;
      if (!SBORROW4((int)puVar5,0xb6)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      in_r2 = puVar4[1];
      uVar8 = puVar4[2];
      unaff_r4 = puVar4 + 3;
      puVar1 = (uint *)(int)(short)uVar8;
      param_2 = *puVar4 + 8;
      if (*puVar4 < 0xfffffff8) break;
      puVar4 = (uint *)(uint)_DAT_0058c480;
      piVar9[0x4d] = piVar9[0xd0];
      *puVar4 = in_r2;
      puVar4[1] = uVar8;
      puVar4[2] = 0x2c6240;
      puVar4 = puVar4 + 3;
      if (!SCARRY4((int)unaff_r4,0x2c6240)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    puVar4 = (uint *)((int)puVar1 << 0x18);
    uVar8 = (uVar3 - 0x3b4000) - (uint)(puVar5 < (uint *)0xb6) ^ unaff_r8 >> 6;
    *(short *)(in_r2 + 6) = (short)uVar7;
    piVar9 = piVar9 + -6;
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__init(unsigned int, char)

void std::__ndk1::basic_string<>::__init(uint param_1,char param_2)

{
  uint *puVar1;
  uint in_r3;
  uint unaff_r5;
  uint unaff_r6;
  
  puVar1 = (uint *)(int)param_2;
  *puVar1 = param_1;
  puVar1[1] = (uint)puVar1;
  puVar1[2] = in_r3;
  puVar1[3] = unaff_r5;
  puVar1[4] = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::insert(unsigned int, char const*)

void std::__ndk1::basic_string<>::insert(uint param_1,char *param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5ce4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_002c6332(undefined4 *param_1)

{
  int iVar1;
  undefined4 unaff_r5;
  int unaff_r7;
  char in_NG;
  bool in_ZR;
  char in_OV;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr10;
  
  *(undefined4 *)(unaff_r7 + 0x50) = unaff_r5;
  if (in_ZR || in_NG != in_OV) {
    *(undefined1 **)(unaff_r7 + 0x4c) = &stack0x00000054;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar1 = -(int)&stack0x00000054;
  coprocessor_function2(0xc,1,0,in_cr10,in_cr6,in_cr5);
  _DAT_cc21dbf3 = param_1[1];
  (*(code *)&DAT_00000076)(*param_1,0x76,iVar1,iVar1 >> 2);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x001ebca6) overlaps instruction at (ram,0x001ebca4)
// 
// WARNING: Removing unreachable block (ram,0x001eb26c)
// WARNING: Removing unreachable block (ram,0x001eb23c)
// WARNING: Removing unreachable block (ram,0x001eb2ee)
// WARNING: Removing unreachable block (ram,0x001eb254)
// WARNING: Removing unreachable block (ram,0x001eb336)
// WARNING: Removing unreachable block (ram,0x001eb3aa)
// WARNING: Removing unreachable block (ram,0x001eb338)
// WARNING: Removing unreachable block (ram,0x001eb3e8)
// WARNING: Removing unreachable block (ram,0x001eae84)
// WARNING: Removing unreachable block (ram,0x001eae9c)
// WARNING: Removing unreachable block (ram,0x001eaf0a)
// WARNING: Removing unreachable block (ram,0x001eaf0c)
// WARNING: Removing unreachable block (ram,0x001eaf2c)
// WARNING: Removing unreachable block (ram,0x001eb230)
// WARNING: Removing unreachable block (ram,0x001eb27c)
// WARNING: Removing unreachable block (ram,0x001eb232)
// WARNING: Removing unreachable block (ram,0x001eb2e0)
// WARNING: Removing unreachable block (ram,0x001eb344)
// WARNING: Removing unreachable block (ram,0x001ea720)
// WARNING: Removing unreachable block (ram,0x001eae4c)
// WARNING: Removing unreachable block (ram,0x001eae68)
// WARNING: Removing unreachable block (ram,0x001eae7a)
// WARNING: Removing unreachable block (ram,0x001eaec8)
// WARNING: Removing unreachable block (ram,0x001eae82)
// WARNING: Removing unreachable block (ram,0x001eaf54)
// WARNING: Removing unreachable block (ram,0x001eb184)
// WARNING: Removing unreachable block (ram,0x001eb212)
// WARNING: Removing unreachable block (ram,0x001eb19c)
// WARNING: Removing unreachable block (ram,0x001eb1b2)
// WARNING: Removing unreachable block (ram,0x001eb1b8)
// WARNING: Removing unreachable block (ram,0x001eb1c0)
// WARNING: Removing unreachable block (ram,0x001eb1c4)
// WARNING: Removing unreachable block (ram,0x001eb21c)
// WARNING: Removing unreachable block (ram,0x001eb592)
// WARNING: Removing unreachable block (ram,0x001eb594)
// WARNING: Removing unreachable block (ram,0x001ebd36)
// WARNING: Removing unreachable block (ram,0x001ebd3e)
// WARNING: Removing unreachable block (ram,0x001eba94)
// WARNING: Removing unreachable block (ram,0x001ebaa0)
// WARNING: Removing unreachable block (ram,0x001ebaa2)
// WARNING: Removing unreachable block (ram,0x001ebae4)
// WARNING: Removing unreachable block (ram,0x001ebaee)
// WARNING: Removing unreachable block (ram,0x001ebaf0)
// WARNING: Removing unreachable block (ram,0x0017c54a)
// WARNING: Removing unreachable block (ram,0x001ebc8e)
// WARNING: Removing unreachable block (ram,0x001ebbcc)
// WARNING: Removing unreachable block (ram,0x001ebb32)
// WARNING: Removing unreachable block (ram,0x001ebb60)
// WARNING: Removing unreachable block (ram,0x001ebb80)
// WARNING: Removing unreachable block (ram,0x001ebb84)
// WARNING: Removing unreachable block (ram,0x001ebb86)
// WARNING: Removing unreachable block (ram,0x001ebb94)
// WARNING: Removing unreachable block (ram,0x001ebc00)
// WARNING: Removing unreachable block (ram,0x001ebc04)
// WARNING: Removing unreachable block (ram,0x001ebc3e)
// WARNING: Removing unreachable block (ram,0x001ebbdc)
// WARNING: Removing unreachable block (ram,0x001ebbe8)
// WARNING: Removing unreachable block (ram,0x001ebca6)
// WARNING: Removing unreachable block (ram,0x001eb1d4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find_last_of(char const*, unsigned int, unsigned int) const

void __thiscall
std::__ndk1::basic_string<>::find_last_of
          (basic_string<> *this,char *param_1,uint param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  int unaff_r5;
  undefined4 *puVar5;
  undefined4 *unaff_r6;
  int unaff_r7;
  char in_NG;
  char in_OV;
  int in_stack_00000100;
  
  if ((in_NG != '\0') && (in_NG == in_OV)) {
    if (in_NG == in_OV) {
      *(undefined **)(in_stack_00000100 + 0x74) = &DAT_002c6538;
                    // WARNING (jumptable): Read-only address (ram,0x002c6538) is written
                    // WARNING (jumptable): Read-only address (ram,0x002c653c) is written
                    // WARNING (jumptable): Read-only address (ram,0x002c6540) is written
                    // WARNING (jumptable): Read-only address (ram,0x002c6544) is written
                    // WARNING (jumptable): Read-only address (ram,0x002c6548) is written
                    // WARNING: Read-only address (ram,0x002c6538) is written
                    // WARNING: Read-only address (ram,0x002c653c) is written
                    // WARNING: Read-only address (ram,0x002c6540) is written
                    // WARNING: Read-only address (ram,0x002c6544) is written
                    // WARNING: Read-only address (ram,0x002c6548) is written
      _DAT_002c6538 = this;
      _UNK_002c653c = &DAT_002c6538;
      _UNK_002c6540 = param_3;
      _UNK_002c6544 = unaff_r5;
      _UNK_002c6548 = in_stack_00000100;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(char *)(unaff_r5 + 0x11) = (char)param_2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (in_NG != '\0') {
    unaff_r7 = *(int *)(param_3 + 0x40);
  }
  if (in_NG == in_OV) {
    if (in_NG == '\0') {
      *(int *)(unaff_r7 + 0x28) = unaff_r7;
      puVar5 = (undefined4 *)(uint)(byte)(&DAT_0016329c)[param_2];
      uVar1 = *(undefined4 *)(this + -0xdc);
      uVar2 = *(undefined4 *)(this + -0xd8);
      uVar3 = *(undefined4 *)(this + -0xd4);
      puVar4 = *(undefined4 **)(this + -0xd0);
      *puVar5 = 0x13;
      puVar5[1] = uVar1;
      puVar5[2] = uVar2;
      puVar5[3] = puVar4;
      puVar5[4] = puVar5;
      *puVar4 = this + -200;
      puVar4[1] = uVar1;
      puVar4[2] = uVar3;
      puVar4[3] = puVar4;
      puVar4[4] = puVar5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *unaff_r6 = &DAT_002c6538;
    unaff_r6[1] = param_2;
    unaff_r6[2] = unaff_r6;
    unaff_r6[3] = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  (*(code *)&LAB_0058c89c)();
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_002c638c(int param_1,undefined2 param_2,int param_3)

{
  *(undefined2 *)(param_3 + 0xe) = param_2;
  *(int *)(param_1 + 0x28) = param_1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5c76)
// WARNING: Removing unreachable block (ram,0x002c5c78)
// WARNING: Removing unreachable block (ram,0x002c5ce4)
// WARNING: Removing unreachable block (ram,0x002c64d8)
// WARNING: Removing unreachable block (ram,0x002c64e0)
// WARNING: Removing unreachable block (ram,0x002c64e6)
// WARNING: Removing unreachable block (ram,0x002c650a)
// WARNING: Removing unreachable block (ram,0x002c6512)
// WARNING: Removing unreachable block (ram,0x002c6518)
// WARNING: Removing unreachable block (ram,0x002c6582)
// WARNING: Removing unreachable block (ram,0x002c6568)
// WARNING: Removing unreachable block (ram,0x002c64ae)
// WARNING: Removing unreachable block (ram,0x002c6456)
// WARNING: Removing unreachable block (ram,0x002c646c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::push_back(char)

void std::__ndk1::basic_string<>::push_back(char param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint uVar6;
  uint *puVar7;
  int in_r3;
  uint uVar8;
  int unaff_r4;
  int iVar9;
  uint uVar10;
  uint unaff_r5;
  int *piVar11;
  uint uVar12;
  undefined2 unaff_r6;
  undefined1 *puVar13;
  uint uVar14;
  uint uVar15;
  int unaff_r7;
  uint uVar16;
  int iVar17;
  undefined4 unaff_r8;
  code *unaff_r9;
  byte *unaff_r10;
  byte *pbVar18;
  int unaff_r11;
  int in_r12;
  undefined1 *puVar19;
  int iVar20;
  undefined4 uVar21;
  code *pcVar22;
  bool bVar23;
  char cVar24;
  bool bVar25;
  bool bVar26;
  char cVar27;
  bool bVar28;
  undefined4 in_cr0;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr7;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined8 extraout_d4;
  uint unaff_s18;
  undefined8 unaff_d14;
  undefined8 in_d25;
  undefined8 uVar29;
  uint uStack0000013c;
  undefined4 in_stack_0000038c;
  undefined4 in_stack_000003b4;
  
  uVar14 = (uint)param_1;
  bVar26 = 0xffffff77 < uVar14;
  cVar27 = SCARRY4(uVar14,0x88);
  cVar24 = (int)(uVar14 + 0x88) < 0;
  bVar25 = uVar14 == 0xffffff78;
  iVar20 = 0x2c63b7;
  pcVar22 = unaff_r9;
  uVar29 = (*unaff_r9)();
  piVar11 = (int *)((ulonglong)uVar29 >> 0x20);
  iVar2 = (int)uVar29;
  if (bVar26 && !bVar25) {
    iVar2 = piVar11[4];
    *(undefined2 *)(unaff_r4 + 0x3e) = unaff_r6;
    piVar11 = (int *)(uint)*(ushort *)(in_r3 + 0xf6);
    *(short *)(unaff_r7 + 0x16) = (short)iVar2;
    *piVar11 = in_r3 + 0xd8;
    piVar11[1] = (int)&DAT_002c643c;
    *(short *)(*(byte *)(unaff_r4 + 0x16) + 0xc) = (short)(piVar11 + 2);
    _UNK_002c648c = *(ushort *)(unaff_r5 + 0x82) + 0x27;
                    // WARNING (jumptable): Read-only address (ram,0x002c648c) is written
                    // WARNING: Read-only address (ram,0x002c648c) is written
    _DAT_cc21dbf3 = piVar11[3];
    coprocessor_function2(0xc,1,0,in_cr10,in_cr6,in_cr5);
    (*(code *)&DAT_00000076)(piVar11[2],0x76,-(int)&stack0x00000054,-(int)&stack0x00000054 >> 2);
    return;
  }
  if (!bVar25 && cVar24 == cVar27) {
    func_0x00655bfe();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)((unaff_r4 >> (unaff_r5 & 0xff)) + 0x1b);
  uStack0000013c = (uint)bVar1;
  *piVar11 = iVar2;
  piVar11 = piVar11 + 1;
  *(undefined2 *)(unaff_r5 + 0x38) = unaff_r6;
  *(byte *)((unaff_r5 >> 0x1e) + iVar2) = bVar1;
  uVar16 = (uint)*(ushort *)(unaff_r5 + in_r3);
  iVar9 = (int)piVar11 * 0x10000;
  *(short *)(iVar2 + 0x10) = (short)unaff_r5;
  *(int **)(uVar16 + 0x48) = piVar11;
  iVar2 = iVar2 + unaff_r5 + (uint)(((uint)piVar11 & 0x10000) != 0);
  cVar24 = SCARRY4(iVar2,0xe0);
  puVar3 = (undefined4 *)(iVar2 + 0xe0);
  *(int *)(iVar20 + 0x59) = unaff_r11;
  uVar14 = (uint)*(char *)(uVar16 + unaff_r5);
  if ((int)puVar3 < 0 != (bool)cVar24) {
    coprocessor_load(0,in_cr0,uVar14);
    *(char *)(uVar14 - 0x4d) = (char)((uint)iVar9 >> 0x18);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (puVar3 == (undefined4 *)0x0) {
    if (((uint)piVar11 & 0x20) == 0 || (int)piVar11 * 0x8000000 == 0) {
      software_hlt(0x25);
      iRam4e68d856 = uVar14 + 0x20;
      uRam4e68d8be = 0x4e68d846;
      uRam4e68d84e = 0x4e68d846;
      iRam4e68d846 = (int)piVar11 * 0x8000000;
      uRam4e68d84a = in_stack_0000038c;
      iRam4e68d852 = iVar9;
      uRam4e68d85a = uVar16;
      *(short *)(iVar9 + *(int *)(uVar16 + 0xc)) = (short)unaff_r5;
      if (uVar14 < 0xffffffe0) {
        in_stack_000003b4 = 0xdcf4b13d;
      }
      else {
        uVar4 = VectorGetElement(extraout_d4,0,2,0);
        VectorMultiplyAddLongScalar(unaff_d14,uVar4,1);
      }
      VectorRoundShiftRight(in_d25,0x3d);
      *(undefined4 *)(unaff_r5 + 0x30) = in_stack_000003b4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (0x86 < uStack0000013c) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = *puVar3;
  uVar8 = *(uint *)(iVar2 + 0xe4);
  piVar11 = *(int **)(iVar2 + 0xe8);
  iVar20 = *(int *)(iVar2 + 0xec);
  iVar17 = *(int *)(iVar2 + 0xf0);
  *(uint *)(iVar9 + 0x48) = uStack0000013c;
  *(short *)(iVar17 + 0x12) = (short)iVar20;
  *(int *)(iVar20 + 0x38) = iVar20;
  *(short *)(uVar8 + 0x10) = (short)iVar20;
  iVar2 = *(int *)(iVar17 + 8);
  *(int *)(iVar2 + 0x58) = iVar2;
  uVar21 = 0x2c6c8d;
  puVar5 = (uint *)func_0x005a3d14(uVar4,&DAT_002c6efc);
  *piVar11 = (int)puVar5;
  piVar11[1] = iVar2;
  piVar11[2] = iVar9;
  *(undefined2 *)((int)puVar5 + 0x2a) = 0;
  *(short *)(iVar17 + 6) = (short)((int)uVar8 >> 9);
  uVar16 = *puVar5;
  puVar7 = (uint *)puVar5[2];
  uVar10 = puVar5[3];
  uVar12 = puVar5[4];
  uVar15 = puVar5[5];
  puVar5 = (uint *)puVar5[6];
  *(char *)(puVar5 + 3) = (char)uVar16;
  coprocessor_storelong(0,in_cr4,unaff_r9);
  uVar14 = 0xc;
  if (cVar24 != '\0') {
    *(undefined1 *)(uVar16 + 3) = 0xc;
    iVar2 = uVar15 + 0xcd;
    puVar7[0xc] = (uint)puVar5;
    *(code **)(unaff_r9 + 0x274) = pcVar22;
    *(int *)(unaff_r9 + 0x278) = iVar2;
    if (iVar2 < 0 != SCARRY4(uVar15,0xcd)) {
      *(uint *)(uVar12 + (int)puVar5) = (uint)(ushort)puVar5[8];
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(uint *)(uVar16 + 100) = (uint)(ushort)puVar5[8];
    uVar14 = puVar5[0xb];
    puVar7 = (uint *)(uint)*(byte *)(uVar12 + 3);
    uVar8 = (uint)*(byte *)((int)puVar7 + (int)puVar5);
    puVar5[9] = uVar12 << 7;
    uVar10 = uVar8 - 0xf8;
    *(short *)(*(int *)(*(int *)(uVar8 + 0x2c) + 0x28) + 0x14) = (short)puVar5;
    *(uint *)((int)puVar5 + uVar10) = uVar16;
    *puVar7 = uVar12 << 7;
    puVar7[1] = uVar14;
    puVar7[2] = uVar10;
    if (SBORROW4(uVar8,0xf8)) {
      *(char *)(uVar14 + 0xe) = (char)uVar10;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  coprocessor_function2(0,4,2,in_cr1,in_cr11,in_cr6);
  uVar15 = unaff_r11 - 0x1bc;
  coprocessor_store(0xe,in_cr4,uVar15);
  if (((int)uVar8 >> 8 & 1U) != 0) {
    *(char *)(puVar7 + 1) = (char)puVar7;
    software_bkpt(0xe9);
                    // WARNING: Does not return
    pcVar22 = (code *)software_udf(0xd1,0x2c6ef0);
    (*pcVar22)();
  }
  puVar13 = (undefined1 *)((int)puVar5 << 0x15);
  bVar25 = 0xffffff7a < uVar16;
  bVar28 = SCARRY4(uVar16,0x85);
  iVar20 = uVar16 + 0x85;
  bVar26 = iVar20 == 0;
  iVar2 = iVar20;
  if (!bVar25 || bVar26) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    bVar23 = iVar2 < 0;
    coprocessor_function2(3,0xb,1,in_cr13,in_cr10,in_cr15);
    if (!bVar28) {
      if (bVar26 || bVar23 != bVar28) {
        *puVar7 = uVar14;
        puVar7[1] = uVar8;
        puVar7[2] = uVar12;
        puVar7[3] = (uint)puVar13;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_002c6a06:
      if (bVar26 || bVar23 != bVar28) {
        if (bVar28) {
          coprocessor_storelong(7,in_cr1,in_r12 + -0x3d4);
        }
        if (bVar23 == bVar28) {
          pbVar18 = unaff_r10 + -0x3e0;
          coprocessor_store(0xb,in_cr9,unaff_r10);
          *(char *)(uVar14 - 0x1ad) = (char)puVar7;
        }
        else {
          software_interrupt(0x58c7cf);
          pbVar18 = unaff_r10;
        }
        if (!bVar23) {
          uVar12 = *puVar5;
        }
        if (bVar28) {
          uVar14 = (uint)(unaff_r9 + 0x9c) & 0xff;
          bVar25 = uVar14 == 0 && bVar25 || uVar14 != 0 && (bool)((byte)(uVar15 >> uVar14 - 1) & 1);
          puVar19 = (undefined1 *)(uVar12 ^ uVar15 >> uVar14);
          bVar23 = (int)puVar19 < 0;
          bVar26 = puVar19 == (undefined1 *)0x0;
        }
        coprocessor_store2(0xe,in_cr7,unaff_r11 + 8);
        if (bVar23 == bVar28) {
          pbVar18 = pbVar18 + 0x5c6;
          uVar8 = (uint)*pbVar18;
        }
        if (!bVar25 || bVar26) {
          *(undefined4 *)pbVar18 = uVar21;
          *(int *)(pbVar18 + -4) = unaff_r11 + 8;
          *(code **)(pbVar18 + -8) = unaff_r9 + 0x9c;
          *(undefined4 *)(pbVar18 + -0xc) = unaff_r8;
          *(undefined1 **)(pbVar18 + -0x10) = puVar13;
          *(uint *)(pbVar18 + -0x14) = uVar10;
          *(uint *)(pbVar18 + -0x18) = uVar8;
          *(int *)(pbVar18 + -0x1c) = iVar20;
        }
        puVar7[-5] = unaff_s18;
        if (!bVar25) {
          coprocessor_function(0xd,5,3,in_cr13,in_cr4,in_cr15);
        }
        if (!bVar26) {
          func_0xffc3caca();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      (*(code *)0x6d4c17f5)(0x933054f,0x4166488b,0xa39f3101);
      return;
    }
    bVar25 = ((int)puVar13 >> 0x17 & 1U) != 0;
    iVar2 = (int)puVar13 >> 0x18;
    bVar26 = iVar2 == 0;
    puVar13 = &stack0x00000098;
    uVar6 = uVar14 + 0xa4;
    coprocessor_load(9,in_cr11,uVar14);
    if (!bVar25 || bVar26) {
      puVar7 = (uint *)0x2c6960;
      puVar5 = (uint *)0xaac53db4;
      *(undefined1 **)(uVar10 + 0x68) = puVar13;
      iVar20 = uVar6 * 0x800000;
      bVar25 = 2 < uVar6;
      bVar28 = SBORROW4(uVar6,3);
      uVar12 = uVar14 + 0xa1;
      bVar23 = (int)uVar12 < 0;
      bVar26 = uVar12 == 0;
      uVar14 = uVar6;
      if (bVar26) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto LAB_002c6a06;
    }
    *(char *)(uVar16 + 0x9d) = (char)puVar7;
    uVar14 = *puVar5;
    uVar8 = puVar5[1];
    uVar10 = puVar5[2];
    puVar5 = (uint *)puVar5[3];
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c5ce4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::append(unsigned int, char)

void std::__ndk1::basic_string<>::append(uint param_1,char param_2)

{
  int iVar1;
  undefined4 unaff_r5;
  int unaff_r7;
  char in_NG;
  bool in_ZR;
  char in_OV;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr10;
  
  *(undefined4 *)(unaff_r7 + 0x50) = unaff_r5;
  if (in_ZR || in_NG != in_OV) {
    *(undefined1 **)(unaff_r7 + 0x4c) = &stack0x00000054;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar1 = -(int)&stack0x00000054;
  coprocessor_function2(0xc,1,0,in_cr10,in_cr6,in_cr5);
  _DAT_cc21dbf3 = *(undefined4 *)(param_1 + 4);
  (*(code *)&DAT_00000076)(*(undefined4 *)param_1,0x76,iVar1,iVar1 >> 2);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c64d8)
// WARNING: Removing unreachable block (ram,0x002c64e0)
// WARNING: Removing unreachable block (ram,0x002c64e6)
// WARNING: Removing unreachable block (ram,0x002c650a)
// WARNING: Removing unreachable block (ram,0x002c6512)
// WARNING: Removing unreachable block (ram,0x002c6518)
// WARNING: Removing unreachable block (ram,0x002c6582)
// WARNING: Removing unreachable block (ram,0x002c6568)
// WARNING: Removing unreachable block (ram,0x002c64ae)
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::rfind(char, unsigned int) const

void std::__ndk1::basic_string<>::rfind(char param_1,uint param_2)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  uint *puVar6;
  uint uVar7;
  uint *puVar8;
  int in_r3;
  int unaff_r4;
  int iVar9;
  uint uVar10;
  uint unaff_r5;
  int *piVar11;
  uint uVar12;
  undefined2 unaff_r6;
  undefined1 *puVar13;
  uint uVar14;
  int iVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  undefined4 unaff_r8;
  int unaff_r9;
  byte *unaff_r10;
  byte *pbVar19;
  int unaff_r11;
  int in_r12;
  undefined1 *puVar20;
  int in_lr;
  undefined4 uVar21;
  undefined4 in_pc;
  bool bVar22;
  bool bVar23;
  bool bVar24;
  bool bVar25;
  char cVar26;
  uint uVar27;
  undefined4 in_cr0;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr7;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined8 in_d4;
  uint unaff_s18;
  undefined8 unaff_d14;
  undefined8 in_d25;
  uint uStack0000013c;
  undefined4 in_stack_0000038c;
  undefined4 in_stack_000003b4;
  
  iVar3 = (int)param_1;
  bVar2 = *(byte *)(unaff_r4 + 0x1b);
  uStack0000013c = (uint)bVar2;
  *(int *)param_2 = iVar3;
  uVar27 = param_2 + 4;
  *(undefined2 *)(unaff_r5 + 0x38) = unaff_r6;
  *(byte *)((unaff_r5 >> 0x1e) + iVar3) = bVar2;
  uVar17 = (uint)*(ushort *)(unaff_r5 + in_r3);
  iVar9 = uVar27 * 0x10000;
  *(short *)(iVar3 + 0x10) = (short)unaff_r5;
  *(uint *)(uVar17 + 0x48) = uVar27;
  iVar3 = iVar3 + unaff_r5 + (uint)((uVar27 & 0x10000) != 0);
  cVar26 = SCARRY4(iVar3,0xe0);
  puVar4 = (undefined4 *)(iVar3 + 0xe0);
  *(int *)(in_lr + 0x59) = unaff_r11;
  uVar14 = (uint)*(char *)(uVar17 + unaff_r5);
  if ((int)puVar4 < 0 != (bool)cVar26) {
    coprocessor_load(0,in_cr0,uVar14);
    *(char *)(uVar14 - 0x4d) = (char)((uint)iVar9 >> 0x18);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (puVar4 == (undefined4 *)0x0) {
    if ((uVar27 & 0x20) == 0 || uVar27 * 0x8000000 == 0) {
      software_hlt(0x25);
      iRam4e68d856 = uVar14 + 0x20;
      uRam4e68d8be = 0x4e68d846;
      uRam4e68d84e = 0x4e68d846;
      iRam4e68d846 = uVar27 * 0x8000000;
      uRam4e68d84a = in_stack_0000038c;
      iRam4e68d852 = iVar9;
      uRam4e68d85a = uVar17;
      *(short *)(iVar9 + *(int *)(uVar17 + 0xc)) = (short)unaff_r5;
      if (uVar14 < 0xffffffe0) {
        in_stack_000003b4 = 0xdcf4b13d;
      }
      else {
        uVar5 = VectorGetElement(in_d4,0,2,0);
        VectorMultiplyAddLongScalar(unaff_d14,uVar5,1);
      }
      VectorRoundShiftRight(in_d25,0x3d);
      *(undefined4 *)(unaff_r5 + 0x30) = in_stack_000003b4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (0x86 < uStack0000013c) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar5 = *puVar4;
  uVar27 = *(uint *)(iVar3 + 0xe4);
  piVar11 = *(int **)(iVar3 + 0xe8);
  iVar15 = *(int *)(iVar3 + 0xec);
  iVar18 = *(int *)(iVar3 + 0xf0);
  *(uint *)(iVar9 + 0x48) = uStack0000013c;
  *(short *)(iVar18 + 0x12) = (short)iVar15;
  *(int *)(iVar15 + 0x38) = iVar15;
  *(short *)(uVar27 + 0x10) = (short)iVar15;
  iVar3 = *(int *)(iVar18 + 8);
  *(int *)(iVar3 + 0x58) = iVar3;
  uVar21 = 0x2c6c8d;
  puVar6 = (uint *)func_0x005a3d14(uVar5,&DAT_002c6efc);
  *piVar11 = (int)puVar6;
  piVar11[1] = iVar3;
  piVar11[2] = iVar9;
  *(undefined2 *)((int)puVar6 + 0x2a) = 0;
  *(short *)(iVar18 + 6) = (short)((int)uVar27 >> 9);
  uVar17 = *puVar6;
  puVar8 = (uint *)puVar6[2];
  uVar10 = puVar6[3];
  uVar12 = puVar6[4];
  uVar16 = puVar6[5];
  puVar6 = (uint *)puVar6[6];
  *(char *)(puVar6 + 3) = (char)uVar17;
  coprocessor_storelong(0,in_cr4,unaff_r9);
  uVar14 = 0xc;
  if (cVar26 != '\0') {
    *(undefined1 *)(uVar17 + 3) = 0xc;
    iVar3 = uVar16 + 0xcd;
    puVar8[0xc] = (uint)puVar6;
    *(undefined4 *)(unaff_r9 + 0x274) = in_pc;
    *(int *)(unaff_r9 + 0x278) = iVar3;
    if (iVar3 < 0 != SCARRY4(uVar16,0xcd)) {
      *(uint *)(uVar12 + (int)puVar6) = (uint)(ushort)puVar6[8];
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(uint *)(uVar17 + 100) = (uint)(ushort)puVar6[8];
    uVar14 = puVar6[0xb];
    puVar8 = (uint *)(uint)*(byte *)(uVar12 + 3);
    uVar27 = (uint)*(byte *)((int)puVar8 + (int)puVar6);
    puVar6[9] = uVar12 << 7;
    uVar10 = uVar27 - 0xf8;
    *(short *)(*(int *)(*(int *)(uVar27 + 0x2c) + 0x28) + 0x14) = (short)puVar6;
    *(uint *)((int)puVar6 + uVar10) = uVar17;
    *puVar8 = uVar12 << 7;
    puVar8[1] = uVar14;
    puVar8[2] = uVar10;
    if (SBORROW4(uVar27,0xf8)) {
      *(char *)(uVar14 + 0xe) = (char)uVar10;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  coprocessor_function2(0,4,2,in_cr1,in_cr11,in_cr6);
  uVar16 = unaff_r11 - 0x1bc;
  coprocessor_store(0xe,in_cr4,uVar16);
  if (((int)uVar27 >> 8 & 1U) != 0) {
    *(char *)(puVar8 + 1) = (char)puVar8;
    software_bkpt(0xe9);
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
    (*pcVar1)();
  }
  puVar13 = (undefined1 *)((int)puVar6 << 0x15);
  bVar24 = 0xffffff7a < uVar17;
  bVar25 = SCARRY4(uVar17,0x85);
  iVar9 = uVar17 + 0x85;
  bVar23 = iVar9 == 0;
  iVar3 = iVar9;
  if (!bVar24 || bVar23) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    bVar22 = iVar3 < 0;
    coprocessor_function2(3,0xb,1,in_cr13,in_cr10,in_cr15);
    if (!bVar25) {
      if (bVar23 || bVar22 != bVar25) {
        *puVar8 = uVar14;
        puVar8[1] = uVar27;
        puVar8[2] = uVar12;
        puVar8[3] = (uint)puVar13;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_002c6a06:
      if (bVar23 || bVar22 != bVar25) {
        if (bVar25) {
          coprocessor_storelong(7,in_cr1,in_r12 + -0x3d4);
        }
        if (bVar22 == bVar25) {
          pbVar19 = unaff_r10 + -0x3e0;
          coprocessor_store(0xb,in_cr9,unaff_r10);
          *(char *)(uVar14 - 0x1ad) = (char)puVar8;
        }
        else {
          software_interrupt(0x58c7cf);
          pbVar19 = unaff_r10;
        }
        if (!bVar22) {
          uVar12 = *puVar6;
        }
        if (bVar25) {
          uVar14 = unaff_r9 + 0x9cU & 0xff;
          bVar24 = uVar14 == 0 && bVar24 || uVar14 != 0 && (bool)((byte)(uVar16 >> uVar14 - 1) & 1);
          puVar20 = (undefined1 *)(uVar12 ^ uVar16 >> uVar14);
          bVar22 = (int)puVar20 < 0;
          bVar23 = puVar20 == (undefined1 *)0x0;
        }
        coprocessor_store2(0xe,in_cr7,unaff_r11 + 8);
        if (bVar22 == bVar25) {
          pbVar19 = pbVar19 + 0x5c6;
          uVar27 = (uint)*pbVar19;
        }
        if (!bVar24 || bVar23) {
          *(undefined4 *)pbVar19 = uVar21;
          *(int *)(pbVar19 + -4) = unaff_r11 + 8;
          *(uint *)(pbVar19 + -8) = unaff_r9 + 0x9cU;
          *(undefined4 *)(pbVar19 + -0xc) = unaff_r8;
          *(undefined1 **)(pbVar19 + -0x10) = puVar13;
          *(uint *)(pbVar19 + -0x14) = uVar10;
          *(uint *)(pbVar19 + -0x18) = uVar27;
          *(int *)(pbVar19 + -0x1c) = iVar9;
        }
        puVar8[-5] = unaff_s18;
        if (!bVar24) {
          coprocessor_function(0xd,5,3,in_cr13,in_cr4,in_cr15);
        }
        if (!bVar23) {
          func_0xffc3caca();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      (*(code *)0x6d4c17f5)(0x933054f,0x4166488b,0xa39f3101);
      return;
    }
    bVar24 = ((int)puVar13 >> 0x17 & 1U) != 0;
    iVar3 = (int)puVar13 >> 0x18;
    bVar23 = iVar3 == 0;
    puVar13 = &stack0x00000098;
    uVar7 = uVar14 + 0xa4;
    coprocessor_load(9,in_cr11,uVar14);
    if (!bVar24 || bVar23) {
      puVar8 = (uint *)0x2c6960;
      puVar6 = (uint *)0xaac53db4;
      *(undefined1 **)(uVar10 + 0x68) = puVar13;
      iVar9 = uVar7 * 0x800000;
      bVar24 = 2 < uVar7;
      bVar25 = SBORROW4(uVar7,3);
      uVar12 = uVar14 + 0xa1;
      bVar22 = (int)uVar12 < 0;
      bVar23 = uVar12 == 0;
      uVar14 = uVar7;
      if (bVar23) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto LAB_002c6a06;
    }
    *(char *)(uVar17 + 0x9d) = (char)puVar8;
    uVar14 = *puVar6;
    uVar27 = puVar6[1];
    uVar10 = puVar6[2];
    puVar6 = (uint *)puVar6[3];
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::assign(unsigned int, char)

void std::__ndk1::basic_string<>::assign(uint param_1,char param_2)

{
  int in_r2;
  int unaff_r4;
  int unaff_r5;
  int unaff_r6;
  undefined4 *puVar1;
  undefined2 unaff_r7;
  int in_r12;
  undefined4 in_cr1;
  undefined4 in_cr9;
  undefined8 in_d25;
  int in_stack_00000000;
  undefined4 in_stack_00000004;
  int in_stack_0000000c;
  undefined4 in_stack_000003b4;
  
  *(undefined2 *)(in_r2 * 2) = unaff_r7;
  if (SCARRY4(unaff_r5,0x48)) {
    VectorRoundShiftRight(in_d25,0x3d);
    *(undefined4 *)(unaff_r5 + 0x78) = in_stack_000003b4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (in_stack_0000000c == 0) {
    software_interrupt(0xbe);
    *(short *)(in_stack_00000000 + 0x30) = (short)*(undefined4 *)(unaff_r6 + -0x7b) + 0x90;
    coprocessor_storelong(9,in_cr9,in_r12 + 0x140);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  coprocessor_load(3,in_cr1,in_stack_00000004);
  if (unaff_r4 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (0x7f < unaff_r6) {
    puVar1 = *(undefined4 **)(((uint)&stack0x000001bc >> 0xf) + 0x24);
    *puVar1 = *(undefined4 *)(unaff_r4 + 0x60);
    puVar1[1] = &stack0x000001bc;
    *(char *)((int)puVar1 + 9) = (char)&stack0x000001bc;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::erase(unsigned int, unsigned int)

void std::__ndk1::basic_string<>::erase(uint param_1,uint param_2)

{
  char cVar1;
  int in_r3;
  int unaff_r5;
  undefined4 in_cr3;
  int in_stack_000001a0;
  
  cVar1 = *(char *)(in_r3 * 2);
  coprocessor_loadlong(5,in_cr3,(int)cVar1);
  *(short *)(unaff_r5 + 0x3a) = (short)in_r3;
  *(short *)(in_stack_000001a0 + 0x36) = (short)*(undefined4 *)((cVar1 + 0x9c >> 1) + 4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__erase_external_with_move(unsigned int, unsigned int)

undefined8 __thiscall
std::__ndk1::basic_string<>::__erase_external_with_move
          (basic_string<> *this,uint param_1,uint param_2)

{
  byte bVar1;
  short sVar2;
  undefined1 *puVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  undefined4 extraout_r1;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  uint *puVar12;
  int iVar13;
  code *pcVar14;
  int *piVar15;
  undefined4 *unaff_r6;
  short *psVar16;
  undefined4 *puVar17;
  undefined *puVar18;
  int unaff_r7;
  undefined1 *puVar19;
  undefined4 in_lr;
  undefined4 in_pc;
  bool bVar20;
  char cVar21;
  undefined4 in_cr0;
  undefined8 in_d22;
  undefined8 uVar22;
  undefined1 *puStack0000001c;
  uint in_stack_000001dc;
  int in_stack_0000027c;
  undefined4 *in_stack_00000318;
  int in_stack_000003a8;
  
  uVar10 = (uint)*(byte *)(param_1 + 0x17);
  if (uVar10 == 0) {
    uRam0000001c = 0;
    *unaff_r6 = this;
    unaff_r6[1] = param_2;
    unaff_r6[2] = 0;
    unaff_r6[3] = unaff_r7;
    uRam00000006 = (char)param_2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar8 = *(uint *)(uVar10 + 4);
  iVar11 = *(int *)(uVar10 + 8);
  iVar13 = *(int *)(uVar10 + 0xc);
  psVar16 = *(short **)(uVar10 + 0x14);
  *(short *)(this + 0x1c) = (short)psVar16;
  uVar5 = (uint)*(ushort *)(this + 0x30);
  puVar17 = (undefined4 *)(int)*psVar16;
  iVar6 = -0xa338048;
  uVar10 = (int)(uVar5 - 2) >> 0x1c;
  puVar12 = (uint *)(iVar11 >> 0x18);
  if (SBORROW4(uVar5,uVar5)) {
    *puVar12 = uVar10;
    puVar12[1] = uVar8;
    puVar12[2] = iVar13 + -0x2f >> (uVar10 & 0xff);
    puVar12[3] = uVar5 - 2;
    puVar12[4] = 0x2c68c8;
    puVar12 = puVar12 + 5;
  }
  else {
    iVar6 = -0x51a;
  }
  sVar2 = *(short *)(*(short *)((int)puVar12 + (uint)*(byte *)(iVar6 + 0x1c)) + 0x1df4a4c6);
  pcVar14 = (code *)(int)sVar2;
  cVar21 = (in_stack_000001dc & 1) == 0;
  if ((in_stack_000001dc & 2) != 0) {
    func_0xff80994c();
    *puVar17 = extraout_r1;
    puVar17[1] = &stack0x00000308;
    puVar17[2] = puVar17;
    iVar6 = 0x3ec812b2;
    *(char *)((int)puVar17 + 0x1e) = (char)sVar2;
    if (0 < (int)puVar17 >> 4) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if ((int)puVar17 >> 4 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar22 = (*pcVar14)();
    puVar7 = (undefined8 *)((ulonglong)uVar22 >> 0x20);
    uVar5 = (uint)uVar22;
    puVar19 = &stack0x00000300;
    uVar10 = uVar5 & 0x1000;
    puVar3 = (undefined1 *)(uVar5 & 0xfff);
    while( true ) {
      if (uVar10 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (puVar3 != (undefined1 *)0x0) break;
      *puVar7 = uVar22;
      *(int *)(puVar7 + 1) = iVar6;
      *(undefined4 *)((int)puVar7 + 0xc) = 0xdf62d0bf;
      *(undefined1 **)(puVar7 + 2) = puVar19;
      uVar10 = iVar6 >> 0x16 & 1;
      puVar19 = (undefined1 *)(iVar6 >> 0x17);
      puVar3 = puVar19;
      if (&stack0x00000308 != (undefined1 *)0x0) {
        return CONCAT44(this,uVar5);
      }
    }
    software_interrupt(0x62);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  FUN_002c9f38((int)((ulonglong)in_d22 >> 0x10));
  if (cVar21 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (puVar17 == (undefined4 *)0x0) {
    puVar17 = in_stack_00000318;
  }
  puStack0000001c = &stack0x000001a0;
  if (pcVar14 == (code *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar10 = *(uint *)pcVar14;
  uVar5 = *(uint *)(pcVar14 + 8);
  puVar12 = *(uint **)(pcVar14 + 0xc);
  *(char *)(*(int *)(pcVar14 + 4) * 0x4000000 + in_stack_000003a8) = (char)uVar10;
  *puVar12 = uVar5;
  do {
  } while (0x91 < uVar5);
  if (uVar10 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar10 = (uint)*(byte *)(in_stack_000003a8 + 0xc);
  while( true ) {
    uVar8 = uVar10;
    puVar12 = (uint *)(uVar8 + 0xe2);
    bVar20 = (int)puVar12 < 0;
    iVar6 = *(int *)(in_stack_000003a8 + 0x1c);
    *puVar12 = uVar5 >> 0x1c;
    *(uint *)(uVar8 + 0xe6) = uVar5;
    *(int *)(uVar8 + 0xea) = in_stack_000003a8;
    uVar10 = uVar8 + 0xee;
    *(uint *)(uVar8 + 0xf2) = uVar5 + 6;
    piVar15 = (int *)(uint)*(ushort *)(uVar5 + 0x1c);
    if (puVar12 != (uint *)0x0 && bVar20 == SCARRY4(uVar8,0xe2)) {
      if (!SCARRY4(uVar5,0x79)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(ushort *)(uVar5 + 0x2e) = *(ushort *)(uVar5 + 0x1c);
                    // WARNING: Does not return
      pcVar14 = (code *)software_udf(0xd1,0x2c6ef0);
      (*pcVar14)();
    }
    in_stack_000003a8 = (uVar5 >> 0x1c) << 8;
    if (uVar5 + 6 != 0) break;
    if (bVar20) {
      puVar12 = (uint *)&stack0x000002f8;
      coprocessor_store(6,in_cr0,iVar6 + 0xbc);
      uVar5 = 0xb47d2b13;
      *(undefined4 *)(iVar6 + 0xc) = 0xb47d2b13;
      *piVar15 = (int)puVar12;
      piVar15[1] = -0x4b82d4ed;
      piVar15[2] = in_stack_000003a8;
      piVar15[3] = (int)piVar15;
      piVar15[4] = 0;
      piVar15[5] = iVar6;
      bVar20 = false;
      iVar6 = 6;
      puVar18 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar12;
LAB_002c6f7e:
      uVar9 = (int)uVar10 >> 0x20;
      if (uVar9 == 0) {
        puVar17 = (undefined4 *)(uint)*(ushort *)((int)puVar12 + 0x2e);
        *(short *)(uVar8 + 0x10e) = (short)puVar12;
        *(short *)((int)piVar15 + *(ushort *)((int)piVar15 + uVar10) + 7) = (short)in_stack_000003a8
        ;
        uVar4 = _DAT_8e000034;
        *puVar17 = 0x8e000000;
        puVar17[1] = uVar4;
        puVar17[2] = puVar17[0x16];
        puVar17[3] = puVar17[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar1 = *(byte *)((int)puVar12 + 0x19);
      puVar17 = (undefined4 *)(uVar9 >> 0x1c);
      *puVar12 = uVar10;
      puVar12[1] = uVar5;
      puVar12[2] = (uint)puVar17;
      *puVar17 = puVar12 + 3;
      puVar17[1] = uVar9;
      puVar17[2] = uVar5;
      puVar17[3] = puVar18;
      puVar17[4] = iVar6;
      if (bVar20) {
        *(char *)(uVar9 + 6) = (char)*(undefined4 *)(bVar1 + 4);
        return CONCAT44(in_lr,unaff_r7 >> 0x1a);
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  if (!bVar20) {
    if (piVar15 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar14 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar14)();
  }
  puVar18 = &UNK_002c6f44 + uVar5;
  if (puVar12 == (uint *)0x0 || bVar20 != SCARRY4(uVar8,0xe2)) {
    *(short *)(uVar5 + 0x2a) = (short)puVar18;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)((int)puVar17 + 0x1f) = (short)((int)puVar17 + 7);
  bVar20 = SCARRY4((int)puVar17 + 7,0x87);
  puVar12 = (uint *)((int)puVar17 + in_stack_0000027c + 0x8e);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::append(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int, unsigned int)

undefined8 std::__ndk1::basic_string<>::append(basic_string *param_1,uint param_2,uint param_3)

{
  byte bVar1;
  short sVar2;
  undefined1 *puVar3;
  undefined4 uVar4;
  uint uVar5;
  uint uVar6;
  undefined8 *puVar7;
  undefined4 extraout_r1;
  int iVar8;
  uint uVar9;
  undefined4 *puVar10;
  int in_r3;
  uint uVar11;
  code *pcVar12;
  int unaff_r5;
  uint *puVar13;
  int *piVar14;
  undefined4 *unaff_r6;
  undefined *puVar15;
  int unaff_r7;
  undefined1 *puVar16;
  int iVar17;
  undefined4 in_pc;
  bool bVar18;
  char cVar19;
  undefined4 in_cr0;
  undefined8 uVar20;
  undefined4 in_stack_00000000;
  undefined8 in_stack_00000010;
  undefined1 *puStack00000034;
  uint in_stack_000001f4;
  int in_stack_00000294;
  undefined4 *in_stack_00000330;
  int in_stack_000003c0;
  
  sVar2 = *(short *)(*(short *)(param_1 + in_r3) + unaff_r5);
  pcVar12 = (code *)(int)sVar2;
  cVar19 = (in_stack_000001f4 & 1) == 0;
  if ((in_stack_000001f4 & 2) != 0) {
    func_0xff80994c();
    *unaff_r6 = extraout_r1;
    unaff_r6[1] = &stack0x00000320;
    unaff_r6[2] = unaff_r6;
    iVar17 = (int)unaff_r6 >> 4;
    iVar8 = 0x3ec812b2;
    *(char *)((int)unaff_r6 + 0x1e) = (char)sVar2;
    if (iVar17 != 0 && iVar17 < 0 == SBORROW4(unaff_r7,8)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (iVar17 == 0) {
      uVar20 = (*pcVar12)();
      puVar7 = (undefined8 *)((ulonglong)uVar20 >> 0x20);
      uVar11 = (uint)uVar20;
      puVar16 = &stack0x00000318;
      uVar5 = uVar11 & 0x1000;
      puVar3 = (undefined1 *)(uVar11 & 0xfff);
      while( true ) {
        if (uVar5 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (puVar3 != (undefined1 *)0x0) break;
        *puVar7 = uVar20;
        *(int *)(puVar7 + 1) = iVar8;
        *(undefined4 *)((int)puVar7 + 0xc) = 0xdf62d0bf;
        *(undefined1 **)(puVar7 + 2) = puVar16;
        uVar5 = iVar8 >> 0x16 & 1;
        puVar16 = (undefined1 *)(iVar8 >> 0x17);
        puVar3 = puVar16;
        if (&stack0x00000320 != (undefined1 *)0x0) {
          return CONCAT44(in_stack_00000000,uVar11);
        }
      }
      software_interrupt(0x62);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  FUN_002c9f38();
  if (cVar19 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (unaff_r6 == (undefined4 *)0x0) {
    unaff_r6 = in_stack_00000330;
  }
  puStack00000034 = &stack0x000001b8;
  if (pcVar12 == (code *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar5 = *(uint *)pcVar12;
  uVar11 = *(uint *)(pcVar12 + 8);
  puVar13 = *(uint **)(pcVar12 + 0xc);
  *(char *)(*(int *)(pcVar12 + 4) * 0x4000000 + in_stack_000003c0) = (char)uVar5;
  *puVar13 = uVar11;
  do {
  } while (0x91 < uVar11);
  if (uVar5 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar5 = (uint)*(byte *)(in_stack_000003c0 + 0xc);
  while( true ) {
    uVar6 = uVar5;
    puVar13 = (uint *)(uVar6 + 0xe2);
    bVar18 = (int)puVar13 < 0;
    iVar17 = *(int *)(in_stack_000003c0 + 0x1c);
    *puVar13 = uVar11 >> 0x1c;
    *(uint *)(uVar6 + 0xe6) = uVar11;
    *(int *)(uVar6 + 0xea) = in_stack_000003c0;
    uVar5 = uVar6 + 0xee;
    *(uint *)(uVar6 + 0xf2) = uVar11 + 6;
    piVar14 = (int *)(uint)*(ushort *)(uVar11 + 0x1c);
    if (puVar13 != (uint *)0x0 && bVar18 == SCARRY4(uVar6,0xe2)) {
      if (SCARRY4(uVar11,0x79)) {
        *(ushort *)(uVar11 + 0x2e) = *(ushort *)(uVar11 + 0x1c);
                    // WARNING: Does not return
        pcVar12 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar12)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_stack_000003c0 = (uVar11 >> 0x1c) << 8;
    if (uVar11 + 6 != 0) break;
    if (bVar18) {
      puVar13 = (uint *)&stack0x00000310;
      coprocessor_store(6,in_cr0,iVar17 + 0xbc);
      uVar11 = 0xb47d2b13;
      *(undefined4 *)(iVar17 + 0xc) = 0xb47d2b13;
      *piVar14 = (int)puVar13;
      piVar14[1] = -0x4b82d4ed;
      piVar14[2] = in_stack_000003c0;
      piVar14[3] = (int)piVar14;
      piVar14[4] = 0;
      piVar14[5] = iVar17;
      bVar18 = false;
      iVar17 = 6;
      puVar15 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar13;
LAB_002c6f7e:
      uVar9 = (int)uVar5 >> 0x20;
      if (uVar9 == 0) {
        puVar10 = (undefined4 *)(uint)*(ushort *)((int)puVar13 + 0x2e);
        *(short *)(uVar6 + 0x10e) = (short)puVar13;
        *(short *)((int)piVar14 + *(ushort *)((int)piVar14 + uVar5) + 7) = (short)in_stack_000003c0;
        uVar4 = _DAT_8e000034;
        *puVar10 = 0x8e000000;
        puVar10[1] = uVar4;
        puVar10[2] = puVar10[0x16];
        puVar10[3] = puVar10[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar1 = *(byte *)((int)puVar13 + 0x19);
      puVar10 = (undefined4 *)(uVar9 >> 0x1c);
      *puVar13 = uVar5;
      puVar13[1] = uVar11;
      puVar13[2] = (uint)puVar10;
      *puVar10 = puVar13 + 3;
      puVar10[1] = uVar9;
      puVar10[2] = uVar11;
      puVar10[3] = puVar15;
      puVar10[4] = iVar17;
      if (!bVar18) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar9 + 6) = (char)*(undefined4 *)(bVar1 + 4);
      return in_stack_00000010;
    }
  }
  if (!bVar18) {
    if (piVar14 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar12 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar12)();
  }
  puVar15 = &UNK_002c6f44 + uVar11;
  if (puVar13 == (uint *)0x0 || bVar18 != SCARRY4(uVar6,0xe2)) {
    *(short *)(uVar11 + 0x2a) = (short)puVar15;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)((int)unaff_r6 + 0x1f) = (short)((int)unaff_r6 + 7);
  bVar18 = SCARRY4((int)unaff_r6 + 7,0x87);
  puVar13 = (uint *)((int)unaff_r6 + in_stack_00000294 + 0x8e);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c660e)
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::compare(char const*) const

undefined8 std::__ndk1::basic_string<>::compare(char *param_1)

{
  code *pcVar1;
  byte bVar2;
  char cVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  int in_r2;
  uint uVar8;
  undefined4 *puVar9;
  int in_r3;
  uint *unaff_r4;
  uint *puVar10;
  int iVar11;
  int unaff_r5;
  undefined1 *puVar12;
  int *piVar13;
  int unaff_r6;
  undefined1 *puVar14;
  int iVar15;
  undefined *puVar16;
  uint uVar17;
  undefined4 unaff_r8;
  undefined4 in_pc;
  undefined1 in_OV;
  bool bVar18;
  undefined4 in_cr0;
  undefined4 in_cr6;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 unaff_d15;
  int in_stack_00000000;
  int in_stack_00000004;
  undefined1 *in_stack_00000008;
  undefined8 in_stack_00000020;
  int in_stack_000002a4;
  int in_stack_0000035a;
  uint in_stack_0000035e;
  int in_stack_000003d0;
  int in_stack_000003dc;
  
  *(int *)in_r2 = in_r2;
  *(int *)(in_r2 + 4) = in_r3;
  *(uint **)(in_r2 + 8) = unaff_r4;
  *(int *)(in_r2 + 0xc) = unaff_r5;
  *(int *)(in_r2 + 0x10) = unaff_r6;
  uVar17 = (uint)*(ushort *)(unaff_r5 + 0x12);
  puVar12 = (undefined1 *)(in_r3 << 0x1c);
  *(int *)(in_r2 + 0x58) = in_r2;
  uVar6 = uRam0000004c;
  puVar14 = puVar12;
  if (puVar12 == (undefined1 *)0x0) {
    uVar17 = (uint)unaff_r4 >> 0x18;
    if (!SBORROW4(uVar17,0x87)) {
      *(short *)(in_stack_00000008 + *(int *)(in_stack_00000000 + 0x3c)) = (short)in_stack_00000004;
      *(char *)(in_stack_00000004 + 3) = (char)in_stack_00000004 + -1;
      *in_stack_00000008 = 0;
      iVar4 = _DAT_0000008d;
      iVar15 = iRam00000008;
      iVar11 = iRam00000004;
      if (!SBORROW4(in_stack_00000004,1)) {
LAB_002c6eec:
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
      puVar10 = (uint *)(iRam00000004 + 0x8e);
      *(short *)(_DAT_0000008d + 0x14) = (short)_DAT_00000081;
      if (iVar15 == 0) {
        iVar15 = *(int *)(iVar4 + 0x10);
      }
      if (puVar10 == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      uVar6 = *puVar10;
      uVar17 = *(uint *)(iVar11 + 0x96);
      puVar10 = *(uint **)(iVar11 + 0x9a);
      *(char *)(*(int *)(iVar11 + 0x92) * 0x4000000 + in_stack_000003d0) = (char)uVar6;
      *puVar10 = uVar17;
      do {
      } while (0x91 < uVar17);
      if (uVar6 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      uVar6 = (uint)*(byte *)(in_stack_000003d0 + 0xc);
      while( true ) {
        uVar7 = uVar6;
        puVar10 = (uint *)(uVar7 + 0xe2);
        bVar18 = (int)puVar10 < 0;
        iVar11 = *(int *)(in_stack_000003d0 + 0x1c);
        *puVar10 = uVar17 >> 0x1c;
        *(uint *)(uVar7 + 0xe6) = uVar17;
        *(int *)(uVar7 + 0xea) = in_stack_000003d0;
        uVar6 = uVar7 + 0xee;
        *(uint *)(uVar7 + 0xf2) = uVar17 + 6;
        piVar13 = (int *)(uint)*(ushort *)(uVar17 + 0x1c);
        if (puVar10 != (uint *)0x0 && bVar18 == SCARRY4(uVar7,0xe2)) {
          if (!SCARRY4(uVar17,0x79)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          *(ushort *)(uVar17 + 0x2e) = *(ushort *)(uVar17 + 0x1c);
          goto LAB_002c6eec;
        }
        in_stack_000003d0 = (uVar17 >> 0x1c) << 8;
        if (uVar17 + 6 != 0) break;
        if (bVar18) {
          puVar10 = (uint *)&stack0x00000320;
          coprocessor_store(6,in_cr0,iVar11 + 0xbc);
          uVar17 = 0xb47d2b13;
          *(undefined4 *)(iVar11 + 0xc) = 0xb47d2b13;
          *piVar13 = (int)puVar10;
          piVar13[1] = -0x4b82d4ed;
          piVar13[2] = in_stack_000003d0;
          piVar13[3] = (int)piVar13;
          piVar13[4] = 0;
          piVar13[5] = iVar11;
          bVar18 = false;
          iVar11 = 6;
          puVar16 = (undefined *)0x0;
          _DAT_b47d2b8b = puVar10;
LAB_002c6f7e:
          uVar8 = (int)uVar6 >> 0x20;
          if (uVar8 == 0) {
            puVar9 = (undefined4 *)(uint)*(ushort *)((int)puVar10 + 0x2e);
            *(short *)(uVar7 + 0x10e) = (short)puVar10;
            *(short *)((int)piVar13 + *(ushort *)((int)piVar13 + uVar6) + 7) =
                 (short)in_stack_000003d0;
            uVar5 = _DAT_8e000034;
            *puVar9 = 0x8e000000;
            puVar9[1] = uVar5;
            puVar9[2] = puVar9[0x16];
            puVar9[3] = puVar9[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          bVar2 = *(byte *)((int)puVar10 + 0x19);
          puVar9 = (undefined4 *)(uVar8 >> 0x1c);
          *puVar10 = uVar6;
          puVar10[1] = uVar17;
          puVar10[2] = (uint)puVar9;
          *puVar9 = puVar10 + 3;
          puVar9[1] = uVar8;
          puVar9[2] = uVar17;
          puVar9[3] = puVar16;
          puVar9[4] = iVar11;
          if (bVar18) {
            *(char *)(uVar8 + 6) = (char)*(undefined4 *)(bVar2 + 4);
            return in_stack_00000020;
          }
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      if (!bVar18) {
        if (piVar13 == (int *)0xffffff42) {
          TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
        (*pcVar1)();
      }
      puVar16 = &UNK_002c6f44 + uVar17;
      if (puVar10 == (uint *)0x0 || bVar18 != SCARRY4(uVar7,0xe2)) {
        *(short *)(uVar17 + 0x2a) = (short)puVar16;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(short *)(iVar15 + 0x1f) = (short)(iVar15 + 7);
      bVar18 = SCARRY4(iVar15 + 7,0x87);
      puVar10 = (uint *)(iVar15 + 0x8e + in_stack_000002a4);
      goto LAB_002c6f7e;
    }
    in_OV = SBORROW4(uVar17,0x54);
    sRam22953444 = (byte)((uint)unaff_r4 >> 0x18) - 0x54;
    puVar12 = &stack0x000003b0;
    unaff_r4 = (uint *)(uint)*(byte *)(unaff_r6 + 0xd);
    cVar3 = *(char *)(in_r3 + unaff_r6);
    *(int *)(uVar17 - 0x294) = (int)cVar3;
    *(undefined1 **)(uVar17 - 0x290) = puVar12;
    puVar14 = (undefined1 *)(uVar6 ^ 0x360);
    VectorRoundShiftLeft(unaff_d15,0x2a,0x40,1);
    while (param_1 = &stack0x00000348, puVar14 == (undefined1 *)0x0) {
      in_OV = SCARRY4((int)param_1,6);
      puVar14 = &stack0x0000034e;
      if ((bool)in_OV) {
        *unaff_r4 = (uint)puVar14;
        unaff_r4[1] = 0x2295341c;
        unaff_r4[2] = (int)cVar3;
        if ((bool)in_OV) {
          coprocessor_store(1,in_cr6,in_stack_0000035e - 0x1b4);
          coprocessor_loadlong(1,in_cr15,&stack0x00000310);
          iVar11 = (in_stack_0000035e >> 0xc | in_stack_0000035e << 0x14) - in_stack_0000035a;
          *(int *)(iVar11 + 100) = iVar11;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    uVar17 = uVar6;
    if (uVar6 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  if (-1 < (int)puVar14) {
    coprocessor_load(6,in_cr11,unaff_r8);
  }
  if (!(bool)in_OV) {
    *(char *)unaff_r4 = (char)uVar17;
  }
  puVar12[0x1e] = (char)param_1;
  *(short *)(in_stack_000003dc + 8) = (short)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::compare(unsigned int, unsigned int, char const*, unsigned int) const

void std::__ndk1::basic_string<>::compare(uint param_1,uint param_2,char *param_3,uint param_4)

{
  char cVar1;
  uint *unaff_r4;
  int iVar2;
  undefined1 *unaff_r5;
  int unaff_r6;
  undefined1 *puVar3;
  int unaff_r7;
  uint uVar4;
  undefined4 unaff_r8;
  undefined1 in_OV;
  undefined4 in_cr6;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 unaff_d15;
  int in_stack_0000035a;
  uint in_stack_0000035e;
  int in_stack_000003dc;
  
  cVar1 = *(char *)(param_4 + unaff_r6);
  uVar4 = *(uint *)(unaff_r7 + 0x4c);
  *(short *)(param_3 + 0x28) = (short)param_1;
  *(int *)(param_1 - 0x240) = (int)cVar1;
  *(undefined1 **)(param_1 - 0x23c) = unaff_r5;
  *unaff_r5 = (char)unaff_r8;
  puVar3 = (undefined1 *)(uVar4 ^ 0x360);
  VectorRoundShiftLeft(unaff_d15,0x2a,0x40,1);
  do {
    if (puVar3 != (undefined1 *)0x0) {
      if (uVar4 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (-1 < (int)puVar3) {
        coprocessor_load(6,in_cr11,unaff_r8);
      }
      if (!(bool)in_OV) {
        *(char *)unaff_r4 = (char)uVar4;
      }
      unaff_r5[0x1e] = (char)&stack0x00000348;
      *(short *)(in_stack_000003dc + 8) = (short)unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_OV = SCARRY4((int)&stack0x00000348,6);
    puVar3 = &stack0x0000034e;
  } while (!(bool)in_OV);
  *unaff_r4 = (uint)puVar3;
  unaff_r4[1] = (uint)param_3;
  unaff_r4[2] = (int)cVar1;
  if (!(bool)in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  coprocessor_store(1,in_cr6,in_stack_0000035e - 0x1b4);
  coprocessor_loadlong(1,in_cr15,unaff_r5 + -0xa0);
  iVar2 = (in_stack_0000035e >> 0xc | in_stack_0000035e << 0x14) - in_stack_0000035a;
  *(int *)(iVar2 + 100) = iVar2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::compare(unsigned int, unsigned int, char const*) const

void __thiscall
std::__ndk1::basic_string<>::compare(basic_string<> *this,uint param_1,uint param_2,char *param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *unaff_r6;
  code *UNRECOVERED_JUMPTABLE;
  basic_string<> *pbVar3;
  
  iVar1 = *(int *)(this + 4);
  uVar2 = *(undefined4 *)(this + 8);
  pbVar3 = this + 0xc;
  *unaff_r6 = pbVar3;
  unaff_r6[1] = param_3;
  unaff_r6[2] = uVar2;
  unaff_r6[3] = unaff_r6;
  if (((int)pbVar3 >> 1 & 1U) != 0) {
    *(basic_string<> **)(iVar1 + 0x28) = pbVar3;
    param_3 = (char *)0x2c67a0;
  }
                    // WARNING: Could not recover jumptable at 0x002c66c4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)(pbVar3,*(ushort *)(iVar1 + 0x28) - 0xe7,iVar1,param_3);
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::at(unsigned int)

void __thiscall std::__ndk1::basic_string<>::at(basic_string<> *this,uint param_1)

{
  undefined1 *puVar1;
  int unaff_r5;
  uint unaff_r6;
  undefined1 unaff_r7;
  undefined4 unaff_r8;
  undefined4 in_cr11;
  int in_stack_000003dc;
  
  puVar1 = (undefined1 *)(unaff_r6 >> 0xb);
  if (-1 < (int)(puVar1 + param_1)) {
    coprocessor_load(6,in_cr11,unaff_r8);
  }
  if (!SCARRY4(param_1,(int)puVar1)) {
    *puVar1 = unaff_r7;
  }
  *(char *)(unaff_r5 + 0x1e) = (char)this;
  *(short *)(in_stack_000003dc + 8) = (short)unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::assign(char const*)

void std::__ndk1::basic_string<>::assign(char *param_1)

{
  char in_r2;
  
  param_1[0xb] = in_r2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x001cba2c)
// WARNING: Removing unreachable block (ram,0x00323648)
// WARNING: Removing unreachable block (ram,0x002c66b2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::find(char const*, unsigned int, unsigned int) const

void __thiscall
std::__ndk1::basic_string<>::find(basic_string<> *this,char *param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  undefined1 uVar2;
  byte bVar3;
  ushort uVar4;
  undefined2 uVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  uint uVar8;
  int iVar9;
  int unaff_r6;
  int iVar10;
  int *unaff_r7;
  code *UNRECOVERED_JUMPTABLE;
  int unaff_r10;
  int in_pc;
  undefined4 in_cr0;
  undefined4 in_cr6;
  undefined4 in_cr9;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined4 in_cr14;
  undefined8 uVar11;
  undefined8 unaff_d8;
  undefined8 in_d30;
  undefined1 in_stack_0000005c;
  uint uStack0000013c;
  undefined4 in_stack_0000021c;
  int in_stack_00000334;
  undefined4 in_stack_00000338;
  
  *(int *)(unaff_r6 + 8) = unaff_r6;
  uVar5 = SUB42(unaff_r7,0);
  *(undefined2 *)(unaff_r6 * 2) = uVar5;
  coprocessor_moveto(0,7,6,unaff_r10,in_cr9,in_cr11);
  if ((int)(param_3 << 0x1b) < 0 != SCARRY4(param_2,0x57)) {
    coprocessor_storelong(0xe,in_cr13,in_pc + 0x398);
    if (-1 < (int)param_1 - unaff_r6) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_movefromRt(7,1,5,in_cr0,in_cr6);
    *(undefined2 *)unaff_r7 = 0;
    puVar7 = _DAT_000000ce;
    uVar6 = uRam00000004;
    *_DAT_000000ce = &stack0x0000033c;
    puVar7[1] = uVar6;
    puVar7[2] = in_stack_00000338;
    puVar7[3] = puVar7;
    uStack0000013c = param_3;
                    // WARNING: Could not recover jumptable at 0x002c66c4. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)
              (&stack0x0000033c,*(ushort *)(in_stack_00000334 + 0x28) - 0xe7,in_stack_00000334,uVar6
              );
    return;
  }
  bVar3 = *(byte *)(unaff_r6 + (int)unaff_r7);
  uVar8 = (uint)bVar3;
  DAT_001cbb3c = unaff_r6;
  *(short *)(unaff_r6 + 0x28) = (short)unaff_r6;
  uVar4 = *(ushort *)((int)this * 2);
  if (unaff_r10 < 0x1cbadc) {
    *(undefined2 *)(&DAT_001cbbf8 + uVar8) = 0xbbf8;
    uVar11 = VectorAdd(unaff_d8,in_d30,8);
    *(basic_string<> **)param_3 = this;
    *(uint *)(param_3 + 4) = uVar8;
    *(uint *)(param_3 + 8) = param_3 << 0x1b;
    *(undefined4 *)(param_3 + 0xc) = in_stack_0000021c;
                    // WARNING: Could not recover jumptable at 0x001cbb16. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)&stack0x00000000)((int)uVar11,&stack0x00000388,uRam00000004);
    return;
  }
  *(char *)(uVar8 + 7) = (char)unaff_r7;
  DAT_0000001f = 0xa8;
  *(char *)unaff_r7 = (char)((int)(uint)uVar4 >> 0xc);
  *(byte *)(unaff_r6 + 0xe) = bVar3;
  if (0xf2 < (int)param_3) {
    if (unaff_r7 == (int *)0x0) {
      unaff_r7 = (int *)0xffffff28;
    }
    uVar2 = *(undefined1 *)((int)unaff_r7 + 0x1f);
    iVar9 = unaff_r7[1];
    iVar10 = unaff_r7[4];
    _DAT_0072eed4 = uVar5;
    *(BADSPACEBASE **)(&stack0x00000000 + *unaff_r7) = register0x00000054;
    coprocessor_store(1,in_cr14,iVar9 + -0x154);
    *(undefined1 *)(iVar9 + 0x1d) = in_stack_0000005c;
    *(undefined1 *)(iVar9 + iVar10) = uVar2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xf6,0x1cbada);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::compare(unsigned int, unsigned int, std::__ndk1::basic_string<char,
// std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> > const&, unsigned int, unsigned
// int) const

void std::__ndk1::basic_string<>::compare
               (uint param_1,uint param_2,basic_string *param_3,uint param_4,uint param_5)

{
  uint uVar1;
  int unaff_r7;
  undefined4 in_cr5;
  undefined4 in_cr10;
  undefined4 in_cr14;
  undefined8 in_d6;
  undefined8 in_d25;
  
  *(short *)(param_4 + 0x10) = (short)param_4;
  coprocessor_function(10,8,7,in_cr10,in_cr14,in_cr5);
  if (unaff_r7 + 0xb7 < 0) {
    FloatVectorAdd(in_d25,in_d6,2);
    uVar1 = (uint)_DAT_00000132;
    *(undefined1 *)(param_2 + 0x32) = 0;
    *(uint *)(*(int *)(param_2 + 0x10) + 0x10) = uVar1;
    *(undefined1 *)(param_2 * 0x40000000 + 0xd) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::_MetaBase<__can_be_converted_to_string_view<char, std::__ndk1::char_traits<char>,
// std::__ndk1::basic_string_view<char, std::__ndk1::char_traits<char> >
// >::value&&(!__is_same_uncvref<std::__ndk1::basic_string_view<char, std::__ndk1::char_traits<char>
// >, std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> >
// >::value)>::_EnableIfImpl<int> std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> >::compare<std::__ndk1::basic_string_view<char,
// std::__ndk1::char_traits<char> > >(unsigned int, unsigned int,
// std::__ndk1::basic_string_view<char, std::__ndk1::char_traits<char> > const&, unsigned int,
// unsigned int) const

void std::__ndk1::basic_string<>::compare<>
               (uint param_1,uint param_2,basic_string_view *param_3,uint param_4,uint param_5)

{
  code *pcVar1;
  ushort uVar2;
  uint unaff_r4;
  int unaff_r5;
  int unaff_r7;
  undefined4 in_cr5;
  undefined4 in_cr10;
  undefined4 in_cr14;
  undefined8 in_d6;
  undefined8 in_d25;
  
  if (unaff_r4 < 0x1e) {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x27,0x2c67c8);
    (*pcVar1)();
  }
  coprocessor_function(10,8,7,in_cr10,in_cr14,in_cr5);
  if (unaff_r7 + 0xb7 < 0) {
    FloatVectorAdd(in_d25,in_d6,2);
    uVar2 = *(ushort *)((unaff_r5 >> 0x11) + 0x11c);
    *(char *)(param_2 + 0x32) = (char)(unaff_r5 >> 0x1f);
    *(uint *)(*(int *)(param_2 + 0x10) + 0x10) = (uint)uVar2;
    *(undefined1 *)(param_2 * 0x40000000 + 0xd) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::char_traits<char>::compare(char const*, char const*, unsigned int)

undefined8 std::__ndk1::char_traits<char>::compare(char *param_1,char *param_2,uint param_3)

{
  byte bVar1;
  byte bVar2;
  ushort uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  undefined4 *puVar8;
  int in_r3;
  int unaff_r4;
  undefined4 *unaff_r5;
  int unaff_r6;
  char in_NG;
  char in_OV;
  undefined8 in_stack_00000000;
  
  *(char **)(in_r3 + 0x28) = param_1;
  *(int *)(unaff_r4 + 0x28) = unaff_r6;
  bVar1 = param_1[4];
  if (in_NG != in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar3 = *(ushort *)(unaff_r6 + 0x24);
  piVar6 = (int *)(uint)uVar3;
  *unaff_r5 = param_1;
  unaff_r5[1] = param_3;
  unaff_r5[2] = unaff_r6;
  unaff_r5[3] = (uint)bVar1;
  iVar5 = in_r3 >> 0x14;
  uVar7 = in_r3 >> 0x1f;
  if (-1 < in_r3) {
    puVar8 = (undefined4 *)(uint)*(ushort *)((int)piVar6 + 0x2e);
    *(ushort *)(iVar5 + 0x20) = uVar3;
    *(undefined2 *)((int)unaff_r5 + *(ushort *)((int)unaff_r5 + iVar5 + 0x10) + 0x17) = 0;
    uVar4 = _DAT_8e000034;
    *puVar8 = 0x8e000000;
    puVar8[1] = uVar4;
    puVar8[2] = puVar8[0x16];
    puVar8[3] = puVar8[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar2 = *(byte *)((int)piVar6 + 0x19);
  puVar8 = (undefined4 *)(uVar7 >> 0x1c);
  *piVar6 = iVar5;
  piVar6[1] = in_r3;
  piVar6[2] = (int)puVar8;
  *puVar8 = piVar6 + 3;
  puVar8[1] = uVar7;
  puVar8[2] = in_r3;
  puVar8[3] = unaff_r6;
  puVar8[4] = (uint)bVar1;
  if (in_OV == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(uVar7 + 6) = (char)*(undefined4 *)(bVar2 + 4);
  return in_stack_00000000;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::TEMPNAMEPLACEHOLDERVALUE(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&)

void __thiscall std::__ndk1::basic_string<>::operator=(basic_string<> *this,basic_string *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> >&
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__assign_no_alias<true>(char const*, unsigned int)

basic_string * std::__ndk1::basic_string<>::__assign_no_alias<true>(char *param_1,uint param_2)

{
  basic_string *pbVar1;
  undefined2 in_r3;
  undefined4 *unaff_r4;
  int unaff_r5;
  int unaff_r7;
  
  *(int *)(unaff_r7 + 0x68) = unaff_r5;
  *unaff_r4 = 0x5f;
  unaff_r4[1] = param_2;
  unaff_r4[2] = unaff_r4;
  unaff_r4[3] = unaff_r5;
  *(undefined2 *)(unaff_r4 + 5) = in_r3;
                    // WARNING: Could not recover jumptable at 0x002c6896. Too many branches
                    // WARNING: Treating indirect jump as call
  pbVar1 = (basic_string *)(*(code *)(uint)*(byte *)(unaff_r5 + 0x1b))();
  return pbVar1;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::append(char const*)

void std::__ndk1::basic_string<>::append(char *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::replace(unsigned int, unsigned int, std::__ndk1::basic_string<char,
// std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> > const&, unsigned int, unsigned
// int)

void std::__ndk1::basic_string<>::replace
               (uint param_1,uint param_2,basic_string *param_3,uint param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  uint unaff_r7;
  int unaff_r8;
  char in_OV;
  undefined4 in_cr5;
  
  coprocessor_storelong(2,in_cr5,unaff_r8 + -0x3a4);
  puVar3 = (uint *)(param_1 * 0x20000000);
  iVar4 = unaff_r7 << 0x1d;
  if (iVar4 != 0 && iVar4 < 0 == (bool)in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar1 = param_1 & 0x1000;
  uVar2 = param_1 & 0xfff;
  while( true ) {
    if (uVar1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (uVar2 != 0) break;
    *puVar3 = param_1;
    puVar3[1] = (uint)puVar3;
    puVar3[2] = (uint)param_3;
    puVar3[3] = 0xdf62d0bf;
    puVar3[4] = unaff_r7;
    uVar1 = (int)param_3 >> 0x16 & 1;
    unaff_r7 = (int)param_3 >> 0x17;
    uVar2 = unaff_r7;
    if (iVar4 != 0) {
      return;
    }
  }
  software_interrupt(0x62);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::insert(std::__ndk1::__wrap_iter<char const*>, char)

void std::__ndk1::basic_string<>::insert(void)

{
  uint uVar1;
  undefined4 uVar2;
  uint in_r3;
  int unaff_r4;
  uint unaff_r5;
  int unaff_r6;
  uint *unaff_r7;
  undefined4 unaff_r8;
  uint unaff_r9;
  byte *unaff_r10;
  byte *pbVar3;
  uint unaff_r11;
  int in_r12;
  undefined1 *puVar4;
  undefined4 uVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  bool bVar9;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr7;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined4 unaff_s18;
  int in_stack_00000128;
  
  uVar5 = 0x2c6975;
  uVar2 = func_0xffd30468();
  bVar8 = SCARRY4(in_stack_00000128,0x74);
  bVar9 = (unaff_r5 & 0x40000000) != 0;
  bVar6 = (int)(unaff_r5 << 2) < 0;
  bVar7 = unaff_r5 << 2 == 0;
  *(short *)(unaff_r6 + 0x26) = (short)unaff_r6;
  coprocessor_function(0xf,0xe,4,in_cr4,in_cr15,in_cr8);
  if (bVar7 || bVar6 != bVar8) {
                    // WARNING (jumptable): Read-only address (ram,0x002c6bf8) is written
                    // WARNING: Read-only address (ram,0x002c6bf8) is written
    DAT_002c6bec = (uint)*(byte *)(unaff_r4 + 0x1d);
    DAT_002c6bf0 = in_r3;
    DAT_002c6bf4 = unaff_r5;
    puRam002c6bf8 = &stack0x00000068;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (bVar7 || bVar6 != bVar8) {
    if (bVar8) {
      coprocessor_storelong(7,in_cr1,in_r12 + -0x3d4);
    }
    if (bVar6 == bVar8) {
      pbVar3 = unaff_r10 + -0x3e0;
      coprocessor_store(0xb,in_cr9,unaff_r10);
      *(undefined1 *)(*(byte *)(unaff_r4 + 0x1d) - 0x1ad) = 0xec;
    }
    else {
      software_interrupt(0x58c7cf);
      pbVar3 = unaff_r10;
    }
    if (!bVar6) {
      unaff_r5 = *unaff_r7;
    }
    if (bVar8) {
      uVar1 = unaff_r9 & 0xff;
      bVar9 = uVar1 == 0 && bVar9 || uVar1 != 0 && (bool)((byte)(unaff_r11 >> uVar1 - 1) & 1);
      puVar4 = (undefined1 *)(unaff_r5 ^ unaff_r11 >> uVar1);
      bVar6 = (int)puVar4 < 0;
      bVar7 = puVar4 == (undefined1 *)0x0;
    }
    coprocessor_store2(0xe,in_cr7,unaff_r11 + 0x1c4);
    if (bVar6 == bVar8) {
      pbVar3 = pbVar3 + 0x5c6;
      in_r3 = (uint)*pbVar3;
    }
    if (!bVar9 || bVar7) {
      *(undefined4 *)pbVar3 = uVar5;
      *(uint *)(pbVar3 + -4) = unaff_r11 + 0x1c4;
      *(uint *)(pbVar3 + -8) = unaff_r9;
      *(undefined4 *)(pbVar3 + -0xc) = unaff_r8;
      *(undefined1 **)(pbVar3 + -0x10) = &stack0x00000068;
      *(int *)(pbVar3 + -0x14) = unaff_r4;
      *(uint *)(pbVar3 + -0x18) = in_r3;
      *(undefined4 *)(pbVar3 + -0x1c) = uVar2;
    }
    if (!bVar9) {
      coprocessor_function(0xd,5,3,in_cr13,in_cr4,in_cr15);
    }
    DAT_002c6bd8 = unaff_s18;
    if (!bVar7) {
      func_0xffc3caca();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  (*(code *)0x6d4c17f5)(0x933054f,0x4166488b,0xa39f3101);
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::resize(unsigned int, char)

void __thiscall std::__ndk1::basic_string<>::resize(basic_string<> *this,uint param_1,char param_2)

{
  *(short *)(param_2 + 0xe) = (short)param_1;
  *(basic_string<> **)(this + 0x28) = this;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::replace(unsigned int, unsigned int, wchar_t const*, unsigned
// int)

void std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,wchar_t *param_3,uint param_4)

{
  *(short *)((*(uint *)(param_1 + 0x58) >> 0x1b) + 4) = (short)param_3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c64d8)
// WARNING: Removing unreachable block (ram,0x002c64e0)
// WARNING: Removing unreachable block (ram,0x002c64e6)
// WARNING: Removing unreachable block (ram,0x002c650a)
// WARNING: Removing unreachable block (ram,0x002c6512)
// WARNING: Removing unreachable block (ram,0x002c6518)
// WARNING: Removing unreachable block (ram,0x002c6582)
// WARNING: Removing unreachable block (ram,0x002c6568)
// WARNING: Removing unreachable block (ram,0x002c64ae)
// std::__ndk1::char_traits<wchar_t>::move(wchar_t*, wchar_t const*, unsigned int)

void std::__ndk1::char_traits<wchar_t>::move(wchar_t *param_1,wchar_t *param_2,uint param_3)

{
  undefined4 uVar1;
  int unaff_r4;
  int unaff_r5;
  uint unaff_r6;
  int unaff_r7;
  undefined8 in_d4;
  undefined8 unaff_d14;
  undefined8 in_d25;
  undefined4 in_stack_0000038c;
  undefined4 in_stack_000003b4;
  
  *(char *)(param_3 + 0x13) = (char)param_3;
  *(uint *)(param_3 + 0x78) = param_3;
  *(wchar_t **)param_3 = param_1;
  *(undefined4 *)(param_3 + 4) = in_stack_0000038c;
  *(uint *)(param_3 + 8) = param_3;
  *(int *)(param_3 + 0xc) = unaff_r4;
  *(uint *)(param_3 + 0x10) = unaff_r6 + 0x20;
  *(int *)(param_3 + 0x14) = unaff_r7;
  *(short *)(unaff_r4 + *(int *)(unaff_r7 + 0xc)) = (short)unaff_r5;
  if (unaff_r6 < 0xffffffe0) {
    in_stack_000003b4 = 0xdcf4b13d;
  }
  else {
    uVar1 = VectorGetElement(in_d4,0,2,0);
    VectorMultiplyAddLongScalar(unaff_d14,uVar1,1);
  }
  VectorRoundShiftRight(in_d25,0x3d);
  *(undefined4 *)(unaff_r5 + 0x30) = in_stack_000003b4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__grow_by_and_replace(unsigned int, unsigned int, unsigned
// int, unsigned int, unsigned int, unsigned int, wchar_t const*)

undefined8
std::__ndk1::basic_string<>::__grow_by_and_replace
          (uint param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint param_6,
          wchar_t *param_7)

{
  int unaff_r4;
  undefined4 *unaff_r6;
  
  *(char *)(unaff_r4 + 0xe) = (char)unaff_r4;
  return CONCAT44(param_5,*unaff_r6);
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::rfind(wchar_t const*, unsigned int, unsigned int) const

void __thiscall
std::__ndk1::basic_string<>::rfind(basic_string<> *this,wchar_t *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  undefined4 unaff_r4;
  uint unaff_r5;
  int unaff_r6;
  uint *unaff_r7;
  undefined4 unaff_r8;
  uint unaff_r9;
  byte *pbVar2;
  byte *unaff_r10;
  uint unaff_r11;
  int in_r12;
  undefined1 *puVar3;
  undefined4 in_lr;
  char in_NG;
  bool in_ZR;
  bool in_CY;
  bool in_OV;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr7;
  undefined4 in_cr9;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined4 unaff_s18;
  
  *(short *)(unaff_r6 + 0x20) = (short)param_3;
  if (in_ZR || (bool)in_NG != in_OV) {
    *(wchar_t **)param_2 = param_1;
    *(uint *)(param_2 + 4) = param_3;
    *(uint *)(param_2 + 8) = unaff_r5;
    *(int *)(param_2 + 0xc) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (in_ZR || (bool)in_NG != in_OV) {
    if (in_OV) {
      coprocessor_storelong(7,in_cr1,in_r12 + -0x3d4);
    }
    if ((bool)in_NG == in_OV) {
      pbVar2 = unaff_r10 + -0x3e0;
      coprocessor_store(0xb,in_cr9,unaff_r10);
      *(char *)((int)param_1 + -0x1ad) = (char)param_2;
    }
    else {
      software_interrupt(0x58c7cf);
      pbVar2 = unaff_r10;
    }
    if (!(bool)in_NG) {
      unaff_r5 = *unaff_r7;
    }
    if (in_OV) {
      uVar1 = unaff_r9 & 0xff;
      in_CY = uVar1 == 0 && in_CY || uVar1 != 0 && (bool)((byte)(unaff_r11 >> uVar1 - 1) & 1);
      puVar3 = (undefined1 *)(unaff_r5 ^ unaff_r11 >> uVar1);
      in_NG = (int)puVar3 < 0;
      in_ZR = puVar3 == (undefined1 *)0x0;
    }
    coprocessor_store2(0xe,in_cr7,unaff_r11 + 0x1c4);
    if ((bool)in_NG == in_OV) {
      pbVar2 = pbVar2 + 0x5c6;
      param_3 = (uint)*pbVar2;
    }
    if (!in_CY || in_ZR) {
      *(undefined4 *)pbVar2 = in_lr;
      *(uint *)(pbVar2 + -4) = unaff_r11 + 0x1c4;
      *(uint *)(pbVar2 + -8) = unaff_r9;
      *(undefined4 *)(pbVar2 + -0xc) = unaff_r8;
      *(int *)(pbVar2 + -0x10) = unaff_r6;
      *(undefined4 *)(pbVar2 + -0x14) = unaff_r4;
      *(uint *)(pbVar2 + -0x18) = param_3;
      *(basic_string<> **)(pbVar2 + -0x1c) = this;
    }
    *(undefined4 *)(param_2 - 0x14) = unaff_s18;
    if (!in_CY) {
      coprocessor_function(0xd,5,3,in_cr13,in_cr4,in_cr15);
    }
    if (!in_ZR) {
      func_0xffc3caca();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  (*(code *)0x6d4c17f5)(0x933054f,0x4166488b,0xa39f3101);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c6d86)
// WARNING: Removing unreachable block (ram,0x002c68e0)
// WARNING: Removing unreachable block (ram,0x002c696c)
// WARNING: Removing unreachable block (ram,0x002c68e4)
// WARNING: Removing unreachable block (ram,0x002c68e6)
// WARNING: Removing unreachable block (ram,0x002c68f2)
// WARNING: Removing unreachable block (ram,0x002c69a8)
// WARNING: Removing unreachable block (ram,0x002c68f4)
// WARNING: Removing unreachable block (ram,0x002c68f6)
// WARNING: Removing unreachable block (ram,0x002c6876)
// WARNING: Removing unreachable block (ram,0x002c687c)
// WARNING: Removing unreachable block (ram,0x002c6866)
// WARNING: Removing unreachable block (ram,0x002c6d92)
// WARNING: Removing unreachable block (ram,0x002c6d98)
// WARNING: Removing unreachable block (ram,0x002c6e20)
// WARNING: Removing unreachable block (ram,0x002c6e22)
// WARNING: Removing unreachable block (ram,0x002c6e2a)
// WARNING: Removing unreachable block (ram,0x002c64d8)
// WARNING: Removing unreachable block (ram,0x002c64e0)
// WARNING: Removing unreachable block (ram,0x002c64e6)
// WARNING: Removing unreachable block (ram,0x002c650a)
// WARNING: Removing unreachable block (ram,0x002c6512)
// WARNING: Removing unreachable block (ram,0x002c6518)
// WARNING: Removing unreachable block (ram,0x002c6582)
// WARNING: Removing unreachable block (ram,0x002c6568)
// WARNING: Removing unreachable block (ram,0x002c64ae)
// WARNING: Removing unreachable block (ram,0x002c6c18)
// WARNING: Removing unreachable block (ram,0x002c6c26)
// WARNING: Removing unreachable block (ram,0x002c6c74)
// WARNING: Removing unreachable block (ram,0x002c6c76)
// WARNING: Removing unreachable block (ram,0x002c6ca0)
// WARNING: Removing unreachable block (ram,0x002c71f2)
// WARNING: Removing unreachable block (ram,0x002c7222)
// WARNING: Removing unreachable block (ram,0x002c728e)
// WARNING: Removing unreachable block (ram,0x002c7292)
// WARNING: Removing unreachable block (ram,0x002c6c4e)
// WARNING: Removing unreachable block (ram,0x002c6c52)
// WARNING: Removing unreachable block (ram,0x002c6c5c)
// WARNING: Removing unreachable block (ram,0x0039fb94)
// WARNING: Removing unreachable block (ram,0x002c64c4)
// WARNING: Removing unreachable block (ram,0x002c64a6)
// WARNING: Removing unreachable block (ram,0x002c64b0)
// WARNING: Removing unreachable block (ram,0x002c64d0)
// WARNING: Removing unreachable block (ram,0x002c64b4)
// WARNING: Removing unreachable block (ram,0x002c705c)
// WARNING: Removing unreachable block (ram,0x002c6d20)
// WARNING: Removing unreachable block (ram,0x002c6dec)
// WARNING: Removing unreachable block (ram,0x002c6e2e)
// WARNING: Removing unreachable block (ram,0x002c6e32)
// WARNING: Removing unreachable block (ram,0x002c6e72)
// WARNING: Removing unreachable block (ram,0x002c6e86)
// WARNING: Removing unreachable block (ram,0x002c6e8a)
// WARNING: Removing unreachable block (ram,0x002c6e8e)
// WARNING: Removing unreachable block (ram,0x002c6f1c)
// WARNING: Removing unreachable block (ram,0x002c6f26)
// WARNING: Removing unreachable block (ram,0x002c6ede)
// WARNING: Removing unreachable block (ram,0x0039b958)
// WARNING: Removing unreachable block (ram,0x002c6ee6)
// WARNING: Removing unreachable block (ram,0x002c6f34)
// WARNING: Removing unreachable block (ram,0x002c6f38)
// WARNING: Removing unreachable block (ram,0x002c6f3a)
// WARNING: Removing unreachable block (ram,0x002c6f3e)
// WARNING: Removing unreachable block (ram,0x002c6fa4)
// WARNING: Removing unreachable block (ram,0x002c6fb0)
// WARNING: Removing unreachable block (ram,0x002c6fb4)
// WARNING: Removing unreachable block (ram,0x002c6fb6)
// WARNING: Removing unreachable block (ram,0x002c6fcc)
// WARNING: Removing unreachable block (ram,0x002c6954)
// WARNING: Removing unreachable block (ram,0x002c695e)
// WARNING: Removing unreachable block (ram,0x002c6798)
// WARNING: Removing unreachable block (ram,0x002c694a)
// WARNING: Removing unreachable block (ram,0x002c694e)
// WARNING: Removing unreachable block (ram,0x002c6988)
// WARNING: Removing unreachable block (ram,0x002c698a)
// WARNING: Removing unreachable block (ram,0x002c6a06)
// WARNING: Removing unreachable block (ram,0x002c6a0a)
// WARNING: Removing unreachable block (ram,0x002c6a0e)
// WARNING: Removing unreachable block (ram,0x002c6a12)
// WARNING: Removing unreachable block (ram,0x002c6a1a)
// WARNING: Removing unreachable block (ram,0x002c6a1e)
// WARNING: Removing unreachable block (ram,0x002c6a22)
// WARNING: Removing unreachable block (ram,0x002c6a26)
// WARNING: Removing unreachable block (ram,0x002c6a2a)
// WARNING: Removing unreachable block (ram,0x002c6a2e)
// WARNING: Removing unreachable block (ram,0x002c6a32)
// WARNING: Removing unreachable block (ram,0x002c6a36)
// WARNING: Removing unreachable block (ram,0x002c6a3a)
// WARNING: Removing unreachable block (ram,0x002c68c8)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__init(wchar_t const*, unsigned int, unsigned int)

undefined8 std::__ndk1::basic_string<>::__init(wchar_t *param_1,uint param_2,uint param_3)

{
  byte bVar1;
  undefined4 uVar2;
  undefined1 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  int in_r3;
  int iVar7;
  short unaff_r4;
  int iVar8;
  int *piVar9;
  int unaff_r6;
  int unaff_r7;
  char *pcVar10;
  int unaff_r11;
  undefined4 in_pc;
  char in_CY;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr11;
  undefined8 in_stack_00000000;
  int in_stack_00000284;
  
  piVar9 = (int *)(uint)*(byte *)(in_r3 + param_3);
  if (in_CY == '\0') {
    func_0xffa07bb4();
    *(short *)(unaff_r6 + 0x18) = (short)&stack0x0000033b;
    coprocessor_function2(0,4,2,in_cr1,in_cr11,in_cr6);
    coprocessor_store(0xe,in_cr4,unaff_r11 + -0x1bc);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  pcVar10 = (char *)(unaff_r7 + 0x40);
  if (param_3 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar3 = &stack0x000001cc;
  iVar8 = 0;
  iVar7 = in_r3;
  if ((int)param_3 < 0) {
    *piVar9 = (int)puVar3;
    piVar9[1] = 0;
    piVar9 = piVar9 + 2;
    puVar3 = *(undefined1 **)(in_r3 + 4);
    iVar7 = *(int *)(in_r3 + 8);
    iVar8 = *(int *)(in_r3 + 0xc);
    param_1 = (wchar_t *)&UNK_002c7160;
    uRam00000000 = 0;
    piRam00000004 = piVar9;
    pcRam00000008 = pcVar10;
    *(char *)(*(int *)(in_r3 + 0x10) + 4) = (char)pcVar10;
    pcVar10 = (char *)(uint)*(ushort *)(unaff_r7 + 0x66);
    if (iVar8 != 0) {
      TTT(in_pc);
      if (!SCARRY4((int)piVar9,0x34)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar3[0x14] = 0;
    unaff_r4 = (short)_DAT_00000078 + 0x45;
    iVar8 = (int)*pcVar10;
    pcVar10[0xe] = (char)iVar7;
  }
  *(short *)(iVar7 + 0x18) = unaff_r4;
  *(short *)(puVar3 + 0x18) = (short)puVar3;
  puVar4 = (undefined4 *)(puVar3 + in_stack_00000284 + 0x87);
  uVar5 = (int)param_1 >> 0x20;
  if (uVar5 == 0) {
    puVar6 = (undefined4 *)(uint)*(ushort *)((int)puVar4 + 0x2e);
    *(short *)(param_1 + 8) = (short)puVar4;
    *(short *)((int)piVar9 + *(ushort *)((int)piVar9 + (int)param_1) + 7) = unaff_r4;
    uVar2 = _DAT_8e000034;
    *puVar6 = 0x8e000000;
    puVar6[1] = uVar2;
    puVar6[2] = puVar6[0x16];
    puVar6[3] = puVar6[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)((int)puVar4 + 0x19);
  puVar6 = (undefined4 *)(uVar5 >> 0x1c);
  *puVar4 = param_1;
  puVar4[1] = iVar7;
  puVar4[2] = puVar6;
  *puVar6 = puVar4 + 3;
  puVar6[1] = uVar5;
  puVar6[2] = iVar7;
  puVar6[3] = iVar8;
  puVar6[4] = pcVar10;
  if (!SCARRY4((int)puVar3,0x87)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(uVar5 + 6) = (char)*(undefined4 *)(bVar1 + 4);
  return in_stack_00000000;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::char_traits<wchar_t>::copy(wchar_t*, wchar_t const*, unsigned int)

undefined8 std::__ndk1::char_traits<wchar_t>::copy(wchar_t *param_1,wchar_t *param_2,uint param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  wchar_t wVar8;
  uint uVar9;
  uint *puVar10;
  uint *puVar11;
  int *piVar12;
  wchar_t wVar13;
  undefined *puVar14;
  int iVar15;
  undefined4 in_pc;
  bool bVar16;
  undefined4 in_cr0;
  undefined8 in_stack_00000000;
  undefined1 *puStack00000024;
  int in_stack_00000284;
  int in_stack_000003b0;
  
  puVar10 = (uint *)param_2[3];
  wVar8 = param_2[5];
  wVar13 = param_2[6];
  *(char *)((int)puVar10 + 1) = (char)wVar13;
  if (L'\x01' < wVar8) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puStack00000024 = &stack0x000001a8;
  if (puVar10 == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = *puVar10;
  uVar9 = puVar10[2];
  puVar11 = (uint *)puVar10[3];
  *(char *)(puVar10[1] * 0x4000000 + in_stack_000003b0) = (char)uVar4;
  *puVar11 = uVar9;
  do {
  } while (0x91 < uVar9);
  if (uVar4 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = (uint)*(byte *)(in_stack_000003b0 + 0xc);
  while( true ) {
    uVar5 = uVar4;
    puVar10 = (uint *)(uVar5 + 0xe2);
    bVar16 = (int)puVar10 < 0;
    iVar15 = *(int *)(in_stack_000003b0 + 0x1c);
    *puVar10 = uVar9 >> 0x1c;
    *(uint *)(uVar5 + 0xe6) = uVar9;
    *(int *)(uVar5 + 0xea) = in_stack_000003b0;
    uVar4 = uVar5 + 0xee;
    *(uint *)(uVar5 + 0xf2) = uVar9 + 6;
    piVar12 = (int *)(uint)*(ushort *)(uVar9 + 0x1c);
    if (puVar10 != (uint *)0x0 && bVar16 == SCARRY4(uVar5,0xe2)) {
      if (SCARRY4(uVar9,0x79)) {
        *(ushort *)(uVar9 + 0x2e) = *(ushort *)(uVar9 + 0x1c);
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_stack_000003b0 = (uVar9 >> 0x1c) << 8;
    if (uVar9 + 6 != 0) break;
    if (bVar16) {
      puVar10 = (uint *)&stack0x00000300;
      coprocessor_store(6,in_cr0,iVar15 + 0xbc);
      uVar9 = 0xb47d2b13;
      *(undefined4 *)(iVar15 + 0xc) = 0xb47d2b13;
      *piVar12 = (int)puVar10;
      piVar12[1] = -0x4b82d4ed;
      piVar12[2] = in_stack_000003b0;
      piVar12[3] = (int)piVar12;
      piVar12[4] = 0;
      piVar12[5] = iVar15;
      bVar16 = false;
      iVar15 = 6;
      puVar14 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar10;
LAB_002c6f7e:
      uVar6 = (int)uVar4 >> 0x20;
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)(uint)*(ushort *)((int)puVar10 + 0x2e);
        *(short *)(uVar5 + 0x10e) = (short)puVar10;
        *(short *)((int)piVar12 + *(ushort *)((int)piVar12 + uVar4) + 7) = (short)in_stack_000003b0;
        uVar3 = _DAT_8e000034;
        *puVar7 = 0x8e000000;
        puVar7[1] = uVar3;
        puVar7[2] = puVar7[0x16];
        puVar7[3] = puVar7[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar2 = *(byte *)((int)puVar10 + 0x19);
      puVar7 = (undefined4 *)(uVar6 >> 0x1c);
      *puVar10 = uVar4;
      puVar10[1] = uVar9;
      puVar10[2] = (uint)puVar7;
      *puVar7 = puVar10 + 3;
      puVar7[1] = uVar6;
      puVar7[2] = uVar9;
      puVar7[3] = puVar14;
      puVar7[4] = iVar15;
      if (!bVar16) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar6 + 6) = (char)*(undefined4 *)(bVar2 + 4);
      return in_stack_00000000;
    }
  }
  if (!bVar16) {
    if (piVar12 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar1)();
  }
  puVar14 = &UNK_002c6f44 + uVar9;
  if (puVar10 == (uint *)0x0 || bVar16 != SCARRY4(uVar5,0xe2)) {
    *(short *)(uVar9 + 0x2a) = (short)puVar14;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(wVar13 + L'\x1f') = (short)(wVar13 + L'\a');
  bVar16 = SCARRY4(wVar13 + L'\a',0x87);
  puVar10 = (uint *)(wVar13 + L'\x8e' + in_stack_00000284);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::basic_string(std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&)

void std::__ndk1::basic_string<>::basic_string(basic_string *param_1)

{
  uint uVar1;
  undefined1 *puVar2;
  undefined8 *puVar3;
  int in_r1;
  undefined4 extraout_r1;
  int iVar4;
  int in_r2;
  int iVar5;
  code *unaff_r4;
  int unaff_r5;
  undefined4 *unaff_r6;
  undefined1 *puVar6;
  int unaff_r7;
  undefined8 uVar7;
  
  software_interrupt(0xa2);
  func_0xff80994c(in_r1 + 7,in_r1,in_r2 << 0xd);
  *unaff_r6 = extraout_r1;
  unaff_r6[1] = unaff_r5;
  unaff_r6[2] = unaff_r6;
  iVar4 = (int)unaff_r6 >> 4;
  iVar5 = 0x3ec812b2;
  *(char *)((int)unaff_r6 + 0x1e) = (char)unaff_r4;
  if (iVar4 != 0 && iVar4 < 0 == SBORROW4(unaff_r7,8)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (iVar4 == 0) {
    uVar7 = (*unaff_r4)();
    puVar3 = (undefined8 *)((ulonglong)uVar7 >> 0x20);
    puVar6 = &stack0x00000318;
    uVar1 = (uint)uVar7 & 0x1000;
    puVar2 = (undefined1 *)((uint)uVar7 & 0xfff);
    while( true ) {
      if (uVar1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (puVar2 != (undefined1 *)0x0) break;
      *puVar3 = uVar7;
      *(int *)(puVar3 + 1) = iVar5;
      *(undefined4 *)((int)puVar3 + 0xc) = 0xdf62d0bf;
      *(undefined1 **)(puVar3 + 2) = puVar6;
      uVar1 = iVar5 >> 0x16 & 1;
      puVar6 = (undefined1 *)(iVar5 >> 0x17);
      puVar2 = puVar6;
      if (unaff_r5 != 0) {
        return;
      }
    }
    software_interrupt(0x62);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::replace(unsigned int, unsigned int, wchar_t const*)

void std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,wchar_t *param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8
FUN_002c6dde(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined8 param_5
            )

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  uint uVar9;
  uint *puVar10;
  uint *puVar11;
  int *piVar12;
  int iVar13;
  undefined *puVar14;
  undefined4 in_pc;
  bool bVar15;
  undefined4 in_cr0;
  undefined1 *puStack00000024;
  int in_stack_00000284;
  int in_stack_000003b0;
  
  puVar10 = *(uint **)(param_2 + 0xc);
  iVar8 = *(int *)(param_2 + 0x14);
  iVar13 = *(int *)(param_2 + 0x18);
  *(char *)((int)puVar10 + 1) = (char)iVar13;
  if (1 < iVar8) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puStack00000024 = &stack0x000001a8;
  if (puVar10 == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = *puVar10;
  uVar9 = puVar10[2];
  puVar11 = (uint *)puVar10[3];
  *(char *)(puVar10[1] * 0x4000000 + in_stack_000003b0) = (char)uVar4;
  *puVar11 = uVar9;
  do {
  } while (0x91 < uVar9);
  if (uVar4 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = (uint)*(byte *)(in_stack_000003b0 + 0xc);
  while( true ) {
    uVar5 = uVar4;
    puVar10 = (uint *)(uVar5 + 0xe2);
    bVar15 = (int)puVar10 < 0;
    iVar8 = *(int *)(in_stack_000003b0 + 0x1c);
    *puVar10 = uVar9 >> 0x1c;
    *(uint *)(uVar5 + 0xe6) = uVar9;
    *(int *)(uVar5 + 0xea) = in_stack_000003b0;
    uVar4 = uVar5 + 0xee;
    *(uint *)(uVar5 + 0xf2) = uVar9 + 6;
    piVar12 = (int *)(uint)*(ushort *)(uVar9 + 0x1c);
    if (puVar10 != (uint *)0x0 && bVar15 == SCARRY4(uVar5,0xe2)) {
      if (SCARRY4(uVar9,0x79)) {
        *(ushort *)(uVar9 + 0x2e) = *(ushort *)(uVar9 + 0x1c);
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_stack_000003b0 = (uVar9 >> 0x1c) << 8;
    if (uVar9 + 6 != 0) break;
    if (bVar15) {
      puVar10 = (uint *)&stack0x00000300;
      coprocessor_store(6,in_cr0,iVar8 + 0xbc);
      uVar9 = 0xb47d2b13;
      *(undefined4 *)(iVar8 + 0xc) = 0xb47d2b13;
      *piVar12 = (int)puVar10;
      piVar12[1] = -0x4b82d4ed;
      piVar12[2] = in_stack_000003b0;
      piVar12[3] = (int)piVar12;
      piVar12[4] = 0;
      piVar12[5] = iVar8;
      bVar15 = false;
      iVar8 = 6;
      puVar14 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar10;
LAB_002c6f7e:
      uVar6 = (int)uVar4 >> 0x20;
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)(uint)*(ushort *)((int)puVar10 + 0x2e);
        *(short *)(uVar5 + 0x10e) = (short)puVar10;
        *(short *)((int)piVar12 + *(ushort *)((int)piVar12 + uVar4) + 7) = (short)in_stack_000003b0;
        uVar3 = _DAT_8e000034;
        *puVar7 = 0x8e000000;
        puVar7[1] = uVar3;
        puVar7[2] = puVar7[0x16];
        puVar7[3] = puVar7[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar2 = *(byte *)((int)puVar10 + 0x19);
      puVar7 = (undefined4 *)(uVar6 >> 0x1c);
      *puVar10 = uVar4;
      puVar10[1] = uVar9;
      puVar10[2] = (uint)puVar7;
      *puVar7 = puVar10 + 3;
      puVar7[1] = uVar6;
      puVar7[2] = uVar9;
      puVar7[3] = puVar14;
      puVar7[4] = iVar8;
      if (!bVar15) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar6 + 6) = (char)*(undefined4 *)(bVar2 + 4);
      return param_5;
    }
  }
  if (!bVar15) {
    if (piVar12 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar1)();
  }
  puVar14 = &UNK_002c6f44 + uVar9;
  if (puVar10 == (uint *)0x0 || bVar15 != SCARRY4(uVar5,0xe2)) {
    *(short *)(uVar9 + 0x2a) = (short)puVar14;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(iVar13 + 0x1f) = (short)(iVar13 + 7);
  bVar15 = SCARRY4(iVar13 + 7,0x87);
  puVar10 = (uint *)(iVar13 + 0x8e + in_stack_00000284);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::basic_string(std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&,
// std::__ndk1::allocator<wchar_t> const&)

void std::__ndk1::basic_string<>::basic_string(basic_string *param_1,allocator *param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find_last_not_of(wchar_t const*, unsigned int, unsigned int)
// const

undefined8 std::__ndk1::basic_string<>::find_last_not_of(wchar_t *param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  wchar_t wVar9;
  int unaff_r5;
  uint *puVar10;
  int *piVar11;
  wchar_t wVar12;
  undefined *puVar13;
  int iVar14;
  undefined4 in_pc;
  bool bVar15;
  undefined4 in_cr0;
  undefined8 in_stack_00000010;
  undefined1 *puStack00000034;
  int in_stack_00000294;
  int in_stack_000003c0;
  
  wVar9 = param_1[1];
  wVar12 = param_1[2];
  *(short *)(unaff_r5 + 0x14) = (short)param_2;
  if (wVar12 == L'\0') {
    wVar12 = *(wchar_t *)(unaff_r5 + 0x10);
  }
  puStack00000034 = &stack0x000001b8;
  if ((uint *)(wVar9 + L'\x8e') == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = *(uint *)(wVar9 + L'\x8e');
  uVar8 = *(uint *)(wVar9 + L'\x96');
  puVar10 = *(uint **)(wVar9 + L'\x9a');
  *(char *)(*(int *)(wVar9 + L'\x92') * 0x4000000 + in_stack_000003c0) = (char)uVar4;
  *puVar10 = uVar8;
  do {
  } while (0x91 < uVar8);
  if (uVar4 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = (uint)*(byte *)(in_stack_000003c0 + 0xc);
  while( true ) {
    uVar5 = uVar4;
    puVar10 = (uint *)(uVar5 + 0xe2);
    bVar15 = (int)puVar10 < 0;
    iVar14 = *(int *)(in_stack_000003c0 + 0x1c);
    *puVar10 = uVar8 >> 0x1c;
    *(uint *)(uVar5 + 0xe6) = uVar8;
    *(int *)(uVar5 + 0xea) = in_stack_000003c0;
    uVar4 = uVar5 + 0xee;
    *(uint *)(uVar5 + 0xf2) = uVar8 + 6;
    piVar11 = (int *)(uint)*(ushort *)(uVar8 + 0x1c);
    if (puVar10 != (uint *)0x0 && bVar15 == SCARRY4(uVar5,0xe2)) {
      if (SCARRY4(uVar8,0x79)) {
        *(ushort *)(uVar8 + 0x2e) = *(ushort *)(uVar8 + 0x1c);
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_stack_000003c0 = (uVar8 >> 0x1c) << 8;
    if (uVar8 + 6 != 0) break;
    if (bVar15) {
      puVar10 = (uint *)&stack0x00000310;
      coprocessor_store(6,in_cr0,iVar14 + 0xbc);
      uVar8 = 0xb47d2b13;
      *(undefined4 *)(iVar14 + 0xc) = 0xb47d2b13;
      *piVar11 = (int)puVar10;
      piVar11[1] = -0x4b82d4ed;
      piVar11[2] = in_stack_000003c0;
      piVar11[3] = (int)piVar11;
      piVar11[4] = 0;
      piVar11[5] = iVar14;
      bVar15 = false;
      iVar14 = 6;
      puVar13 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar10;
LAB_002c6f7e:
      uVar6 = (int)uVar4 >> 0x20;
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)(uint)*(ushort *)((int)puVar10 + 0x2e);
        *(short *)(uVar5 + 0x10e) = (short)puVar10;
        *(short *)((int)piVar11 + *(ushort *)((int)piVar11 + uVar4) + 7) = (short)in_stack_000003c0;
        uVar3 = _DAT_8e000034;
        *puVar7 = 0x8e000000;
        puVar7[1] = uVar3;
        puVar7[2] = puVar7[0x16];
        puVar7[3] = puVar7[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar2 = *(byte *)((int)puVar10 + 0x19);
      puVar7 = (undefined4 *)(uVar6 >> 0x1c);
      *puVar10 = uVar4;
      puVar10[1] = uVar8;
      puVar10[2] = (uint)puVar7;
      *puVar7 = puVar10 + 3;
      puVar7[1] = uVar6;
      puVar7[2] = uVar8;
      puVar7[3] = puVar13;
      puVar7[4] = iVar14;
      if (!bVar15) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar6 + 6) = (char)*(undefined4 *)(bVar2 + 4);
      return in_stack_00000010;
    }
  }
  if (!bVar15) {
    if (piVar11 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar1)();
  }
  puVar13 = &UNK_002c6f44 + uVar8;
  if (puVar10 == (uint *)0x0 || bVar15 != SCARRY4(uVar5,0xe2)) {
    *(short *)(uVar8 + 0x2a) = (short)puVar13;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(wVar12 + L'\x1f') = (short)(wVar12 + L'\a');
  bVar15 = SCARRY4(wVar12 + L'\a',0x87);
  puVar10 = (uint *)(wVar12 + L'\x8e' + in_stack_00000294);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::~basic_string()

undefined8 __thiscall std::__ndk1::basic_string<>::~basic_string(basic_string<> *this)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  undefined1 in_r2;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  uint *unaff_r4;
  uint *puVar9;
  int *piVar10;
  int iVar11;
  undefined *puVar12;
  int unaff_r7;
  int iVar13;
  undefined4 in_pc;
  bool bVar14;
  undefined4 in_cr0;
  undefined8 in_stack_00000000;
  int iStack00000024;
  int in_stack_00000284;
  int in_stack_000003b0;
  
  *(undefined1 *)((int)unaff_r4 + 0x1e) = in_r2;
  iVar11 = *(int *)(unaff_r7 + 8);
  iStack00000024 = unaff_r7 + 0xc;
  uVar4 = *unaff_r4;
  uVar8 = unaff_r4[2];
  puVar9 = (uint *)unaff_r4[3];
  *(char *)(unaff_r4[1] * 0x4000000 + in_stack_000003b0) = (char)uVar4;
  *puVar9 = uVar8;
  do {
  } while (0x91 < uVar8);
  if (uVar4 < 0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = (uint)*(byte *)(in_stack_000003b0 + 0xc);
  while( true ) {
    uVar5 = uVar4;
    puVar9 = (uint *)(uVar5 + 0xe2);
    bVar14 = (int)puVar9 < 0;
    iVar13 = *(int *)(in_stack_000003b0 + 0x1c);
    *puVar9 = uVar8 >> 0x1c;
    *(uint *)(uVar5 + 0xe6) = uVar8;
    *(int *)(uVar5 + 0xea) = in_stack_000003b0;
    uVar4 = uVar5 + 0xee;
    *(uint *)(uVar5 + 0xf2) = uVar8 + 6;
    piVar10 = (int *)(uint)*(ushort *)(uVar8 + 0x1c);
    if (puVar9 != (uint *)0x0 && bVar14 == SCARRY4(uVar5,0xe2)) {
      if (SCARRY4(uVar8,0x79)) {
        *(ushort *)(uVar8 + 0x2e) = *(ushort *)(uVar8 + 0x1c);
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_stack_000003b0 = (uVar8 >> 0x1c) << 8;
    if (uVar8 + 6 != 0) break;
    if (bVar14) {
      puVar9 = (uint *)&stack0x00000300;
      coprocessor_store(6,in_cr0,iVar13 + 0xbc);
      uVar8 = 0xb47d2b13;
      *(undefined4 *)(iVar13 + 0xc) = 0xb47d2b13;
      *piVar10 = (int)puVar9;
      piVar10[1] = -0x4b82d4ed;
      piVar10[2] = in_stack_000003b0;
      piVar10[3] = (int)piVar10;
      piVar10[4] = 0;
      piVar10[5] = iVar13;
      bVar14 = false;
      iVar13 = 6;
      puVar12 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar9;
LAB_002c6f7e:
      uVar6 = (int)uVar4 >> 0x20;
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)(uint)*(ushort *)((int)puVar9 + 0x2e);
        *(short *)(uVar5 + 0x10e) = (short)puVar9;
        *(short *)((int)piVar10 + *(ushort *)((int)piVar10 + uVar4) + 7) = (short)in_stack_000003b0;
        uVar3 = _DAT_8e000034;
        *puVar7 = 0x8e000000;
        puVar7[1] = uVar3;
        puVar7[2] = puVar7[0x16];
        puVar7[3] = puVar7[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar2 = *(byte *)((int)puVar9 + 0x19);
      puVar7 = (undefined4 *)(uVar6 >> 0x1c);
      *puVar9 = uVar4;
      puVar9[1] = uVar8;
      puVar9[2] = (uint)puVar7;
      *puVar7 = puVar9 + 3;
      puVar7[1] = uVar6;
      puVar7[2] = uVar8;
      puVar7[3] = puVar12;
      puVar7[4] = iVar13;
      if (!bVar14) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar6 + 6) = (char)*(undefined4 *)(bVar2 + 4);
      return in_stack_00000000;
    }
  }
  if (!bVar14) {
    if (piVar10 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar1)();
  }
  puVar12 = &UNK_002c6f44 + uVar8;
  if (puVar9 == (uint *)0x0 || bVar14 != SCARRY4(uVar5,0xe2)) {
    *(short *)(uVar8 + 0x2a) = (short)puVar12;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(iVar11 + 0x1f) = (short)(iVar11 + 7);
  bVar14 = SCARRY4(iVar11 + 7,0x87);
  puVar9 = (uint *)(iVar11 + 0x8e + in_stack_00000284);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x003670f2)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find_first_not_of(wchar_t const*, unsigned int, unsigned int)
// const

undefined8
std::__ndk1::basic_string<>::find_first_not_of(wchar_t *param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  uint uVar4;
  uint *puVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint in_r3;
  int unaff_r4;
  uint *unaff_r5;
  int *piVar8;
  int unaff_r6;
  undefined *puVar9;
  int iVar10;
  undefined4 in_pc;
  bool bVar11;
  uint uVar12;
  undefined4 in_cr0;
  undefined8 in_stack_00000000;
  int in_stack_00000284;
  
  *unaff_r5 = in_r3;
  do {
  } while (0x91 < in_r3);
  if (param_1 < (wchar_t *)0xffffff40) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar12 = (uint)*(byte *)(unaff_r4 + 0xc);
  while( true ) {
    uVar4 = uVar12;
    puVar5 = (uint *)(uVar4 + 0xe2);
    bVar11 = (int)puVar5 < 0;
    iVar10 = *(int *)(unaff_r4 + 0x1c);
    *puVar5 = in_r3 >> 0x1c;
    *(uint *)(uVar4 + 0xe6) = in_r3;
    *(int *)(uVar4 + 0xea) = unaff_r4;
    uVar12 = uVar4 + 0xee;
    *(uint *)(uVar4 + 0xf2) = in_r3 + 6;
    piVar8 = (int *)(uint)*(ushort *)(in_r3 + 0x1c);
    if (puVar5 != (uint *)0x0 && bVar11 == SCARRY4(uVar4,0xe2)) {
      if (SCARRY4(in_r3,0x79)) {
        *(ushort *)(in_r3 + 0x2e) = *(ushort *)(in_r3 + 0x1c);
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
        (*pcVar1)();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    unaff_r4 = (in_r3 >> 0x1c) << 8;
    if (in_r3 + 6 != 0) break;
    if (bVar11) {
      puVar5 = (uint *)&stack0x00000300;
      coprocessor_store(6,in_cr0,iVar10 + 0xbc);
      in_r3 = 0xb47d2b13;
      *(undefined4 *)(iVar10 + 0xc) = 0xb47d2b13;
      *piVar8 = (int)puVar5;
      piVar8[1] = -0x4b82d4ed;
      piVar8[2] = unaff_r4;
      piVar8[3] = (int)piVar8;
      piVar8[4] = 0;
      piVar8[5] = iVar10;
      bVar11 = false;
      iVar10 = 6;
      puVar9 = (undefined *)0x0;
      _DAT_b47d2b8b = puVar5;
LAB_002c6f7e:
      uVar6 = (int)uVar12 >> 0x20;
      if (uVar6 == 0) {
        puVar7 = (undefined4 *)(uint)*(ushort *)((int)puVar5 + 0x2e);
        *(short *)(uVar4 + 0x10e) = (short)puVar5;
        *(short *)((int)piVar8 + *(ushort *)((int)piVar8 + uVar12) + 7) = (short)unaff_r4;
        uVar3 = _DAT_8e000034;
        *puVar7 = 0x8e000000;
        puVar7[1] = uVar3;
        puVar7[2] = puVar7[0x16];
        puVar7[3] = puVar7[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar2 = *(byte *)((int)puVar5 + 0x19);
      puVar7 = (undefined4 *)(uVar6 >> 0x1c);
      *puVar5 = uVar12;
      puVar5[1] = in_r3;
      puVar5[2] = (uint)puVar7;
      *puVar7 = puVar5 + 3;
      puVar7[1] = uVar6;
      puVar7[2] = in_r3;
      puVar7[3] = puVar9;
      puVar7[4] = iVar10;
      if (!bVar11) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(uVar6 + 6) = (char)*(undefined4 *)(bVar2 + 4);
      return in_stack_00000000;
    }
  }
  if (!bVar11) {
    if (piVar8 == (int *)0xffffff42) {
      TTT(in_pc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x2a,0x2c6fb2);
    (*pcVar1)();
  }
  puVar9 = &UNK_002c6f44 + in_r3;
  if (puVar5 == (uint *)0x0 || bVar11 != SCARRY4(uVar4,0xe2)) {
    *(short *)(in_r3 + 0x2a) = (short)puVar9;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r6 + 0x1f) = (short)(unaff_r6 + 7);
  bVar11 = SCARRY4(unaff_r6 + 7,0x87);
  puVar5 = (uint *)(unaff_r6 + 0x8e + in_stack_00000284);
  goto LAB_002c6f7e;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::insert(unsigned int, unsigned int, wchar_t)

void std::__ndk1::basic_string<>::insert(uint param_1,uint param_2,wchar_t param_3)

{
  code *pcVar1;
  int in_r3;
  undefined2 unaff_r5;
  int unaff_r6;
  
  if (SCARRY4(in_r3,0x79)) {
    *(undefined2 *)(unaff_r6 + 0x28) = unaff_r5;
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xd1,0x2c6ef0);
    (*pcVar1)();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__grow_by(unsigned int, unsigned int, unsigned int, unsigned
// int, unsigned int, unsigned int)

void std::__ndk1::basic_string<>::__grow_by
               (uint param_1,uint param_2,uint param_3,uint param_4,uint param_5,uint param_6)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined2 unaff_r4;
  int unaff_r5;
  
  puVar2 = (undefined4 *)(uint)*(ushort *)(param_2 + 0x2e);
  *(short *)(param_1 + 0x20) = (short)param_2;
  *(undefined2 *)(unaff_r5 + *(ushort *)(unaff_r5 + param_1) + 7) = unaff_r4;
  uVar1 = _DAT_8e000034;
  *puVar2 = 0x8e000000;
  puVar2[1] = uVar1;
  puVar2[2] = puVar2[0x16];
  puVar2[3] = puVar2[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<wchar_t>::assign(wchar_t*, unsigned int, wchar_t)

void std::__ndk1::char_traits<wchar_t>::assign(wchar_t *param_1,uint param_2,wchar_t param_3)

{
  software_bkpt(0x14);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::TEMPNAMEPLACEHOLDERVALUE(wchar_t)

void __thiscall std::__ndk1::basic_string<>::operator=(basic_string<> *this,wchar_t param_1)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  int in_r3;
  int *unaff_r4;
  int iVar4;
  undefined4 *unaff_r5;
  int unaff_r7;
  int iVar5;
  int iVar6;
  int unaff_r9;
  char in_OV;
  undefined4 in_cr9;
  int in_stack_0000021c;
  
  uVar2 = (uint)unaff_r4 >> 5;
  if (uVar2 != 0 && in_OV == '\0') {
    piVar3 = (int *)(uint)*(ushort *)((int)unaff_r5 + 0x1e);
    cVar1 = *(char *)((int)unaff_r5 + 5);
    iVar4 = *(int *)(unaff_r7 + 4);
    iVar5 = *(int *)(unaff_r7 + 8);
    iVar6 = *(int *)(cVar1 + 0x5c);
    *(short *)(*(int *)(iVar4 + -0x130) + 0x12) = (short)*(undefined4 *)(in_r3 + 0x1c);
    *piVar3 = iVar4 + -0x134;
    piVar3[1] = (int)cVar1;
    piVar3[2] = (iVar5 >> 0x1a) + -100;
    piVar3[3] = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(uint *)(unaff_r7 + 0x34) = uVar2;
  coprocessor_store(10,in_cr9,unaff_r9 + 0xec);
  if (uVar2 != 0 && in_OV == '\0') {
    *(char *)(unaff_r7 + 1) = (char)this;
    *(uint *)(unaff_r7 + 0x44) = uVar2;
    coprocessor_store(0xf,in_cr9,unaff_r9 + 0xec);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *unaff_r5 = this;
  unaff_r5[1] = in_r3;
  *unaff_r4 = (int)(unaff_r5 + 2) * 0x400;
  unaff_r4[1] = uVar2;
  unaff_r4[2] = (int)unaff_r4;
  unaff_r4[3] = in_stack_0000021c;
  *(short *)(unaff_r4 + 5) = (short)in_r3;
                    // WARNING: Could not recover jumptable at 0x002c6896. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)(uint)*(byte *)(in_stack_0000021c + 0x1b))();
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::at(unsigned int) const

void std::__ndk1::basic_string<>::at(uint param_1)

{
  int in_r1;
  undefined4 *in_r2;
  undefined2 in_r3;
  undefined4 unaff_r4;
  undefined4 unaff_r5;
  undefined4 unaff_r6;
  undefined4 unaff_r7;
  
  *(undefined2 *)(in_r1 + 0x12) = in_r3;
  *in_r2 = unaff_r4;
  in_r2[1] = unaff_r5;
  in_r2[2] = unaff_r6;
  in_r2[3] = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::insert(unsigned int, wchar_t const*, unsigned int)

void std::__ndk1::basic_string<>::insert(uint param_1,wchar_t *param_2,uint param_3)

{
  ushort uVar1;
  int unaff_r5;
  uint *puVar2;
  uint *unaff_r7;
  undefined4 in_cr2;
  undefined4 in_cr3;
  undefined4 in_cr13;
  undefined4 in_cr15;
  
  *unaff_r7 = (uint)*(ushort *)((int)unaff_r7 + unaff_r5);
  uVar1 = *(ushort *)(param_3 + 0x28);
  puVar2 = (uint *)(uint)uVar1;
  DAT_00000076 = (char)param_3;
  *puVar2 = param_1;
  puVar2[1] = 0x6e;
  puVar2[2] = (uint)puVar2;
  puVar2[3] = 0;
  coprocessor_moveto(0xb,6,0,param_3,in_cr15,in_cr3);
  software_interrupt(0x22);
  *(char *)((int)puVar2 + 2) = (char)uVar1 - (char)param_3;
  coprocessor_function(10,8,7,in_cr15,in_cr2,in_cr13);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find_first_of(wchar_t const*, unsigned int, unsigned int)
// const

void std::__ndk1::basic_string<>::find_first_of(wchar_t *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  undefined1 *puVar2;
  undefined8 *puVar3;
  undefined4 extraout_r1;
  int iVar4;
  int iVar5;
  code *unaff_r4;
  int unaff_r5;
  undefined4 *unaff_r6;
  undefined1 *puVar6;
  int unaff_r7;
  undefined8 uVar7;
  
  func_0xff80994c(param_1,param_2,*(undefined4 *)((int)param_1 + param_3));
  *unaff_r6 = extraout_r1;
  unaff_r6[1] = unaff_r5;
  unaff_r6[2] = unaff_r6;
  iVar4 = (int)unaff_r6 >> 4;
  iVar5 = 0x3ec812b2;
  *(char *)((int)unaff_r6 + 0x1e) = (char)unaff_r4;
  if (iVar4 != 0 && iVar4 < 0 == SBORROW4(unaff_r7,8)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (iVar4 == 0) {
    uVar7 = (*unaff_r4)();
    puVar3 = (undefined8 *)((ulonglong)uVar7 >> 0x20);
    puVar6 = &stack0x00000318;
    uVar1 = (uint)uVar7 & 0x1000;
    puVar2 = (undefined1 *)((uint)uVar7 & 0xfff);
    while( true ) {
      if (uVar1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (puVar2 != (undefined1 *)0x0) break;
      *puVar3 = uVar7;
      *(int *)(puVar3 + 1) = iVar5;
      *(undefined4 *)((int)puVar3 + 0xc) = 0xdf62d0bf;
      *(undefined1 **)(puVar3 + 2) = puVar6;
      uVar1 = iVar5 >> 0x16 & 1;
      puVar6 = (undefined1 *)(iVar5 >> 0x17);
      puVar2 = puVar6;
      if (unaff_r5 != 0) {
        return;
      }
    }
    software_interrupt(0x62);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::replace(unsigned int, unsigned int, unsigned int, wchar_t)

void std::__ndk1::basic_string<>::replace(uint param_1,uint param_2,uint param_3,wchar_t param_4)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int unaff_r5;
  int unaff_r7;
  int unaff_r9;
  undefined4 in_pc;
  char in_NG;
  char in_OV;
  undefined4 in_cr10;
  undefined4 in_stack_00000220;
  
  *(int *)(unaff_r5 + 0x7c) = unaff_r7;
  coprocessor_loadlong(6,in_cr10,unaff_r9);
  *(int *)(*(byte *)(param_2 + 0x19) + 0x30) = unaff_r7;
  *(undefined4 *)(unaff_r9 + 0x1d8) = in_pc;
  *(undefined4 *)(unaff_r9 + 0x1dc) = in_stack_00000220;
  if (in_NG != in_OV) {
    *(uint *)(unaff_r5 + unaff_r7) = (uint)*(ushort *)(unaff_r7 + 0x20);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(uint *)(param_1 + 100) = (uint)*(ushort *)(unaff_r7 + 0x20);
  iVar2 = *(int *)(unaff_r7 + 0x2c);
  piVar1 = (int *)(uint)*(byte *)(unaff_r5 + 3);
  uVar3 = (uint)*(byte *)((int)piVar1 + unaff_r7);
  *(int *)(unaff_r7 + 0x24) = unaff_r5 << 7;
  iVar4 = uVar3 - 0xf8;
  *(short *)(*(int *)(*(int *)(uVar3 + 0x2c) + 0x28) + 0x14) = (short)unaff_r7;
  *(uint *)(unaff_r7 + iVar4) = param_1;
  *piVar1 = unaff_r5 << 7;
  piVar1[1] = iVar2;
  piVar1[2] = iVar4;
  if (!SBORROW4(uVar3,0xf8)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(iVar2 + 0xe) = (char)iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::assign(wchar_t const*, unsigned int)

void std::__ndk1::basic_string<>::assign(wchar_t *param_1,uint param_2)

{
  int unaff_r4;
  undefined4 unaff_r7;
  undefined4 in_cr0;
  undefined4 in_cr5;
  undefined4 in_cr6;
  undefined4 in_cr7;
  undefined4 in_cr11;
  undefined4 in_cr12;
  
  *(short *)(unaff_r4 + 0x1e) = (short)unaff_r7;
  coprocessor_function2(0xd,7,4,in_cr7,in_cr6,in_cr11);
  *(undefined4 *)(unaff_r4 + 0x40) = unaff_r7;
  coprocessor_function2(0xf,2,3,in_cr0,in_cr5,in_cr12);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered unimplemented instructions
// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c728c) overlaps instruction at (ram,0x002c728a)
// 
// WARNING: Removing unreachable block (ram,0x003b9b9c)
// WARNING: Removing unreachable block (ram,0x002c710a)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::reserve(unsigned int)

void __thiscall std::__ndk1::basic_string<>::reserve(basic_string<> *this,uint param_1)

{
  ushort uVar1;
  undefined4 uVar2;
  int extraout_r1;
  undefined4 *extraout_r1_00;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 unaff_r4;
  uint unaff_r5;
  int unaff_r6;
  int unaff_r7;
  uint unaff_r8;
  char in_CY;
  char cVar7;
  undefined4 in_cr1;
  undefined4 in_cr2;
  undefined4 in_cr5;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined1 in_q4 [16];
  undefined4 in_stack_0000012c;
  
  if (in_CY == '\0') {
    *(undefined4 *)(this + 100) = unaff_r4;
    iVar4 = *(int *)(unaff_r7 + 0x2c);
    piVar3 = (int *)(uint)*(byte *)(unaff_r5 + 3);
    uVar5 = (uint)*(byte *)((int)piVar3 + unaff_r7);
    *(uint *)(unaff_r7 + 0x24) = unaff_r5 << 7;
    iVar6 = uVar5 - 0xf8;
    *(short *)(*(int *)(*(int *)(uVar5 + 0x2c) + 0x28) + 0x14) = (short)unaff_r7;
    *(basic_string<> **)(unaff_r7 + iVar6) = this;
    *piVar3 = unaff_r5 << 7;
    piVar3[1] = iVar4;
    piVar3[2] = iVar6;
    if (SBORROW4(uVar5,0xf8)) {
      *(char *)(iVar4 + 0xe) = (char)iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    *(short *)(unaff_r5 + unaff_r6) = (short)unaff_r5;
    VectorRoundShiftLeft(in_q4,0x13,0x40,1);
    coprocessor_function2(0xc,8,3,in_cr13,in_cr5,in_cr2);
    software_bkpt(0xec);
    cVar7 = SBORROW4((int)this,0xd9);
    uVar1 = *(ushort *)((unaff_r5 >> ((unaff_r8 | 0xffb0ffff) & 0xff)) + 0x18);
    _DAT_2d34cff6 = (undefined2)param_1;
    iVar4 = 0xb4d;
    func_0xffbd1216(this + -0xd9);
    func_0xff9bcc0a();
    uVar2 = *(undefined4 *)(extraout_r1 + iVar4);
    *(undefined4 *)(extraout_r1 + 0x28) = in_stack_0000012c;
    iVar4 = (uint)uVar1 * 0x1000000;
    if (iVar4 == 0 || iVar4 < 0 != (bool)cVar7) {
      FUN_001aa684(uVar2);
      *extraout_r1_00 = *(undefined4 *)(iVar4 + 0x58);
                    // WARNING: Unimplemented instruction - Truncating control flow here
      halt_unimplemented();
    }
    coprocessor_function2(6,0,0,in_cr13,in_cr15,in_cr1);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::append(wchar_t const*, unsigned int)

void __thiscall
std::__ndk1::basic_string<>::append(basic_string<> *this,wchar_t *param_1,uint param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  int unaff_r4;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined4 in_cr11;
  
  piVar4 = *(int **)(unaff_r4 + 4);
  iVar6 = *(int *)(unaff_r4 + 8);
  *(basic_string<> **)(*(int *)(unaff_r4 + 0xc) + 0x58) = this;
  coprocessor_moveto(0xe,0,1,param_2,in_cr11,in_cr11);
  iVar2 = *piVar4;
  puVar3 = (undefined4 *)piVar4[1];
  iVar5 = piVar4[2];
  *(short *)(iVar2 + 0x20) = (short)param_1;
  *(short *)(iVar6 + *(ushort *)(iVar6 + iVar2) + 7) = (short)iVar5;
  uVar1 = _DAT_8e000034;
  *puVar3 = 0x8e000000;
  puVar3[1] = uVar1;
  puVar3[2] = puVar3[0x16];
  puVar3[3] = puVar3[0x16] + -6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::assign(std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&, unsigned int,
// unsigned int)

void std::__ndk1::basic_string<>::assign(basic_string *param_1,uint param_2,uint param_3)

{
  byte bVar1;
  undefined4 uVar2;
  undefined2 unaff_r4;
  int unaff_r5;
  undefined4 unaff_r8;
  undefined4 in_cr6;
  
  bVar1 = *(byte *)(param_3 + 10);
  coprocessor_loadlong(0xe,in_cr6,unaff_r8);
  *(short *)(bVar1 + 0x20) = (short)param_2;
  *(undefined2 *)(unaff_r5 + *(ushort *)(unaff_r5 + (uint)bVar1) + 7) = unaff_r4;
  uVar2 = _DAT_8e000034;
  *(undefined4 *)param_3 = 0x8e000000;
  *(undefined4 *)(param_3 + 4) = uVar2;
  *(int *)(param_3 + 8) = *(int *)(param_3 + 0x58);
  *(int *)(param_3 + 0xc) = *(int *)(param_3 + 0x58) + -6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c747c)
// WARNING: Removing unreachable block (ram,0x002c746c)
// WARNING: Removing unreachable block (ram,0x002c746e)
// WARNING: Removing unreachable block (ram,0x00376f28)
// WARNING: Removing unreachable block (ram,0x002c754e)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::copy(wchar_t*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::copy(wchar_t *param_1,uint param_2,uint param_3)

{
  uint unaff_r5;
  uint in_stack_00000004;
  int in_stack_00000008;
  undefined4 in_stack_00000104;
  wchar_t *pwStack00000110;
  
  if ((unaff_r5 & 0x7fffffff) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!SCARRY4(unaff_r5,unaff_r5)) {
    *(undefined4 *)(param_2 + 0x28) = in_stack_00000104;
    DAT_002c770c = 0;
    *(undefined2 *)(in_stack_00000004 + 4) = 0x76dc;
    if ((in_stack_00000004 & 0x1fffff) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    pwStack00000110 = param_1;
                    // WARNING: Could not recover jumptable at 0x002c74f8. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(in_stack_00000008 + -5))(0xffffff4b,&UNK_002c77a0);
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::basic_string(std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&, unsigned int,
// unsigned int, std::__ndk1::allocator<wchar_t> const&)

void std::__ndk1::basic_string<>::basic_string
               (basic_string *param_1,uint param_2,uint param_3,allocator *param_4)

{
  char in_NG;
  char in_OV;
  undefined4 in_cr1;
  undefined4 in_cr2;
  
  if (in_NG == in_OV) {
    coprocessor_movefromRt(6,6,1,in_cr2,in_cr1);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find(wchar_t, unsigned int) const

void std::__ndk1::basic_string<>::find(wchar_t param_1,uint param_2)

{
  return;
}



void FUN_002c756e(void)

{
  return;
}



// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__init(unsigned int, wchar_t)

void std::__ndk1::basic_string<>::__init(uint param_1,wchar_t param_2)

{
  code *pcVar1;
  
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0x59,0x2c75b4);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::insert(unsigned int, wchar_t const*)

void std::__ndk1::basic_string<>::insert(uint param_1,wchar_t *param_2)

{
  undefined4 in_r3;
  int unaff_r6;
  undefined8 in_d4;
  
  *(undefined4 *)(unaff_r6 + 0x24) = in_r3;
  VectorShiftLeft(in_d4,0x33,0x40,1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find_last_of(wchar_t const*, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::find_last_of(wchar_t *param_1,uint param_2,uint param_3)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x002c7630. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::push_back(wchar_t)

void std::__ndk1::basic_string<>::push_back(wchar_t param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int unaff_r7;
  int *piVar4;
  char in_NG;
  char in_OV;
  undefined1 in_q6 [16];
  
  piVar4 = *(int **)(unaff_r7 + 0x18);
  if (in_NG == in_OV) {
    iVar2 = **(int **)(unaff_r7 + 0x10);
    iVar3 = (*(int **)(unaff_r7 + 0x10))[1];
    bVar1 = *(byte *)(iVar2 + 0x1a);
    *piVar4 = iVar2;
    piVar4[1] = (uint)bVar1;
    piVar4[2] = iVar3;
    piVar4[3] = (int)piVar4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  DAT_68d67eda = *(undefined1 *)(unaff_r7 + 4);
  VectorCopyNarrow(in_q6,8);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Control flow encountered unimplemented instructions
// WARNING: Removing unreachable block (ram,0x002c68e6)
// WARNING: Removing unreachable block (ram,0x002c68f2)
// WARNING: Removing unreachable block (ram,0x002c69a8)
// WARNING: Removing unreachable block (ram,0x002c68f4)
// WARNING: Removing unreachable block (ram,0x002c68f6)
// WARNING: Removing unreachable block (ram,0x002c6876)
// WARNING: Removing unreachable block (ram,0x002c687c)
// WARNING: Removing unreachable block (ram,0x002c726c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::append(unsigned int, wchar_t)

undefined8 std::__ndk1::basic_string<>::append(uint param_1,wchar_t param_2)

{
  byte bVar1;
  ushort uVar2;
  undefined4 extraout_r1;
  int extraout_r1_00;
  undefined4 *extraout_r1_01;
  int iVar3;
  undefined4 *in_r2;
  undefined4 uVar4;
  int in_r3;
  int *piVar5;
  undefined4 *unaff_r4;
  undefined1 *puVar6;
  int unaff_r5;
  undefined4 *puVar7;
  uint unaff_r7;
  char in_NG;
  char in_ZR;
  char in_OV;
  char cVar8;
  undefined4 in_cr1;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined8 in_stack_00000000;
  undefined4 in_stack_0000012c;
  byte in_stack_000002d3;
  
  puVar7 = (undefined4 *)(uint)in_stack_000002d3;
  if (in_ZR == '\0') {
    unaff_r7 = (uint)*(byte *)(param_2 + L'\x03');
    if (in_r3 != 0) {
      bVar1 = *(byte *)(param_2 + L'\x19');
      piVar5 = (int *)((uint)in_r2 >> 0x1c);
      *(uint *)param_2 = param_1;
      *(uint *)(param_2 + L'\x04') = (uint)unaff_r4 >> 5;
      *(int **)(param_2 + L'\b') = piVar5;
      *piVar5 = param_2 + L'\f';
      piVar5[1] = (int)in_r2;
      piVar5[2] = (uint)unaff_r4 >> 5;
      piVar5[3] = (int)puVar7;
      piVar5[4] = unaff_r7;
      if (SBORROW4((int)unaff_r4,0xe)) {
        *(char *)((int)in_r2 + 6) = (char)*(undefined4 *)(bVar1 + 4);
        return in_stack_00000000;
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_OV = SBORROW4(unaff_r7,0x76);
    param_2 = 0xbe40dcd5U >> (unaff_r7 & 0x1f) | -0x41bf232b << 0x20 - (unaff_r7 & 0x1f);
    in_NG = param_2 < L'\0';
    in_ZR = param_2 == L'\0';
    if (in_NG == in_OV) {
      uVar4 = unaff_r4[0xd];
      *in_r2 = unaff_r4;
      in_r2[1] = uVar4;
      in_r2[2] = puVar7;
      in_r2[3] = (int)puVar7 + -6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  uVar4 = *(undefined4 *)(param_1 + 0x68);
  *(undefined1 *)(param_2 + L'\x18') = 0xb0;
  *puVar7 = &DAT_002c77b0;
  puVar7[1] = in_r2;
  puVar7[2] = uVar4;
  puVar7[3] = unaff_r4;
  if ((bool)in_ZR || in_NG != in_OV) {
    if (in_NG != in_OV) {
      *(undefined4 **)(unaff_r5 + unaff_r7) = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (puVar7 + 4 != (undefined4 *)0x0) {
    *unaff_r4 = &DAT_002c77b0;
    unaff_r4[1] = param_2;
    unaff_r4[2] = uVar4;
    unaff_r4[3] = unaff_r7;
    puVar6 = *(undefined1 **)(unaff_r5 + 0x24);
    *puVar6 = (char)(puVar7 + 4);
    cVar8 = '\0';
    uVar2 = *(ushort *)(*(byte *)(((uint)in_r2 & ~(uint)puVar6) * 2) + 0x18);
    _DAT_2d34cff6 = (undefined2)param_2;
    iVar3 = 0xb4d;
    func_0xffbd1216(&DAT_002c76d7);
    func_0xff9bcc0a();
    uVar4 = *(undefined4 *)(extraout_r1_00 + iVar3);
    *(undefined4 *)(extraout_r1_00 + 0x28) = in_stack_0000012c;
    iVar3 = (uint)uVar2 * 0x1000000;
    if (iVar3 != 0 && iVar3 < 0 == (bool)cVar8) {
      coprocessor_function2(6,0,0,in_cr13,in_cr15,in_cr1);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    FUN_001aa684(uVar4);
    *extraout_r1_01 = *(undefined4 *)(iVar3 + 0x58);
                    // WARNING: Unimplemented instruction - Truncating control flow here
    halt_unimplemented();
  }
  func_0xff80994c(&DAT_002c77b0,param_2,(uint)*(byte *)(unaff_r4 + 4) << 0xd);
  _DAT_0000005b = extraout_r1;
  _DAT_0000005f = unaff_r5 >> 5;
  _DAT_00000063 = 0x5b;
  DAT_00000079 = (char)unaff_r4;
  if (SBORROW4(unaff_r7,8)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::rfind(wchar_t, unsigned int) const

void std::__ndk1::basic_string<>::rfind(wchar_t param_1,uint param_2)

{
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::assign(unsigned int, wchar_t)

void std::__ndk1::basic_string<>::assign(uint param_1,wchar_t param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::erase(unsigned int, unsigned int)

void std::__ndk1::basic_string<>::erase(uint param_1,uint param_2)

{
  uint uVar1;
  uint in_r3;
  uint *unaff_r4;
  uint unaff_r5;
  uint *puVar2;
  uint unaff_r6;
  int iVar3;
  int unaff_r9;
  undefined4 in_cr9;
  uint in_stack_0000021c;
  
  uVar1 = (uint)*(byte *)(param_1 + 5);
  iVar3 = *(int *)((int)unaff_r4 + uVar1);
  *unaff_r4 = param_1;
  unaff_r4[1] = in_r3;
  unaff_r4[2] = unaff_r5;
  unaff_r4[3] = unaff_r6;
  *(uint *)(unaff_r5 + 0x74) = uVar1;
  puVar2 = (uint *)(unaff_r5 + 0x1a);
  coprocessor_store(10,in_cr9,unaff_r9 + 0xec);
  if (puVar2 != (uint *)0x0 && (int)puVar2 < 0 == SCARRY4(unaff_r5,0x1a)) {
    *(char *)(iVar3 + 1) = (char)param_1;
    *(uint *)(iVar3 + 0x44) = uVar1;
    coprocessor_store(0xf,in_cr9,unaff_r9 + 0xec);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *puVar2 = param_1;
  *(uint *)(unaff_r5 + 0x1e) = in_r3;
  unaff_r4[4] = (unaff_r5 + 0x22) * 0x400;
  unaff_r4[5] = uVar1;
  unaff_r4[6] = (uint)(unaff_r4 + 4);
  unaff_r4[7] = in_stack_0000021c;
  *(short *)(unaff_r4 + 9) = (short)in_r3;
                    // WARNING: Could not recover jumptable at 0x002c6896. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)(uint)*(byte *)(in_stack_0000021c + 0x1b))();
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__erase_external_with_move(unsigned int, unsigned int)

void std::__ndk1::basic_string<>::__erase_external_with_move(uint param_1,uint param_2)

{
  int iVar1;
  int unaff_r5;
  undefined4 unaff_r6;
  bool in_CY;
  
  iVar1 = -(uint)!in_CY;
  *(undefined4 *)(unaff_r5 + iVar1 + -0x5e804) = unaff_r6;
  *(uint *)(unaff_r5 + iVar1 + -0x5e808) = param_2;
  *(uint *)(unaff_r5 + iVar1 + -0x5e80c) = param_1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered unimplemented instructions
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::append(std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&, unsigned int,
// unsigned int)

void std::__ndk1::basic_string<>::append(basic_string *param_1,uint param_2,uint param_3)

{
                    // WARNING: Unimplemented instruction - Truncating control flow here
  halt_unimplemented();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::compare(wchar_t const*) const

void std::__ndk1::basic_string<>::compare(wchar_t *param_1)

{
  int iVar1;
  undefined4 in_r1;
  int in_r2;
  undefined1 *puVar2;
  undefined1 *puVar3;
  int unaff_r4;
  uint uVar4;
  undefined4 *unaff_r5;
  undefined4 *puVar5;
  uint unaff_r6;
  uint uVar6;
  bool bVar7;
  undefined4 in_cr1;
  undefined4 in_cr3;
  undefined4 in_cr12;
  undefined4 in_cr13;
  undefined4 in_cr14;
  
  puVar3 = &stack0x00000210;
  uVar6 = (uint)*(byte *)(unaff_r6 + unaff_r4);
  iVar1 = 0x2c7bf0;
  bVar7 = SCARRY4(in_r2,0xef);
  puVar2 = (undefined1 *)(in_r2 + 0xef);
  if ((int)puVar2 < 0) {
    coprocessor_moveto(0xe,0,5,in_r1,in_cr1,in_cr13);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    uVar4 = unaff_r6 >> 0x18;
    software_hlt(0x1e);
    *(undefined1 **)((int)register0x00000054 + 0x68) = puVar3;
    *(undefined1 **)(puVar2 + 0x44) = puVar2;
    if (uVar4 == 0 || bVar7) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar5 = unaff_r5;
    if (uVar4 == 0) {
      *(undefined4 **)((int)register0x00000054 + -4) = unaff_r5;
      *(undefined4 *)((int)register0x00000054 + -8) = 0x7d;
      *(undefined1 **)((int)register0x00000054 + -0xc) = puVar2;
      *(undefined4 *)((int)register0x00000054 + -0x10) = in_r1;
      *(int *)((int)register0x00000054 + -0x14) = iVar1;
      uVar4 = unaff_r5[0xb];
      if (unaff_r6 < 0xffffff0b) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      coprocessor_moveto(0,7,2,puVar3,in_cr14,in_cr3);
      *(char *)(uVar6 + 0x1a) = (char)uVar6;
      *(int *)(puVar2 + 100) = iVar1;
      coprocessor_movefromRt(1,5,6,in_cr1,in_cr12);
      puVar5 = (undefined4 *)((int)unaff_r5 + -0x1f);
      *(undefined4 *)(unaff_r6 + 0xf5) = in_r1;
      *(undefined1 **)(unaff_r6 + 0xf9) = puVar2;
      *(undefined1 **)(unaff_r6 + 0xfd) = puVar3;
      *(uint *)(unaff_r6 + 0x101) = uVar4;
      *(undefined4 **)(unaff_r6 + 0x105) = puVar5;
      unaff_r6 = unaff_r6 + 0x109;
      puVar2 = (undefined1 *)((int)register0x00000054 + 8);
      puVar3 = (undefined1 *)(*(byte *)((int)unaff_r5 + -9) + 0x44);
      register0x00000054 = *(BADSPACEBASE **)(iVar1 + 0x59);
    }
    uVar6 = 0x44;
    iVar1 = (int)*(short *)((int)puVar5 + uVar4);
    *(char *)(puVar5 + 2) = (char)puVar5;
    *puVar5 = in_r1;
    puVar5[1] = uVar4;
    puVar5[2] = puVar5;
    unaff_r5 = (undefined4 *)(puVar3 + unaff_r6);
    if (SCARRY4(unaff_r6,(int)puVar3)) break;
    bVar7 = SBORROW4(unaff_r6,0x19);
    unaff_r6 = unaff_r6 - 0x19;
  }
  *(undefined4 *)(uVar4 + 0x24) = 0x44;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0023b324) overlaps instruction at (ram,0x0023b322)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::compare(unsigned int, unsigned int, wchar_t const*, unsigned
// int) const

void std::__ndk1::basic_string<>::compare(uint param_1,uint param_2,wchar_t *param_3,uint param_4)

{
  code *pcVar1;
  byte bVar2;
  ushort uVar3;
  ushort *puVar4;
  char *pcVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  int iVar8;
  uint uVar9;
  undefined *puVar10;
  int *piVar11;
  uint *puVar12;
  uint unaff_r4;
  uint uVar13;
  undefined4 *unaff_r5;
  int *piVar14;
  undefined4 *puVar15;
  uint unaff_r6;
  uint uVar16;
  undefined4 *puVar17;
  uint *unaff_r10;
  undefined4 unaff_r11;
  uint *puVar18;
  uint in_lr;
  bool bVar19;
  bool bVar20;
  bool bVar21;
  bool bVar22;
  undefined4 in_cr0;
  undefined4 in_cr7;
  undefined4 in_cr8;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 in_d6;
  undefined8 in_d7;
  undefined8 uVar23;
  undefined8 unaff_d13;
  undefined8 in_d18;
  undefined8 in_d22;
  undefined8 in_d25;
  undefined8 in_d29;
  uint uStack_18;
  uint uStack_14;
  wchar_t *pwStack_10;
  uint uStack_c;
  
  uVar9 = *(uint *)(unaff_r6 + 0xcf);
  piVar11 = *(int **)(unaff_r6 + 0xd3);
  puVar17 = *(undefined4 **)(unaff_r6 + 0xd7);
  if (unaff_r6 < 0xffffff31 || (uint *)(unaff_r6 + 0xcf) == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uStack_18 = param_1;
  uStack_14 = param_2;
  pwStack_10 = param_3;
  uStack_c = param_4;
  if (*(char *)(uVar9 + (int)puVar17) != '\0') {
    iVar8 = piVar11[1];
    piVar14 = (int *)piVar11[2];
    bVar2 = *(byte *)(*piVar11 + 7);
    coprocessor_moveto(0xb,7,1,unaff_r11,in_cr15,in_cr7);
    *piVar14 = *piVar11;
    piVar14[1] = iVar8;
    piVar14[2] = (int)(piVar11 + 4);
    piVar14[3] = (int)unaff_r5;
    piVar14[4] = (uint)bVar2;
    func_0xfff5bdb0();
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(1,0x23acf6);
    (*pcVar1)();
  }
  puVar10 = (undefined *)0x0;
  bVar22 = SBORROW4((int)unaff_r5,3);
  puVar6 = (undefined4 *)((int)unaff_r5 + -3);
  *(char *)((int)puVar17 + 1) = (char)(unaff_r6 + 0xdb);
  uVar9 = uVar9 >> ((uint)puVar6 & 0x1f) | uVar9 << 0x20 - ((uint)puVar6 & 0x1f);
  bVar21 = ((uint)puVar6 & 0xff) == 0 && (undefined4 *)0x2 < unaff_r5 ||
           ((uint)puVar6 & 0xff) != 0 && (uVar9 & 0x80000000) != 0;
  bVar20 = uVar9 == 0;
  puVar4 = (ushort *)0x0;
  puVar18 = &uStack_18;
  uVar13 = uVar9;
  if (bVar22) {
    puVar6 = (undefined4 *)((int)unaff_r4 >> 5);
    _DAT_44ecbb43 = 0;
    if (puVar6 != (undefined4 *)0x0) {
      _DAT_44ecbb43 = -10;
      *puVar6 = 0xfffffff6;
      puVar6 = puVar6 + 1;
    }
    puVar17[0xb] = puVar17;
    bVar21 = (bool)hasExclusiveAccess(puVar6 + 6);
    if (bVar21) {
      puVar6[6] = unaff_r4;
    }
    if (!bVar22) {
      puVar17 = (undefined4 *)&stack0x000002bc;
    }
    if (!bVar22) {
      *(short *)(_DAT_44ecbb43 + 6) = (short)_DAT_44ecbb43;
    }
    coprocessor_store(0xf,in_cr0,uVar9 + 0x84);
    _DAT_44ecbb47 = (uint)!bVar21;
    _DAT_44ecbb4b = 0x22;
    _DAT_44ecbb4f = (uint)unaff_r5 >> 7;
    *(undefined2 *)((int)puVar17 + unaff_r6 + 0xdb) = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    bVar19 = (int)uVar13 < 0;
    *(undefined4 **)(uVar9 * 2) = puVar17;
    if (bVar19 != bVar22) {
                    // WARNING: Does not return
      pcVar1 = (code *)software_udf(0x77,0x23ad36);
      (*pcVar1)();
    }
    puVar15 = (undefined4 *)((uint)puVar6 & 0xff);
    if (bVar20 || bVar19 != bVar22) break;
    bVar21 = ((int)puVar17 >> 0x1e & 1U) != 0;
    unaff_r4 = (int)puVar17 >> 0x1f;
    bVar20 = -1 < (int)puVar17;
    puVar4 = (ushort *)0xd7d2770a;
    puVar18 = puVar18 + 0x60;
    uVar13 = unaff_r4;
  }
  if (!bVar21 || bVar20) {
    if (bVar20 || bVar19 != bVar22) {
      *(short *)((int)unaff_r5 + 0x32) = (short)puVar15;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(undefined4 **)puVar4 = puVar6;
    puVar4[2] = 0;
    puVar4[3] = 0;
    *(undefined4 **)(puVar4 + 4) = unaff_r5;
    *(undefined4 **)(puVar4 + 6) = puVar17;
    puVar4 = puVar4 + 8;
    *unaff_r5 = puVar4;
    unaff_r5[1] = (int)(char)unaff_r4;
    unaff_r5[2] = unaff_r4;
    unaff_r5[3] = unaff_r5;
    uVar9 = (int)unaff_r5 - 0x57;
    if (unaff_r4 != 0) {
      if (!SBORROW4((int)unaff_r5,0x57)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)((int)unaff_r5 + 1) = (char)puVar6;
      puRam00000000 = puVar4;
      iRam00000004 = 0;
      puRam00000008 = puVar15;
      VectorComplexMultiplyAccumulateByElement(in_d6,in_d18,in_d29,0x10e,2);
      if (!SBORROW4((int)unaff_r5,0x57)) {
        iRam00000004 = uVar9 * 0x1000000;
        *(char *)((int)puVar15 + unaff_r4) = (char)puVar6;
        iRam0000000c = CONCAT22(iRam0000000c._2_2_,(short)puVar18[0x154]);
        *(undefined2 *)(puVar18[0x154] + 8) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar13 = puVar18[0x12f];
    *(char *)(uVar13 + 0x10) = (char)uVar9;
    uVar16 = uVar13 + 6;
    if (uVar13 < 0xfffffffa || uVar16 == 0) {
      puVar12 = (uint *)puVar15[0xf];
      uVar13 = 0x54cc7b52;
      uVar23 = VectorSub(in_d7,unaff_d13,4,0);
      SatQ(uVar23,4,0);
    }
    else {
      puVar12 = (uint *)puVar18[0x62];
      puVar10 = &DAT_0029f0c8;
      puVar7 = (undefined4 *)puVar18[0x65];
      puVar17 = (undefined4 *)puVar18[0x66];
      uVar9 = puVar18[0x67];
      uVar16 = puVar18[0x68];
      puVar12[0x1d] = uVar9;
      uVar13 = 0xc3557ef0;
      *(uint *)(uVar16 + 4) = uVar16;
      bVar2 = *(byte *)((int)puVar7 + 0x12);
      puVar15 = (undefined4 *)(uint)bVar2;
      *puVar7 = 0xc3557ef0;
      puVar7[1] = puVar17;
      puVar7[2] = uVar9;
      puVar7[3] = puVar15;
      puVar6 = puVar7 + 4;
      puVar18[0x68] = in_lr;
      puVar18[0x67] = uVar9;
      puVar18[0x66] = (uint)puVar17;
      puVar18[0x65] = (uint)puVar6;
      if (puVar12 != (uint *)0x0) {
        pcVar5 = "_11char_traitsIcEENS_9allocatorIcEEE6appendEjc";
        *puVar15 = "_11char_traitsIcEENS_9allocatorIcEEE6appendEjc";
        *(byte *)(uVar9 + 0x17) = bVar2;
        uVar9 = puVar18[0x117];
        *puVar17 = "_11char_traitsIcEENS_9allocatorIcEEE6appendEjc";
        puVar17[1] = puVar6;
        puVar17[2] = puVar17;
        puVar17[3] = puVar12;
        puVar17[4] = uVar9;
        puVar17[5] = uVar16;
        puVar7[0x14] = &DAT_0029f0c8;
        do {
          puVar15 = puVar17;
          uVar9 = (int)puVar6 * 0x1000;
          pcVar5 = pcVar5 + -0x300;
          coprocessor_store(7,in_cr8,pcVar5);
          DAT_0029f144 = &DAT_0029f0c8;
          bVar2 = *(byte *)(uVar9 + 0xc);
          if (uVar9 >> 0x1a != 0 && !SBORROW4((int)puVar15,0xf1)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          puVar12 = puVar18 + 0xcf;
          puVar17 = (undefined4 *)((int)puVar15 + -0x12);
        } while (SBORROW4((int)puVar15,0x12));
        if (!SBORROW4((int)puVar15,0x12)) {
          *(short *)(puVar18 + 0xdb) = (short)puVar12;
          *(ushort *)(puVar15 + 10) = (ushort)(uVar9 >> 0x1a);
          _DAT_00000078 = puVar18[0x89];
          *(undefined1 *)(puVar15 + 3) = 0xce;
          pcVar5 = pcVar5 + _DAT_00000078;
          pcVar5[0] = 't';
          pcVar5[1] = '\0';
          pcVar5[2] = '\0';
          pcVar5[3] = '\0';
          puVar18[0x102] = _DAT_00000078;
          _DAT_b11decce = puRam00000000;
          _DAT_b11decd2 = iRam00000004;
          _DAT_b11decd6 = &DAT_b11decce;
          _DAT_b11decda = 0x37;
          _DAT_000000c4 = 0x85f98aac;
          _DAT_00000074 = puRam00000000;
          _DAT_0000007c = iRam00000004;
          _DAT_00000080 = 0x37;
          _DAT_00000084 = 0x74;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        iVar8 = (int)puVar18 + 0x2b9;
        if (0x82 < (int)puVar12) {
          uVar13 = (uint)*(ushort *)(bVar2 + 0x2a);
          _DAT_000000e8 = (ushort)(byte)pcVar5[iVar8];
          puVar18[0x123] = 0xd6;
          coprocessor_storelong(9,in_cr7,(uVar9 >> 0x1a) - 0xeb02c3);
          iVar8 = *(int *)(uVar13 - 0x5e);
          uVar9 = *(uint *)(uVar13 - 0x56);
          do {
            uVar9 = uVar9 >> 3;
          } while (uVar9 != 0);
          _DAT_00000078 = (uint)bVar2;
          *(short *)(iVar8 + 0xc) = (short)iVar8;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (puVar12 < &DAT_00000083 || iVar8 == 0) {
          if (puVar12 < &DAT_00000083 || iVar8 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(undefined2 *)(puVar15 + 7) = 0xecce;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    *(short *)((int)puVar15 + 0x3a) = (short)uVar13;
    *puVar12 = uVar13;
    puVar12[1] = (uint)puVar6;
    puVar12[2] = uVar9;
    puVar12[3] = uVar16;
    coprocessor_store(3,in_cr11,puVar12 + 4);
    *(undefined **)(puVar10 + -99) = puVar10 + -99;
    *(uint *)(puVar10 + -0x5f) = uVar13 >> 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!bVar21) {
    puVar18[0x143] = (uint)unaff_r5;
    disableFIQinterrupts();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    *puVar17 = puVar6;
    puVar17[1] = uVar9;
    puVar17[2] = unaff_r4;
    puVar17[3] = unaff_r5;
    puVar17[4] = puVar15;
    puVar7 = puVar17 + 5;
    bVar2 = *(byte *)((int)puVar15 + uVar9);
    uVar13 = (uint)bVar2;
    unaff_r10[-0xbb] = uVar13;
    unaff_r10[-0xba] = (uint)puVar6;
    uVar9 = *(uint *)(puVar4 + 0x38);
    VectorPairwiseAdd(in_d22,in_d25,1);
    puVar6 = (undefined4 *)(int)*(short *)(uVar13 + 0xcfd);
    if (bVar20 || bVar19 != bVar22) {
      *puVar4 = (ushort)bVar2;
      unaff_r4 = 0x10;
      uVar13 = (uint)*(ushort *)(iRam0000000c + 0x10);
      puVar6 = (undefined4 *)(uint)*(ushort *)(iRam0000000c + 0x1e);
      puVar15 = puRam00000008;
LAB_0023b1aa:
      *(char *)(puVar15 + 2) = (char)puVar6;
      uVar9 = (int)puVar6 >> 0xf;
      *(uint *)(unaff_r4 + 0x68) = uVar13;
      uVar3 = *(ushort *)(uVar9 + (int)(puVar18 + 0x7a));
      puVar18[0xe2] = uVar9;
      puVar18[0x8f] = (uint)(puVar18 + 0x7a);
      iVar8 = (int)puVar15 + uVar9;
      *(int *)(uVar13 + 8) = iVar8;
      *(char *)(unaff_r4 + 4) = (char)uVar3;
      if (iVar8 == 0 || iVar8 < 0 != SCARRY4((int)puVar15,uVar9)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(undefined1 *)((uint)uVar3 * 0x1000 + 5) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (!bVar20) {
      if (!bVar21) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto LAB_0023b1aa;
    }
    bVar21 = (undefined4 *)0xfffffffc < puVar7;
    bVar22 = SCARRY4((int)puVar7,3);
    unaff_r5 = (undefined4 *)((int)puVar17 + 0x17);
    bVar19 = (int)unaff_r5 < 0;
    bVar20 = unaff_r5 == (undefined4 *)0x0;
    puVar17 = puVar7;
    unaff_r10 = unaff_r10 + -0xbb;
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::compare(unsigned int, unsigned int, wchar_t const*) const

void std::__ndk1::basic_string<>::compare(uint param_1,uint param_2,wchar_t *param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c79c6) overlaps instruction at (ram,0x002c79c4)
// 
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::at(unsigned int)

void __thiscall std::__ndk1::basic_string<>::at(basic_string<> *this,uint param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint unaff_r4;
  uint *unaff_r5;
  uint unaff_r6;
  uint uVar3;
  int iVar4;
  undefined4 in_cr1;
  undefined4 in_cr3;
  undefined4 in_cr12;
  undefined4 in_cr14;
  
  do {
    puVar1 = (undefined4 *)((int)register0x00000054 + 0x1c);
    iVar2 = *(byte *)((int)unaff_r5 + 0x16) + 0x44;
    iVar4 = *(int *)(this + 0x59);
    do {
      uVar3 = unaff_r6;
      this = (basic_string<> *)(int)*(short *)((int)unaff_r5 + unaff_r4);
      *(char *)(unaff_r5 + 2) = (char)unaff_r5;
      *unaff_r5 = param_1;
      unaff_r5[1] = unaff_r4;
      unaff_r5[2] = (uint)unaff_r5;
      unaff_r5 = (uint *)(uVar3 + iVar2);
      if (SCARRY4(uVar3,iVar2)) {
        *(undefined4 *)(unaff_r4 + 0x24) = 0x44;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      unaff_r6 = uVar3 - 0x19;
      unaff_r4 = unaff_r6 >> 0x18;
      software_hlt(0x1e);
      *(int *)(iVar4 + 0x68) = iVar2;
      *(undefined4 **)((int)register0x00000054 + 0x60) = puVar1;
      if (unaff_r4 == 0 || SBORROW4(uVar3,0x19)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    } while (unaff_r4 != 0);
    *(uint **)(iVar4 + -4) = unaff_r5;
    *(undefined4 *)(iVar4 + -8) = 0x7d;
    *(undefined4 **)(iVar4 + -0xc) = puVar1;
    *(uint *)(iVar4 + -0x10) = param_1;
    *(undefined4 *)(iVar4 + -0x14) = this;
    unaff_r4 = unaff_r5[0xb];
    if (unaff_r6 < 0xffffff0b) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_moveto(0,7,2,iVar2,in_cr14,in_cr3);
    uRam0000005e = 0x44;
    *(basic_string<> **)((int)register0x00000054 + 0x80) = this;
    coprocessor_movefromRt(1,5,6,in_cr1,in_cr12);
    unaff_r5 = (uint *)((int)unaff_r5 + -0x1f);
    *(uint *)(uVar3 + 0xdc) = param_1;
    *(undefined4 **)(uVar3 + 0xe0) = puVar1;
    *(int *)(uVar3 + 0xe4) = iVar2;
    *(uint *)(uVar3 + 0xe8) = unaff_r4;
    *(uint **)(uVar3 + 0xec) = unaff_r5;
    unaff_r6 = uVar3 + 0xf0;
    register0x00000054 = (BADSPACEBASE *)(iVar4 + -0x14);
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::assign(wchar_t const*)

void std::__ndk1::basic_string<>::assign(wchar_t *param_1)

{
  int *in_r2;
  undefined4 unaff_r6;
  
  *(int *)(*in_r2 + 0x412b20b4) = (int)(in_r2 + 3) * 0x8000000;
  *(undefined4 *)((int)(in_r2 + 3) * 0x10000000) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::find(wchar_t const*, unsigned int, unsigned int) const

void __thiscall
std::__ndk1::basic_string<>::find(basic_string<> *this,wchar_t *param_1,uint param_2,uint param_3)

{
  undefined4 *unaff_r4;
  undefined4 unaff_r5;
  undefined4 unaff_r6;
  undefined4 unaff_r7;
  
  *unaff_r4 = this + 8;
  unaff_r4[1] = param_1;
  unaff_r4[2] = param_2;
  unaff_r4[3] = unaff_r4;
  unaff_r4[4] = unaff_r5;
  unaff_r4[5] = unaff_r7;
  *(short *)(param_2 + 0xc) = (short)param_1;
  *(uint *)((int)(this + 8) * 2) = param_3;
  *(undefined4 *)
   (((int)param_1 << 0x18 | ((uint)param_1 >> 8 & 0xff) << 0x10 |
     ((uint)param_1 >> 0x10 & 0xff) << 8 | (uint)param_1 >> 0x18) + (int)unaff_r4) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c79c6) overlaps instruction at (ram,0x002c79c4)
// 
// WARNING: Removing unreachable block (ram,0x002c79b6)
// WARNING: Removing unreachable block (ram,0x002c79c8)
// WARNING: Removing unreachable block (ram,0x002c79d8)
// WARNING: Removing unreachable block (ram,0x002c7982)
// WARNING: Removing unreachable block (ram,0x002c7990)
// WARNING: Removing unreachable block (ram,0x002c79c6)
// WARNING: Removing unreachable block (ram,0x002c7a7c)
// WARNING: Removing unreachable block (ram,0x002c7a86)
// WARNING: Removing unreachable block (ram,0x002c79aa)
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::compare(unsigned int, unsigned int,
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::compare
               (uint param_1,uint param_2,basic_string *param_3,uint param_4,uint param_5)

{
  code *pcVar1;
  int unaff_r4;
  uint *unaff_r5;
  char in_OV;
  
  if (in_OV == '\0') {
    DAT_002c7df0 = *(uint *)(unaff_r4 + (int)unaff_r5);
    *unaff_r5 = param_1;
    unaff_r5[1] = (uint)param_3;
    unaff_r5[2] = DAT_002c7df0;
    unaff_r5[3] = 199;
    unaff_r5[4] = 0xf35570b9;
    DAT_002c7df8 = *(undefined4 *)(param_1 + 0x18);
    DAT_002c7df4 = 199;
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x6c,0x2c7a74);
    DAT_002c7de8 = param_1;
    DAT_002c7dec = param_2;
    (*pcVar1)();
  }
  FUN_000ef876();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c79c6) overlaps instruction at (ram,0x002c79c4)
// 
// WARNING: Removing unreachable block (ram,0x002c79b6)
// WARNING: Removing unreachable block (ram,0x002c79c8)
// WARNING: Removing unreachable block (ram,0x002c79d8)
// WARNING: Removing unreachable block (ram,0x002c7982)
// WARNING: Removing unreachable block (ram,0x002c7990)
// WARNING: Removing unreachable block (ram,0x002c79c6)
// WARNING: Removing unreachable block (ram,0x002c7a7c)
// WARNING: Removing unreachable block (ram,0x002c7a86)
// WARNING: Removing unreachable block (ram,0x002c79aa)
// std::__ndk1::_MetaBase<__can_be_converted_to_string_view<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::basic_string_view<wchar_t,
// std::__ndk1::char_traits<wchar_t> >
// >::value&&(!__is_same_uncvref<std::__ndk1::basic_string_view<wchar_t,
// std::__ndk1::char_traits<wchar_t> >, std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> >
// >::value)>::_EnableIfImpl<int> std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t>
// >::compare<std::__ndk1::basic_string_view<wchar_t, std::__ndk1::char_traits<wchar_t> > >(unsigned
// int, unsigned int, std::__ndk1::basic_string_view<wchar_t, std::__ndk1::char_traits<wchar_t> >
// const&, unsigned int, unsigned int) const

void std::__ndk1::basic_string<>::compare<>
               (uint param_1,uint param_2,basic_string_view *param_3,uint param_4,uint param_5)

{
  code *pcVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  uint *unaff_r5;
  int iVar8;
  undefined4 *unaff_r7;
  undefined4 unaff_r9;
  int unaff_r11;
  undefined4 in_r12;
  char in_OV;
  undefined8 uVar9;
  int in_stack_000003d0;
  
  iVar6 = param_4 * 0x100000;
  *(uint *)param_4 = param_1;
  *(basic_string_view **)(param_4 + 4) = param_3;
  *(int *)(param_4 + 8) = iVar6;
  *(uint **)(param_4 + 0xc) = unaff_r5;
  *(undefined4 **)(param_4 + 0x10) = unaff_r7;
  if (iVar6 != 0 && iVar6 < 0 == (bool)in_OV) {
    if (in_OV == '\0') {
      DAT_002c7df0 = unaff_r5[param_4 * 0x40000];
      *unaff_r5 = param_1;
      unaff_r5[1] = (uint)param_3;
      unaff_r5[2] = DAT_002c7df0;
      unaff_r5[3] = 199;
      unaff_r5[4] = 0xf35570b9;
      DAT_002c7df8 = *(undefined4 *)(param_1 + 0x18);
      DAT_002c7df4 = 199;
                    // WARNING: Does not return
      pcVar1 = (code *)software_udf(0x6c,0x2c7a74);
      DAT_002c7de8 = param_1;
      DAT_002c7dec = param_2;
      (*pcVar1)();
    }
    FUN_000ef876();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar5 = (int *)*unaff_r7;
  iVar7 = unaff_r7[1];
  iVar8 = unaff_r7[2];
  iVar6 = unaff_r7[5] + 0xe1;
  if (0xffffff1e < (uint)unaff_r7[5] && iVar6 != 0) {
    *(int *)param_2 = iVar6;
    *(int *)(param_2 + 4) = iVar7;
    *(int *)(param_2 + 8) = (int)param_2 >> 0xe;
    uVar9 = func_0xffbfc058(iVar6,param_2 + 0xc);
    iVar3 = (int)((ulonglong)uVar9 >> 0x20);
    *(undefined4 *)(unaff_r11 + -0x2b4) = in_r12;
    *(undefined4 *)(unaff_r11 + -0x2b0) = unaff_r9;
    iVar4 = iVar3 >> 0x10;
    if (iVar4 < 0) {
      *(char *)((int)uVar9 + 0x17) = (char)*(undefined4 *)(iVar4 + 0xc);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(short *)(iVar4 + 0x38) = (short)iVar8;
    uVar2 = *(ushort *)(iVar4 + 0x3a);
    *piVar5 = iVar3;
    piVar5[1] = (uint)uVar2;
    piVar5[2] = iVar7;
    piVar5[3] = iVar8;
    piVar5[4] = iVar7 - iVar6;
    piVar5[5] = in_stack_000003d0;
    *(short *)(iVar3 + 0x22) = (short)piVar5 + 0x18;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(int *)(param_2 + iVar7) = iVar8;
  *(int *)(iVar8 * 2) = (int)param_2 >> 0xe;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<wchar_t>::compare(wchar_t const*, wchar_t const*, unsigned int)

void std::__ndk1::char_traits<wchar_t>::compare(wchar_t *param_1,wchar_t *param_2,uint param_3)

{
  FUN_000ef876();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >& std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t>
// >::__assign_no_alias<true>(wchar_t const*, unsigned int)

basic_string * std::__ndk1::basic_string<>::__assign_no_alias<true>(wchar_t *param_1,uint param_2)

{
  undefined4 in_cr0;
  undefined4 in_cr5;
  undefined8 in_d5;
  undefined8 unaff_d12;
  
  coprocessor_movefromRt(1,3,6,in_cr0,in_cr5);
  FloatVectorCompareGreaterThan(unaff_d12,in_d5,4);
  software_interrupt(0xbd);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >& std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t>
// >::__assign_no_alias<false>(wchar_t const*, unsigned int)

basic_string * std::__ndk1::basic_string<>::__assign_no_alias<false>(wchar_t *param_1,uint param_2)

{
  undefined1 in_r2;
  int in_r3;
  int unaff_r5;
  
  *(undefined1 *)(in_r3 + *(int *)(unaff_r5 + 4)) = in_r2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::append(wchar_t const*)

void std::__ndk1::basic_string<>::append(wchar_t *param_1)

{
  uint uVar1;
  code *pcVar2;
  byte bVar3;
  ushort uVar4;
  undefined4 *puVar5;
  undefined1 *puVar6;
  uint in_r1;
  uint uVar7;
  uint in_r2;
  int iVar8;
  uint uVar9;
  int iVar10;
  int unaff_r5;
  uint unaff_r6;
  uint unaff_r7;
  int unaff_r8;
  int unaff_r10;
  undefined4 in_cr5;
  undefined4 in_cr7;
  undefined8 in_d16;
  undefined8 in_d23;
  undefined8 uVar11;
  
  iVar8 = in_r1 << 0x14;
  if (-1 < iVar8) {
    _DAT_00000031 = 0x15;
    *(undefined4 *)(((int)(uint)*(ushort *)(DAT_03c2fdf4 + 0x1e17efa) >> 3) + 0x1c) = 0x1e17efa;
    *(char *)((in_r1 ^ (uint)&stack0x00000378) + in_r2) = (char)in_r2;
    FUN_001b77cc();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  software_bkpt(0x8a);
  bVar3 = *(byte *)(unaff_r7 + 8);
  uVar4 = *(ushort *)(unaff_r5 + (uint)bVar3);
  puVar5 = (undefined4 *)(uint)uVar4;
  uVar1 = ~in_r2;
  iVar10 = unaff_r5 + 200;
  if (SCARRY4(unaff_r5,200)) {
    coprocessor_store(0xe,in_cr5,unaff_r10 + 0x228);
    uVar7 = in_r2 - 0x4c;
    puVar6 = (undefined1 *)((int)puVar5 + -7);
    uVar9 = (uVar7 >> 0x10) << 0x18 | (uVar7 >> 0x18) << 0x10 | (uVar7 & 0xff) << 8 |
            uVar7 >> 8 & 0xff;
    *(undefined1 **)puVar6 = puVar6;
    *(uint *)((int)puVar5 + -3) = uVar9;
    if ((undefined1 *)0xffffff2c < puVar6 && puVar5 + 0x33 != (undefined4 *)0x0) {
      *puVar5 = puVar5 + 0x33;
      puVar5[1] = uVar7;
      puVar5[2] = iVar8;
      puVar5[3] = uVar9;
      puVar5[4] = &DAT_002c7d9c;
      puVar5[5] = unaff_r6;
      puVar5[6] = in_r1 << 0x1a;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_r2 = (uint)*(byte *)(puVar5 + 2);
    vectorFusedMultiplyAccumulate(in_d23,in_d16,2);
    *(char *)(uVar9 + 0x10) = (char)unaff_r6;
    unaff_r6 = (uint)_DAT_df886b72;
    iVar10 = uVar9 << 0xc;
    puVar5 = (undefined4 *)&DAT_000000e8;
    iVar8 = (int)(unaff_r7 & uVar1) >> 0x1c;
  }
  else {
    *(ushort *)(in_r2 + (unaff_r7 & uVar1)) = uVar4;
    coprocessor_storelong(4,in_cr7,unaff_r8 + -0x104);
    *(int *)(in_r2 * 2) = iVar10;
    if (bVar3 != 0x5d) {
                    // WARNING: Does not return
      pcVar2 = (code *)software_udf(0xd2,0x2c7b60);
      (*pcVar2)();
    }
  }
  uVar11 = func_0x0100baa0(puVar5);
  puVar5 = (undefined4 *)uVar11;
  *puVar5 = (int)((ulonglong)uVar11 >> 0x20);
  puVar5[1] = in_r2;
  puVar5[2] = iVar8;
  puVar5[3] = iVar10;
  puVar5[4] = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::replace(unsigned int, unsigned int,
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int, unsigned int)

void std::__ndk1::basic_string<>::replace
               (uint param_1,uint param_2,basic_string *param_3,uint param_4,uint param_5)

{
  param_3[param_2] = SUB41(param_3,0);
  FUN_001b77cc();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::insert(std::__ndk1::__wrap_iter<wchar_t const*>, wchar_t)

void std::__ndk1::basic_string<>::insert(void)

{
  int unaff_r5;
  int unaff_r6;
  
  *(int *)(unaff_r5 + 0x60) = unaff_r6 + 0x2a;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c7680)
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::resize(unsigned int, wchar_t)

void std::__ndk1::basic_string<>::resize(uint param_1,wchar_t param_2)

{
  int in_r2;
  undefined4 in_r3;
  int unaff_r4;
  int unaff_r5;
  
  *(short *)(param_1 + 0x1a) = (short)unaff_r4;
  *(char *)(*(int *)(in_r2 + 0x10) + 0x17) = (char)param_2;
  *(undefined4 *)(unaff_r5 + 8) = in_r3;
  *(uint *)(in_r2 * 0x20000000 + 0x14) = param_1;
  *(int *)(*(short *)(unaff_r4 * 2) * 2) = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::insert(unsigned int, std::__ndk1::basic_string<wchar_t,
// std::__ndk1::char_traits<wchar_t>, std::__ndk1::allocator<wchar_t> > const&, unsigned int,
// unsigned int)

void std::__ndk1::basic_string<>::insert
               (uint param_1,basic_string *param_2,uint param_3,uint param_4)

{
  int unaff_r7;
  
  *(char *)(unaff_r7 + 0x1d) = (char)param_1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> >
// std::__ndk1::TEMPNAMEPLACEHOLDERVALUE(char const*, std::__ndk1::basic_string<char,
// std::__ndk1::char_traits<char>, std::__ndk1::allocator<char> > const&)

void std::__ndk1::operator+(char *param_1,basic_string *param_2)

{
  int unaff_r7;
  undefined4 in_cr3;
  int in_stack_00000080;
  
  software_hlt(0x32);
  *(int *)(in_stack_00000080 * 2 + unaff_r7) = (int)param_2 >> 0x12;
  coprocessor_movefromRt(6,2,3,in_cr3,in_cr3);
  software_interrupt(0x88);
  if ((int)param_2 >> 0x12 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return;
}



// std::__ndk1::stoi(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*, int)

void std::__ndk1::stoi(basic_string *param_1,uint *param_2,int param_3)

{
  int unaff_r4;
  undefined2 unaff_r5;
  int unaff_r6;
  uint unaff_r7;
  
  *(undefined2 *)(param_1 + 0x32) = unaff_r5;
  *(char *)(unaff_r6 + unaff_r4) = (char)unaff_r6;
  *(char *)((unaff_r7 >> 0x1b) + 8) = (char)param_2;
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::basic_string<decltype(nullptr)>(char const*)

void std::__ndk1::basic_string<>::basic_string<>(char *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoi(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*, int)

void std::__ndk1::stoi(basic_string *param_1,uint *param_2,int param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c7eb2)
// std::__ndk1::stol(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*, int)

void std::__ndk1::stol(basic_string *param_1,uint *param_2,int param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stol(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*, int)

void __thiscall std::__ndk1::stol(__ndk1 *this,basic_string *param_1,uint *param_2,int param_3)

{
  int *piVar1;
  uint unaff_r4;
  int iVar2;
  undefined4 *unaff_r5;
  int unaff_r6;
  undefined4 unaff_r7;
  
  *unaff_r5 = param_1;
  unaff_r5[1] = param_2;
  unaff_r5[2] = param_3;
  unaff_r5[3] = unaff_r6;
  unaff_r5[4] = unaff_r7;
  iVar2 = unaff_r4 + 0x6a;
  piVar1 = (int *)(uint)*(byte *)(unaff_r6 + 0x14);
  if (0xffffff95 < unaff_r4 && iVar2 != 0) {
    *(char *)((int)param_2 + 7) = (char)(unaff_r5 + 5);
    *piVar1 = (int)unaff_r4 >> 0x11;
    piVar1[1] = iVar2;
    piVar1[2] = (int)(unaff_r5 + 5);
    if (iVar2 < 0 != SCARRY4(unaff_r4,0x6a)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (iVar2 < 0) {
    *(ushort *)(((int)unaff_r4 >> 0x11) + 10) = (ushort)*(byte *)(unaff_r6 + 0x14);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoul(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*, int)

void std::__ndk1::stoul(basic_string *param_1,uint *param_2,int param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoul(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*, int)

void std::__ndk1::stoul(basic_string *param_1,uint *param_2,int param_3)

{
  undefined1 unaff_r4;
  int unaff_r5;
  undefined4 unaff_r6;
  
  *(undefined4 *)(unaff_r5 + param_3) = unaff_r6;
  *(undefined1 *)(param_3 + 0x1c) = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoll(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*, int)

void __thiscall std::__ndk1::stoll(__ndk1 *this,basic_string *param_1,uint *param_2,int param_3)

{
  bool in_ZR;
  bool in_CY;
  
  if (!in_CY || in_ZR) {
    *(basic_string **)(param_3 + 0x2c) = param_1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoll(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*, int)

void std::__ndk1::stoll(basic_string *param_1,uint *param_2,int param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *in_r3;
  undefined4 *unaff_r5;
  uint unaff_r7;
  
  software_bkpt(0xbf);
  uVar3 = *in_r3;
  uVar4 = in_r3[1];
  iVar5 = in_r3[2];
  *(short *)((int)unaff_r5 + 10) = (short)unaff_r5;
  if (0x24 < unaff_r7) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar2 = *(byte *)(iVar5 + 0x16);
  *unaff_r5 = uVar3;
  unaff_r5[1] = uVar4;
  unaff_r5[2] = (uint)bVar2;
  unaff_r5[3] = unaff_r7;
  *(short *)((int)unaff_r5 + 0x16) = (short)unaff_r5 + 0x10;
  if (unaff_r7 < 0xac) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xee,0x2c81c4);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoull(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*, int)

void std::__ndk1::stoull(basic_string *param_1,uint *param_2,int param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stoull(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*, int)

void std::__ndk1::stoull(basic_string *param_1,uint *param_2,int param_3)

{
  undefined4 unaff_r5;
  int unaff_r7;
  
  *(undefined4 *)(param_3 + unaff_r7) = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stof(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*)

void std::__ndk1::stof(basic_string *param_1,uint *param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c8352)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::stof(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*)

void std::__ndk1::stof(basic_string *param_1,uint *param_2)

{
  short sVar1;
  int iVar2;
  undefined *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  int unaff_r9;
  bool bVar7;
  undefined4 in_cr10;
  undefined4 in_cr11;
  uint in_stack_00000054;
  uint in_stack_00000070;
  undefined1 *puStack00000174;
  undefined1 *in_stack_0000026c;
  
  puStack00000174 = (undefined1 *)*param_2;
  uVar5 = param_2[1];
  uVar6 = param_2[3];
  puVar4 = (undefined4 *)((int)in_stack_00000054 >> 0x1b);
  puVar3 = &UNK_002c85f0;
  if (uVar6 != 0) {
    if (uVar6 < in_stack_00000054) {
      if (in_stack_00000054 != 0) {
        while( true ) {
          *(short *)(in_stack_00000054 + 0x14) = (short)puVar3;
          puVar3 = puVar3 + in_stack_00000054;
          bVar7 = param_1 == (basic_string *)0xc6;
          if (bVar7) {
            puStack00000174 = puStack00000174 + 0xc0;
          }
          if (bVar7) {
            puStack00000174 = &stack0x00000114;
          }
          if (!bVar7) {
            *(uint *)(unaff_r9 + 0x50) = uVar5;
          }
          *(undefined1 **)(unaff_r9 + 0x50) = puStack00000174;
          if ((int)param_1 < 199) break;
          bVar7 = SCARRY4(uVar6,0x1a);
          uVar6 = uVar6 + 0x1a;
          if ((int)uVar6 < 0 == bVar7) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          param_1 = (basic_string *)&UNK_002c8414;
          coprocessor_store(2,in_cr11,unaff_r9);
          puStack00000174 = in_stack_0000026c;
        }
                    // WARNING: Read-only address (ram,0x002c8520) is written
        uRam002c8520 = 0x84f4;
        *(undefined4 *)(&stack0x0000015c + (int)puVar3) = 0x6b;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(undefined1 *)(in_stack_00000070 + 8) = 0;
      *(undefined4 *)(uVar6 + 4) = 0;
      uVar6 = _DAT_a10354a6;
    }
    _DAT_a10354a6 = uVar6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    uVar6 = in_stack_00000054 + 0x14c;
    coprocessor_load(3,in_cr10,in_stack_00000054);
    *(undefined1 **)((int)register0x00000054 + 0xbc) = puStack00000174;
    sVar1 = *(short *)(param_1 + uVar5);
    iVar2 = *(int *)((int)register0x00000054 + 0x3f4);
    *(uint *)(in_stack_00000054 + 0x184) = uVar6;
    if (in_stack_00000070 <= uVar6) break;
    *(int *)((int)register0x00000054 + 0x304) = *(int *)((int)register0x00000054 + 0x3c);
    *(char *)(*(int *)((int)register0x00000054 + 0x3c) + uVar5 + 2) =
         (char)((uint)(int)sVar1 >> 6) + 'T';
    puStack00000174 = (undefined1 *)0x2c8530;
    param_1 = *(basic_string **)register0x00000054;
    in_stack_00000054 = *(uint *)((int)register0x00000054 + 8);
    puVar4 = *(undefined4 **)((int)register0x00000054 + 0xc);
    uVar5 = *(uint *)((int)register0x00000054 + 0x10);
    in_stack_00000070 = *(uint *)((int)register0x00000054 + 0x14);
    register0x00000054 = (BADSPACEBASE *)((int)register0x00000054 + 0x1c);
  }
  *(short *)((int)puVar4 + iVar2) = (short)puVar4;
  if ((int)puVar4 << 0xf < 0) {
    *(char *)(*(ushort *)(in_stack_00000054 + 0x180) + 0x1b) = (char)param_1;
    *(char *)(in_stack_00000070 + 7) = (char)(undefined4 *)((int)register0x00000054 + 0xfc);
    if ((undefined4 *)((int)register0x00000054 + 0xfc) != (undefined4 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(basic_string **)(iVar2 + 0x2c) = param_1;
    uRam00000000 = 0;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *puVar4 = param_1;
  puVar4[1] = iVar2;
  puVar4[2] = uVar6;
  puVar4[3] = puVar4;
  puVar4[4] = in_stack_00000070;
  puVar4[5] = (undefined4 *)((int)register0x00000054 + 0x340);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::stod(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*)

void std::__ndk1::stod(basic_string *param_1,uint *param_2)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  uint in_r2;
  int iVar5;
  int in_r3;
  int *piVar6;
  undefined1 *puVar7;
  uint *unaff_r4;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined4 *unaff_r7;
  int unaff_r9;
  int *piVar11;
  undefined4 in_lr;
  bool bVar12;
  undefined4 in_cr0;
  undefined4 in_cr2;
  undefined4 in_cr6;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  undefined1 in_q13 [16];
  undefined1 in_q14 [16];
  int in_stack_00000078;
  undefined1 auStack_c0 [192];
  
  bVar12 = SBORROW4((int)unaff_r7,0xea);
  iVar8 = (int)param_1 << 0x1d;
  uVar10 = 0x2c8574;
  if (iVar8 < 0) {
    if (((uint)param_1 & 8) != 0) {
      while( true ) {
        if (unaff_r4 != (uint *)0x0) goto LAB_002c8536;
        *unaff_r7 = param_1;
        unaff_r7[1] = param_2;
        unaff_r7[2] = in_r2;
        unaff_r7[3] = in_r3;
        unaff_r7[4] = 0;
        unaff_r7[5] = iVar8;
        unaff_r7 = unaff_r7 + 6;
        if (bVar12) break;
        in_r2 = *param_2;
        param_2 = param_2 + 1;
        param_1 = (basic_string *)&UNK_002c84f4;
      }
      *(basic_string **)(((int)param_2 >> 3) + 0x74) = param_1;
      puVar7 = &stack0x000003e8;
      param_1[0xe] = SUB41(unaff_r7,0);
      piVar11 = (int *)register0x00000054;
      while( true ) {
        puVar7[in_stack_00000078] = (char)((uint)unaff_r7 >> 6) + 'T';
        iVar3 = *piVar11;
        iVar5 = piVar11[2];
        piVar6 = (int *)piVar11[3];
        iVar8 = piVar11[4];
        uVar9 = piVar11[5];
        register0x00000054 = (BADSPACEBASE *)(piVar11 + 7);
        uVar10 = iVar5 + 0x14c;
        coprocessor_load(3,in_cr10,iVar5);
        piVar11[0x36] = 0x2c8530;
        unaff_r7 = (undefined4 *)(int)*(short *)(iVar8 + iVar3);
        iVar4 = piVar11[0x104];
        *(uint *)(iVar5 + 0x184) = uVar10;
        if (uVar9 <= uVar10) break;
LAB_002c8536:
        puVar7 = *(undefined1 **)((int)register0x00000054 + 0x3c);
        *(undefined1 **)((int)register0x00000054 + 0x304) = puVar7;
        in_stack_00000078 = iVar8 + 2;
        piVar11 = (int *)register0x00000054;
      }
      *(short *)((int)piVar6 + iVar4) = (short)piVar6;
      if ((int)piVar6 << 0xf < 0) {
        *(char *)(*(ushort *)(iVar5 + 0x180) + 0x1b) = (char)iVar3;
        *(char *)(uVar9 + 7) = (char)(piVar11 + 0x46);
        if (piVar11 + 0x46 != (int *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(int *)(iVar4 + 0x2c) = iVar3;
        uRam00000000 = 0;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *piVar6 = iVar3;
      piVar6[1] = iVar4;
      piVar6[2] = uVar10;
      piVar6[3] = (int)piVar6;
      piVar6[4] = uVar9;
      piVar6[5] = (int)(piVar11 + 0xd7);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (in_r3 == 0) goto LAB_002c85a0;
    uVar10 = 0x72221800;
    if (iVar8 < 0 == bVar12) {
      uVar9 = unaff_r4[0xb];
      *(uint *)(in_r3 + -0xba) = uVar9;
      software_bkpt(0xd7);
      to_string = (undefined2)in_r2;
      *(undefined2 *)((int)unaff_r7 + 0x2c88ef) = to_string;
      uVar2 = *(ushort *)((int)unaff_r7 + 6);
      in_r3 = *(int *)(uVar9 - 0x46);
      coprocessor_storelong(6,in_cr11,unaff_r9 + -0x3b4);
      coprocessor_function2(3,8,0,in_cr0,in_cr0,in_cr2);
      uVar10 = (uint)uVar2 << 0x1a;
      in_r2 = *(uint *)(*(int *)(uVar9 - 0x4a) + 0x74);
      param_2 = (uint *)(*(int *)(uVar9 - 0x42) + 0x722218c2);
      *unaff_r4 = in_r2;
      unaff_r4[1] = uVar10;
      unaff_r4[2] = (uint)uVar2;
      register0x00000054 = (BADSPACEBASE *)auStack_c0;
      unaff_r4 = (uint *)(uint)*(ushort *)(in_r2 + 0x3a);
      unaff_r7 = (undefined4 *)0xbe69699c;
    }
  }
  unaff_r7 = (undefined4 *)(uint)*(ushort *)(unaff_r7 + 6);
LAB_002c85a0:
  if (uVar10 != 0) {
    bVar1 = *(byte *)(uVar10 + 8);
    coprocessor_function2(0xf,3,4,in_cr9,in_cr9,in_cr6);
    iVar8 = *(int *)((int)register0x00000054 + 400);
    *(short *)(iVar8 + 0x24) = (short)in_r2;
    VectorAbsoluteDifference(in_q14,in_q13,2,1);
    _DAT_00000068 = uVar10 << 0x10;
    param_1 = (basic_string *)((int)param_1 * 2);
    *(char *)(bVar1 + 8) = (char)in_r2;
    *(undefined4 *)((int)register0x00000054 + -4) = in_lr;
    *(uint *)((int)register0x00000054 + -8) = uVar10;
    *(undefined4 *)((int)register0x00000054 + -0xc) = 100;
    *(uint *)((int)register0x00000054 + -0x10) = (uint)bVar1;
    *(int *)((int)register0x00000054 + -0x14) = iVar8;
    *(int *)((int)register0x00000054 + -0x18) = (int)param_1;
    param_2 = *(uint **)((int)register0x00000054 + -0x18);
    in_r3 = *(int *)((int)register0x00000054 + -0x14);
    unaff_r4 = *(uint **)((int)register0x00000054 + -0x10);
    *(uint *)((int)register0x00000054 + 0x2e8) = in_r2 - 0xd4;
    _DAT_00000064 = param_1;
    _DAT_0000006c = unaff_r7;
  }
  uVar10 = unaff_r4[1];
  uVar9 = unaff_r4[2];
  *(uint **)param_1 = param_2;
  *(int *)(param_1 + 4) = in_r3;
  *(uint *)(param_1 + 8) = uVar10;
  *(uint *)(param_1 + 0xc) = uVar9;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stod(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*)

void std::__ndk1::stod(basic_string *param_1,uint *param_2)

{
  int in_r3;
  int unaff_r6;
  
  *(char *)(*(ushort *)(in_r3 + 0x34) + 0x1b) = (char)param_1;
  *(char *)(unaff_r6 + 7) = (char)&stack0x000000fc;
  if (&stack0x000000fc != (undefined1 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  param_2[0xb] = (uint)param_1;
  uRam00000000 = 0xe0000000;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stold(std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>,
// std::__ndk1::allocator<char> > const&, unsigned int*)

void std::__ndk1::stold(basic_string *param_1,uint *param_2)

{
  int unaff_r4;
  int unaff_r6;
  int unaff_r7;
  
  *(int *)(unaff_r6 + 0x30) = unaff_r6;
  *(undefined2 *)(param_1 + unaff_r7) = 0x8910;
  *(short *)(param_1 + 0x10) = (short)param_2;
  *(uint **)(unaff_r4 + 0xc) = param_2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::stold(std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> > const&, unsigned int*)

void std::__ndk1::stold(basic_string *param_1,uint *param_2)

{
  int unaff_r7;
  undefined4 in_cr0;
  undefined4 in_cr8;
  undefined2 in_stack_00000000;
  int in_stack_00000010;
  
  coprocessor_movefromRt(4,7,5,in_cr0,in_cr8);
  *(undefined2 *)(*(int *)(unaff_r7 + in_stack_00000010) + 0x24) = in_stack_00000000;
  software_bkpt(0x6f);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_string(int)

void std::__ndk1::to_string(int param_1)

{
  byte in_r3;
  undefined4 unaff_r5;
  char in_ZR;
  
  if (in_ZR != '\0') {
    do {
      *(undefined4 *)(in_r3 + 0x78) = unaff_r5;
    } while( true );
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_string(long)

void std::__ndk1::to_string(long param_1)

{
  int iVar1;
  int in_r1;
  int in_r2;
  undefined4 unaff_r4;
  int unaff_r5;
  undefined4 unaff_r6;
  undefined4 unaff_r7;
  
  *(long *)(in_r2 + 0x22) = param_1;
  *(int *)(in_r2 + 0x26) = in_r1 + -0xee;
  *(long **)(in_r2 + 0x2a) = (long *)(in_r2 + 0x22);
  *(undefined4 *)(in_r2 + 0x2e) = unaff_r4;
  *(int *)(in_r2 + 0x32) = unaff_r5;
  *(undefined4 *)(in_r2 + 0x36) = unaff_r6;
  iVar1 = *(int *)(unaff_r5 + 8);
  software_bkpt(0xd4);
  *(char *)(in_r2 + 0x26) = (char)unaff_r6;
  *(undefined4 *)(iVar1 + 0x40) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c8a0c) overlaps instruction at (ram,0x002c8a0a)
// 
// WARNING: Removing unreachable block (ram,0x002c88d0)
// std::__ndk1::to_string(long long)

undefined8 std::__ndk1::to_string(longlong param_1)

{
  char cVar1;
  undefined4 *puVar2;
  int *in_r0;
  int *piVar3;
  int in_r1;
  undefined4 extraout_r1;
  int in_r2;
  int *in_r3;
  int iVar4;
  undefined4 *unaff_r4;
  int unaff_r5;
  int iVar5;
  int iVar6;
  uint uVar7;
  code *UNRECOVERED_JUMPTABLE;
  int unaff_r7;
  undefined8 *puVar8;
  undefined4 *unaff_r9;
  uint unaff_r11;
  undefined4 uVar9;
  undefined4 in_cr0;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 uVar10;
  undefined8 extraout_d1;
  undefined8 extraout_d2;
  undefined8 in_d6;
  undefined4 unaff_s31;
  undefined8 in_d20;
  uint in_stack_00000010;
  
  in_r0[6] = (int)UNRECOVERED_JUMPTABLE;
  *in_r3 = (int)in_r0;
  in_r3[1] = in_r2;
  in_r3[2] = (int)in_r3;
  in_r3[3] = unaff_r5;
  in_r3[4] = (int)UNRECOVERED_JUMPTABLE;
  *in_r0 = in_r1;
  in_r0[1] = (int)in_r3;
  in_r0[2] = unaff_r5;
  in_r0[3] = unaff_r7;
  piVar3 = in_r0 + 4;
  UNRECOVERED_JUMPTABLE[0x16] = SUB41(UNRECOVERED_JUMPTABLE,0);
  if (unaff_r5 == 0) {
    *(char *)(unaff_r4 + 1) = (char)in_r2;
    iVar6 = 0;
    if (in_r1 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
      *(short *)(unaff_r7 + -0xde) = (short)piVar3;
                    // WARNING: Could not recover jumptable at 0x002c893e. Too many branches
                    // WARNING: Treating indirect jump as call
      uVar10 = (*UNRECOVERED_JUMPTABLE)(*unaff_r4,unaff_r4[1]);
      return uVar10;
    }
    unaff_r4 = (undefined4 *)unaff_r4[2];
    VectorMultiply(in_d20,in_d6,1,1);
    register0x00000054 = (BADSPACEBASE *)&stack0x00000014;
    iVar5 = (int)param_1 * 2;
    iVar4 = param_1._4_4_ * 0x800000;
    *(int *)(param_1._4_4_ + 0x28) = iVar4;
    *(char *)(iVar4 + in_stack_00000010) = (char)((ulonglong)param_1 >> 0x20);
    *(short *)((in_stack_00000010 >> 0x17) + 0x14) = (short)iVar5;
    iVar6 = iVar5 + -0x2b0;
    coprocessor_loadlong(0xe,in_cr0,iVar5);
    *(char *)(iVar4 + 10) = (char)in_stack_00000010;
    piVar3 = (int *)(uint)*(ushort *)((in_stack_00000010 >> 0x17) + 0x1e);
  }
  puVar8 = (undefined8 *)(uint)*(ushort *)(iVar6 + 0x1e);
  if (puVar8 != (undefined8 *)0x0) {
    *(char *)((int)piVar3 + 9) = (char)piVar3;
    uVar10 = func_0xffa36274(piVar3,(int)register0x00000054 + 0x254);
    *puVar8 = uVar10;
    puVar8[1] = extraout_d1;
    puVar8[2] = extraout_d2;
    *(undefined4 *)(UNRECOVERED_JUMPTABLE + 0x39) = extraout_r1;
    coprocessor_store(7,in_cr11,(int)register0x00000054 + 0x274);
    software_bkpt(0xe3);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    iVar4 = 0x4e004e - (int)puVar8;
    puVar8 = (undefined8 *)((int)register0x00000054 + 0x388);
    *(short *)(unaff_r4 + 2) = (short)iVar6;
    *(undefined4 **)((int)register0x00000054 + 0x288) = unaff_r4;
    *(short *)((int)piVar3 + 0x5e) = (short)(0x5e - iVar6);
    uVar7 = unaff_r11 | ~(0x5e - iVar6 >> 2);
    *unaff_r9 = unaff_s31;
    unaff_r9 = (undefined4 *)((int)unaff_r9 + (int)piVar3);
    iVar6 = uVar7 - 0x27;
    if (-1 < iVar6) {
      uVar9 = 0x2c8a6b;
      iVar5 = func_0x00b79770();
      *(int *)((int)register0x00000054 + 100) = iVar4;
      coprocessor_loadlong(0xf,in_cr15,uVar7 + 0x271);
      *(int *)(UNRECOVERED_JUMPTABLE + 0x5a + iVar4) = iVar4;
      puVar2 = puRam00000008;
      piVar3 = piRam00000000;
      coprocessor_storelong(9,in_cr15,uVar9);
      cVar1 = *(char *)((int)puVar8 + iVar6);
      *piRam00000000 = iVar5;
      piVar3[1] = (int)puVar2;
      piVar3[2] = (int)cVar1;
      piVar3[3] = (int)puVar8;
      piVar3[0x14] = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (iVar6 != 0) break;
    UNRECOVERED_JUMPTABLE = (code *)((int)(UNRECOVERED_JUMPTABLE + 0x5a) * 0x40);
    uVar7 = (uint)unaff_r4 & 0x1fff;
    iVar6 = 0;
    unaff_r4 = (undefined4 *)((int)unaff_r4 << 0x12);
    if (piVar3 == (int *)0x0) {
      if (uVar7 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(undefined1 *)((int)register0x00000054 + 0x39f) = 0;
      *(code **)((int)register0x00000054 + 0x360) = UNRECOVERED_JUMPTABLE;
      puVar8 = (undefined8 *)(*(int *)((int)register0x00000054 + 0x38c) + -6);
      piVar3 = piRam00000000;
      unaff_r4 = puRam00000008;
    }
  }
  *(undefined4 *)((int)register0x00000054 + 0x368) = 0x8bac;
  return *(undefined8 *)register0x00000054;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c8a0c) overlaps instruction at (ram,0x002c8a0a)
// 
// std::__ndk1::to_string(unsigned int)

undefined8 std::__ndk1::to_string(uint param_1)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int in_r1;
  undefined4 extraout_r1;
  int iVar4;
  uint unaff_r4;
  int unaff_r5;
  uint uVar5;
  int iVar6;
  int unaff_r6;
  undefined8 *puVar7;
  undefined4 *unaff_r9;
  uint unaff_r11;
  undefined4 uVar8;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 uVar9;
  undefined8 extraout_d1;
  undefined8 extraout_d2;
  undefined4 unaff_s31;
  undefined8 in_stack_00000000;
  int in_stack_0000038c;
  
  if (in_r1 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar7 = (undefined8 *)(uint)*(ushort *)(unaff_r5 + 0x1e);
  if (puVar7 == (undefined8 *)0x0) {
    while( true ) {
      iVar4 = 0x4e004e - (int)puVar7;
      puVar7 = (undefined8 *)&stack0x00000388;
      *(short *)(unaff_r4 + 8) = (short)unaff_r5;
      *(short *)(param_1 + 0x5e) = (short)(0x5e - unaff_r5);
      uVar5 = unaff_r11 | ~(0x5e - unaff_r5 >> 2);
      *unaff_r9 = unaff_s31;
      unaff_r9 = (undefined4 *)((int)unaff_r9 + param_1);
      iVar6 = uVar5 - 0x27;
      if (-1 < iVar6) {
        uVar8 = 0x2c8a6b;
        uVar3 = func_0x00b79770();
        coprocessor_loadlong(0xf,in_cr15,uVar5 + 0x271);
        *(int *)(unaff_r6 + 0x5a + iVar4) = iVar4;
        uVar5 = uRam00000008;
        puVar2 = puRam00000000;
        coprocessor_storelong(9,in_cr15,uVar8);
        cVar1 = *(char *)((int)puVar7 + iVar6);
        *puRam00000000 = uVar3;
        puVar2[1] = uVar5;
        puVar2[2] = (int)cVar1;
        puVar2[3] = puVar7;
        puVar2[0x14] = iVar6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (iVar6 != 0) break;
      unaff_r6 = (unaff_r6 + 0x5a) * 0x40;
      uVar5 = unaff_r4 & 0x1fff;
      unaff_r5 = 0;
      unaff_r4 = unaff_r4 << 0x12;
      if ((undefined4 *)param_1 == (undefined4 *)0x0) {
        if (uVar5 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar7 = (undefined8 *)(in_stack_0000038c - 6);
        param_1 = (uint)puRam00000000;
        unaff_r4 = uRam00000008;
      }
    }
    return in_stack_00000000;
  }
  *(char *)(param_1 + 9) = (char)param_1;
  uVar9 = func_0xffa36274(param_1,&stack0x00000254);
  *puVar7 = uVar9;
  puVar7[1] = extraout_d1;
  puVar7[2] = extraout_d2;
  *(undefined4 *)(unaff_r6 + 0x39) = extraout_r1;
  coprocessor_store(7,in_cr11,&stack0x00000274);
  software_bkpt(0xe3);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c8a0c) overlaps instruction at (ram,0x002c8a0a)
// 
// std::__ndk1::to_string(unsigned long)

undefined8 std::__ndk1::to_string(ulong param_1)

{
  ushort uVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 extraout_r1;
  int iVar5;
  int unaff_r4;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int unaff_r6;
  undefined8 *puVar10;
  undefined4 *unaff_r9;
  uint unaff_r11;
  undefined4 uVar11;
  undefined4 in_cr0;
  undefined4 in_cr11;
  undefined4 in_cr15;
  undefined8 uVar12;
  undefined8 extraout_d1;
  undefined8 extraout_d2;
  undefined8 in_d6;
  undefined4 unaff_s31;
  undefined8 in_d20;
  int in_stack_00000000;
  int in_stack_00000004;
  uint in_stack_00000010;
  undefined8 in_stack_00000014;
  int in_stack_000003a0;
  
  uVar6 = *(uint *)(unaff_r4 + 8);
  VectorMultiply(in_d20,in_d6,1,1);
  iVar7 = in_stack_00000000 * 2;
  iVar5 = in_stack_00000004 * 0x800000;
  *(int *)(in_stack_00000004 + 0x28) = iVar5;
  *(char *)(iVar5 + in_stack_00000010) = (char)in_stack_00000004;
  *(short *)((in_stack_00000010 >> 0x17) + 0x14) = (short)iVar7;
  iVar8 = iVar7 + -0x2b0;
  coprocessor_loadlong(0xe,in_cr0,iVar7);
  *(char *)(iVar5 + 10) = (char)in_stack_00000010;
  uVar1 = *(ushort *)((in_stack_00000010 >> 0x17) + 0x1e);
  puVar3 = (undefined4 *)(uint)uVar1;
  puVar10 = (undefined8 *)(uint)*(ushort *)(iVar7 + -0x292);
  if (puVar10 != (undefined8 *)0x0) {
    *(char *)((int)puVar3 + 9) = (char)uVar1;
    uVar12 = func_0xffa36274(puVar3,&stack0x00000268,(int)(char)uVar6);
    *puVar10 = uVar12;
    puVar10[1] = extraout_d1;
    puVar10[2] = extraout_d2;
    *(undefined4 *)(unaff_r6 + 0x39) = extraout_r1;
    coprocessor_store(7,in_cr11,&stack0x00000288);
    software_bkpt(0xe3);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    iVar5 = 0x4e004e - (int)puVar10;
    puVar10 = (undefined8 *)&stack0x0000039c;
    *(short *)(uVar6 + 8) = (short)iVar8;
    *(short *)((int)puVar3 + 0x5e) = (short)(0x5e - iVar8);
    uVar9 = unaff_r11 | ~(0x5e - iVar8 >> 2);
    *unaff_r9 = unaff_s31;
    unaff_r9 = (undefined4 *)((int)unaff_r9 + (int)puVar3);
    iVar8 = uVar9 - 0x27;
    if (-1 < iVar8) {
      uVar11 = 0x2c8a6b;
      uVar4 = func_0x00b79770();
      coprocessor_loadlong(0xf,in_cr15,uVar9 + 0x271);
      *(int *)(unaff_r6 + 0x5a + iVar5) = iVar5;
      uVar6 = uRam00000008;
      puVar3 = puRam00000000;
      coprocessor_storelong(9,in_cr15,uVar11);
      cVar2 = *(char *)((int)puVar10 + iVar8);
      *puRam00000000 = uVar4;
      puVar3[1] = uVar6;
      puVar3[2] = (int)cVar2;
      puVar3[3] = puVar10;
      puVar3[0x14] = iVar8;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (iVar8 != 0) break;
    unaff_r6 = (unaff_r6 + 0x5a) * 0x40;
    uVar9 = uVar6 & 0x1fff;
    iVar8 = 0;
    uVar6 = uVar6 << 0x12;
    if (puVar3 == (undefined4 *)0x0) {
      if (uVar9 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar10 = (undefined8 *)(in_stack_000003a0 - 6);
      puVar3 = puRam00000000;
      uVar6 = uRam00000008;
    }
  }
  return in_stack_00000014;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_string(unsigned long long)

void __thiscall std::__ndk1::to_string(__ndk1 *this,ulonglong param_1)

{
  undefined4 in_r1;
  int unaff_r6;
  undefined4 in_cr11;
  
  *(undefined4 *)(unaff_r6 + 0x1c) = in_r1;
  coprocessor_store(7,in_cr11,&stack0x00000274);
  software_bkpt(0xe3);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x002c8a0c) overlaps instruction at (ram,0x002c8a0a)
// 
// std::__ndk1::to_wstring(int)

undefined8 std::__ndk1::to_wstring(int param_1)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  uint unaff_r4;
  uint *puVar6;
  uint uVar7;
  int unaff_r5;
  int unaff_r6;
  undefined1 *unaff_r7;
  undefined4 *unaff_r9;
  uint unaff_r11;
  undefined4 uVar8;
  undefined4 in_cr15;
  undefined4 unaff_s31;
  undefined8 in_stack_00000000;
  
  do {
    if ((param_1 == 0) && ((unaff_r4 & 0x7fffffff) != 0)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    unaff_r7[0x17] = (char)unaff_r5;
    puVar6 = (uint *)((uint)param_1 >> 9);
    param_1 = *puVar6;
    uVar7 = puVar6[2];
    iVar5 = 0x4e004e - (*(int *)(unaff_r7 + 4) + -6);
    unaff_r7 = &stack0x00000388;
    *(short *)(uVar7 + 8) = (short)unaff_r5;
    unaff_r4 = uVar7 << 0x12;
    unaff_r6 = unaff_r6 * 0x40 + 0x5a;
    *(short *)(param_1 + 0x5e) = (short)(0x5e - unaff_r5);
    uVar7 = unaff_r11 | ~(0x5e - unaff_r5 >> 2);
    *unaff_r9 = unaff_s31;
    unaff_r9 = (undefined4 *)((int)unaff_r9 + param_1);
    unaff_r5 = uVar7 - 0x27;
    if (-1 < unaff_r5) {
      uVar8 = 0x2c8a6b;
      uVar4 = func_0x00b79770();
      coprocessor_loadlong(0xf,in_cr15,uVar7 + 0x271);
      *(int *)(unaff_r6 + iVar5) = iVar5;
      uVar3 = uRam00000008;
      puVar2 = puRam00000000;
      coprocessor_storelong(9,in_cr15,uVar8);
      cVar1 = unaff_r7[unaff_r5];
      *puRam00000000 = uVar4;
      puVar2[1] = uVar3;
      puVar2[2] = (int)cVar1;
      puVar2[3] = unaff_r7;
      puVar2[0x14] = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  } while (unaff_r5 == 0);
  return in_stack_00000000;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::to_wstring(long)

void std::__ndk1::to_wstring(long param_1)

{
  code *pcVar1;
  byte bVar2;
  ushort uVar3;
  int iVar4;
  int *in_r1;
  int iVar5;
  uint uVar6;
  int in_r3;
  int *piVar7;
  undefined1 *puVar8;
  int *unaff_r4;
  int iVar9;
  uint uVar10;
  int iVar11;
  int unaff_r7;
  undefined4 *puVar12;
  int unaff_r9;
  int *piVar13;
  undefined4 in_lr;
  char in_CY;
  char in_OV;
  undefined4 in_cr0;
  undefined4 in_cr2;
  undefined4 in_cr6;
  undefined4 in_cr9;
  undefined4 in_cr10;
  undefined4 in_cr11;
  undefined1 in_q13 [16];
  undefined1 in_q14 [16];
  int in_stack_00000078;
  int in_stack_00000140;
  undefined1 auStack_c0 [192];
  
  if (in_CY == '\0') {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x54,0x2c8dba);
    (*pcVar1)();
  }
  puVar12 = (undefined4 *)(unaff_r7 * 0x400);
  iVar9 = (int)unaff_r4 >> 3;
  iVar11 = 0x2c8574;
  if (iVar9 < 0) {
    if (((int)unaff_r4 >> 2 & 1U) != 0) {
      while( true ) {
        if (unaff_r4 != (int *)0x0) goto LAB_002c8536;
        *puVar12 = param_1;
        puVar12[1] = in_r1;
        puVar12[2] = in_stack_00000140;
        puVar12[3] = in_r3;
        puVar12[4] = 0;
        puVar12[5] = iVar9;
        puVar12 = puVar12 + 6;
        if (in_OV != '\0') break;
        in_stack_00000140 = *in_r1;
        in_r1 = in_r1 + 1;
        param_1 = (long)&UNK_002c84f4;
      }
      *(long *)(((int)in_r1 >> 3) + 0x74) = param_1;
      puVar8 = &stack0x000003e8;
      *(char *)(param_1 + 0xe) = (char)puVar12;
      piVar13 = (int *)register0x00000054;
      while( true ) {
        puVar8[in_stack_00000078] = (char)((uint)puVar12 >> 6) + 'T';
        iVar11 = *piVar13;
        iVar5 = piVar13[2];
        piVar7 = (int *)piVar13[3];
        iVar9 = piVar13[4];
        uVar10 = piVar13[5];
        register0x00000054 = (BADSPACEBASE *)(piVar13 + 7);
        uVar6 = iVar5 + 0x14c;
        coprocessor_load(3,in_cr10,iVar5);
        piVar13[0x36] = 0x2c8530;
        puVar12 = (undefined4 *)(int)*(short *)(iVar9 + iVar11);
        iVar4 = piVar13[0x104];
        *(uint *)(iVar5 + 0x184) = uVar6;
        if (uVar10 <= uVar6) break;
LAB_002c8536:
        puVar8 = *(undefined1 **)((int)register0x00000054 + 0x3c);
        *(undefined1 **)((int)register0x00000054 + 0x304) = puVar8;
        in_stack_00000078 = iVar9 + 2;
        piVar13 = (int *)register0x00000054;
      }
      *(short *)((int)piVar7 + iVar4) = (short)piVar7;
      if ((int)piVar7 << 0xf < 0) {
        *(char *)(*(ushort *)(iVar5 + 0x180) + 0x1b) = (char)iVar11;
        *(char *)(uVar10 + 7) = (char)(piVar13 + 0x46);
        if (piVar13 + 0x46 != (int *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(int *)(iVar4 + 0x2c) = iVar11;
        uRam00000000 = 0;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *piVar7 = iVar11;
      piVar7[1] = iVar4;
      piVar7[2] = uVar6;
      piVar7[3] = (int)piVar7;
      piVar7[4] = uVar10;
      piVar7[5] = (int)(piVar13 + 0xd7);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (in_r3 == 0) goto LAB_002c85a0;
    iVar11 = 0x72221800;
    if (iVar9 < 0 == (bool)in_OV) {
      iVar9 = unaff_r4[0xb];
      *(int *)(in_r3 + -0xba) = iVar9;
      software_bkpt(0xd7);
      to_string = (undefined2)in_stack_00000140;
      *(undefined2 *)((int)puVar12 + 0x2c88ef) = to_string;
      uVar3 = *(ushort *)((int)puVar12 + 6);
      in_r3 = *(int *)(iVar9 + -0x46);
      coprocessor_storelong(6,in_cr11,unaff_r9 + -0x3b4);
      coprocessor_function2(3,8,0,in_cr0,in_cr0,in_cr2);
      iVar11 = (uint)uVar3 << 0x1a;
      in_stack_00000140 = *(int *)(*(int *)(iVar9 + -0x4a) + 0x74);
      in_r1 = (int *)(*(int *)(iVar9 + -0x42) + 0x722218c2);
      *unaff_r4 = in_stack_00000140;
      unaff_r4[1] = iVar11;
      unaff_r4[2] = (uint)uVar3;
      register0x00000054 = (BADSPACEBASE *)auStack_c0;
      unaff_r4 = (int *)(uint)*(ushort *)(in_stack_00000140 + 0x3a);
      puVar12 = (undefined4 *)0xbe69699c;
    }
  }
  puVar12 = (undefined4 *)(uint)*(ushort *)(puVar12 + 6);
LAB_002c85a0:
  if (iVar11 != 0) {
    bVar2 = *(byte *)(iVar11 + 8);
    coprocessor_function2(0xf,3,4,in_cr9,in_cr9,in_cr6);
    iVar9 = *(int *)((int)register0x00000054 + 400);
    *(short *)(iVar9 + 0x24) = (short)in_stack_00000140;
    VectorAbsoluteDifference(in_q14,in_q13,2,1);
    _DAT_00000068 = iVar11 << 0x10;
    param_1 = param_1 * 2;
    *(char *)(bVar2 + 8) = (char)in_stack_00000140;
    *(undefined4 *)((int)register0x00000054 + -4) = in_lr;
    *(int *)((int)register0x00000054 + -8) = iVar11;
    *(undefined4 *)((int)register0x00000054 + -0xc) = 100;
    *(uint *)((int)register0x00000054 + -0x10) = (uint)bVar2;
    *(int *)((int)register0x00000054 + -0x14) = iVar9;
    *(int *)((int)register0x00000054 + -0x18) = param_1;
    in_r1 = *(int **)((int)register0x00000054 + -0x18);
    in_r3 = *(int *)((int)register0x00000054 + -0x14);
    unaff_r4 = *(int **)((int)register0x00000054 + -0x10);
    *(int *)((int)register0x00000054 + 0x2e8) = in_stack_00000140 + -0xd4;
    _DAT_00000064 = (int *)param_1;
    _DAT_0000006c = puVar12;
  }
  iVar9 = unaff_r4[1];
  iVar11 = unaff_r4[2];
  *(int **)param_1 = in_r1;
  *(int *)(param_1 + 4) = in_r3;
  *(int *)(param_1 + 8) = iVar9;
  *(int *)(param_1 + 0xc) = iVar11;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(long long)

void std::__ndk1::to_wstring(longlong param_1)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 in_r0;
  int in_r3;
  int unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_lr;
  undefined4 in_cr15;
  
  coprocessor_loadlong(0xf,in_cr15,unaff_r5 + 0x298);
  *(int *)(unaff_r6 + in_r3) = in_r3;
  uVar3 = uRam00000008;
  puVar2 = puRam00000000;
  coprocessor_storelong(9,in_cr15,in_lr);
  cVar1 = *(char *)(unaff_r7 + unaff_r5);
  *puRam00000000 = in_r0;
  puVar2[1] = uVar3;
  puVar2[2] = (int)cVar1;
  puVar2[3] = unaff_r7;
  puVar2[0x14] = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(unsigned int)

void std::__ndk1::to_wstring(uint param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(unsigned long)

void std::__ndk1::to_wstring(ulong param_1)

{
  int in_r1;
  int in_r2;
  int unaff_r4;
  int in_stack_00000024;
  
  *(char *)(in_stack_00000024 + 0xd) = (char)unaff_r4;
  *(char *)(in_r2 + unaff_r4) = (char)in_stack_00000024;
  *(char *)(in_stack_00000024 + 8) = (char)in_r2;
  *(undefined1 *)(*(int *)(in_r1 + 0x10) + *(int *)(in_r1 + 4)) = 0x94;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0020d8e4)
// WARNING: Removing unreachable block (ram,0x002c8b4c)
// std::__ndk1::to_wstring(unsigned long long)

void std::__ndk1::to_wstring(ulonglong param_1)

{
  undefined4 *in_r3;
  int unaff_r4;
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 in_cr4;
  
  puVar1 = (undefined4 *)in_r3[2];
  uVar2 = in_r3[3];
  *puVar1 = *in_r3;
  puVar1[1] = puVar1;
  puVar1[2] = uVar2;
  coprocessor_load(0xf,in_cr4,unaff_r4 + -0x14c);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_string(float)

void std::__ndk1::to_string(float param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0027de80)
// WARNING: Removing unreachable block (ram,0x0027dda6)
// WARNING: Removing unreachable block (ram,0x0027ddb2)
// WARNING: Removing unreachable block (ram,0x0027de3e)
// WARNING: Removing unreachable block (ram,0x0027de98)
// WARNING: Removing unreachable block (ram,0x0027d804)
// WARNING: Removing unreachable block (ram,0x0027d816)
// WARNING: Removing unreachable block (ram,0x0027d79a)
// WARNING: Removing unreachable block (ram,0x0027dea0)
// WARNING: Removing unreachable block (ram,0x002447b6)
// WARNING: Removing unreachable block (ram,0x0027dec0)
// WARNING: Removing unreachable block (ram,0x0027e3ac)
// WARNING: Removing unreachable block (ram,0x0027e33a)
// WARNING: Removing unreachable block (ram,0x0027e348)
// WARNING: Removing unreachable block (ram,0x0027e35e)
// WARNING: Removing unreachable block (ram,0x0027e3a2)
// WARNING: Removing unreachable block (ram,0x0027e3a8)
// WARNING: Removing unreachable block (ram,0x0027e386)
// WARNING: Removing unreachable block (ram,0x0027e388)
// WARNING: Removing unreachable block (ram,0x0027e2c2)
// WARNING: Removing unreachable block (ram,0x0027e726)
// WARNING: Removing unreachable block (ram,0x0027e728)
// WARNING: Removing unreachable block (ram,0x0027e72a)
// WARNING: Removing unreachable block (ram,0x0027e72c)
// WARNING: Removing unreachable block (ram,0x0027e72e)
// WARNING: Removing unreachable block (ram,0x0027e736)
// WARNING: Removing unreachable block (ram,0x0027e392)
// WARNING: Removing unreachable block (ram,0x0027e3b0)
// WARNING: Removing unreachable block (ram,0x002c87fe)
// WARNING: Removing unreachable block (ram,0x002c8814)
// WARNING: Removing unreachable block (ram,0x002c8818)
// WARNING: Removing unreachable block (ram,0x002c879a)
// WARNING: Removing unreachable block (ram,0x002c87ba)
// WARNING: Removing unreachable block (ram,0x0027e24e)
// WARNING: Removing unreachable block (ram,0x002c8c60)
// WARNING: Removing unreachable block (ram,0x002c8c72)
// WARNING: Removing unreachable block (ram,0x002c8c74)
// WARNING: Removing unreachable block (ram,0x002c8c78)
// WARNING: Removing unreachable block (ram,0x002c8cf2)
// WARNING: Removing unreachable block (ram,0x002c8cf4)
// WARNING: Removing unreachable block (ram,0x002c8c7a)
// WARNING: Restarted to delay deadcode elimination for space: stack
// std::__ndk1::to_string(double)

void std::__ndk1::to_string(double param_1)

{
  code *pcVar1;
  short sVar2;
  byte bVar3;
  undefined1 auVar4 [16];
  uint uVar5;
  int in_r1;
  int in_r2;
  int in_r3;
  undefined4 *puVar6;
  uint unaff_r4;
  int *piVar7;
  uint *puVar8;
  int *unaff_r5;
  int iVar9;
  int iVar10;
  int unaff_r7;
  int *piVar11;
  undefined4 *puVar12;
  undefined4 in_lr;
  undefined4 in_pc;
  char in_OV;
  bool bVar13;
  uint *puVar14;
  undefined4 in_cr0;
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr14;
  undefined4 in_cr15;
  undefined4 extraout_s4;
  undefined4 extraout_s5;
  undefined8 extraout_d3;
  undefined1 in_q6 [16];
  undefined1 in_q14 [16];
  uint in_stack_00000008;
  int in_stack_0000000c;
  uint *in_stack_00000028;
  int in_stack_00000094;
  int in_stack_00000110;
  uint *in_stack_00000118;
  int in_stack_0000011c;
  uint uStack00000120;
  uint uStack00000124;
  uint uStack00000128;
  undefined4 uStack0000012c;
  uint *puStack00000134;
  uint *puVar15;
  
  sVar2 = *(short *)(in_r2 + in_r3);
  *unaff_r5 = in_r2;
  unaff_r5[1] = unaff_r4;
  unaff_r5[2] = (int)sVar2;
  unaff_r5[3] = unaff_r7;
  *(char *)(in_r3 + 0x13) = (char)unaff_r5 + '\x10';
  *(char *)((int)unaff_r5 + 0x1d) = (char)sVar2;
  puVar12 = &stack0x00000008;
  if (in_OV == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar13 = &param_1 == (double *)0xfffffd04;
  bVar3 = *(byte *)(in_r1 + 0x583);
  puVar14 = param_1._0_4_;
  if (&param_1 == (double *)0xfffffd04) {
    in_stack_00000028[0x11] = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    puVar8 = puVar14;
    uStack00000120 = *in_stack_00000028;
    uVar5 = in_stack_00000028[1];
    puVar14 = in_stack_00000028 + 2;
    puVar15 = in_stack_00000028 + 3;
    in_stack_00000028 = (uint *)in_stack_00000028[4];
    software_bkpt(0xed);
    if (!bVar13) {
      *(char *)(*puVar15 + 0x18) = (char)*puVar15;
                    // WARNING: Could not recover jumptable at 0x002c8bcc. Too many branches
                    // WARNING: Treating indirect jump as call
      (*(code *)((undefined4 *)(uint)bVar3)[7])(uStack00000120,uVar5,*(undefined4 *)(uint)bVar3);
      return;
    }
    bVar13 = puVar8 == (uint *)0xdb;
    uStack00000124 = *(uint *)(*puVar14 * 2);
    if (0xdb < (int)puVar8) break;
    piVar7 = (int *)&stack0x00000120;
    in_stack_00000094 = in_stack_00000110;
    puVar14 = in_stack_00000118;
    if (!bVar13) {
      if ((uint *)0xdb < puVar8) {
        iVar9 = (*(code *)&SUB_002c8da0)();
        *(int *)(iVar9 + 0x6c) = iVar9;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar3 = *(byte *)(uStack00000120 + 0x1a);
      in_stack_00000028 = (uint *)(uint)bVar3;
      puVar6 = (undefined4 *)&DAT_002c8d74;
      *(undefined **)(uStack00000124 + 0x58) = &DAT_002c8d74;
      SUB_002c8da0 = 0x8d74;
      in_stack_0000000c = in_stack_0000011c;
      if (bVar13) {
        *(byte *)(uStack00000124 * 0x1000 + 0x6ee) = bVar3;
        *(uint *)uStack00000124 = uStack00000124;
        *(undefined4 *)(uStack00000124 + 4) = 0xd7400000;
        *(uint **)(uStack00000124 + 8) = in_stack_00000118;
        *(undefined1 *)((int)in_stack_00000028 + 0x1a) = 0;
        uVar5 = (uint)*(byte *)(uStack00000124 + 0x19);
        do {
          if (!SBORROW4(uStack00000124,0xf)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        } while (0xf < (int)uStack00000124);
        uStack0000012c = 0xd7400000;
        uStack00000128 = uVar5;
        puStack00000134 = in_stack_00000028;
        func_0xff821c28();
        coprocessor_storelong(6,in_cr0,uVar5);
        auVar4._4_4_ = extraout_s5;
        auVar4._0_4_ = extraout_s4;
        auVar4._8_8_ = extraout_d3;
        SHA256ScheduleUpdate1(in_q6,in_q14,auVar4);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_002c8d1c:
      puVar12[-1] = in_lr;
      puVar12[-2] = in_stack_0000000c;
      puVar12[-3] = in_stack_00000028;
      puVar12[-4] = puVar6;
      puVar12[-5] = in_stack_00000094;
      coprocessor_store(4,in_cr6,puVar12 + -5);
      *(short *)(in_stack_0000000c + 0x3a) = (short)puVar6;
      iVar9 = piVar7[2];
      iVar10 = piVar7[3];
      if ((int)piVar7 < 0x58) {
        if (iVar9 == 0) {
          *(int *)(uStack00000124 + 0x2c) = *piVar7;
          uRam00000000 = 0;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      piVar11 = (int *)((uint)piVar7[1] >> 0xd);
      bVar13 = false;
      if (*piVar7 == 0) {
        *(char *)(piVar7[1] + iVar10) = (char)iVar9;
        *puVar6 = 0;
        puVar6[1] = iVar9;
        puVar6[2] = iVar10;
        puVar6[3] = piVar11;
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(0x54,0x2c8dba);
        (*pcVar1)();
      }
      while (bVar13 != SBORROW4((int)piVar7,0x57)) {
        bVar13 = iVar9 >> 5 < 0;
      }
      *(short *)(*piVar11 + piVar11[2]) = (short)piVar11[1];
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  coprocessor_function2(0xc,10,6,in_cr14,in_cr15,in_cr1);
  *puVar8 = uStack00000120;
  puVar8[1] = uStack00000124;
  puVar8[2] = (int)(short)((ushort)((uStack00000120 & 0xff) << 8) |
                          (ushort)(uStack00000120 >> 8) & 0xff);
  puVar12 = (undefined4 *)&stack0x00000010;
  *(char *)((int)in_stack_00000028 + in_stack_0000000c) = (char)in_stack_00000028;
  *(short *)(in_stack_00000094 + 0x38) = (short)in_stack_0000000c;
  piVar7 = &DAT_002c8fd0;
  puVar6 = (undefined4 *)&DAT_3c8ff04b;
  coprocessor_moveto(0xd,6,2,in_pc,in_cr4,in_cr15);
  uStack00000124 = in_stack_00000008;
  goto LAB_002c8d1c;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_string(long double)

void __thiscall std::__ndk1::to_string(__ndk1 *this,longdouble param_1)

{
  int in_r1;
  __ndk1 unaff_r5;
  undefined2 unaff_r6;
  undefined8 in_d0;
  undefined8 unaff_d13;
  
  *(undefined2 *)(in_r1 + 0x36) = unaff_r6;
  VectorCompareGreaterThan(unaff_d13,in_d0,2);
  this[0x1c] = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(float)

void std::__ndk1::to_wstring(float param_1)

{
  undefined4 in_r0;
  int in_r1;
  int in_r3;
  int unaff_r4;
  int iVar1;
  
  iVar1 = *(int *)(unaff_r4 + 0x30);
  *(char *)(*(ushort *)(in_r3 + 0x34) + 0x1b) = (char)in_r0;
  *(char *)(iVar1 + 7) = (char)&stack0x000000fc;
  if (&stack0x000000fc != (undefined1 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined4 *)(in_r1 + 0x2c) = in_r0;
  uRam00000000 = 0xe0000000;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(double)

void std::__ndk1::to_wstring(double param_1)

{
  int unaff_r6;
  
  *(int *)(unaff_r6 + 0x38) = unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::to_wstring(long double)

void __thiscall std::__ndk1::to_wstring(__ndk1 *this,longdouble param_1)

{
  int in_r1;
  int unaff_r5;
  
  if (unaff_r5 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined4 *)(in_r1 * 0x10000 + 0x40) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// char const* std::__ndk1::__find_end<bool (*)(char, char) noexcept, char const*, char const*>(char
// const*, char const*, char const*, char const*, bool (*)(char, char) noexcept,
// std::__ndk1::random_access_iterator_tag, std::__ndk1::random_access_iterator_tag)

char * std::__ndk1::__find_end<>(int param_1,undefined4 param_2,uint param_3,int param_4)

{
  code *pcVar1;
  byte bVar2;
  uint unaff_r4;
  uint *unaff_r5;
  uint unaff_r7;
  int in_stack_00000010;
  undefined4 uStack000000dc;
  undefined4 in_stack_00000110;
  undefined4 in_stack_00000144;
  
  *unaff_r5 = param_3;
  unaff_r5[1] = unaff_r4;
  unaff_r5[2] = (uint)unaff_r5;
  unaff_r5[3] = unaff_r7;
  if (param_4 < 0x93) {
    bVar2 = *(byte *)(unaff_r4 + 2);
    *(short *)(unaff_r4 + 0x32) = (short)param_1;
    unaff_r5[0x10] = unaff_r4;
    *(uint *)(param_1 + 0x38) = (uint)bVar2;
    if (param_3 >> 0xf != 0 && !SBORROW4(param_4,0x93)) {
      *(char *)(*(byte *)((param_3 >> 0xf) + 1) + 0xc) = (char)&stack0x000000e8;
      return &DAT_002c92a4;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (param_4 < 0x94) {
    *(short *)(&stack0x000000e8 + unaff_r4) = (short)unaff_r5;
  }
  else {
    *(short *)(unaff_r4 + 0xe) = (short)param_2;
    if (SBORROW4(param_4,0x93)) {
      if (0x92 < param_4) {
                    // WARNING: Does not return
        pcVar1 = (code *)software_udf(4,0x2c925a);
        uStack000000dc = param_2;
        (*pcVar1)();
      }
      software_interrupt(0x9c);
      if (in_stack_00000010 != 0) {
        *(char *)(_DAT_abb765d4 + _DAT_abb765c8) = (char)&stack0x000001a8;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<char>::eq(char, char)

void std::__ndk1::char_traits<char>::eq(char param_1,char param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<char>::find(char const*, unsigned int, char const&)

void std::__ndk1::char_traits<char>::find(char *param_1,uint param_2,char *param_3)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// char const* std::__ndk1::__search_substring<char, std::__ndk1::char_traits<char> >(char const*,
// char const*, char const*, char const*)

char * std::__ndk1::__search_substring<>(char *param_1,char *param_2,char *param_3,char *param_4)

{
  undefined4 unaff_r4;
  undefined4 unaff_r5;
  int unaff_r7;
  
  if (param_1 == (char *)0x0) {
    *(undefined4 *)(unaff_r7 + 0x1c) = unaff_r4;
    *(char **)param_3 = param_3;
    *(char **)(param_3 + 4) = param_4;
    *(undefined4 *)(param_3 + 8) = unaff_r4;
    *(undefined4 *)(param_3 + 0xc) = unaff_r5;
    *(int *)(param_3 + 0x10) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// wchar_t const* std::__ndk1::__find_end<bool (*)(wchar_t, wchar_t) noexcept, wchar_t const*,
// wchar_t const*>(wchar_t const*, wchar_t const*, wchar_t const*, wchar_t const*, bool (*)(wchar_t,
// wchar_t) noexcept, std::__ndk1::random_access_iterator_tag,
// std::__ndk1::random_access_iterator_tag)

wchar_t * std::__ndk1::__find_end<>(wchar_t *param_1)

{
  return param_1;
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<wchar_t>::eq(wchar_t, wchar_t)

void std::__ndk1::char_traits<wchar_t>::eq(wchar_t param_1,wchar_t param_2)

{
  int unaff_r6;
  
  *(undefined1 *)(unaff_r6 + param_2) = 0x94;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::char_traits<wchar_t>::find(wchar_t const*, unsigned int, wchar_t const&)

void __thiscall
std::__ndk1::char_traits<wchar_t>::find
          (char_traits<wchar_t> *this,wchar_t *param_1,uint param_2,wchar_t *param_3)

{
  int unaff_r6;
  
  *(char *)((int)param_3 + 6) = (char)this;
  *(char *)(unaff_r6 + (int)param_1) = (char)param_3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Control flow encountered unimplemented instructions
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// wchar_t const* std::__ndk1::__search_substring<wchar_t, std::__ndk1::char_traits<wchar_t>
// >(wchar_t const*, wchar_t const*, wchar_t const*, wchar_t const*)

wchar_t * std::__ndk1::__search_substring<>
                    (wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,wchar_t *param_4)

{
  code *pcVar1;
  undefined4 uVar2;
  int iVar3;
  int unaff_r4;
  wchar_t unaff_r5;
  uint uVar4;
  undefined4 *unaff_r6;
  int unaff_r7;
  char in_OV;
  bool bVar5;
  bool bVar6;
  int in_stack_00000010;
  int iStack000000dc;
  undefined4 uStack00000144;
  byte in_stack_0000018c;
  
  if (param_2 == (wchar_t *)0x0) {
    uVar4 = (uint)in_stack_0000018c;
    uVar2 = *(undefined4 *)(uVar4 - 0x78);
    *unaff_r6 = *(undefined4 *)(uVar4 - 0x7c);
    unaff_r6[1] = &DAT_002c9478;
    unaff_r6[2] = uVar2;
    unaff_r6[3] = &stack0x00000170;
    unaff_r6[4] = uVar4;
    unaff_r6[5] = unaff_r6;
    unaff_r6[6] = unaff_r7;
    uStack00000144 = 0x773dcc26;
    func_0x00b313bc();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_1 = (wchar_t)param_1;
  param_1[1] = (wchar_t)param_2;
  param_1[2] = (wchar_t)param_3;
  param_1[3] = unaff_r5;
  if (param_4 != (wchar_t *)0x0) {
    param_4[0x1e] = (wchar_t)param_4;
    unaff_r6[0x19] = param_3;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(wchar_t **)(unaff_r5 + unaff_r7) = param_3;
  if (((uint)param_1 ^ 0x2f40000) == 0 || (int)((uint)param_1 ^ 0x2f40000) < 0 != (bool)in_OV) {
    bVar6 = SCARRY4(unaff_r4,2);
    bVar5 = unaff_r4 + 2 < 0;
    if (bVar5 == bVar6) {
      halt_baddata();
    }
    if (bVar6) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iStack000000dc = -0x3e9f44aa;
  }
  else {
    bVar6 = SCARRY4((int)param_2,0xd6);
    iStack000000dc = (int)param_2 + 0xd6;
    if (-1 < iStack000000dc) {
                    // WARNING: Unimplemented instruction - Truncating control flow here
      halt_unimplemented();
    }
    iVar3 = unaff_r5 >> 0x12;
    bVar5 = iVar3 < 0;
    if (iVar3 == 0 || bVar5 != bVar6) goto LAB_002c921e;
    *(char *)(iVar3 + 0x1a) = (char)unaff_r7;
    if (iVar3 == 0 || bVar5 != bVar6) {
      *(short *)(iVar3 + (int)unaff_r6) = (short)unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(short *)(iVar3 + 0xe) = (short)iStack000000dc;
    if (!bVar6) {
      halt_baddata();
    }
  }
  register0x00000054 = (BADSPACEBASE *)&stack0x00000014;
  if (bVar5 == bVar6) {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(4,0x2c925a);
    (*pcVar1)();
  }
  software_interrupt(0x9c);
  iStack000000dc = _DAT_abb765c8;
  iVar3 = _DAT_abb765d0;
  unaff_r6 = _DAT_abb765d4;
  if (in_stack_00000010 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_002c921e:
  *(undefined4 *)((int)register0x00000054 + -4) = 0x16;
  *(int *)((int)register0x00000054 + -8) = iVar3;
  *(undefined1 *)((int)register0x00000054 + 0x19a) = 0x8c;
  *(char *)((int)unaff_r6 + iStack000000dc) = (char)(undefined1 *)((int)register0x00000054 + 0x194);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string_view<char, std::__ndk1::char_traits<char>
// >::compare(std::__ndk1::basic_string_view<char, std::__ndk1::char_traits<char> >) const

void std::__ndk1::basic_string_view<>::compare(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint *puVar1;
  uint unaff_r5;
  undefined4 in_cr13;
  
  puVar1 = (uint *)(param_3 * 0x40000000);
  *puVar1 = (uint)puVar1 >> 0xb;
  puVar1[1] = (uint)puVar1;
  puVar1[2] = unaff_r5;
  puVar1[3] = unaff_r5 << 0x14;
  coprocessor_load(0xd,in_cr13,puVar1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::basic_string_view<wchar_t, std::__ndk1::char_traits<wchar_t>
// >::compare(std::__ndk1::basic_string_view<wchar_t, std::__ndk1::char_traits<wchar_t> >) const

void std::__ndk1::basic_string_view<>::compare
               (undefined2 param_1,undefined4 param_2,undefined1 param_3,int param_4)

{
  uint unaff_r5;
  int unaff_r6;
  int unaff_r7;
  char in_NG;
  char in_OV;
  
  if (in_NG != in_OV) {
    param_4 = *(int *)(~unaff_r5 + 4);
    param_3 = 0xc;
  }
  software_bkpt(0x58);
  *(int *)(unaff_r6 + 8) = param_4;
  *(undefined1 *)(unaff_r6 + 4) = param_3;
  *(char *)(((int)unaff_r5 >> 9) + 1) = (char)((uint)(unaff_r6 - param_4) >> 0x10);
  *(uint *)(unaff_r6 + 0x40) = unaff_r5;
  *(undefined2 *)((unaff_r5 - unaff_r7) * 2) = param_1;
  if (-1 < (int)((unaff_r5 - unaff_r7) * 0x2000)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Could not recover jumptable at 0x002c952c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)((uint)(unaff_r6 - param_4) >> 0x10))();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c94a4)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::_MetaBase<__is_cpp17_forward_iterator<char*>::value>::_EnableIfImpl<void>
// std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>
// >::__init<char*>(char*, char*)

void std::__ndk1::basic_string<>::__init<char*>(char *param_1,char *param_2)

{
  bool bVar1;
  undefined *puVar2;
  byte bVar3;
  undefined2 uVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  int iVar8;
  uint *puVar9;
  uint uVar10;
  int in_r2;
  undefined *puVar11;
  int in_r3;
  uint unaff_r4;
  uint uVar12;
  int unaff_r5;
  uint uVar13;
  undefined4 uVar14;
  int unaff_r6;
  int unaff_r7;
  int iVar15;
  code *in_lr;
  int iVar16;
  undefined4 in_cr3;
  undefined8 unaff_d9;
  undefined8 in_d27;
  undefined1 in_q15 [16];
  undefined8 uVar17;
  char *in_stack_00000000;
  int in_stack_00000008;
  int in_stack_0000002c;
  
  if (unaff_r6 != 0) {
    puVar11 = (undefined *)(in_r2 + 3);
    if ((int)puVar11 < 0 != SCARRY4(in_r2,3)) {
      _UNK_002c9830 = (char *)0x2388ba30;
      _UNK_002c9834 = 0xa0a5f1db;
      _UNK_002c983c = (undefined *)0x7864ab92;
      _UNK_002c9840 = 0xdf8adb17;
      _UNK_002c9844 = 0x8a9211d2;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar15 = unaff_r7 + -0x2a;
    if (SBORROW4(unaff_r7,0x2a)) {
      _UNK_002c9844 = (uint)(byte)param_1[in_r3];
      register0x00000054 = (BADSPACEBASE *)&stack0x00000014;
      unaff_r6 = *(int *)(in_stack_00000008 + 0x60);
                    // WARNING: Read-only address (ram,0x002c9830) is written
                    // WARNING: Read-only address (ram,0x002c9834) is written
                    // WARNING: Read-only address (ram,0x002c983c) is written
                    // WARNING: Read-only address (ram,0x002c9840) is written
                    // WARNING: Read-only address (ram,0x002c9844) is written
      _UNK_002c9830 = in_stack_00000000;
      _UNK_002c9834 = 0xc9830000;
      ___init<char*> = 0xfc;
      _UNK_002c983c = &UNK_002c9830;
      iVar15 = in_stack_00000008 >> 2;
      _UNK_002c9840 = unaff_r6;
      in_stack_00000000[0x5c] = 'd';
      unaff_r5 = _DAT_0000006c;
      in_stack_00000000[0x5d] = '\0';
      in_stack_00000000[0x5e] = '\0';
      in_stack_00000000[0x5f] = '\0';
      iVar16 = 0x70;
      *(char *)(iVar15 + 0x1c) = (char)_DAT_0000006c;
      puVar11 = &UNK_002c9600;
      *(char *)(iVar15 + 10) = (char)unaff_r6;
      if (SBORROW4(unaff_r7,0x2a)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    else {
      iVar16 = unaff_r4 + 0x98;
      in_stack_00000000 = param_1;
      in_stack_0000002c = in_r3;
      if (unaff_r4 < 0xffffff68 || iVar16 == 0) {
        _UNK_002c9830 = (char *)0x2388ba30;
        _UNK_002c9834 = 0xa0a5f1db;
        _UNK_002c983c = (undefined *)0x7864ab92;
        _UNK_002c9840 = 0xdf8adb17;
        _UNK_002c9844 = 0x8a9211d2;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    iVar8 = unaff_r5 << 5;
    *(short *)(iVar15 + unaff_r5) = (short)iVar8;
    uVar10 = (uint)*(ushort *)(puVar11 + unaff_r6);
    *(int *)((int)register0x00000054 + 0x2d8) = iVar8;
    if (iVar8 >> 0x19 == 0) {
      if (iVar8 >> 0x19 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      piVar7 = *(int **)((int)register0x00000054 + 0x3a4);
      uVar10 = (uint)*(ushort *)(unaff_r6 + (int)piVar7);
      *(int *)(unaff_r5 + 0x7c) = unaff_r6;
      *piVar7 = unaff_r5;
      iVar15 = *(int *)(iVar15 + -0x1b);
      coprocessor_load(6,in_cr3,in_lr);
      uVar14 = *(undefined4 *)(&DAT_002b24b0 + iVar15);
      bVar3 = *(byte *)(iVar15 + 3);
      *(uint *)((int)register0x00000054 + 0x1c) = uVar10;
      *(short *)(iVar16 + 0x2a) = (short)(iVar16 << 0xb);
      *(uint *)(uVar10 + 3) = uVar10;
      *(undefined4 *)(uVar10 + 7) = 0x2b22440;
      *(uint *)(uVar10 + 0xb) = (uint)bVar3;
      *(undefined4 *)(uVar10 + 0xf) = uVar14;
      *(int *)(uVar10 + 0x13) = iVar15;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(int *)((int)register0x00000054 + -4) = iVar15;
    *(int *)((int)register0x00000054 + -8) = unaff_r5;
    *(int *)((int)register0x00000054 + -0xc) = in_stack_0000002c;
    *(uint *)((int)register0x00000054 + -0x10) = uVar10;
    *(uint *)((int)register0x00000054 + -0x14) = (uint)in_stack_00000000;
    uVar14 = *(undefined4 *)(iVar15 + 0x6c);
    *(short *)(iVar15 + 0xc) = (short)unaff_r5;
    *(short *)(unaff_r5 + 0x26) = (short)iVar15;
    if (iVar16 != 0) {
      *(short *)(unaff_r6 + 0xc) = (short)uVar14;
      uVar4 = *(undefined2 *)(unaff_r6 + in_stack_0000002c);
      *(short *)(iVar16 + 0xe) = (short)(iVar8 >> 0x19);
      *(char *)(*(int *)(unaff_r6 + 0x44) + 0xf) = (char)uVar14;
      *(undefined4 *)((int)register0x00000054 + 0x3cc) = 0xf4;
      *(undefined2 *)(unaff_r6 + 0x3e) = uVar4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar17 = (*in_lr)();
    *(short *)((int)((ulonglong)uVar17 >> 0x20) + (int)uVar17) = (short)uVar10;
    uVar12 = _DAT_0ab36001;
    puVar11 = &DAT_002e144d + _DAT_0ab35ffd;
    bVar1 = SCARRY4(_DAT_0ab35ffd,0x2e144d);
    puVar2 = &DAT_002e144d + _DAT_0ab35ffd;
    uVar10 = _DAT_0ab36001 >> 0x1d;
    puVar9 = (uint *)(_DAT_0ab36001 >> 0x1e);
    *(char *)(_DAT_0ab36005 + 0x19) = (char)_DAT_0ab36005;
    uVar6 = _DAT_23383f4e;
    uVar5 = _DAT_23383f4a;
    if ((uVar10 & 1) != 0 && puVar9 != (uint *)0x0) {
      VectorShiftLeft(in_d27,0x29,0x40,0);
      *(uint *)(uVar12 + 0x78) = uVar12;
      DAT_002e14b1 = puVar2;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (bVar1 != SCARRY4((int)puVar11,0)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar10 = *(uint *)((int)register0x00000054 + -0x14);
    uVar12 = **(uint **)((int)register0x00000054 + 0x38c);
    uVar13 = (*(uint **)((int)register0x00000054 + 0x38c))[1];
    *puVar9 = (int)puVar9 * 0x200;
    puVar9[1] = uVar10;
    puVar9[2] = uVar12;
    puVar9[3] = uVar13;
    *puVar9 = (uint)puVar9;
    puVar9[1] = uVar13;
    puVar9[2] = uVar5;
    puVar9[3] = uVar6;
    uVar14 = VectorGetElement(unaff_d9,0,4,0);
    FloatVectorMultiplySubtract(in_q15,uVar14,2,0x20);
    if ((uint)((int)puVar9 * 0x200) <= uVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (((int)*(char *)(uVar10 + (int)puVar9) & uVar10 + (int)puVar9 * -0x200) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::_MetaBase<__is_cpp17_forward_iterator<char*>::value>::_EnableIfImpl<void>
// std::__ndk1::basic_string<wchar_t, std::__ndk1::char_traits<wchar_t>,
// std::__ndk1::allocator<wchar_t> >::__init<char*>(char*, char*)

void std::__ndk1::basic_string<>::__init<char*>(char *param_1,char *param_2)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c9aa0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::__ndk1::__itoa::__u32toa(unsigned int, char*)

void std::__ndk1::__itoa::__u32toa(uint param_1,char *param_2)

{
  byte bVar1;
  ushort uVar2;
  int *piVar3;
  int iVar4;
  char *pcVar5;
  int unaff_r4;
  undefined4 *unaff_r5;
  uint uVar6;
  int unaff_r7;
  uint *unaff_r8;
  code *UNRECOVERED_JUMPTABLE;
  char cVar7;
  char in_OV;
  bool bVar8;
  bool bVar9;
  undefined4 in_cr0;
  undefined4 in_cr4;
  undefined4 in_cr8;
  undefined4 in_cr12;
  undefined8 uVar10;
  undefined4 in_stack_000000c8;
  undefined4 *in_stack_000000cc;
  undefined4 in_stack_000000d0;
  uint uStack000000ec;
  int iStack000001a4;
  undefined4 in_stack_00000250;
  
  bVar9 = ((int)unaff_r5 >> 0x17 & 1U) != 0;
  uStack000000ec = (int)unaff_r5 >> 0x18;
  bVar8 = uStack000000ec == 0;
  piVar3 = (int *)*unaff_r5;
  pcVar5 = (char *)unaff_r5[1];
  uVar6 = unaff_r5[2];
  iVar4 = (int)unaff_r5 >> 0x1f;
  if (!bVar9 || bVar8) {
    *(uint *)(param_2 + uVar6) = uVar6;
                    // WARNING: Could not recover jumptable at 0x002c98d0. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(iVar4,param_2 + 0x99,*(undefined4 *)(unaff_r4 + 0x20));
    return;
  }
  if (unaff_r7 == 0) {
    *(short *)(param_2 + 0x2a) = (short)(char)((uint)unaff_r5 >> 0x18);
    if (bVar9) {
      if (!bVar9 || bVar8) {
        *(char **)(param_2 + 0x78) = param_2;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(short *)piVar3 = (short)unaff_r4;
      if ((int)param_2 < 6) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      iStack000001a4 = -(uint)(param_2 < (char *)0x86);
      coprocessor_function(0xe,8,1,in_cr0,in_cr12,in_cr0);
      *(int **)((int)unaff_r8 + (int)pcVar5) = piVar3;
      bVar8 = (char *)0xfffffff6 < pcVar5;
      pcVar5 = pcVar5 + 9;
      bVar9 = false;
      cVar7 = '\0';
      uVar10 = func_0x00f3da1a();
      iVar4 = (int)((ulonglong)uVar10 >> 0x20);
      if (!bVar8 || bVar9) {
        *(undefined2 *)(iVar4 + 0x3a) = 0xd6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(unaff_r8 + 7) = (char)unaff_r8;
      if (cVar7 == '\0') {
        *(undefined8 *)(pcVar5 + -0x11) = uVar10;
        *(char **)(pcVar5 + -9) = pcVar5 + -0x11;
        *(undefined4 *)(pcVar5 + -5) = in_stack_00000250;
        pcVar5[-0xffffffff00000001] = '\0';
        pcVar5[0] = '\0';
        pcVar5[1] = '\0';
        pcVar5[2] = '\0';
        *(int *)(pcVar5 + 3) = iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      pcVar5[5] = '\0';
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (iVar4 < 0 == (bool)in_OV) {
      coprocessor_loadlong(1,in_cr4,uStack000000ec);
      *(undefined1 *)((uint)*(ushort *)((byte)pcVar5[0x19] + 0x38) + (uStack000000ec - 0x2ef)) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(undefined4 *)(iVar4 + 100) = 0;
    unaff_r8 = (uint *)&stack0x000002e0;
    uVar6 = *(uint *)(iVar4 + 0x70);
    unaff_r4 = iVar4 << 0xd;
    uStack000000ec = (uint)(short)unaff_r4;
    pcVar5 = (char *)((int)piVar3 + (int)param_2);
  }
  else if (((int)uStack000000ec >= 0) || (param_2 = param_2 + 0x34, bVar8)) {
    if (!bVar8 && (int)uStack000000ec < 0 == (bool)in_OV) {
      bVar1 = param_2[4];
      *(short *)((int)unaff_r8 + 0x32) = (short)unaff_r4;
      *(short *)((uint)bVar1 + *piVar3 + -0xca) = (short)pcVar5;
      software_interrupt(0x98);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    software_bkpt(0xad);
    bVar1 = pcVar5[3];
    in_stack_000000cc[0x19] = in_stack_000000c8;
    *in_stack_000000cc = in_stack_000000c8;
    in_stack_000000cc[1] = &DAT_002c9d58;
    in_stack_000000cc[2] = pcVar5;
    in_stack_000000cc[3] = &stack0x00000290;
    in_stack_000000cc[4] = uVar6;
    in_stack_000000cc[5] = in_stack_000000d0;
    in_stack_000000cc[6] = (uint)bVar1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(uStack000000ec + uVar6);
  uVar2 = *(ushort *)(unaff_r4 + 0x1c);
  coprocessor_load(9,in_cr8,param_2 + 0x3d4);
  *(short *)(uVar6 + (int)unaff_r8) = (short)pcVar5;
  *(short *)(uVar2 + 0x2e) = (short)uVar6;
  *unaff_r8 = (uint)bVar1;
  unaff_r8[1] = uStack000000ec;
  unaff_r8[2] = uVar6;
  unaff_r8[3] = (uint)uVar2;
  _DAT_2191f375 = (short)uVar6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::__ndk1::__itoa::__u64toa(unsigned long long, char*)

void __thiscall std::__ndk1::__itoa::__u64toa(__itoa *this,ulonglong param_1,char *param_2)

{
  int iVar1;
  int iVar2;
  uint in_r2;
  undefined2 unaff_r4;
  int unaff_r6;
  int unaff_r7;
  char cVar3;
  bool in_ZR;
  bool in_CY;
  bool bVar4;
  bool bVar5;
  undefined4 in_cr0;
  undefined4 in_cr12;
  undefined8 uVar6;
  int iStack000001a4;
  undefined4 in_stack_00000250;
  
  if (!in_CY || in_ZR) {
    *(char **)(param_2 + 0x78) = param_2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined2 *)(this + unaff_r7) = unaff_r4;
  if ((int)param_2 < 6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iStack000001a4 = -(uint)(param_2 < (char *)0x86);
  coprocessor_function(0xe,8,1,in_cr0,in_cr12,in_cr0);
  *(__itoa **)(unaff_r6 + in_r2) = this;
  bVar5 = 0xfffffff6 < in_r2;
  iVar2 = in_r2 + 9;
  bVar4 = false;
  cVar3 = '\0';
  uVar6 = func_0x00f3da1a();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  if (!bVar5 || bVar4) {
    *(undefined2 *)(iVar1 + 0x3a) = 0xd6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(unaff_r6 + 0x1c) = (char)unaff_r6;
  if (cVar3 == '\0') {
    *(undefined8 *)(iVar2 + -0x11) = uVar6;
    *(undefined8 **)(iVar2 + -9) = (undefined8 *)(iVar2 + -0x11);
    *(undefined4 *)(iVar2 + -5) = in_stack_00000250;
    *(int *)(iVar2 + -1) = unaff_r7;
    *(int *)(iVar2 + 3) = iVar1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(iVar2 + 5) = (char)unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_end_cleanup(undefined4 param_1,undefined4 param_2,int param_3)

{
  int unaff_r6;
  undefined4 in_cr8;
  undefined4 in_cr10;
  undefined4 in_cr12;
  
  coprocessor_function2(0,7,5,in_cr12,in_cr8,in_cr10);
  *(char *)(param_3 + unaff_r6) = (char)unaff_r6;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_allocate_exception(undefined4 param_1,undefined4 param_2,undefined4 *param_3,int param_4)

{
  ushort uVar1;
  int iVar2;
  undefined4 *unaff_r5;
  int iVar3;
  undefined4 unaff_r8;
  char in_OV;
  bool bVar4;
  undefined4 in_cr3;
  undefined4 in_cr5;
  undefined4 in_cr7;
  
  uVar1 = *(ushort *)(unaff_r5 + 4);
  iVar3 = param_4 << 0xf;
  param_4 = param_4 << 4;
  if (param_4 != 0 && param_4 < 0 == (bool)in_OV) {
    *param_3 = param_1;
    param_3[1] = 0x6d3bf238;
    param_3[2] = (uint)uVar1;
    param_3[3] = iVar3;
    coprocessor_moveto(1,3,0,unaff_r8,in_cr3,in_cr5);
    do {
      *(undefined4 *)((int)register0x00000054 + 0xf0) = 0xda7;
      bVar4 = SCARRY4(param_4,0x77);
      param_4 = param_4 + 0x77;
      coprocessor_load(0xd,in_cr7,iVar3 + -0x1e0);
      register0x00000054 = (BADSPACEBASE *)0xe5;
      iVar2 = *(int *)(iVar3 + 4);
      iVar3 = iVar3 + 8;
      *(short *)(iVar2 + 0x38) = (short)unaff_r5;
    } while (!bVar4);
    *unaff_r5 = 0xda7;
    unaff_r5[1] = iVar2;
    unaff_r5[2] = (uint)uVar1;
    unaff_r5[3] = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  software_bkpt(0x2a);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_allocate_dependent_exception
               (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 unaff_r4;
  undefined4 *unaff_r5;
  
  *unaff_r5 = param_3;
  unaff_r5[1] = param_4;
  unaff_r5[2] = unaff_r4;
  unaff_r5[3] = unaff_r5;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_free_dependent_exception(void)

{
  int *unaff_r7;
  
  if (*unaff_r7 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_throw(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c9aa0)
// WARNING: Removing unreachable block (ram,0x002c99c6)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_begin_cleanup(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  byte bVar1;
  ushort uVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int unaff_r4;
  uint uVar8;
  undefined4 *unaff_r5;
  undefined4 *puVar9;
  int unaff_r7;
  uint *unaff_r8;
  int unaff_r9;
  char cVar10;
  char in_OV;
  bool bVar11;
  bool bVar12;
  undefined4 in_cr0;
  undefined4 in_cr4;
  undefined4 in_cr8;
  undefined4 in_cr12;
  undefined4 in_cr15;
  undefined8 uVar13;
  undefined4 in_stack_000000c8;
  undefined4 *in_stack_000000cc;
  undefined4 in_stack_000000d0;
  undefined4 in_stack_00000250;
  
  coprocessor_storelong(7,in_cr15,unaff_r9);
  puVar9 = (undefined4 *)(unaff_r4 >> 4);
  iVar4 = 0x97;
  if ((unaff_r4 >> 3 & 1U) != 0) {
    DAT_00000021 = (undefined1)(param_4 + -0xfe);
    *puVar9 = param_1;
    puVar9[1] = 0x1b;
    puVar9[2] = param_4 + -0xfe;
    puVar9[3] = unaff_r5;
    puVar9[4] = puVar9;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar12 = ((int)unaff_r5 >> 0x17 & 1U) != 0;
  uVar7 = (int)unaff_r5 >> 0x18;
  bVar11 = uVar7 == 0;
  piVar3 = (int *)*unaff_r5;
  uVar5 = unaff_r5[1];
  uVar8 = unaff_r5[2];
  iVar6 = (int)unaff_r5 >> 0x1f;
  if (!bVar12 || bVar11) {
    *(uint *)(uVar8 + 0x97) = uVar8;
                    // WARNING: Could not recover jumptable at 0x002c98d0. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(unaff_r9 + 0x278))(iVar6,0x130,*(undefined4 *)(unaff_r4 + 0x20));
    return;
  }
  if (unaff_r7 == 0) {
    sRam000000c1 = (short)(char)((uint)unaff_r5 >> 0x18);
    if (bVar12) {
      if (!bVar12 || bVar11) {
        uRam0000010f = 0x97;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(short *)piVar3 = (short)unaff_r4;
      coprocessor_function(0xe,8,1,in_cr0,in_cr12,in_cr0);
      *(int **)((int)unaff_r8 + uVar5) = piVar3;
      bVar11 = 0xfffffff6 < uVar5;
      iVar6 = uVar5 + 9;
      bVar12 = false;
      cVar10 = '\0';
      uVar13 = func_0x00f3da1a();
      iVar4 = (int)((ulonglong)uVar13 >> 0x20);
      if (!bVar11 || bVar12) {
        *(undefined2 *)(iVar4 + 0x3a) = 0xd6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(char *)(unaff_r8 + 7) = (char)unaff_r8;
      if (cVar10 == '\0') {
        *(undefined8 *)(iVar6 + -0x11) = uVar13;
        *(undefined8 **)(iVar6 + -9) = (undefined8 *)(iVar6 + -0x11);
        *(undefined4 *)(iVar6 + -5) = in_stack_00000250;
        *(undefined4 *)(iVar6 + -1) = 0;
        *(int *)(iVar6 + 3) = iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(undefined1 *)(iVar6 + 5) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (iVar6 < 0 == (bool)in_OV) {
      coprocessor_loadlong(1,in_cr4,uVar7);
      *(undefined1 *)((uint)*(ushort *)(*(byte *)(uVar5 + 0x19) + 0x38) + (uVar7 - 0x2ef)) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(undefined4 *)(iVar6 + 100) = 0;
    unaff_r8 = (uint *)&stack0x000002e0;
    uVar8 = *(uint *)(iVar6 + 0x70);
    unaff_r4 = iVar6 << 0xd;
    uVar7 = (uint)(short)unaff_r4;
    uVar5 = (int)piVar3 + 0x97;
  }
  else if (((int)uVar7 >= 0) || (iVar4 = 0xcb, bVar11)) {
    if (!bVar11 && (int)uVar7 < 0 == (bool)in_OV) {
      bVar1 = *(byte *)(iVar4 + 4);
      *(short *)((int)unaff_r8 + 0x32) = (short)unaff_r4;
      *(short *)((uint)bVar1 + *piVar3 + -0xca) = (short)uVar5;
      software_interrupt(0x98);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    software_bkpt(0xad);
    bVar1 = *(byte *)(uVar5 + 3);
    in_stack_000000cc[0x19] = in_stack_000000c8;
    *in_stack_000000cc = in_stack_000000c8;
    in_stack_000000cc[1] = &DAT_002c9d58;
    in_stack_000000cc[2] = uVar5;
    in_stack_000000cc[3] = &stack0x00000290;
    in_stack_000000cc[4] = uVar8;
    in_stack_000000cc[5] = in_stack_000000d0;
    in_stack_000000cc[6] = (uint)bVar1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(uVar7 + uVar8);
  uVar2 = *(ushort *)(unaff_r4 + 0x1c);
  coprocessor_load(9,in_cr8,iVar4 + 0x3d4);
  *(short *)(uVar8 + (int)unaff_r8) = (short)uVar5;
  *(short *)(uVar2 + 0x2e) = (short)uVar8;
  *unaff_r8 = (uint)bVar1;
  unaff_r8[1] = uVar7;
  unaff_r8[2] = uVar8;
  unaff_r8[3] = (uint)uVar2;
  _DAT_2191f375 = (short)uVar8;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c9d72)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_begin_catch(undefined4 param_1,int param_2,int *param_3,int param_4)

{
  code *pcVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *unaff_r7;
  uint uVar6;
  
  uVar2 = *unaff_r7;
  iVar4 = unaff_r7[1];
  puVar5 = (undefined4 *)unaff_r7[2];
  *puVar5 = param_3;
  *(char *)(unaff_r7 + 8) = (char)param_3;
  *(undefined4 *)(param_4 + 0xb3) = uVar2;
  *(int *)(param_4 + 0xb7) = param_2;
  *(int **)(param_4 + 0xbb) = param_3;
  *(int *)(param_4 + 0xbf) = iVar4;
  *(int *)(param_4 + 0xc3) = (int)puVar5 + -0x79;
  iVar3 = *param_3;
  *(undefined1 **)(iVar4 + 8) = &DAT_54b07591;
  *(int *)(param_4 + 199) = iVar3;
  *(int *)(param_4 + 0xcb) = param_2;
  *(int *)(param_4 + 0xcf) = iVar4;
  *(undefined1 **)(param_4 + 0xd3) = &DAT_54b07591;
  *(int *)(param_4 + 0xd7) = (int)(unaff_r7 + 3) * 8;
  _DAT_54b07595 = param_4 + 0xdb;
  uVar6 = (uint)*(ushort *)(param_4 + 0xfd);
  _DAT_54b07591 = iVar3;
  _DAT_54b07599 = iVar4;
  _DAT_54b0759d = &stack0x000002b8;
  *(int *)param_2 = param_2;
  *(int *)(param_2 + 4) = iVar4;
  *(undefined1 **)(param_2 + 8) = &stack0x000002b8;
  *(uint *)(param_2 + 0xc) = uVar6;
  *(int *)(param_2 + 0x4c) = param_2;
  *(char *)(*(int *)(uVar6 + 0x10) + iVar3 * 0x4000000) = (char)*(undefined4 *)(uVar6 + 4);
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0x56,0x2c9d40);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c9d90)
// WARNING: Removing unreachable block (ram,0x002c9d08)
// WARNING: Removing unreachable block (ram,0x002c9d36)
// WARNING: Removing unreachable block (ram,0x002c9db2)
// WARNING: Removing unreachable block (ram,0x002c9d72)

void __cxa_end_catch(void)

{
  int extraout_r1;
  uint unaff_r4;
  int unaff_r5;
  undefined4 *unaff_r6;
  int in_stack_000002cc;
  
  func_0xff7252a8();
  software_bkpt(0x1b);
  *(char *)(unaff_r4 + 1) = (char)unaff_r6;
  *(undefined2 *)(unaff_r5 + extraout_r1) = 0x7598;
  *(int *)((unaff_r4 >> 0x11) + in_stack_000002cc) = unaff_r5;
  *unaff_r6 = 0x54b07598;
  unaff_r6[1] = unaff_r4 >> 0x11;
  unaff_r6[2] = unaff_r5;
  unaff_r6[3] = unaff_r6;
  unaff_r6[4] = in_stack_000002cc;
  *(char *)(~unaff_r4 + 0x18) = (char)*(undefined4 *)(unaff_r5 + 4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_decrement_exception_refcount
               (undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 unaff_r4;
  undefined4 *unaff_r6;
  undefined4 unaff_r7;
  
  *unaff_r6 = param_1;
  unaff_r6[1] = param_2;
  unaff_r6[2] = param_4;
  unaff_r6[3] = unaff_r4;
  unaff_r6[4] = unaff_r7;
  *(short *)(param_2 + 0x26) = (short)unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002ca57c)
// WARNING: Removing unreachable block (ram,0x002ca580)
// WARNING: Removing unreachable block (ram,0x002ca582)
// WARNING: Removing unreachable block (ram,0x002ca5cc)
// WARNING: Removing unreachable block (ram,0x002ca66c)
// WARNING: Removing unreachable block (ram,0x002ca5e2)
// WARNING: Removing unreachable block (ram,0x002cac8a)
// WARNING: Removing unreachable block (ram,0x002cacf0)
// WARNING: Removing unreachable block (ram,0x002cad02)
// WARNING: Removing unreachable block (ram,0x002cae00)
// WARNING: Removing unreachable block (ram,0x002cad12)
// WARNING: Removing unreachable block (ram,0x002cad14)
// WARNING: Removing unreachable block (ram,0x002caccc)
// WARNING: Removing unreachable block (ram,0x002cac8e)
// WARNING: Removing unreachable block (ram,0x002cac0a)
// WARNING: Removing unreachable block (ram,0x002cabe0)
// WARNING: Removing unreachable block (ram,0x002ca8f2)
// WARNING: Removing unreachable block (ram,0x002ca8fa)
// WARNING: Removing unreachable block (ram,0x002ca972)
// WARNING: Removing unreachable block (ram,0x002cac3c)
// WARNING: Removing unreachable block (ram,0x002cac4e)
// WARNING: Removing unreachable block (ram,0x002cac50)
// WARNING: Removing unreachable block (ram,0x002cac66)
// WARNING: Removing unreachable block (ram,0x002cac16)
// WARNING: Removing unreachable block (ram,0x002cab9e)
// WARNING: Removing unreachable block (ram,0x002cac18)
// WARNING: Removing unreachable block (ram,0x002cac2c)
// WARNING: Removing unreachable block (ram,0x002cb35c)
// WARNING: Removing unreachable block (ram,0x002cbaac)
// WARNING: Removing unreachable block (ram,0x002ca672)
// WARNING: Removing unreachable block (ram,0x002ca676)
// WARNING: Removing unreachable block (ram,0x002ca67e)
// WARNING: Removing unreachable block (ram,0x002ca83e)
// WARNING: Removing unreachable block (ram,0x002ca850)
// WARNING: Removing unreachable block (ram,0x002caff8)
// WARNING: Removing unreachable block (ram,0x002ca82c)
// WARNING: Removing unreachable block (ram,0x002ca83a)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_current_exception_type(uint param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  int extraout_r1;
  int iVar2;
  uint uVar3;
  int unaff_r5;
  uint unaff_r7;
  int iVar4;
  uint uStack_78;
  
  uVar3 = param_1 >> 2;
  *(undefined4 *)(uVar3 + 0x40) = param_2;
  *(uint *)(uVar3 + 0x50) = uVar3;
  if ((param_1 >> 1 & 1) == 0) {
    *(char *)(unaff_r5 + param_3) = (char)param_2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  software_interrupt(0xee);
  software_bkpt(0xd0);
  uVar3 = *(uint *)((unaff_r7 >> 0xe) + 0x20);
  *(uint *)(uVar3 + 0x60) = (uint)_DAT_fdff9bbc;
  func_0x0057c93a();
  iVar2 = (uVar3 >> (uStack_78 & 0x1f) | uVar3 << 0x20 - (uStack_78 & 0x1f)) << 9;
  iVar4 = iVar2 >> 0x18;
  if (iVar4 == 0) {
    *(short *)(extraout_r1 + 0x20) = (short)iVar2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined1 **)(iVar4 + 0x38) = &stack0x00000018;
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xa3,0x2ca630);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_rethrow(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int unaff_r4;
  char in_NG;
  bool in_ZR;
  char in_OV;
  
  if (!in_ZR && in_NG == in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined4 *)(unaff_r4 + 0x54) = param_3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002ca57c)
// WARNING: Removing unreachable block (ram,0x002ca580)
// WARNING: Removing unreachable block (ram,0x002ca582)
// WARNING: Removing unreachable block (ram,0x002ca5cc)
// WARNING: Removing unreachable block (ram,0x002ca66c)
// WARNING: Removing unreachable block (ram,0x002ca5e2)
// WARNING: Removing unreachable block (ram,0x002cac8a)
// WARNING: Removing unreachable block (ram,0x002cacf0)
// WARNING: Removing unreachable block (ram,0x002cad02)
// WARNING: Removing unreachable block (ram,0x002cae00)
// WARNING: Removing unreachable block (ram,0x002cad12)
// WARNING: Removing unreachable block (ram,0x002cad14)
// WARNING: Removing unreachable block (ram,0x002caccc)
// WARNING: Removing unreachable block (ram,0x002cac8e)
// WARNING: Removing unreachable block (ram,0x002cac0a)
// WARNING: Removing unreachable block (ram,0x002cabe0)
// WARNING: Removing unreachable block (ram,0x002ca8f2)
// WARNING: Removing unreachable block (ram,0x002ca8fa)
// WARNING: Removing unreachable block (ram,0x002ca972)
// WARNING: Removing unreachable block (ram,0x002cac3c)
// WARNING: Removing unreachable block (ram,0x002cac4e)
// WARNING: Removing unreachable block (ram,0x002cac50)
// WARNING: Removing unreachable block (ram,0x002cac66)
// WARNING: Removing unreachable block (ram,0x002cac16)
// WARNING: Removing unreachable block (ram,0x002cab9e)
// WARNING: Removing unreachable block (ram,0x002cac18)
// WARNING: Removing unreachable block (ram,0x002cac2c)
// WARNING: Removing unreachable block (ram,0x002cb35c)
// WARNING: Removing unreachable block (ram,0x002cbaac)
// WARNING: Removing unreachable block (ram,0x002ca672)
// WARNING: Removing unreachable block (ram,0x002ca676)
// WARNING: Removing unreachable block (ram,0x002ca67e)
// WARNING: Removing unreachable block (ram,0x002ca83e)
// WARNING: Removing unreachable block (ram,0x002ca850)
// WARNING: Removing unreachable block (ram,0x002caff8)
// WARNING: Removing unreachable block (ram,0x002ca82c)
// WARNING: Removing unreachable block (ram,0x002ca83a)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_increment_exception_refcount(void)

{
  code *pcVar1;
  int extraout_r1;
  uint uVar2;
  int iVar3;
  int unaff_r6;
  int iVar4;
  uint local_78;
  
  uVar2 = *(uint *)(unaff_r6 + 0x20);
  *(uint *)(uVar2 + 0x60) = (uint)_DAT_fdff9bbc;
  func_0x0057c93a();
  iVar3 = (uVar2 >> (local_78 & 0x1f) | uVar2 << 0x20 - (local_78 & 0x1f)) << 9;
  iVar4 = iVar3 >> 0x18;
  if (iVar4 == 0) {
    *(short *)(extraout_r1 + 0x20) = (short)iVar3;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined1 **)(iVar4 + 0x38) = &stack0x00000018;
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xa3,0x2ca630);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002ca706)

void __cxa_current_primary_exception(int param_1,int param_2)

{
  code *pcVar1;
  int unaff_r6;
  int unaff_r7;
  
  software_interrupt(0xca);
  *(char *)((param_1 - unaff_r7) + 0x13) = (char)(param_1 - unaff_r7);
  func_0xff6956ae(unaff_r6 + param_2,param_2,0x6d);
  puRam00000004 = &stack0x000000a4;
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xa3,0x2ca630);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data

void FUN_002c9f38(int param_1,int param_2,int param_3,int param_4)

{
  int *unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_cr4;
  
  if (param_4 != 0) {
    return;
  }
  *(short *)(param_1 + 0x1e) = (short)unaff_r7;
  *unaff_r5 = param_1;
  unaff_r5[1] = param_2;
  unaff_r5[2] = param_3;
  unaff_r5[3] = 0;
  unaff_r5[4] = unaff_r6;
  unaff_r5[5] = unaff_r7;
  if (0x67 < param_3) {
    coprocessor_movefromRt(4,8,in_cr4);
    coprocessor_movefromRt2(4,8,in_cr4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Could not recover jumptable at 0x002ca046. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)&stack0x002ca04a)(0x75ceda94);
  return;
}



// WARNING: Control flow encountered bad instruction data

void __cxa_rethrow_primary_exception(void)

{
  undefined4 in_cr4;
  
  coprocessor_movefromRt(4,8,in_cr4);
  coprocessor_movefromRt2(4,8,in_cr4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_uncaught_exception(int param_1,int param_2,code *param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int *unaff_r5;
  uint uVar7;
  undefined4 *puVar8;
  int unaff_r6;
  int iVar9;
  uint uVar10;
  int iVar11;
  code *unaff_r8;
  uint unaff_r11;
  undefined1 *puVar12;
  char cVar13;
  undefined4 in_cr3;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr12;
  undefined4 in_cr15;
  undefined8 uVar14;
  int in_stack_000000b8;
  undefined4 *in_stack_000000c0;
  int in_stack_000000c4;
  undefined4 in_stack_00000150;
  undefined4 in_stack_000001dc;
  undefined4 in_stack_000001ec;
  undefined4 in_stack_00000280;
  int in_stack_00000330;
  
  uVar5 = *(undefined4 *)(param_2 + 0x50);
  *unaff_r5 = param_1;
  unaff_r5[1] = param_2;
  unaff_r5[2] = (int)param_3;
  unaff_r5[3] = param_4;
  unaff_r5[4] = unaff_r6;
  *(short *)(param_1 + 0x1c) = (short)(unaff_r5 + 5);
  uVar14 = (*param_3)();
  cVar13 = DAT_00594050;
  iVar9 = (int)((ulonglong)uVar14 >> 0x20);
  iVar11 = (int)DAT_00594050;
  *(short *)(param_3 + (int)(unaff_r5 + 5)) = (short)uVar5;
  *(int *)((int)uVar14 + 0x74) = param_4;
  *(undefined8 *)param_3 = uVar14;
  *(int *)(param_3 + 8) = param_4;
  *(undefined4 *)(param_3 + 0xc) = 0x458215e3;
  *(int *)(param_3 + 0x10) = iVar11;
  uVar7 = *(uint *)(iVar9 + 0x34);
  *(char *)(iVar9 + 0x458215e3) = cVar13;
  uVar10 = _DAT_00000037;
  iVar11 = iVar9 + 0xb2;
  if (iVar11 < 0 == SCARRY4(iVar9,0xb2)) {
    _DAT_0000004b = CONCAT13((char)uVar7,_DAT_0000004b);
    *(ushort *)(iVar9 + 0xb6) = (ushort)(byte)((uint)in_stack_00000280 >> 0x10);
    *(short *)(uVar7 + 0x10) = (short)param_4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar4 = (undefined4 *)(_DAT_0000003f >> 8);
  iVar9 = coprocessor_movefromRt(0xb,0,6,in_cr9,in_cr3);
  piVar1 = *(int **)(uVar7 + (int)puVar4);
  *puVar4 = puVar4;
  puVar4[1] = 0x43;
  puVar4[2] = uVar7;
  puVar4[3] = &stack0x00000158;
  *piVar1 = (int)piVar1;
  piVar1[1] = (int)puVar4;
  piVar1[2] = 0x43;
  piVar1[3] = iVar9 + 0x4c;
  piVar1[4] = (int)&stack0x00000158;
  *piVar1 = iVar11;
  piVar1[1] = uVar10;
  piVar1[2] = (int)puVar4;
  piVar1[3] = iVar9 + 0x4c;
  piVar1[4] = (int)&stack0x00000158;
  if (uVar7 == 0) {
    *(ushort *)(DAT_00000056 + 0x22) = (ushort)DAT_00000056;
    software_interrupt(0xd5);
    iVar9 = (unaff_r11 >> 6) - unaff_r11;
    iVar2 = *(int *)(iVar9 + _DAT_0000004b);
    iVar11 = (int)*(char *)((_DAT_00000047 >> 0x1e) + 0xbe);
    cVar13 = SCARRY4(iVar11,0x4f);
    uVar7 = iVar11 + 0x4f;
    iVar9 = FUN_002b6260(*(undefined4 *)(*(int *)(uVar10 + 4) + 0x48),iVar9,&stack0x00000328);
    uVar10 = iVar2 >> (uVar7 & 0xff);
    if (cVar13 == '\0') {
      coprocessor_function(7,0xc,3,in_cr9,in_cr12,in_cr4);
      *(short *)(in_stack_00000330 + uVar10) = (short)iVar9;
      *(undefined1 *)(iVar11 + 0xe7c7237) = 0;
      iVar9 = *(int *)(((int)(uVar10 << 0x16) >> 0x15) + 4);
      *(char *)(in_stack_00000330 + iVar9) = (char)iVar9;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_load(10,in_cr15,unaff_r8);
    (*(code *)(uVar10 >> 0x1d))(iVar9,*(undefined1 *)(iVar9 + 0xb));
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_0000004b = CONCAT13(0x43,_DAT_0000004b);
  puVar12 = &stack0x000000b4;
  in_stack_00000150 = 0x43;
  iVar2 = (int)puVar4 + -3;
  if (iVar2 == 0) {
    iVar11 = *(int *)(*(char *)(((uint)(iVar11 >> 0xe) >> 0x1c) + 0x43) + 0x5c);
    if (uVar10 == 0) {
      *(undefined4 **)(iVar9 + 0x70) = puVar4;
      puVar12 = &stack0x000000cc;
      in_stack_000000c4 = in_stack_000000c4 + 0xde;
      iVar11 = in_stack_000000b8;
      puVar4 = in_stack_000000c0;
    }
    else {
      in_stack_000000c4 = (uVar10 >> 0x16) << 0x11;
    }
    *(short *)(in_stack_000000c4 + iVar11) = (short)puVar4;
    *(undefined1 **)(puVar12 + 0x3b8) = puVar12 + 0x29c;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar8 = (undefined4 *)(uVar7 & 0xffff);
  uVar5 = *puVar4;
  uVar6 = puVar4[2];
  uVar3 = *(undefined4 *)(iVar2 + puVar4[1]);
  if (iVar2 * 0x80000 < 0 != SBORROW4((int)puVar4,3)) {
    *puVar8 = uVar5;
    puVar8[1] = uVar6;
    puVar8[2] = iVar2 * 0x80000;
    uVar5 = (*unaff_r8)(iVar2,uVar5,uVar3);
    coprocessor_function(6,7,3,in_cr4,in_cr6,in_cr9);
    coprocessor_load(1,in_cr8,uVar5);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_uncaught_exceptions(int param_1,int param_2,int *param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  undefined2 unaff_r4;
  undefined4 uVar7;
  int unaff_r5;
  uint uVar8;
  undefined4 *puVar9;
  int iVar10;
  uint uVar11;
  int unaff_r7;
  code *unaff_r8;
  uint unaff_r11;
  undefined1 *puVar12;
  char cVar13;
  undefined4 in_cr3;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr12;
  undefined4 in_cr15;
  int in_stack_000000cc;
  undefined4 *in_stack_000000d4;
  int in_stack_000000d8;
  undefined4 in_stack_00000164;
  undefined4 in_stack_000001f0;
  undefined4 in_stack_00000294;
  int in_stack_00000344;
  
  *(undefined2 *)((int)param_3 + unaff_r5) = unaff_r4;
  *(int *)(param_1 + 0x74) = param_4;
  *param_3 = param_1;
  param_3[1] = param_2;
  param_3[2] = param_4;
  param_3[3] = 0x458215e3;
  param_3[4] = unaff_r7;
  uVar8 = *(uint *)(param_2 + 0x34);
  *(char *)(param_2 + 0x458215e3) = (char)unaff_r7;
  uVar11 = _DAT_00000037;
  iVar3 = param_2 + 0xb2;
  if (iVar3 < 0 == SCARRY4(param_2,0xb2)) {
    _DAT_0000004b = CONCAT13((char)uVar8,_DAT_0000004b);
    *(ushort *)(param_2 + 0xb6) = (ushort)(byte)((uint)in_stack_00000294 >> 0x10);
    *(short *)(uVar8 + 0x10) = (short)param_4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar6 = (undefined4 *)(_DAT_0000003f >> 8);
  iVar10 = coprocessor_movefromRt(0xb,0,6,in_cr9,in_cr3);
  piVar1 = *(int **)(uVar8 + (int)puVar6);
  *puVar6 = puVar6;
  puVar6[1] = 0x43;
  puVar6[2] = uVar8;
  puVar6[3] = &stack0x0000016c;
  *piVar1 = (int)piVar1;
  piVar1[1] = (int)puVar6;
  piVar1[2] = 0x43;
  piVar1[3] = iVar10 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  *piVar1 = iVar3;
  piVar1[1] = uVar11;
  piVar1[2] = (int)puVar6;
  piVar1[3] = iVar10 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  if (uVar8 == 0) {
    *(ushort *)(DAT_00000056 + 0x22) = (ushort)DAT_00000056;
    software_interrupt(0xd5);
    iVar3 = (unaff_r11 >> 6) - unaff_r11;
    iVar2 = *(int *)(iVar3 + _DAT_0000004b);
    iVar10 = (int)*(char *)((_DAT_00000047 >> 0x1e) + 0xbe);
    cVar13 = SCARRY4(iVar10,0x4f);
    uVar8 = iVar10 + 0x4f;
    iVar3 = FUN_002b6260(*(undefined4 *)(*(int *)(uVar11 + 4) + 0x48),iVar3,&stack0x0000033c);
    uVar11 = iVar2 >> (uVar8 & 0xff);
    if (cVar13 == '\0') {
      coprocessor_function(7,0xc,3,in_cr9,in_cr12,in_cr4);
      *(short *)(in_stack_00000344 + uVar11) = (short)iVar3;
      *(undefined1 *)(iVar10 + 0xe7c7237) = 0;
      iVar3 = *(int *)(((int)(uVar11 << 0x16) >> 0x15) + 4);
      *(char *)(in_stack_00000344 + iVar3) = (char)iVar3;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_load(10,in_cr15,unaff_r8);
    (*(code *)(uVar11 >> 0x1d))(iVar3,*(undefined1 *)(iVar3 + 0xb));
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_0000004b = CONCAT13(0x43,_DAT_0000004b);
  puVar12 = &stack0x000000c8;
  in_stack_00000164 = 0x43;
  iVar2 = (int)puVar6 + -3;
  if (iVar2 == 0) {
    iVar3 = *(int *)(*(char *)(((uint)(iVar3 >> 0xe) >> 0x1c) + 0x43) + 0x5c);
    if (uVar11 == 0) {
      *(undefined4 **)(iVar10 + 0x70) = puVar6;
      puVar12 = &stack0x000000e0;
      in_stack_000000d8 = in_stack_000000d8 + 0xde;
      iVar3 = in_stack_000000cc;
      puVar6 = in_stack_000000d4;
    }
    else {
      in_stack_000000d8 = (uVar11 >> 0x16) << 0x11;
    }
    *(short *)(in_stack_000000d8 + iVar3) = (short)puVar6;
    *(undefined1 **)(puVar12 + 0x3b8) = puVar12 + 0x29c;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar9 = (undefined4 *)(uVar8 & 0xffff);
  uVar4 = *puVar6;
  uVar7 = puVar6[2];
  uVar5 = *(undefined4 *)(iVar2 + puVar6[1]);
  if (iVar2 * 0x80000 < 0 != SBORROW4((int)puVar6,3)) {
    *puVar9 = uVar4;
    puVar9[1] = uVar7;
    puVar9[2] = iVar2 * 0x80000;
    uVar4 = (*unaff_r8)(iVar2,uVar4,uVar5);
    coprocessor_function(6,7,3,in_cr4,in_cr6,in_cr9);
    coprocessor_load(1,in_cr8,uVar4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c9494)
// WARNING: Removing unreachable block (ram,0x002c94a4)
// WARNING: Removing unreachable block (ram,0x002c926c)
// WARNING: Removing unreachable block (ram,0x002c9270)
// WARNING: Removing unreachable block (ram,0x002c9350)
// WARNING: Removing unreachable block (ram,0x002c9354)
// WARNING: Removing unreachable block (ram,0x002c939a)
// WARNING: Removing unreachable block (ram,0x002c975a)
// WARNING: Removing unreachable block (ram,0x002c975c)
// WARNING: Removing unreachable block (ram,0x002c96c0)
// WARNING: Removing unreachable block (ram,0x002c982e)
// WARNING: Removing unreachable block (ram,0x002c9cce)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_get_globals(uint param_1,int param_2,undefined4 param_3,int param_4)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int unaff_r4;
  uint uVar6;
  int *piVar7;
  undefined4 uVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  uint *unaff_r7;
  undefined4 in_lr;
  undefined4 in_cr3;
  undefined4 in_cr11;
  undefined4 in_cr13;
  undefined8 in_d6;
  undefined8 in_d27;
  int in_stack_00000018;
  int *in_stack_00000238;
  int *in_stack_000003a4;
  
  piVar7 = (int *)(unaff_r4 >> 0x1e);
  uVar3 = param_1 >> ((uint)unaff_r7 & 0x1f) | param_1 << 0x20 - ((uint)unaff_r7 & 0x1f);
  uVar6 = *(uint *)(unaff_r4 + param_4);
  uVar5 = 0;
  if (!SBORROW4((int)piVar7,(int)piVar7)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(char *)(uVar6 + 0xb) = (char)unaff_r7;
  *(undefined4 *)(param_2 + 0xc) = 0;
  piVar9 = (int *)&stack0x00000204;
  if (piVar7 == (int *)0x0) {
    *(undefined2 *)(uVar3 + 0x20) = 0;
    piVar7 = (int *)((int)&stack0x00000204 + uVar3 * -0x8000 * 4);
    uVar6 = *unaff_r7;
    VectorAdd(in_d6,in_d27,4);
    unaff_r7 = (uint *)0x309751b3;
    param_2 = param_2 + -0xa0;
    uVar5 = uVar6 >> 5;
    piVar9 = in_stack_00000238;
    if ((uVar6 >> 4 & 1) != 0 && uVar5 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  _DAT_000000af = (int)unaff_r7 + -0xe3;
  *(char *)(uVar3 * 0x20000) = (char)uVar5;
  bVar1 = *(byte *)(param_2 + 0x12);
  *(char *)((int)piVar9 + 0x1d) = (char)uVar5;
  *(char *)((uint)bVar1 + (int)piVar9) = (char)uVar6;
  software_interrupt(0x39);
  piVar7[0xe] = (uint)bVar1;
  *(uint *)(&stack0x00000039 + (int)unaff_r7) = uVar6;
  _DAT_0000009b = *piVar9;
  piVar7 = piVar9 + 2;
  iVar4 = coprocessor_movefromRt(0xc,4,4,in_cr13,in_cr11);
  _DAT_0000009f = &DAT_0009b000;
  _DAT_000000a3 = 0xfc;
  _DAT_000000a7 = 0x9b;
  iVar11 = iVar4 + 0xd5 >> 2;
  _DAT_000000ab = piVar7;
  *(undefined4 *)(_DAT_0000009b + 0x5c) = 0;
  iVar10 = iRam00000008;
  *(char *)(iVar11 + 0x1c) = (char)iRam00000008;
  *(char *)(iVar11 + 10) = (char)piVar7;
  if (SCARRY4(iVar4,0xd5)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar4 = iVar10 << 5;
  *(short *)(iVar11 + iVar10) = (short)iVar4;
  if (iVar4 >> 0x19 != 0) {
    uVar8 = *(undefined4 *)(iVar11 + 0x6c);
    *(short *)(iVar11 + 0xc) = (short)iVar10;
    *(short *)(iVar10 + 0x26) = (short)iVar11;
    *(short *)(piVar9 + 5) = (short)uVar8;
    uVar2 = *(undefined2 *)((int)piVar7 + in_stack_00000018);
    _DAT_0000001a = (short)(iVar4 >> 0x19);
    *(char *)(piVar9[0x13] + 0xf) = (char)uVar8;
    *(undefined2 *)((int)piVar9 + 0x46) = uVar2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (iVar4 >> 0x19 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar3 = (uint)*(ushort *)((int)piVar7 + (int)in_stack_000003a4);
  *(int **)(iVar10 + 0x7c) = piVar7;
  *in_stack_000003a4 = iVar10;
  iVar10 = *(int *)(iVar11 + -0x1b);
  coprocessor_load(6,in_cr3,in_lr);
  uVar8 = *(undefined4 *)(&DAT_002b24b0 + iVar10);
  bVar1 = *(byte *)(iVar10 + 3);
  uRam00000036 = 0x6000;
  *(uint *)(uVar3 + 3) = uVar3;
  *(undefined4 *)(uVar3 + 7) = 0x2b22440;
  *(uint *)(uVar3 + 0xb) = (uint)bVar1;
  *(undefined4 *)(uVar3 + 0xf) = uVar8;
  *(int *)(uVar3 + 0x13) = iVar10;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002ca402)
// WARNING: Removing unreachable block (ram,0x002ca406)
// WARNING: Removing unreachable block (ram,0x002caeee)
// WARNING: Removing unreachable block (ram,0x002cafdc)
// WARNING: Removing unreachable block (ram,0x002ca3f2)
// WARNING: Removing unreachable block (ram,0x002ca466)
// WARNING: Removing unreachable block (ram,0x002ca4e4)
// WARNING: Removing unreachable block (ram,0x002ca4b8)
// WARNING: Removing unreachable block (ram,0x002ca4ee)
// WARNING: Removing unreachable block (ram,0x002ca3fa)
// WARNING: Removing unreachable block (ram,0x002ca4c8)
// WARNING: Removing unreachable block (ram,0x002ca562)
// WARNING: Removing unreachable block (ram,0x002ca620)
// WARNING: Removing unreachable block (ram,0x002ca706)
// WARNING: Removing unreachable block (ram,0x002ca628)
// WARNING: Removing unreachable block (ram,0x002ca672)
// WARNING: Removing unreachable block (ram,0x002ca676)
// WARNING: Removing unreachable block (ram,0x002ca67e)
// WARNING: Removing unreachable block (ram,0x002ca83e)
// WARNING: Removing unreachable block (ram,0x002ca850)
// WARNING: Removing unreachable block (ram,0x002ca82c)
// WARNING: Removing unreachable block (ram,0x002ca83a)
// WARNING: Removing unreachable block (ram,0x002ca57c)
// WARNING: Removing unreachable block (ram,0x002ca580)
// WARNING: Removing unreachable block (ram,0x002ca5cc)
// WARNING: Removing unreachable block (ram,0x002ca582)
// WARNING: Removing unreachable block (ram,0x002ca66c)
// WARNING: Removing unreachable block (ram,0x002ca5e2)
// WARNING: Removing unreachable block (ram,0x002cac8a)
// WARNING: Removing unreachable block (ram,0x002cacf0)
// WARNING: Removing unreachable block (ram,0x002cad02)
// WARNING: Removing unreachable block (ram,0x002cae00)
// WARNING: Removing unreachable block (ram,0x002cad12)
// WARNING: Removing unreachable block (ram,0x002cad14)
// WARNING: Removing unreachable block (ram,0x002caff8)
// WARNING: Removing unreachable block (ram,0x002caccc)
// WARNING: Removing unreachable block (ram,0x002cac8e)
// WARNING: Removing unreachable block (ram,0x002cac0a)
// WARNING: Removing unreachable block (ram,0x002cabe0)
// WARNING: Removing unreachable block (ram,0x002ca8f2)
// WARNING: Removing unreachable block (ram,0x002ca972)
// WARNING: Removing unreachable block (ram,0x002ca8fa)
// WARNING: Removing unreachable block (ram,0x002cac3c)
// WARNING: Removing unreachable block (ram,0x002cac4e)
// WARNING: Removing unreachable block (ram,0x002cac50)
// WARNING: Removing unreachable block (ram,0x002cac16)
// WARNING: Removing unreachable block (ram,0x002cab9e)
// WARNING: Removing unreachable block (ram,0x002cac18)
// WARNING: Removing unreachable block (ram,0x002cac2c)
// WARNING: Removing unreachable block (ram,0x002cbaac)
// WARNING: Removing unreachable block (ram,0x002cb35c)
// WARNING: Removing unreachable block (ram,0x002ca444)
// WARNING: Removing unreachable block (ram,0x002ca3ec)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_get_globals_fast(int param_1,int param_2)

{
  undefined4 unaff_r4;
  int unaff_r5;
  int unaff_r7;
  char in_OV;
  
  if (unaff_r5 == 0) {
    if (in_OV != '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    param_1 = param_1 >> 0x15;
    *(int *)param_2 = param_2;
    *(undefined4 *)(param_2 + 4) = 0;
    *(undefined4 *)(param_2 + 8) = unaff_r4;
    *(int *)param_1 = param_1;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_r7;
    if (unaff_r5 >> 0x1a != -0xbd) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    *(short *)(unaff_r7 + 0x1c) = (short)(unaff_r5 >> 0x1a);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_unexpected()

void std::get_unexpected(void)

{
  int in_r0;
  int in_r1;
  undefined2 in_r3;
  int unaff_r4;
  int unaff_r5;
  
  *(char *)(unaff_r4 + 0x17) = (char)unaff_r5;
  *(ushort *)(in_r1 + 4) = (ushort)*(byte *)(in_r0 + 0x12);
  *(undefined2 *)(unaff_r5 + 0x10) = in_r3;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::terminate()

void std::terminate(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x002ca2ea. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)(&stack0x000003fc);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::unexpected()

void std::unexpected(void)

{
  int unaff_r11;
  undefined4 in_cr14;
  
  coprocessor_loadlong(4,in_cr14,unaff_r11 + 0x2a4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_terminate()

void std::get_terminate(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_002ca36e(int param_1,int param_2,int *param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  undefined2 unaff_r4;
  undefined4 uVar7;
  uint uVar8;
  int unaff_r5;
  undefined4 *puVar9;
  int iVar10;
  uint uVar11;
  int unaff_r7;
  code *unaff_r8;
  uint unaff_r11;
  undefined1 *puVar12;
  char cVar13;
  undefined4 in_cr3;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr12;
  undefined4 in_cr15;
  int in_stack_000000cc;
  undefined4 *in_stack_000000d4;
  int in_stack_000000d8;
  undefined4 in_stack_00000164;
  undefined4 in_stack_000001f0;
  undefined4 in_stack_00000294;
  int in_stack_00000344;
  
  *(undefined2 *)((int)param_3 + unaff_r5) = unaff_r4;
  *(int *)(param_1 + 0x74) = param_4;
  *param_3 = param_1;
  param_3[1] = param_2;
  param_3[2] = param_4;
  param_3[3] = 0x458215e3;
  param_3[4] = unaff_r7;
  uVar8 = *(uint *)(param_2 + 0x34);
  *(char *)(param_2 + 0x458215e3) = (char)unaff_r7;
  uVar11 = _DAT_00000037;
  iVar3 = param_2 + 0xb2;
  if (iVar3 < 0 == SCARRY4(param_2,0xb2)) {
    _DAT_0000004b = CONCAT13((char)uVar8,_DAT_0000004b);
    *(ushort *)(param_2 + 0xb6) = (ushort)(byte)((uint)in_stack_00000294 >> 0x10);
    *(short *)(uVar8 + 0x10) = (short)param_4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar6 = (undefined4 *)(_DAT_0000003f >> 8);
  iVar10 = coprocessor_movefromRt(0xb,0,6,in_cr9,in_cr3);
  piVar1 = *(int **)(uVar8 + (int)puVar6);
  *puVar6 = puVar6;
  puVar6[1] = 0x43;
  puVar6[2] = uVar8;
  puVar6[3] = &stack0x0000016c;
  *piVar1 = (int)piVar1;
  piVar1[1] = (int)puVar6;
  piVar1[2] = 0x43;
  piVar1[3] = iVar10 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  *piVar1 = iVar3;
  piVar1[1] = uVar11;
  piVar1[2] = (int)puVar6;
  piVar1[3] = iVar10 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  if (uVar8 == 0) {
    *(ushort *)(DAT_00000056 + 0x22) = (ushort)DAT_00000056;
    software_interrupt(0xd5);
    iVar3 = (unaff_r11 >> 6) - unaff_r11;
    iVar2 = *(int *)(iVar3 + _DAT_0000004b);
    iVar10 = (int)*(char *)((_DAT_00000047 >> 0x1e) + 0xbe);
    cVar13 = SCARRY4(iVar10,0x4f);
    uVar8 = iVar10 + 0x4f;
    iVar3 = FUN_002b6260(*(undefined4 *)(*(int *)(uVar11 + 4) + 0x48),iVar3,&stack0x0000033c);
    uVar11 = iVar2 >> (uVar8 & 0xff);
    if (cVar13 == '\0') {
      coprocessor_function(7,0xc,3,in_cr9,in_cr12,in_cr4);
      *(short *)(in_stack_00000344 + uVar11) = (short)iVar3;
      *(undefined1 *)(iVar10 + 0xe7c7237) = 0;
      iVar3 = *(int *)(((int)(uVar11 << 0x16) >> 0x15) + 4);
      *(char *)(in_stack_00000344 + iVar3) = (char)iVar3;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_load(10,in_cr15,unaff_r8);
    (*(code *)(uVar11 >> 0x1d))(iVar3,*(undefined1 *)(iVar3 + 0xb));
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_0000004b = CONCAT13(0x43,_DAT_0000004b);
  puVar12 = &stack0x000000c8;
  in_stack_00000164 = 0x43;
  iVar2 = (int)puVar6 + -3;
  if (iVar2 == 0) {
    iVar3 = *(int *)(*(char *)(((uint)(iVar3 >> 0xe) >> 0x1c) + 0x43) + 0x5c);
    if (uVar11 == 0) {
      *(undefined4 **)(iVar10 + 0x70) = puVar6;
      puVar12 = &stack0x000000e0;
      in_stack_000000d8 = in_stack_000000d8 + 0xde;
      iVar3 = in_stack_000000cc;
      puVar6 = in_stack_000000d4;
    }
    else {
      in_stack_000000d8 = (uVar11 >> 0x16) << 0x11;
    }
    *(short *)(in_stack_000000d8 + iVar3) = (short)puVar6;
    *(undefined1 **)(puVar12 + 0x3b8) = puVar12 + 0x29c;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar9 = (undefined4 *)(uVar8 & 0xffff);
  uVar4 = *puVar6;
  uVar7 = puVar6[2];
  uVar5 = *(undefined4 *)(iVar2 + puVar6[1]);
  if (iVar2 * 0x80000 < 0 != SBORROW4((int)puVar6,3)) {
    *puVar9 = uVar4;
    puVar9[1] = uVar7;
    puVar9[2] = iVar2 * 0x80000;
    uVar4 = (*unaff_r8)(iVar2,uVar4,uVar5);
    coprocessor_function(6,7,3,in_cr4,in_cr6,in_cr9);
    coprocessor_load(1,in_cr8,uVar4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002c99e0)
// WARNING: Removing unreachable block (ram,0x002ca05c)
// WARNING: Removing unreachable block (ram,0x002ca070)
// WARNING: Removing unreachable block (ram,0x002ca126)
// WARNING: Removing unreachable block (ram,0x002ca136)
// WARNING: Removing unreachable block (ram,0x002ca1a8)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_new_handler(void (*)())

void std::set_new_handler(_func_void *param_1)

{
  byte bVar1;
  int in_r1;
  short sVar2;
  undefined4 in_r2;
  int unaff_r4;
  int unaff_r5;
  int unaff_r7;
  bool in_ZR;
  bool in_CY;
  
  *(undefined4 *)(unaff_r7 + unaff_r4) = in_r2;
  if (in_CY && !in_ZR) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  DAT_00000108 = SUB41(param_1,0);
  sVar2 = 0x1945;
  bVar1 = *(byte *)(in_r1 + -0x4e + (int)set_unexpected);
  if (unaff_r5 != 0) {
    (*(code *)&SUB_000000ec)();
    sRam00000032 = sVar2 >> 0xd;
    return;
  }
  *(short *)(set_unexpected + 0x22) = set_unexpected;
  _DAT_00000070 = 0;
  uRam00000000 = (uint)bVar1;
  uRam00000004 = 0xd6;
  uRam00000008 = 0xec;
  uRam0000000c = 0x2ca4d0;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::get_new_handler()

void std::get_new_handler(void)

{
  int *piVar1;
  int iVar2;
  int in_r1;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined1 *puVar7;
  uint unaff_r5;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  code *unaff_r8;
  uint unaff_r11;
  char cVar12;
  undefined4 in_cr3;
  undefined4 in_cr4;
  undefined4 in_cr6;
  undefined4 in_cr8;
  undefined4 in_cr9;
  undefined4 in_cr12;
  undefined4 in_cr15;
  int in_stack_000000cc;
  undefined4 *in_stack_000000d4;
  int in_stack_000000d8;
  undefined1 *puStack00000164;
  int in_stack_00000344;
  uint in_stack_00000398;
  uint in_stack_000003a0;
  uint in_stack_000003a8;
  int in_stack_000003ac;
  byte in_stack_000003b7;
  
  puStack00000164 = &stack0x000003a4;
  puVar5 = (undefined4 *)(in_stack_000003a0 >> 8);
  iVar9 = coprocessor_movefromRt(0xb,0,6,in_cr9,in_cr3);
  piVar1 = *(int **)(unaff_r5 + (int)puVar5);
  *puVar5 = puVar5;
  puVar5[1] = puStack00000164;
  puVar5[2] = unaff_r5;
  puVar5[3] = &stack0x0000016c;
  *piVar1 = (int)piVar1;
  piVar1[1] = (int)puVar5;
  piVar1[2] = (int)puStack00000164;
  piVar1[3] = iVar9 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  *piVar1 = in_r1;
  piVar1[1] = in_stack_00000398;
  piVar1[2] = (int)puVar5;
  piVar1[3] = iVar9 + 0x4c;
  piVar1[4] = (int)&stack0x0000016c;
  if (unaff_r5 == 0) {
    *(ushort *)(in_stack_000003b7 + 0x22) = (ushort)in_stack_000003b7;
    software_interrupt(0xd5);
    iVar9 = (unaff_r11 >> 6) - unaff_r11;
    iVar10 = *(int *)(iVar9 + in_stack_000003ac);
    iVar2 = (int)(char)(&stack0x000003b0)[(in_stack_000003a8 >> 0x1e) + 0x6f];
    cVar12 = SCARRY4(iVar2,(int)&stack0x000003b0);
    puVar7 = &stack0x000003b0 + iVar2;
    iVar9 = FUN_002b6260(*(undefined4 *)(*(int *)(in_stack_00000398 + 4) + 0x48),iVar9,
                         &stack0x0000033c);
    uVar11 = iVar10 >> ((uint)puVar7 & 0xff);
    if (cVar12 == '\0') {
      coprocessor_function(7,0xc,3,in_cr9,in_cr12,in_cr4);
      *(short *)(in_stack_00000344 + uVar11) = (short)iVar9;
      *(undefined1 *)(iVar2 + 0xe7c7237) = 0;
      iVar9 = *(int *)(((int)(uVar11 << 0x16) >> 0x15) + 4);
      *(char *)(in_stack_00000344 + iVar9) = (char)iVar9;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    coprocessor_load(10,in_cr15,unaff_r8);
    (*(code *)(uVar11 >> 0x1d))(iVar9,*(undefined1 *)(iVar9 + 0xb));
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar7 = &stack0x000000c8;
  iVar2 = (int)puVar5 + -3;
  if (iVar2 != 0) {
    puVar8 = (undefined4 *)(unaff_r5 & 0xffff);
    uVar3 = *puVar5;
    uVar6 = puVar5[2];
    uVar4 = *(undefined4 *)(iVar2 + puVar5[1]);
    if (iVar2 * 0x80000 < 0 != SBORROW4((int)puVar5,3)) {
      *puVar8 = uVar3;
      puVar8[1] = uVar6;
      puVar8[2] = iVar2 * 0x80000;
      uVar3 = (*unaff_r8)(iVar2,uVar3,uVar4);
      coprocessor_function(6,7,3,in_cr4,in_cr6,in_cr9);
      coprocessor_load(1,in_cr8,uVar3);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar2 = *(int *)((char)puStack00000164[(uint)(in_r1 >> 0xe) >> 0x1c] + 0x5c);
  if (in_stack_00000398 == 0) {
    *(undefined4 **)(iVar9 + 0x70) = puVar5;
    puVar7 = &stack0x000000e0;
    iVar9 = in_stack_000000d8 + 0xde;
    iVar2 = in_stack_000000cc;
    puVar5 = in_stack_000000d4;
  }
  else {
    iVar9 = (in_stack_00000398 >> 0x16) << 0x11;
  }
  *(short *)(iVar9 + iVar2) = (short)puVar5;
  *(undefined1 **)(puVar7 + 0x3b8) = puVar7 + 0x29c;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002ca402)
// WARNING: Removing unreachable block (ram,0x002ca406)
// WARNING: Removing unreachable block (ram,0x002caeee)
// WARNING: Removing unreachable block (ram,0x002cafdc)
// WARNING: Removing unreachable block (ram,0x002ca3f2)
// WARNING: Removing unreachable block (ram,0x002ca466)
// WARNING: Removing unreachable block (ram,0x002ca4e4)
// WARNING: Removing unreachable block (ram,0x002ca4b8)
// WARNING: Removing unreachable block (ram,0x002ca4ee)
// WARNING: Removing unreachable block (ram,0x002ca3fa)
// WARNING: Removing unreachable block (ram,0x002ca4c8)
// WARNING: Removing unreachable block (ram,0x002ca562)
// WARNING: Removing unreachable block (ram,0x002ca620)
// WARNING: Removing unreachable block (ram,0x002ca706)
// WARNING: Removing unreachable block (ram,0x002ca628)
// WARNING: Removing unreachable block (ram,0x002ca672)
// WARNING: Removing unreachable block (ram,0x002ca676)
// WARNING: Removing unreachable block (ram,0x002ca67e)
// WARNING: Removing unreachable block (ram,0x002ca83e)
// WARNING: Removing unreachable block (ram,0x002ca850)
// WARNING: Removing unreachable block (ram,0x002ca82c)
// WARNING: Removing unreachable block (ram,0x002ca83a)
// WARNING: Removing unreachable block (ram,0x002ca57c)
// WARNING: Removing unreachable block (ram,0x002ca580)
// WARNING: Removing unreachable block (ram,0x002ca5cc)
// WARNING: Removing unreachable block (ram,0x002ca582)
// WARNING: Removing unreachable block (ram,0x002ca66c)
// WARNING: Removing unreachable block (ram,0x002ca5e2)
// WARNING: Removing unreachable block (ram,0x002cac8a)
// WARNING: Removing unreachable block (ram,0x002cacf0)
// WARNING: Removing unreachable block (ram,0x002cad02)
// WARNING: Removing unreachable block (ram,0x002cae00)
// WARNING: Removing unreachable block (ram,0x002cad12)
// WARNING: Removing unreachable block (ram,0x002cad14)
// WARNING: Removing unreachable block (ram,0x002caff8)
// WARNING: Removing unreachable block (ram,0x002caccc)
// WARNING: Removing unreachable block (ram,0x002cac8e)
// WARNING: Removing unreachable block (ram,0x002cac0a)
// WARNING: Removing unreachable block (ram,0x002cabe0)
// WARNING: Removing unreachable block (ram,0x002ca8f2)
// WARNING: Removing unreachable block (ram,0x002ca972)
// WARNING: Removing unreachable block (ram,0x002ca8fa)
// WARNING: Removing unreachable block (ram,0x002cac3c)
// WARNING: Removing unreachable block (ram,0x002cac4e)
// WARNING: Removing unreachable block (ram,0x002cac50)
// WARNING: Removing unreachable block (ram,0x002cac16)
// WARNING: Removing unreachable block (ram,0x002cab9e)
// WARNING: Removing unreachable block (ram,0x002cac18)
// WARNING: Removing unreachable block (ram,0x002cac2c)
// WARNING: Removing unreachable block (ram,0x002cbaac)
// WARNING: Removing unreachable block (ram,0x002cb35c)
// WARNING: Removing unreachable block (ram,0x002ca444)
// WARNING: Removing unreachable block (ram,0x002ca3ec)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_002ca474(int param_1,int param_2)

{
  undefined4 unaff_r4;
  int unaff_r5;
  int unaff_r7;
  char in_OV;
  
  if (unaff_r5 == 0) {
    if (in_OV != '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    param_1 = param_1 >> 0x15;
    *(int *)param_2 = param_2;
    *(undefined4 *)(param_2 + 4) = 0;
    *(undefined4 *)(param_2 + 8) = unaff_r4;
    *(int *)param_1 = param_1;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_r7;
    if (unaff_r5 >> 0x1a != -0xbd) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    *(short *)(unaff_r7 + 0x1c) = (short)(unaff_r5 >> 0x1a);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_unexpected(void (*)())

void std::set_unexpected(_func_void *param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// std::set_terminate(void (*)())

void std::set_terminate(_func_void *param_1)

{
  code *pcVar1;
  
                    // WARNING: Does not return
  pcVar1 = (code *)software_udf(0xe9,0x2ca4fe);
  (*pcVar1)();
}



// WARNING: Control flow encountered bad instruction data

void __cxa_demangle(undefined4 param_1,int param_2)

{
  undefined1 unaff_r4;
  int unaff_r7;
  
  *(undefined1 *)(param_2 + 5) = unaff_r4;
  *(short *)(unaff_r7 + 0xe) = (short)(unaff_r7 >> 0xc) + 0xaa;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_002d1e9c(int param_1)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  int unaff_r4;
  undefined2 unaff_r5;
  int *piVar5;
  uint unaff_r7;
  undefined4 unaff_r9;
  undefined4 in_cr2;
  undefined4 in_cr3;
  int in_stack_00000004;
  undefined4 in_stack_000001d4;
  
  *(undefined2 *)(param_1 + 0x2e) = unaff_r5;
  uVar2 = _DAT_00000070;
  piVar5 = *(int **)(unaff_r4 + 0x1c);
  uVar3 = *(uint *)(unaff_r4 + 4);
  uVar1 = uVar3 & 0x1f;
  coprocessor_load(0xd,in_cr2,unaff_r9);
  coprocessor_loadlong(0xd,in_cr3,in_stack_000001d4);
  uVar4 = (uint)_DAT_00000070;
  *(undefined1 *)(((unaff_r7 >> uVar1 | unaff_r7 << 0x20 - uVar1) & 0xb4) + 0x14) = 0xb4;
  *piVar5 = (int)&stack0x00000304;
  piVar5[1] = uVar3;
  piVar5[2] = (uint)(uVar2 >> 4);
  piVar5[3] = (int)piVar5;
  if (uVar2 >> 4 == 0) {
    *(undefined2 *)(uVar4 + 0x28) = 0xb4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iRam00000000 = in_stack_00000004;
  uRam00000008 = 0xb4;
  uRam00000004 = uVar4;
  *(int *)(in_stack_00000004 + 8) = in_stack_00000004;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __gxx_personality_v0(int param_1)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  int unaff_r4;
  undefined2 unaff_r5;
  int *piVar5;
  uint unaff_r7;
  undefined4 unaff_r9;
  undefined4 in_cr2;
  undefined4 in_cr3;
  int in_stack_00000004;
  undefined4 in_stack_000001d4;
  
  *(undefined2 *)(param_1 + 0x2e) = unaff_r5;
  uVar2 = _DAT_00000070;
  piVar5 = *(int **)(unaff_r4 + 0x1c);
  uVar3 = *(uint *)(unaff_r4 + 4);
  uVar1 = uVar3 & 0x1f;
  coprocessor_load(0xd,in_cr2,unaff_r9);
  coprocessor_loadlong(0xd,in_cr3,in_stack_000001d4);
  uVar4 = (uint)_DAT_00000070;
  *(undefined1 *)(((unaff_r7 >> uVar1 | unaff_r7 << 0x20 - uVar1) & 0xb4) + 0x14) = 0xb4;
  *piVar5 = (int)&stack0x00000304;
  piVar5[1] = uVar3;
  piVar5[2] = (uint)(uVar2 >> 4);
  piVar5[3] = (int)piVar5;
  if (uVar2 >> 4 == 0) {
    *(undefined2 *)(uVar4 + 0x28) = 0xb4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iRam00000000 = in_stack_00000004;
  uRam00000008 = 0xb4;
  uRam00000004 = uVar4;
  *(int *)(in_stack_00000004 + 8) = in_stack_00000004;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_call_unexpected
               (int param_1,int param_2,int param_3,int param_4,undefined4 param_5,
               undefined2 param_6,int param_7)

{
  code *pcVar1;
  ushort uVar2;
  int iVar3;
  int unaff_r4;
  int unaff_r5;
  undefined4 *puVar4;
  int *unaff_r7;
  char in_NG;
  char in_OV;
  
  *(int *)(param_2 + 0x68) = param_3;
  if (in_NG != in_OV) {
    if (param_2 >> 10 == 0 || param_2 >> 10 < 0 != (bool)in_OV) {
      *(undefined2 *)(param_7 + 0x3c) = param_6;
      *(char *)(param_7 + 0x1c) = (char)param_7;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if ((param_2 >> 9 & 1U) == 0) {
      DAT_0000001b = (char)param_2;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar3 = (int)*(char *)(param_4 + -0x53 + param_3);
  *(int *)(param_1 + 0x20) = iVar3;
  if (unaff_r5 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar2 = *(ushort *)(iVar3 + 0x2a);
  if (!SBORROW4(iVar3 + -0x8e,0x3c)) {
    *unaff_r7 = param_1;
    unaff_r7[1] = unaff_r4;
    unaff_r7[2] = (int)unaff_r7;
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x75,0x2d2164);
    (*pcVar1)();
  }
  *(short *)(param_2 + 0x116) = (short)*(char *)(uVar2 + 0xae);
  puVar4 = *(undefined4 **)((int)unaff_r7 * 0x10 + 0xab);
  if (-1 < (int)unaff_r7 * 0x10) {
    *puVar4 = 0xab;
    puVar4[1] = uVar2 + 3;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void __dynamic_cast(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  int in_pc;
  bool bVar1;
  undefined4 in_cr10;
  int in_stack_00000174;
  undefined4 *in_stack_000003c4;
  
  bVar1 = 0x7f < param_3;
  coprocessor_load(0xd,in_cr10,in_pc + 0xfc);
  if (-1 < (int)(param_3 - 0x80)) {
    *(undefined4 *)(in_stack_00000174 + 0x70) = param_4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  func_0x00841d10();
  if (!bVar1) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(param_3 + in_stack_000003c4[2]) = (short)*in_stack_000003c4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_pure_virtual(undefined4 param_1,uint param_2)

{
  software_interrupt(0x12);
  _DAT_2a702c70 = 0x1638;
  *(undefined2 *)((param_2 & 0xffffca7f) + 0x3e) = 0x1638;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cxa_deleted_virtual(void)

{
  int in_r3;
  
  software_interrupt(0x12);
  _DAT_2a702c70 = 0x1638;
  *(undefined2 *)(in_r3 + 0x3e) = 0x1638;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::exception::what() const

void std::exception::what(void)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  int in_r0;
  uint uVar4;
  undefined1 *in_r1;
  int in_r2;
  int iVar5;
  int in_r3;
  uint unaff_r4;
  int unaff_r7;
  undefined4 in_lr;
  char in_OV;
  char cVar6;
  undefined4 in_cr5;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined2 in_stack_00000054;
  int in_stack_00000074;
  undefined4 in_stack_000000f4;
  int in_stack_00000324;
  
  *(char *)(in_r2 + in_r0) = (char)unaff_r7;
  *in_r1 = (char)in_r0;
  uVar4 = unaff_r4 >> 0x13;
  if ((unaff_r4 >> 0x12 & 1) == 0 || uVar4 == 0) {
    *(char *)(in_r3 + (uint)_DAT_9dec3739) = (char)unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(uint *)(in_r3 + 0x40) = unaff_r4;
  if (uVar4 != 0 && in_OV == '\0') {
    *(undefined4 *)(uVar4 + 0x48) = 0x9dec3727;
    *(char *)(unaff_r7 + in_r2) = (char)unaff_r4;
    *(short *)(in_r1 + 0x1e) = (short)in_r3;
    *(undefined2 *)(in_r1 + 0x1c) = in_stack_00000054;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uRam9dec3729 = (undefined2)in_stack_000000f4;
  *(undefined4 *)(in_r1 + 0x14) = in_stack_000000f4;
  bVar2 = *(byte *)(in_stack_00000074 + 0x1e);
  if (((uint)in_r1 & 0x4000) == 0) {
    *(char *)(in_stack_00000074 + 0x1f) = (char)in_stack_00000074;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(bad_alloc::what + in_r3))();
    return;
  }
  iVar5 = in_r3 + -0xd;
  if (iVar5 < 0) {
    cVar6 = SBORROW4(in_stack_00000074,0x7c);
    *(int *)((uint)bVar2 + iVar5) = iVar5;
    coprocessor_storelong(6,in_cr5,in_lr);
    iVar3 = func_0x01067cd8((uint)bVar2,unaff_r7 << 0x1d);
    if (cVar6 == '\0') {
                    // WARNING: Does not return
      pcVar1 = (code *)software_udf(0xfb,0x2be968);
      (*pcVar1)();
    }
    *(char *)(iVar3 + 0x1a) = (char)unaff_r7;
    coprocessor_movefromRt(0xe,7,0,in_cr15,in_cr13);
    *(undefined1 *)(in_r2 * 0x2000000) = 0;
    if ((in_r2 >> 0x23 & 1U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    do {
      *(undefined2 *)(iVar5 + 0x18) = 0xfbde;
      iVar5 = iVar5 + -0x22;
    } while (-1 < iVar5);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(int *)in_stack_00000324 = in_stack_00000324;
  *(int *)(in_stack_00000324 + 4) = in_r2;
  *(undefined4 *)(in_stack_00000324 + 8) = 0x9dec3727;
  *(int *)(in_stack_00000324 + 0xc) = in_stack_00000074;
  *(int *)(in_stack_00000324 + 0x10) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_exception::~bad_exception()

void __thiscall std::bad_exception::~bad_exception(bad_exception *this)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  uint in_r1;
  int in_r2;
  int iVar4;
  int in_r3;
  undefined4 unaff_r4;
  int unaff_r5;
  int unaff_r7;
  undefined4 in_lr;
  char in_NG;
  bool in_ZR;
  char in_OV;
  char cVar5;
  undefined4 in_cr5;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined2 in_stack_00000054;
  int in_stack_00000074;
  undefined4 in_stack_000000f4;
  int in_stack_00000324;
  
  *(undefined4 *)(in_r3 + 0x40) = unaff_r4;
  if (!in_ZR && in_NG == in_OV) {
    *(int *)(this + 0x48) = unaff_r5;
    *(char *)(unaff_r7 + in_r2) = (char)unaff_r4;
    *(short *)(in_r1 + 0x1e) = (short)in_r3;
    *(undefined2 *)(in_r1 + 0x1c) = in_stack_00000054;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r5 + 2) = (short)in_stack_000000f4;
  *(undefined4 *)(in_r1 + 0x14) = in_stack_000000f4;
  bVar2 = *(byte *)(in_stack_00000074 + 0x1e);
  if ((in_r1 & 0x4000) == 0) {
    *(char *)(in_stack_00000074 + 0x1f) = (char)in_stack_00000074;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(bad_alloc::what + in_r3))();
    return;
  }
  iVar4 = in_r3 + -0xd;
  if (-1 < iVar4) {
    *(int *)in_stack_00000324 = in_stack_00000324;
    *(int *)(in_stack_00000324 + 4) = in_r2;
    *(int *)(in_stack_00000324 + 8) = unaff_r5;
    *(int *)(in_stack_00000324 + 0xc) = in_stack_00000074;
    *(int *)(in_stack_00000324 + 0x10) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar5 = SBORROW4(in_stack_00000074,0x7c);
  *(int *)((uint)bVar2 + iVar4) = iVar4;
  coprocessor_storelong(6,in_cr5,in_lr);
  iVar3 = func_0x01067cd8((uint)bVar2,unaff_r7 << 0x1d);
  if (cVar5 == '\0') {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xfb,0x2be968);
    (*pcVar1)();
  }
  *(char *)(iVar3 + 0x1a) = (char)unaff_r7;
  coprocessor_movefromRt(0xe,7,0,in_cr15,in_cr13);
  *(undefined1 *)(in_r2 * 0x2000000) = 0;
  if ((in_r2 >> 0x23 & 1U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    *(undefined2 *)(iVar4 + 0x18) = 0xfbde;
    iVar4 = iVar4 + -0x22;
  } while (-1 < iVar4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_exception::what() const

void std::bad_exception::what(void)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  int in_r0;
  uint in_r1;
  int in_r2;
  int iVar4;
  int in_r3;
  undefined1 unaff_r4;
  int unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_lr;
  char in_NG;
  bool in_ZR;
  char in_OV;
  char cVar5;
  undefined4 in_cr5;
  undefined4 in_cr13;
  undefined4 in_cr15;
  undefined2 in_stack_00000054;
  undefined4 in_stack_000000f4;
  int in_stack_00000324;
  
  if (!in_ZR && in_NG == in_OV) {
    *(int *)(in_r0 + 0x48) = unaff_r5;
    *(undefined1 *)(unaff_r7 + in_r2) = unaff_r4;
    *(short *)(in_r1 + 0x1e) = (short)in_r3;
    *(undefined2 *)(in_r1 + 0x1c) = in_stack_00000054;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(short *)(unaff_r5 + 2) = (short)in_stack_000000f4;
  *(undefined4 *)(in_r1 + 0x14) = in_stack_000000f4;
  bVar2 = *(byte *)(unaff_r6 + 0x1e);
  if ((in_r1 & 0x4000) == 0) {
    *(char *)(unaff_r6 + 0x1f) = (char)unaff_r6;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(bad_alloc::what + in_r3))();
    return;
  }
  iVar4 = in_r3 + -0xd;
  if (-1 < iVar4) {
    *(int *)in_stack_00000324 = in_stack_00000324;
    *(int *)(in_stack_00000324 + 4) = in_r2;
    *(int *)(in_stack_00000324 + 8) = unaff_r5;
    *(int *)(in_stack_00000324 + 0xc) = unaff_r6;
    *(int *)(in_stack_00000324 + 0x10) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar5 = SBORROW4(unaff_r6,0x7c);
  *(int *)((uint)bVar2 + iVar4) = iVar4;
  coprocessor_storelong(6,in_cr5,in_lr);
  iVar3 = func_0x01067cd8((uint)bVar2,unaff_r7 << 0x1d);
  if (cVar5 == '\0') {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xfb,0x2be968);
    (*pcVar1)();
  }
  *(char *)(iVar3 + 0x1a) = (char)unaff_r7;
  coprocessor_movefromRt(0xe,7,0,in_cr15,in_cr13);
  *(undefined1 *)(in_r2 * 0x2000000) = 0;
  if ((in_r2 >> 0x23 & 1U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    *(undefined2 *)(iVar4 + 0x18) = 0xfbde;
    iVar4 = iVar4 + -0x22;
  } while (-1 < iVar4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_alloc::bad_alloc()

void __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  int in_r2;
  int iVar4;
  int in_r3;
  undefined4 unaff_r5;
  int unaff_r6;
  int unaff_r7;
  undefined4 in_lr;
  char in_CY;
  char cVar5;
  undefined4 in_cr5;
  undefined4 in_cr13;
  undefined4 in_cr15;
  int in_stack_00000324;
  
  bVar2 = *(byte *)(unaff_r6 + 0x1e);
  if (in_CY == '\0') {
    *(char *)(unaff_r6 + 0x1f) = (char)unaff_r6;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(what + in_r3))();
    return;
  }
  iVar4 = in_r3 + -0xd;
  if (-1 < iVar4) {
    *(int *)in_stack_00000324 = in_stack_00000324;
    *(int *)(in_stack_00000324 + 4) = in_r2;
    *(undefined4 *)(in_stack_00000324 + 8) = unaff_r5;
    *(int *)(in_stack_00000324 + 0xc) = unaff_r6;
    *(int *)(in_stack_00000324 + 0x10) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar5 = SBORROW4(unaff_r6,0x7c);
  *(int *)((uint)bVar2 + iVar4) = iVar4;
  coprocessor_storelong(6,in_cr5,in_lr);
  iVar3 = func_0x01067cd8((uint)bVar2,unaff_r7 << 0x1d);
  if (cVar5 == '\0') {
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0xfb,0x2be968);
    (*pcVar1)();
  }
  *(char *)(iVar3 + 0x1a) = (char)unaff_r7;
  coprocessor_movefromRt(0xe,7,0,in_cr15,in_cr13);
  *(undefined1 *)(in_r2 * 0x2000000) = 0;
  if ((in_r2 >> 0x23 & 1U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    *(undefined2 *)(iVar4 + 0x18) = 0xfbde;
    iVar4 = iVar4 + -0x22;
  } while (-1 < iVar4);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::bad_alloc::~bad_alloc()

void __thiscall std::bad_alloc::~bad_alloc(bad_alloc *this)

{
  int in_r3;
  
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(what + in_r3))();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d397a)
// WARNING: Removing unreachable block (ram,0x002d38aa)
// WARNING: Removing unreachable block (ram,0x002d37d8)
// WARNING: Removing unreachable block (ram,0x002d38b6)
// WARNING: Removing unreachable block (ram,0x002d38ba)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_alloc::what() const

undefined8 std::bad_alloc::what(void)

{
  byte bVar1;
  short sVar2;
  undefined1 auVar3 [16];
  uint in_r0;
  int *piVar4;
  int in_r1;
  int iVar5;
  int in_r2;
  int in_r3;
  uint uVar6;
  undefined4 *puVar7;
  int iVar8;
  uint unaff_r5;
  uint uVar9;
  int unaff_r6;
  undefined4 uVar10;
  uint *unaff_r7;
  undefined1 *puVar11;
  int unaff_r9;
  undefined4 in_r12;
  uint in_pc;
  bool bVar12;
  undefined4 in_cr9;
  undefined4 in_cr13;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 in_d27;
  undefined8 in_d30;
  undefined8 uVar13;
  undefined4 uStack_f4;
  
  if (in_r3 != 0) {
    *(int *)(in_r3 + unaff_r6) = in_r1;
    *(short *)(in_r2 + 0x34) = (short)unaff_r7;
    *(char *)(in_r3 + in_r1 + 0x51) = (char)unaff_r5;
    *(char *)(unaff_r6 + 0x1f) = (char)unaff_r6;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar13 = (*(what + in_r3))(in_r0,&stack0x00000088);
    return uVar13;
  }
  uVar6 = *(ushort *)(in_r0 + 0x12) & in_r0;
  VectorMultiplyAddLongVector(in_d30,in_d27,1);
  uVar9 = unaff_r7[3];
  iVar8 = *(int *)(in_r2 + in_r1);
  if ((unaff_r5 >> 0x18 & 1) == 0 || uVar6 == 0) {
    coprocessor_storelong(0xe,in_cr13,unaff_r9 + 0x238);
    uVar9 = in_r0 - 2;
    *unaff_r7 = unaff_r5 >> 0x19;
    unaff_r7[1] = in_pc;
    iVar8 = *(int *)((unaff_r5 >> 0x19) + 4);
    in_r1 = *(int *)(uVar6 + 4);
    in_r2 = *(int *)(uVar6 + 8);
  }
  *(char *)(iVar8 + 0xc) = (char)*(undefined2 *)(iVar8 + 10);
  *(int *)(in_r1 + -0x3fa7d603) = in_r2;
  uVar6 = (uint)*(byte *)(in_r1 + -0x3fa7d603);
  iVar8 = *(int *)(uVar6 + 4);
  if (0xffffffc3 < uVar9) {
    *(char *)(*(int *)(uVar6 + 8) + 9) = (char)iVar8;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!SBORROW4(*(int *)(uVar6 + 8),0x96)) {
    *(undefined4 *)(iVar8 + (uint)_DAT_0174daa5) = *(undefined4 *)(uVar6 + 0x10);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  DAT_5fafc8fe = (undefined1)*(undefined4 *)(uVar6 + 0x10);
  *(undefined2 *)(__bad_typeid + 0x38) = 0xdbca;
  puVar11 = &stack0x00000030;
  if (SBORROW4(iVar8,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_5907dc46 = __bad_typeid;
  bVar12 = SCARRY4(__bad_typeid,0xf5);
  if (0xffffff0a < __bad_typeid) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    software_interrupt(0xa7);
    piVar4 = (int *)((int)puVar11 * 0x8000000);
    if (bVar12) {
      coprocessor_store(0xd,in_cr14,piVar4 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar8 = *piVar4;
    iVar5 = piVar4[1];
    sVar2 = *(short *)(piVar4[3] + piVar4[4]);
    puVar11 = (undefined1 *)(int)sVar2;
    if (!bVar12) break;
    if (iVar5 * piVar4[2] != 0 && iVar5 * piVar4[2] < 0 == bVar12) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  auVar3._8_8_ = unaff_d13;
  auVar3._0_8_ = unaff_d12;
  uVar13 = VectorShiftRightNarrow(auVar3,5,1,0);
  SatQ(uVar13,1,0);
  DAT_782345c0 = (undefined1)iVar8;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  _DAT_7f4ff773 = sVar2;
  puVar7 = *(undefined4 **)(iVar8 + 4);
  uVar10 = *(undefined4 *)(iVar8 + 8);
  if (SBORROW4(iVar8,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar5 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar7 = 0x8d168400;
  puVar7[1] = iVar5;
  puVar7[2] = puVar7;
  puVar7[3] = 0x782345a1;
  puVar7[4] = uVar10;
  puVar7[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar7 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar5 + 0x782344ab) = 0x3cdc;
  if (-1 < iVar5 + -0xf6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(uStack_f4,0x8d168400);
}



// std::bad_array_new_length::bad_array_new_length()

void __thiscall std::bad_array_new_length::bad_array_new_length(bad_array_new_length *this)

{
  int in_r3;
  int unaff_r6;
  
  *(char *)(unaff_r6 + 0x1f) = (char)unaff_r6;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(bad_alloc::what + in_r3))(this,&stack0x00000088);
  return;
}



// WARNING: Control flow encountered bad instruction data
// std::bad_array_new_length::~bad_array_new_length()

void __thiscall std::bad_array_new_length::~bad_array_new_length(bad_array_new_length *this)

{
  int in_r3;
  undefined1 unaff_r4;
  int unaff_r7;
  
  *(undefined1 *)(in_r3 + unaff_r7) = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d3994)
// WARNING: Removing unreachable block (ram,0x002d3a06)
// WARNING: Removing unreachable block (ram,0x002d3a0c)
// WARNING: Removing unreachable block (ram,0x002d39f0)
// WARNING: Removing unreachable block (ram,0x002d3936)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::domain_error::~domain_error()

undefined4 __thiscall std::domain_error::~domain_error(domain_error *this)

{
  byte bVar1;
  undefined1 auVar2 [16];
  int iVar3;
  undefined4 uVar4;
  int in_r2;
  int in_r3;
  undefined4 *puVar5;
  int unaff_r4;
  int unaff_r6;
  undefined1 unaff_r7;
  undefined4 in_r12;
  char in_NG;
  char in_ZR;
  char in_OV;
  undefined4 in_cr9;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar6;
  ulonglong uVar7;
  
  if (in_ZR == '\0') {
    if (in_NG == in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar7 = func_0x01016478();
  *(short *)(in_r3 + unaff_r6) = (short)uVar7;
  if (0x16ffffffff < uVar7) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (&stack0x0000019c != (undefined1 *)0x0) {
    uVar4 = *(undefined4 *)(((uint)uVar7 >> 0x18) + unaff_r4);
    *(char *)(in_r2 + 0x1a) = (char)&stack0x0000019c;
    return uVar4;
  }
  *(undefined1 *)(in_r2 + 0x13) = unaff_r7;
  if (SBORROW4(in_r3,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(undefined4 *)((int)(uVar7 >> 0x20) + 0x7c) = 0;
  iVar3 = iRam80000004;
  software_interrupt(0xa7);
  _DAT_7f4ff773 = *(undefined2 *)(iRam8000000c + iRam80000010);
  auVar2._8_8_ = unaff_d13;
  auVar2._0_8_ = unaff_d12;
  uVar6 = VectorShiftRightNarrow(auVar2,5,1,0);
  SatQ(uVar6,1,0);
  DAT_782345c0 = (undefined1)iRam80000000;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  puVar5 = *(undefined4 **)(iRam80000000 + 4);
  uVar4 = *(undefined4 *)(iRam80000000 + 8);
  if (SBORROW4(iRam80000000,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iRam80000004 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar5 = 0x8d168400;
  puVar5[1] = iVar3;
  puVar5[2] = puVar5;
  puVar5[3] = 0x782345a1;
  puVar5[4] = uVar4;
  puVar5[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar5 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar3 + 0x782344ab) = 0x3cdc;
  if (iVar3 + -0xf6 < 0) {
    return 0x8d168400;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::logic_error::~logic_error()

void __thiscall std::logic_error::~logic_error(logic_error *this)

{
  undefined4 unaff_r4;
  int unaff_r7;
  
  *(short *)(unaff_r7 + 0xe) = (short)unaff_r4;
                    // WARNING: Read-only address (ram,0x002d3b24) is written
  uRam002d3b24 = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d397a)
// WARNING: Removing unreachable block (ram,0x002d38aa)
// WARNING: Removing unreachable block (ram,0x002d37d8)
// WARNING: Removing unreachable block (ram,0x002d38b6)
// WARNING: Removing unreachable block (ram,0x002d38ba)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::logic_error::what() const

undefined8 std::logic_error::what(void)

{
  byte bVar1;
  short sVar2;
  undefined1 auVar3 [16];
  int *piVar4;
  int iVar5;
  int iVar6;
  int in_r3;
  undefined4 *puVar7;
  int unaff_r4;
  undefined4 uVar8;
  undefined4 unaff_r7;
  int iVar9;
  undefined4 in_r12;
  bool bVar10;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar11;
  undefined4 uStack_f4;
  
  if (!SBORROW4(unaff_r4,0x96)) {
    *(undefined4 *)(in_r3 + (uint)_DAT_0174daa5) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Read-only address (ram,0x002d39fc) is written
  bad_typeid::bad_typeid = 0x5907dbca;
  DAT_5fafc8fe = (undefined1)unaff_r7;
  *(undefined2 *)(__bad_typeid + 0x38) = 0xdbca;
  iVar9 = 0x30;
  if (SBORROW4(in_r3,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_5907dc46 = __bad_typeid;
  bVar10 = SCARRY4(__bad_typeid,0xf5);
  if (0xffffff0a < __bad_typeid) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    software_interrupt(0xa7);
    piVar4 = (int *)(iVar9 * 0x8000000);
    if (bVar10) {
      coprocessor_store(0xd,in_cr14,piVar4 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar5 = *piVar4;
    iVar6 = piVar4[1];
    sVar2 = *(short *)(piVar4[3] + piVar4[4]);
    iVar9 = (int)sVar2;
    if (!bVar10) break;
    if (iVar6 * piVar4[2] != 0 && iVar6 * piVar4[2] < 0 == bVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  auVar3._8_8_ = unaff_d13;
  auVar3._0_8_ = unaff_d12;
  uVar11 = VectorShiftRightNarrow(auVar3,5,1,0);
  SatQ(uVar11,1,0);
  DAT_782345c0 = (undefined1)iVar5;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  _DAT_7f4ff773 = sVar2;
  puVar7 = *(undefined4 **)(iVar5 + 4);
  uVar8 = *(undefined4 *)(iVar5 + 8);
  if (SBORROW4(iVar5,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar6 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar7 = 0x8d168400;
  puVar7[1] = iVar6;
  puVar7[2] = puVar7;
  puVar7[3] = 0x782345a1;
  puVar7[4] = uVar8;
  puVar7[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar7 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar6 + 0x782344ab) = 0x3cdc;
  if (-1 < iVar6 + -0xf6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(uStack_f4,0x8d168400);
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d397a)
// WARNING: Removing unreachable block (ram,0x002d38aa)
// WARNING: Removing unreachable block (ram,0x002d37d8)
// WARNING: Removing unreachable block (ram,0x002d38b6)
// WARNING: Removing unreachable block (ram,0x002d38ba)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::underflow_error::~underflow_error()

undefined8 __thiscall std::underflow_error::~underflow_error(underflow_error *this)

{
  byte bVar1;
  short sVar2;
  undefined1 auVar3 [16];
  int *piVar4;
  int iVar5;
  int iVar6;
  int in_r3;
  undefined4 *puVar7;
  undefined4 uVar8;
  undefined4 unaff_r7;
  int iVar9;
  undefined4 in_r12;
  char in_OV;
  bool bVar10;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar11;
  undefined4 uStack_f4;
  
  if (in_OV == '\0') {
    *(undefined4 *)(in_r3 + (uint)_DAT_0174daa5) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Read-only address (ram,0x002d39fc) is written
  bad_typeid::bad_typeid = 0x5907dbca;
  DAT_5fafc8fe = (undefined1)unaff_r7;
  *(undefined2 *)(__bad_typeid + 0x38) = 0xdbca;
  iVar9 = 0x30;
  if (SBORROW4(in_r3,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _DAT_5907dc46 = __bad_typeid;
  bVar10 = SCARRY4(__bad_typeid,0xf5);
  if (0xffffff0a < __bad_typeid) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    software_interrupt(0xa7);
    piVar4 = (int *)(iVar9 * 0x8000000);
    if (bVar10) {
      coprocessor_store(0xd,in_cr14,piVar4 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar5 = *piVar4;
    iVar6 = piVar4[1];
    sVar2 = *(short *)(piVar4[3] + piVar4[4]);
    iVar9 = (int)sVar2;
    if (!bVar10) break;
    if (iVar6 * piVar4[2] != 0 && iVar6 * piVar4[2] < 0 == bVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  auVar3._8_8_ = unaff_d13;
  auVar3._0_8_ = unaff_d12;
  uVar11 = VectorShiftRightNarrow(auVar3,5,1,0);
  SatQ(uVar11,1,0);
  DAT_782345c0 = (undefined1)iVar5;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  _DAT_7f4ff773 = sVar2;
  puVar7 = *(undefined4 **)(iVar5 + 4);
  uVar8 = *(undefined4 *)(iVar5 + 8);
  if (SBORROW4(iVar5,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar6 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar7 = 0x8d168400;
  puVar7[1] = iVar6;
  puVar7[2] = puVar7;
  puVar7[3] = 0x782345a1;
  puVar7[4] = uVar8;
  puVar7[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar7 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar6 + 0x782344ab) = 0x3cdc;
  if (-1 < iVar6 + -0xf6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(uStack_f4,0x8d168400);
}



// WARNING: Control flow encountered bad instruction data
// std::runtime_error::~runtime_error()

void __thiscall std::runtime_error::~runtime_error(runtime_error *this)

{
  int in_r1;
  int in_r2;
  int in_r3;
  undefined1 unaff_r4;
  int unaff_r5;
  int unaff_r6;
  int *unaff_r7;
  undefined2 in_stack_00000054;
  
  *unaff_r7 = in_r1;
  unaff_r7[1] = in_r2;
  unaff_r7[2] = unaff_r5;
  unaff_r7[3] = unaff_r6;
  *(undefined2 *)(in_r3 + 0x12) = 0;
  *(undefined1 *)((int)unaff_r7 + 0x12) = 0;
  *(int *)(this + 0x48) = unaff_r5;
  *(undefined1 *)((int)unaff_r7 + in_r2 + 0x10) = unaff_r4;
  *(short *)(in_r1 + 0x1e) = (short)in_r3;
  *(undefined2 *)(in_r1 + 0x1c) = in_stack_00000054;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::runtime_error::what() const

void std::runtime_error::what(void)

{
  int in_r1;
  undefined2 in_stack_00000054;
  
  *(undefined2 *)(in_r1 + 0x1c) = in_stack_00000054;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::domain_error::~domain_error()

void __thiscall std::domain_error::~domain_error(domain_error *this)

{
  int in_r1;
  undefined2 unaff_r4;
  
  *(undefined2 *)(in_r1 + 0x1c) = unaff_r4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::invalid_argument::~invalid_argument()

void __thiscall std::invalid_argument::~invalid_argument(invalid_argument *this)

{
  undefined4 in_r2;
  int in_r3;
  int unaff_r5;
  int iVar1;
  int unaff_r6;
  int unaff_r7;
  char in_ZR;
  bool bVar2;
  undefined2 in_stack_0000032c;
  int in_stack_00000390;
  
  if (in_ZR != '\0') {
    *(char *)(unaff_r6 + 0x1f) = (char)unaff_r6;
                    // WARNING: Could not recover jumptable at 0x002d3878. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(bad_alloc::what + in_r3))(this,&stack0x00000088);
    return;
  }
  *(undefined4 *)(unaff_r7 + unaff_r5) = in_r2;
  bVar2 = SBORROW4((uint)*(byte *)(unaff_r6 + 0x1d),0xdc);
  iVar1 = *(byte *)(unaff_r6 + 0x1d) - 0xdc;
  if (!bVar2) {
    iVar1 = in_stack_00000390 + -0x53;
  }
  if (bVar2 || SBORROW4(in_stack_00000390,0x53)) {
    *(undefined2 *)(this + unaff_r6) = in_stack_0000032c;
  }
  if (iVar1 < 0 == (bVar2 || SBORROW4(in_stack_00000390,0x53))) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::length_error::~length_error()

void __thiscall std::length_error::~length_error(length_error *this)

{
  undefined2 unaff_r4;
  int unaff_r6;
  int unaff_r7;
  char in_NG;
  char in_OV;
  
  if (in_OV == '\0') {
    in_OV = SBORROW4(unaff_r7,0x53);
    in_NG = unaff_r7 + -0x53 < 0;
  }
  if (in_OV != '\0') {
    *(undefined2 *)(this + unaff_r6) = unaff_r4;
  }
  if (in_NG == in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::out_of_range::~out_of_range()

void __thiscall std::out_of_range::~out_of_range(out_of_range *this)

{
  int unaff_r5;
  undefined1 unaff_r7;
  
  *(undefined1 *)(unaff_r5 + 0x1c) = unaff_r7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::range_error::~range_error()

void __thiscall std::range_error::~range_error(range_error *this)

{
  ushort uVar1;
  undefined4 in_r1;
  int in_r2;
  undefined4 in_cr14;
  
  uVar1 = *(ushort *)(in_r2 + 0x38);
  *(undefined4 *)this = in_r1;
  *(uint *)(this + 4) = (uint)uVar1;
  coprocessor_store(0xd,in_cr14,this + -300);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d397a)
// WARNING: Removing unreachable block (ram,0x002d38aa)
// WARNING: Removing unreachable block (ram,0x002d37d8)
// WARNING: Removing unreachable block (ram,0x002d38b6)
// WARNING: Removing unreachable block (ram,0x002d38ba)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::overflow_error::~overflow_error()

undefined8 __thiscall std::overflow_error::~overflow_error(overflow_error *this)

{
  byte bVar1;
  undefined1 auVar2 [16];
  uint uVar3;
  uint uVar4;
  int *piVar5;
  int in_r1;
  int iVar6;
  int *in_r2;
  int in_r3;
  int iVar7;
  undefined4 *puVar8;
  uint unaff_r4;
  int unaff_r5;
  undefined4 uVar9;
  uint unaff_r7;
  undefined1 *puVar10;
  undefined4 in_r12;
  bool in_CY;
  char in_OV;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar11;
  undefined1 auStack_f4 [244];
  
  puVar10 = (undefined1 *)(unaff_r7 >> (unaff_r4 & 0x1f) | unaff_r7 << 0x20 - (unaff_r4 & 0x1f));
  if (puVar10 == (undefined1 *)0x0) {
    bVar1 = *(byte *)(unaff_r5 + 0x1a);
    *in_r2 = in_r1;
    in_r2[1] = (uint)bVar1;
    in_r2[2] = unaff_r4;
    *(char *)(unaff_r4 + 0xc) = (char)*(undefined2 *)(unaff_r4 + 10);
    *(undefined1 **)(in_r1 + -0x3fa7d603) = &stack0x00000144;
    uVar3 = __bad_typeid;
    uVar4 = (uint)*(byte *)(in_r1 + -0x3fa7d603);
    iVar7 = *(int *)(uVar4 + 4);
    if ((unaff_r4 & 0xff) == 0 && in_CY ||
        (unaff_r4 & 0xff) != 0 && ((uint)puVar10 & 0x80000000) != 0) {
      *(char *)(*(int *)(uVar4 + 8) + 9) = (char)iVar7;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (!SBORROW4(*(int *)(uVar4 + 8),0x96)) {
      *(undefined4 *)(iVar7 + (uint)_DAT_0174daa5) = *(undefined4 *)(uVar4 + 0x10);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Read-only address (ram,0x002d39fc) is written
    DAT_5fafc8fe = (undefined1)*(undefined4 *)(uVar4 + 0x10);
    *(short *)(__bad_typeid + 0x38) = (short)bad_typeid::bad_typeid;
    puVar10 = &stack0x00000030;
    if (SBORROW4(iVar7,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(uint *)(bad_typeid::bad_typeid + 0x7c) = __bad_typeid;
    in_OV = SCARRY4(uVar3,0xf5);
    register0x00000054 = (BADSPACEBASE *)auStack_f4;
    if (0xffffff0a < uVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    bad_typeid::bad_typeid = 0x5907dbca;
                    // WARNING: Read-only address (ram,0x002d39fc) is written
    if (in_r1 * in_r3 != 0 && in_r1 * in_r3 < 0 == (bool)in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  software_interrupt(0xa7);
  piVar5 = (int *)((int)puVar10 * 0x8000000);
  if (in_OV != '\0') {
    coprocessor_store(0xd,in_cr14,piVar5 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar7 = *piVar5;
  iVar6 = piVar5[1];
  _DAT_7f4ff773 = *(undefined2 *)(piVar5[3] + piVar5[4]);
  auVar2._8_8_ = unaff_d13;
  auVar2._0_8_ = unaff_d12;
  uVar11 = VectorShiftRightNarrow(auVar2,5,1,0);
  SatQ(uVar11,1,0);
  DAT_782345c0 = (undefined1)iVar7;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  puVar8 = *(undefined4 **)(iVar7 + 4);
  uVar9 = *(undefined4 *)(iVar7 + 8);
  if (SBORROW4(iVar7,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar6 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar8 = 0x8d168400;
  puVar8[1] = iVar6;
  puVar8[2] = puVar8;
  puVar8[3] = 0x782345a1;
  puVar8[4] = uVar9;
  puVar8[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar8 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar6 + 0x782344ab) = 0x3cdc;
  if (-1 < iVar6 + -0xf6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(*(undefined4 *)register0x00000054,0x8d168400);
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d397a)
// WARNING: Removing unreachable block (ram,0x002d38aa)
// WARNING: Removing unreachable block (ram,0x002d37d8)
// WARNING: Removing unreachable block (ram,0x002d38b6)
// WARNING: Removing unreachable block (ram,0x002d38ba)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::underflow_error::~underflow_error()

undefined8 __thiscall std::underflow_error::~underflow_error(underflow_error *this)

{
  byte bVar1;
  short sVar2;
  undefined1 auVar3 [16];
  uint uVar4;
  uint uVar5;
  int *piVar6;
  int in_r1;
  int iVar7;
  undefined4 in_r2;
  int iVar8;
  undefined4 *puVar9;
  int unaff_r4;
  undefined4 uVar10;
  undefined1 unaff_r7;
  int iVar11;
  undefined4 in_r12;
  char in_CY;
  bool bVar12;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar13;
  undefined4 uStack_f4;
  
  *(undefined1 *)(unaff_r4 + 0xc) = unaff_r7;
  *(undefined4 *)(in_r1 + -0x3fa7d603) = in_r2;
  uVar4 = __bad_typeid;
  uVar5 = (uint)*(byte *)(in_r1 + -0x3fa7d603);
  iVar8 = *(int *)(uVar5 + 4);
  if (in_CY != '\0') {
    *(char *)(*(int *)(uVar5 + 8) + 9) = (char)iVar8;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!SBORROW4(*(int *)(uVar5 + 8),0x96)) {
    *(undefined4 *)(iVar8 + (uint)_DAT_0174daa5) = *(undefined4 *)(uVar5 + 0x10);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Read-only address (ram,0x002d39fc) is written
  DAT_5fafc8fe = (undefined1)*(undefined4 *)(uVar5 + 0x10);
  *(short *)(__bad_typeid + 0x38) = (short)bad_typeid::bad_typeid;
  iVar11 = 0x30;
  if (SBORROW4(iVar8,0x23)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *(uint *)(bad_typeid::bad_typeid + 0x7c) = __bad_typeid;
  bVar12 = SCARRY4(uVar4,0xf5);
  if (0xffffff0a < uVar4) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    software_interrupt(0xa7);
    piVar6 = (int *)(iVar11 * 0x8000000);
    if (bVar12) {
      coprocessor_store(0xd,in_cr14,piVar6 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar8 = *piVar6;
    iVar7 = piVar6[1];
    sVar2 = *(short *)(piVar6[3] + piVar6[4]);
    iVar11 = (int)sVar2;
    if (!bVar12) break;
    if (iVar7 * piVar6[2] != 0 && iVar7 * piVar6[2] < 0 == bVar12) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  auVar3._8_8_ = unaff_d13;
  auVar3._0_8_ = unaff_d12;
  uVar13 = VectorShiftRightNarrow(auVar3,5,1,0);
  SatQ(uVar13,1,0);
  DAT_782345c0 = (undefined1)iVar8;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  _DAT_7f4ff773 = sVar2;
  puVar9 = *(undefined4 **)(iVar8 + 4);
  uVar10 = *(undefined4 *)(iVar8 + 8);
  if (SBORROW4(iVar8,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar7 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar9 = 0x8d168400;
  puVar9[1] = iVar7;
  puVar9[2] = puVar9;
  puVar9[3] = 0x782345a1;
  puVar9[4] = uVar10;
  puVar9[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar9 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar7 + 0x782344ab) = 0x3cdc;
  if (-1 < iVar7 + -0xf6) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(uStack_f4,0x8d168400);
}



// WARNING: Control flow encountered bad instruction data
// std::type_info::~type_info()

void __thiscall std::type_info::~type_info(type_info *this)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::type_info::~type_info()

void __thiscall std::type_info::~type_info(type_info *this)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::bad_cast::bad_cast()

void __thiscall std::bad_cast::bad_cast(bad_cast *this)

{
  undefined4 in_cr1;
  undefined4 in_cr4;
  undefined4 in_cr14;
  
  coprocessor_function2(9,5,7,in_cr14,in_cr4,in_cr1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::bad_cast::~bad_cast()

void __thiscall std::bad_cast::~bad_cast(bad_cast *this)

{
  undefined2 in_r3;
  int unaff_r5;
  undefined2 *unaff_r6;
  undefined4 in_cr0;
  
  *unaff_r6 = in_r3;
  coprocessor_storelong(6,in_cr0,unaff_r5 + -300);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::bad_cast::~bad_cast()

void __thiscall std::bad_cast::~bad_cast(bad_cast *this)

{
  int unaff_r5;
  undefined4 in_cr0;
  
  coprocessor_storelong(6,in_cr0,unaff_r5 + -300);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d3a06)
// WARNING: Removing unreachable block (ram,0x002d3a0c)
// WARNING: Removing unreachable block (ram,0x002d39f0)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_typeid::bad_typeid()

void __thiscall std::bad_typeid::bad_typeid(bad_typeid *this)

{
  byte bVar1;
  undefined1 auVar2 [16];
  int iVar3;
  int in_r1;
  int iVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 in_r12;
  char in_OV;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar7;
  
  if (in_OV != '\0') {
    coprocessor_store(0xd,in_cr14,this + -0x134);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar3 = *(int *)this;
  iVar4 = *(int *)(this + 4);
  _DAT_7f4ff773 = *(undefined2 *)(*(int *)(this + 0xc) + *(int *)(this + 0x10));
  auVar2._8_8_ = unaff_d13;
  auVar2._0_8_ = unaff_d12;
  uVar7 = VectorShiftRightNarrow(auVar2,5,1,0);
  SatQ(uVar7,1,0);
  DAT_782345c0 = (undefined1)iVar3;
  _DAT_00000f06 = (undefined2)*(undefined4 *)(in_r1 + 8);
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  puVar5 = *(undefined4 **)(iVar3 + 4);
  uVar6 = *(undefined4 *)(iVar3 + 8);
  if (!SBORROW4(iVar3,0xf04)) {
    bVar1 = *(byte *)(iVar4 + 8);
    _DAT_072cb1f6 = _DAT_00000f06;
    *puVar5 = 0x8d168400;
    puVar5[1] = iVar4;
    puVar5[2] = puVar5;
    puVar5[3] = 0x782345a1;
    puVar5[4] = uVar6;
    puVar5[5] = (uint)bVar1;
    *(undefined1 *)((int)puVar5 + 0xc2) = 0xc2;
    *(undefined2 *)(iVar4 + 0x782344ab) = 0x3cdc;
    if (iVar4 + -0xf6 < 0) {
      return;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x002d3a06)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// std::bad_typeid::~bad_typeid()

void __thiscall std::bad_typeid::~bad_typeid(bad_typeid *this)

{
  byte bVar1;
  undefined1 auVar2 [16];
  int *piVar3;
  int iVar4;
  int iVar5;
  int in_r1;
  int in_r3;
  undefined4 *puVar6;
  undefined4 uVar7;
  int unaff_r7;
  undefined4 in_r12;
  char in_OV;
  undefined4 in_cr9;
  undefined4 in_cr14;
  undefined8 unaff_d12;
  undefined8 unaff_d13;
  undefined8 uVar8;
  
  if (in_r1 * in_r3 != 0 && in_r1 * in_r3 < 0 == (bool)in_OV) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  software_interrupt(0xa7);
  piVar3 = (int *)(unaff_r7 * 0x8000000);
  if (in_OV != '\0') {
    coprocessor_store(0xd,in_cr14,piVar3 + -0x4d);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar4 = *piVar3;
  iVar5 = piVar3[1];
  _DAT_7f4ff773 = *(undefined2 *)(piVar3[3] + piVar3[4]);
  auVar2._8_8_ = unaff_d13;
  auVar2._0_8_ = unaff_d12;
  uVar8 = VectorShiftRightNarrow(auVar2,5,1,0);
  SatQ(uVar8,1,0);
  DAT_782345c0 = (undefined1)iVar4;
  _DAT_00000f06 = 0x87ee;
  coprocessor_loadlong(0xf,in_cr9,in_r12);
  puVar6 = *(undefined4 **)(iVar4 + 4);
  uVar7 = *(undefined4 *)(iVar4 + 8);
  if (SBORROW4(iVar4,0xf04)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar1 = *(byte *)(iVar5 + 8);
  _DAT_00000f06 = 0x87ee;
  _DAT_072cb1f6 = 0x87ee;
  *puVar6 = 0x8d168400;
  puVar6[1] = iVar5;
  puVar6[2] = puVar6;
  puVar6[3] = 0x782345a1;
  puVar6[4] = uVar7;
  puVar6[5] = (uint)bVar1;
  *(undefined1 *)((int)puVar6 + 0xc2) = 0xc2;
  *(undefined2 *)(iVar5 + 0x782344ab) = 0x3cdc;
  if (iVar5 + -0xf6 < 0) {
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// std::bad_typeid::~bad_typeid()

void __thiscall std::bad_typeid::~bad_typeid(bad_typeid *this)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// std::bad_typeid::what() const

undefined8 std::bad_typeid::what(void)

{
  int in_r0;
  int in_r1;
  undefined4 in_r2;
  undefined4 in_stack_00000000;
  
  *(undefined4 *)(in_r0 + 0xe1) = in_r2;
  return CONCAT44(in_r1 << 0x1e,in_stack_00000000);
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_002d3a3a(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  code *pcVar1;
  byte bVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined4 unaff_r5;
  int iVar7;
  int unaff_r6;
  int unaff_r7;
  undefined4 *puVar8;
  undefined4 in_cr0;
  int in_stack_000003b4;
  
  _DAT_c7b93e2c = unaff_r5;
  *(short *)(param_3 + unaff_r7) = (short)param_3;
  iVar7 = param_4 - param_3;
  *(undefined **)(param_3 + 100) = &DAT_002d3d48;
  iVar5 = _DAT_c7b93e20;
  if (param_4 < param_3 || iVar7 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar6 = (int *)(uint)*(ushort *)(&DAT_002d3d94 + _DAT_c7b93e20);
  iVar4 = (int)*(char *)((uint)*(ushort *)(param_4 + 0x2a) + (uint)*(byte *)(unaff_r6 + 4));
  if (iVar7 == 0) {
    puVar8 = (undefined4 *)(uint)*(byte *)(iVar4 + 10);
    iVar5 = *(int *)(_DAT_c7b93e20 + 4);
    iVar7 = *(int *)(_DAT_c7b93e20 + 0x10);
    iVar4 = *(int *)(_DAT_c7b93e20 + 0x14);
    *(undefined4 *)(iVar5 + 0x18) = param_1;
    *puVar8 = param_1;
    puVar8[1] = iVar5;
    puVar8[2] = iVar7;
    puVar8[3] = iVar4;
    *(short *)(puVar8 + 8) = (short)iVar7;
    if (0x42 < iVar7) {
      software_interrupt(0x38);
      puVar8 = *(undefined4 **)(iVar4 + 0x68);
      uVar3 = *puVar8;
      iVar5 = puVar8[1];
      iVar7 = puVar8[2];
      _DAT_00000052 = puVar8[5];
      bVar2 = *(byte *)(in_stack_000003b4 + 0xb);
      *(int *)(puVar8[4] + 0x60) = iVar5;
      *(char *)(iVar7 + 0x16) = (char)uVar3;
      coprocessor_storelong(10,in_cr0,in_stack_000003b4 * 0x4000 + iVar5 + -0x2d3);
      _DAT_0000004a = 0x45;
      _DAT_0000004e = &DAT_002d3db8;
      _DAT_00000056 = (uint)bVar2;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Does not return
    pcVar1 = (code *)software_udf(0x70,0x2d39d0);
    (*pcVar1)();
  }
  bVar2 = *(byte *)(_DAT_c7b93e20 + 8);
  *(ushort *)(iVar4 + 0x24) = *(ushort *)(param_4 + 0x2a);
  *piVar6 = iVar7 * 0x400;
  piVar6[1] = iVar5;
  piVar6[2] = (int)piVar6;
  piVar6[3] = iVar7;
  piVar6[4] = unaff_r6;
  piVar6[5] = (uint)bVar2;
  *(undefined1 *)((int)piVar6 + 0xc2) = 0xc2;
  iVar5 = iVar5 + -0xf6;
  *(undefined2 *)(iVar7 + iVar5) = 0x3cdc;
  if (-1 < iVar5) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return;
}



// WARNING: Control flow encountered bad instruction data

void logl(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int unaff_r6;
  int unaff_r7;
  undefined4 *puVar4;
  
  iVar2 = *(int *)(unaff_r6 + 8);
  iVar3 = *(int *)(unaff_r6 + 0xc);
  *(short *)(*(int *)(unaff_r6 + 0x10) + unaff_r7) = (short)unaff_r7;
  *(char *)(iVar2 + 0x14) = (char)unaff_r7;
  iVar1 = iVar3 * 2;
  puVar4 = (undefined4 *)(uint)*(byte *)(iVar1 + 7);
  *puVar4 = param_1;
  puVar4[1] = iVar2;
  puVar4[2] = iVar1;
  puVar4[3] = iVar3;
  puVar4[4] = puVar4;
  *(undefined4 **)(iVar2 + 0x28) = puVar4;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void _INIT_1(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int extraout_r1;
  undefined4 *unaff_r5;
  undefined4 *puVar1;
  int unaff_r10;
  undefined4 in_r12;
  undefined4 in_cr4;
  undefined4 in_cr7;
  undefined8 unaff_d11;
  undefined8 in_d29;
  
  coprocessor_moveto(4,5,3,in_r12,in_cr7,in_cr4);
  software_bkpt(0x1d);
  func_0xff859ed8(unaff_r10 + 0xeb00eb);
  puVar1 = (undefined4 *)unaff_r5[2];
  VectorShiftRightAccumulate(unaff_d11,in_d29,10);
  *puVar1 = *unaff_r5;
  puVar1[1] = param_3;
  puVar1[2] = param_4;
  puVar1[3] = &DAT_002d9cc8;
  puVar1[4] = extraout_r1 << 0x17;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void _INIT_4(undefined4 param_1,undefined4 param_2)

{
  uint unaff_r4;
  uint unaff_r5;
  undefined4 unaff_r7;
  uint unaff_r8;
  uint unaff_r10;
  undefined4 unaff_r11;
  undefined4 *in_r12;
  undefined4 in_lr;
  char in_NG;
  undefined1 in_ZR;
  byte in_CY;
  char in_OV;
  
  if (!(bool)in_NG) {
    in_CY = 0;
    in_NG = (int)(unaff_r10 ^ 0xea000) < 0;
    in_ZR = (unaff_r10 ^ 0xea000) == 0;
  }
  if (!(bool)in_ZR && in_NG == in_OV) {
    unaff_r5 = unaff_r8 | (uint)in_CY << 0x1f | unaff_r4 >> 1;
  }
  if ((bool)in_ZR) {
    *in_r12 = &UNK_002feccc;
    in_r12[-1] = in_lr;
    in_r12[-2] = unaff_r11;
    in_r12[-3] = unaff_r7;
    in_r12[-4] = unaff_r5;
    in_r12[-5] = unaff_r4;
    in_r12[-6] = param_2;
    in_r12[-7] = param_1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


