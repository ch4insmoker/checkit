#pragma once

#define EI_NIDENT   16

#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7
#define PT_LOOS    0x60000000
#define PT_HIOS    0x6fffffff
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME (PT_LOOS + 0x474e550)
#define PT_GNU_STACK    (PT_LOOS + 0x474e551)
#define PT_GNU_RELRO    (PT_LOOS + 0x474e552)
#define PT_GNU_PROPERTY (PT_LOOS + 0x474e553)

#define PF_R        0x4
#define PF_W        0x2
#define PF_X        0x1


#define DT_NULL     0        
#define DT_NEEDED   1     
#define DT_PLTRELSZ 2     
#define DT_PLTGOT   3   
#define DT_HASH     4        
#define DT_STRTAB   5   
#define DT_SYMTAB   6   
#define DT_RELA     7  
#define DT_RELASZ   8     
#define DT_RELAENT  9  
#define DT_STRSZ    10
#define DT_SYMENT   11     
#define DT_INIT     12   
#define DT_FINI     13    
#define DT_SONAME   14
#define DT_RPATH    15   
#define DT_SYMBOLIC 16   
#define DT_REL      17
#define DT_RELSZ    18   
#define DT_RELENT   19
#define DT_PLTREL   20
#define DT_DEBUG    21     
#define DT_TEXTREL  22     
#define DT_JMPREL   23  
#define DT_BIND_NOW 24
#define DT_INIT_ARRAY   25
#define DT_FINI_ARRAY   26
#define DT_INIT_ARRAYSZRAY
#define DT_FINI_ARRAYSZRAY
#define DT_RUNPATH  29
#define DT_FLAGS    30
#define DT_ENCODING 32   
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33
#define DT_SYMTAB_SHNDX 34     
#define DT_NUM      35         
#define DT_LOOS     0x6000000d 
#define DT_HIOS     0x6ffff000 
#define DT_LOPROC   0x70000000 
#define DT_HIPROC   0x7fffffff 
#define DT_PROCNUM  0x36

#define SHT_NULL      0  
#define SHT_PROGBITS  1                     
#define SHT_SYMTAB    2
#define SHT_STRTAB    3
#define SHT_RELA      4
#define SHT_HASH      5        
#define SHT_DYNAMIC   6
#define SHT_NOTE      7             
#define SHT_NOBITS    8
#define SHT_REL       9
#define SHT_SHLIB     10       
#define SHT_DYNSYM    11       
#define SHT_INIT_ARRAY    14   
#define SHT_FINI_ARRAY    15
#define SHT_PREINIT_ARRAY 16     
#define SHT_GROUP     17       
#define SHT_SYMTAB_SHNDX  18    
#define SHT_NUM       19       
#define SHT_LOOS      0x60000000    
#define SHT_GNU_ATTRIBUTES 0x6ffffff5   
#define SHT_GNU_HASH      0x6ffffff6
#define SHT_GNU_LIBLIST   0x6ffffff7     
#define SHT_CHECKSUM      0x6ffffff8    
#define SHT_LOSUNW    0x6ffffffa
#define SHT_SUNW_move     0x6ffffffa
#define SHT_SUNW_COMDAT   0x6ffffffb
#define SHT_SUNW_syminfo  0x6ffffffc
#define SHT_GNU_verdef    0x6ffffffd
#define SHT_GNU_verneed   0x6ffffffe
#define SHT_GNU_versym    0x6fffffff
#define SHT_HISUNW    0x6fffffff
#define SHT_HIOS      0x6fffffff
#define SHT_LOPROC    0x70000000
#define SHT_HIPROC    0x7fffffff
#define SHT_LOUSER    0x80000000
#define SHT_HIUSER    0x8fffffff

#pragma pack(push, 1)
namespace elf
{


    typedef unsigned long long   Elf64_Addr;
    typedef unsigned short       Elf64_Half;
    typedef signed short         Elf64_SHalf;
    typedef unsigned long long   Elf64_Off;
    typedef int                  Elf64_Sword;
    typedef unsigned int         Elf64_Word;
    typedef unsigned long long   Elf64_Xword;
    typedef signed long long     Elf64_Sxword;
    typedef unsigned short       Elf64_Section;


    struct elf64_hdr {
        unsigned char e_ident[EI_NIDENT];
        Elf64_Half e_type;
        Elf64_Half e_machine;
        Elf64_Word e_version;
        Elf64_Addr e_entry;
        Elf64_Off e_phoff;
        Elf64_Off e_shoff;
        Elf64_Word e_flags;
        Elf64_Half e_ehsize;
        Elf64_Half e_phentsize;
        Elf64_Half e_phnum;
        Elf64_Half e_shentsize;
        Elf64_Half e_shnum;
        Elf64_Half e_shstrndx;
    };

    struct elf64_phdr {
        Elf64_Word p_type;
        Elf64_Word p_flags;
        Elf64_Off p_offset;
        Elf64_Addr p_vaddr;
        Elf64_Addr p_paddr;
        Elf64_Xword p_filesz;
        Elf64_Xword p_memsz;
        Elf64_Xword p_align;
    };

    struct elf64_dyn {
        Elf64_Sxword d_tag;
        union {
            Elf64_Xword d_val;
            Elf64_Addr d_ptr;
        } d_un;
    };

    struct elf64_shdr {
        Elf64_Word    sh_name;
        Elf64_Word    sh_type;         
        Elf64_Xword   sh_flags;         
        Elf64_Addr    sh_addr;       
        Elf64_Off     sh_offset;        
        Elf64_Xword   sh_size;      
        Elf64_Word    sh_link;
        Elf64_Word    sh_info;      
        Elf64_Xword   sh_addralign;     
        Elf64_Xword   sh_entsize;    
    };
    
    struct elf64_sym {
        Elf64_Word    st_name;  
        unsigned char st_info;  
        unsigned char st_other; 
        Elf64_Section st_shndx; 
        Elf64_Addr    st_value; 
        Elf64_Xword   st_size;  
    };
};
#pragma pack(pop)