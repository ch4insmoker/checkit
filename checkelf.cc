#include "checkelf.h"
#include <stdio.h>


// void parse_sym_table(unsigned long long sym_off, unsigned long long str_off, unsigned long long sz, FILE *elf) {
//     for (size_t j = 0; j * sizeof(elf::elf64_sym) < sz; j++) {
//         elf::elf64_sym sym;
//         fseek(elf, sym_off + j * sizeof(elf::elf64_sym), SEEK_SET);
//         fread(&sym, sizeof(elf::elf64_sym), 1, elf);

//         if (sym.st_name != 0) {
//             char str_sym[256];
//             fseek(elf, str_off + sym.st_name, SEEK_SET);
//             fread(&str_sym, 1, 256, elf);
//             std::cout << str_sym;
//         }
//   }
// }

// void stk_cookie(elf::elf64_hdr header, FILE *elf) {
//     elf::elf64_shdr *sections = (elf::elf64_shdr *)malloc(header.e_shnum * header.e_shentsize);

//     unsigned long long str_off, sz, sym_off;

//     for (int i = 0; i < header.e_shnum; i++) {
//         fseek(elf, header.e_shentsize * i + header.e_shoff, SEEK_SET);
//         fread(&sections[i], sizeof(elf::elf64_shdr), 1, elf);
//         if (sections[i].sh_type == SHT_SYMTAB) {
//             sz = sections[i].sh_size;
//             sym_off = sections[i].sh_offset;
//         }
//         if (sections[i].sh_type == SHT_STRTAB) {
//             str_off = sections[i].sh_offset;
//         }
//     }

//     parse_sym_table(sym_off, str_off,  sz, elf);
// }

bool full_relro(elf::elf64_phdr phdr, FILE *elf) {

    elf::elf64_dyn dyn;
    if (phdr.p_type == PT_DYNAMIC) {
        size_t dyn_entry_size = sizeof(elf::elf64_dyn);
        int n = phdr.p_memsz / dyn_entry_size;

        fseek(elf, phdr.p_offset, SEEK_SET);

        for (int i = 0; i < n; i++) {

            fread(&dyn, dyn_entry_size, 1, elf);

            if (dyn.d_tag ==  DT_FLAGS && (dyn.d_un.d_val & DT_BIND_NOW) ) {
                return 1;
            }
        }
    }

    return 0;
}


bool relro(elf::elf64_phdr phdr) {

    return (phdr.p_type == PT_GNU_RELRO);
}

bool pie(elf::elf64_hdr header) {
    return (header.e_type == ET_DYN);
}

bool nx(elf::elf64_phdr phdr) {
    return (phdr.p_type == PT_GNU_STACK && (phdr.p_flags == (PF_W | PF_R)));
}

// uint8_t get_ver(FILE *fp) {
//     uint8_t ver;

//     fseek(fp, 4, SEEK_SET);
//     fread(&ver, 1, 1, fp);
//     return ver;
// }

void checkelf(FILE *fp) {

    elf::elf64_hdr header;
    elf::elf64_phdr phdr;

    std::string nx_ = "Disabled", pie_ = "Disabled", canary_ = "Disabled";

    int relro_ = 0;
    int full_relro_ = 0;

    fseek(fp, 0, SEEK_SET);
    fread(&header, sizeof(elf::elf64_hdr), 1, fp);

    for (int i = 0; i < header.e_phnum; i++) {

        fseek(fp, header.e_phoff + i * header.e_phentsize, SEEK_SET);
        fread(&phdr, sizeof(phdr), 1, fp);

        if(nx(phdr)) {
            nx_ = "Enabled";
        } if(pie(header)) {
            pie_ = "Enabled";
        } 
        
        if(relro(phdr)) {relro_ = 1;}
        if(full_relro(phdr,fp)) {full_relro_ = 2;}
    }

    stk_cookie(header, fp);

    std::string relrox = ((full_relro_ == 2 && relro_ == 1) ? "Full" : relro_ == 1 ? "Partial" : "No Relro");

    std::cout << "NX    : " << nx_ << std::endl;
    std::cout << "PIE   : " << pie_ << std::endl;
    std::cout << "RELRO : " << relrox << std::endl;
    std::cout << "CANARY: " << canary_ << std::endl;

}