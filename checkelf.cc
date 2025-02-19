#include "checkelf.h"


bool parse_sym_table(elf::elf64_shdr *symtab, elf::elf64_shdr *strtab, FILE *elf) {
    // ... if binary is stripped program can't find exported function for checking stack canary... if you have idea around this, pls open pull request!!!
    
    if (!symtab || !strtab) {
        fprintf(stderr, "Error: Symbol table or string table is NULL OR STRIPPED\n");
        return false;
    }

    size_t num_of_symbols = symtab->sh_size / symtab->sh_entsize;
    elf::elf64_sym *symtabx = (elf::elf64_sym *)malloc(symtab->sh_size);

    fseek(elf, symtab->sh_offset, SEEK_SET);
    fread(symtabx, symtab->sh_size, 1, elf);

    char *symstrtab = (char *)malloc(strtab->sh_size);

    fseek(elf, strtab->sh_offset, SEEK_SET);
    fread(symstrtab, strtab->sh_size, 1, elf);

    for (size_t i = 0; i < num_of_symbols; i++) {
        std::string func = symstrtab + symtabx[i].st_name;
        if (func.contains("__stack_chk_fail")) {
            return true;
        }
    }

    free(symtabx);
    free(symstrtab);

    return false;
}

bool stk_cookie(elf::elf64_hdr header, FILE *elf) {
    elf::elf64_shdr *sections = (elf::elf64_shdr *)malloc(header.e_shnum * header.e_shentsize);

    elf::elf64_shdr *symtab = NULL;
    elf::elf64_shdr *strtab = NULL;

    for (int i = 0; i < header.e_shnum; i++) {
        fseek(elf, (header.e_shoff + (i * header.e_shentsize)), SEEK_SET);
        fread(&sections[i], sizeof(elf::elf64_shdr), 1, elf);

        if (sections[i].sh_type == SHT_SYMTAB) {
            symtab = &sections[i];
            break;
        }
    }

    if (symtab != NULL) {
        for (int i = 0; i < header.e_shnum; i++) {
            fseek(elf, (header.e_shoff + (i * header.e_shentsize)), SEEK_SET);
            fread(&sections[i], sizeof(elf::elf64_shdr), 1, elf) != 1;
 
            if (symtab->sh_link == i) {
              strtab = &sections[i];
              break;
            }
        }
    }

    bool f = parse_sym_table(symtab, strtab, elf);
    free(sections);

    return f;
}

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

    if (stk_cookie(header, fp)) {
        canary_ = "Enabled";
    }

    std::string relrox = ((full_relro_ == 2 && relro_ == 1) ? "Full" : relro_ == 1 ? "Partial" : "No Relro");   

    std::cout << "NX    : " << nx_ << std::endl;
    std::cout << "PIE   : " << pie_ << std::endl;
    std::cout << "RELRO : " << relrox << std::endl;
    std::cout << "CANARY: " << canary_ << std::endl;

}