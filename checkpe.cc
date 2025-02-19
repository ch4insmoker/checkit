#include "checkpe.h"

uint32_t rva_to_off(uint16_t numofsec, uint32_t rva, win::section_header_t *sections) {

    for (int i = 0; i < numofsec; ++i) {
        if ( sections[i].virtual_address <= rva && rva < sections[i].virtual_address + sections[i].virtual_size) {
            return rva - sections[i].virtual_address + sections[i].ptr_raw_data;
        }
    }
    return 0;
}

win::load_config_directory_x64_t *get_load_conf_64(FILE *fp, win::optional_header_x64_t *OPT_HDR, uint16_t numofsec, uint32_t nt_off) {

    win::section_header_t* sections = (win::section_header_t*)malloc(numofsec * sizeof(win::section_header_t));

    for (int i = 0; i < numofsec; ++i) {
      fseek(fp, nt_off + sizeof(win::nt_headers_x64_t)+i*sizeof(win::section_header_t), SEEK_SET);
      fread(&sections[i], sizeof(win::section_header_t), 1, fp);
    }

    win::load_config_directory_x64_t *LOAD_CONF_DIR = (win::load_config_directory_x64_t *)malloc(sizeof(win::load_config_directory_x64_t));
    win::data_directory_t DATA_DIR = OPT_HDR->data_directories.load_config_directory;

    uint32_t off = rva_to_off(numofsec, DATA_DIR.rva, sections);
    fseek(fp, off, SEEK_SET);

    fread(LOAD_CONF_DIR, sizeof(win::load_config_directory_x64_t), 1, fp);
    free(sections);
    return LOAD_CONF_DIR;
}

win::load_config_directory_x86_t *get_load_conf_32(FILE *fp, win::optional_header_x86_t *OPT_HDR, uint16_t numofsec, uint32_t nt_off) {

    win::section_header_t* sections = (win::section_header_t*)malloc(numofsec * sizeof(win::section_header_t));

    for (int i = 0; i < numofsec; ++i) {
      fseek(fp, nt_off + sizeof(win::nt_headers_x86_t)+i*sizeof(win::section_header_t), SEEK_SET);
      fread(&sections[i], sizeof(win::section_header_t), 1, fp);
    }

    win::load_config_directory_x86_t *LOAD_CONF_DIR = (win::load_config_directory_x86_t *)malloc(sizeof(win::load_config_directory_x86_t));
    win::data_directory_t DATA_DIR = OPT_HDR->data_directories.load_config_directory;

    uint32_t off = rva_to_off(numofsec, DATA_DIR.rva, sections);
    fseek(fp, off, SEEK_SET);

    fread(LOAD_CONF_DIR, sizeof(win::load_config_directory_x86_t), 1, fp);
    free(sections);
    return LOAD_CONF_DIR;
}

win::optional_header_x86_t *get_opt_hdr_32(FILE *fp) {
    win::optional_header_x86_t *OPT_HDR = (win::optional_header_x86_t *)malloc(sizeof(win::optional_header_x86_t));
    fread(OPT_HDR, sizeof(win::optional_header_x86_t), 1, fp);
    return OPT_HDR;
}

win::optional_header_x64_t *get_opt_hdr_64(FILE *fp) {
    win::optional_header_x64_t *OPT_HDR = (win::optional_header_x64_t *)malloc(sizeof(win::optional_header_x64_t));
    fread(OPT_HDR, sizeof(win::optional_header_x64_t), 1, fp);
    return OPT_HDR;
}

bool check_seh(uint16_t dll_chars) {
    return !(dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH);
}

bool check_isolation(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION;
}

bool check_force_integrity(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
}

bool check_cfg(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF;
}

bool check_high_entropy_va(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
}

bool check_dynamic_base(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

// bool check_aslr(uint16_t dll_chars) {
//     return check_high_entropy_va(OPT_HDR) & check_dynamic_base(OPT_HDR);
// }

bool check_nx(uint16_t dll_chars) {
    return dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
}

bool check_cookie_64(win::load_config_directory_x64_t *LOAD_CONF_DIR) {
    return LOAD_CONF_DIR->security_cookie != 0;
}

bool check_cookie_32(win::load_config_directory_x86_t *LOAD_CONF_DIR) {
    return LOAD_CONF_DIR->security_cookie != 0;
}

// Safe seh can only be applied to applied to 32-bit binaries
bool check_safe_seh(win::load_config_directory_x86_t *LOAD_CONF_DIR) {
    return LOAD_CONF_DIR->se_handler_table.count != 0 && LOAD_CONF_DIR->se_handler_table.virtual_address != 0;
}

uint8_t pe_ver(FILE *fp) {
    uint16_t ver;
    fread(&ver, 2, 1, fp);

   switch (ver) {
    case chk_IMAGE_NT_OPTIONAL_HDR32_MAGIC: return 1; break;
    case chk_IMAGE_NT_OPTIONAL_HDR64_MAGIC: return 2; break;
    default: return 0; break;
   }
}

void checkpe(FILE *fp) {

    uint16_t dll_chars;
    bool cookie,safe_seh; 
    win::dos_header_t DOS_HDR;
    
    fseek(fp, 0, SEEK_SET);
    fread(&DOS_HDR, sizeof(win::dos_header_t), 1, fp);

    fseek(fp, DOS_HDR.e_lfanew + sizeof(int) + sizeof(win::file_header_t), SEEK_SET);
    long unsigned offset = ftell(fp); // save offset
    uint8_t pe_version = pe_ver(fp);

    if (pe_version == 2) {
        // FOR 64-BIT BINARY
        win::nt_headers_x64_t NT_HDR;
        fseek(fp, DOS_HDR.e_lfanew, SEEK_SET);
        fread(&NT_HDR, sizeof(win::nt_headers_x64_t), 1, fp);

        fseek(fp, offset, SEEK_SET);
        auto OPT_HDR = get_opt_hdr_64(fp);
        win::load_config_directory_x64_t *LOAD_CONFIG = get_load_conf_64(fp, OPT_HDR, NT_HDR.file_header.num_sections, DOS_HDR.e_lfanew);

        dll_chars = OPT_HDR->characteristics.flags;
        cookie = check_cookie_64(LOAD_CONFIG);
        safe_seh = false;
        free(OPT_HDR);
        free(LOAD_CONFIG);
    } else if (pe_version == 1) {
        // FOR 32-BIT BINARY

        win::nt_headers_x86_t NT_HDR;
        fseek(fp, DOS_HDR.e_lfanew, SEEK_SET);
        fread(&NT_HDR, sizeof(win::nt_headers_x86_t), 1, fp);

        fseek(fp, offset, SEEK_SET);
        auto OPT_HDR = get_opt_hdr_32(fp);
        win::load_config_directory_x86_t *LOAD_CONFIG = get_load_conf_32(fp, OPT_HDR, NT_HDR.file_header.num_sections, DOS_HDR.e_lfanew);
        
        dll_chars = OPT_HDR->characteristics.flags;
        cookie = check_cookie_32(LOAD_CONFIG);
        safe_seh = check_safe_seh(LOAD_CONFIG);
        free(OPT_HDR);
        free(LOAD_CONFIG);
    } else {
        puts("Failed while parsing");
        exit(0);
    }

    std::cout << "stack cookie   : " << (cookie ? "Enabled": "Disabled") << std::endl;
    std::cout << "NX             : " << (check_nx(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "Dynamic base   : " << (check_dynamic_base(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "high entropy VA: " << (check_high_entropy_va(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "CFG            : " << (check_cfg(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "force integrity: " << (check_force_integrity(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "isolation      : " <<  (check_isolation(dll_chars) ? "Disabled": "Enabled") << std::endl;
    std::cout << "SEH            : " << (check_seh(dll_chars) ? "Enabled": "Disabled") << std::endl;
    std::cout << "SAFE SEH       : " <<  ((safe_seh && check_seh(dll_chars)) ? "Enabled": "Disabled") << std::endl;
}