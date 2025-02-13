// Copyright (c) 2020 Can Boluk
// All rights reserved.   
//    
// Redistribution and use in source and binary forms, with or without   
// modification, are permitted provided that the following conditions are met: 
//    
// 1. Redistributions of source code must retain the above copyright notice,   
//    this list of conditions and the following disclaimer.   
// 2. Redistributions in binary form must reproduce the above copyright   
//    notice, this list of conditions and the following disclaimer in the   
//    documentation and/or other materials provided with the distribution.   
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.   
//    
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE   
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR   
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF   
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS   
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  
// POSSIBILITY OF SUCH DAMAGE.        
//
#pragma once
#include "../../img_common.hpp"
#include "../data_directories.hpp"
//#include "dir_relocs.hpp"

WIN_STRUCT_PACKING
namespace win
{
    // Enclave configuration
    //
    struct enclave_config_x64_t
    {
        uint32_t                    size;
        uint32_t                    minimum_required_config_size;
        uint32_t                    policy_flags;
        uint32_t                    number_of_imports;
        uint32_t                    import_list;
        uint32_t                    import_entry_size;
        uint8_t                     family_id[ 16 ];
        uint8_t                     image_id[ 16 ];
        uint32_t                    image_version;
        uint32_t                    security_version;
        uint64_t                    enclave_size;
        uint32_t                    number_of_threads;
        uint32_t                    enclave_flags;
    };
    struct enclave_config_x86_t
    {
        uint32_t                    size;
        uint32_t                    minimum_required_config_size;
        uint32_t                    policy_flags;
        uint32_t                    number_of_imports;
        uint32_t                    import_list;
        uint32_t                    import_entry_size;
        uint8_t                     family_id[ 16 ];
        uint8_t                     image_id[ 16 ];
        uint32_t                    image_version;
        uint32_t                    security_version;
        uint32_t                    enclave_size;
        uint32_t                    number_of_threads;
        uint32_t                    enclave_flags;
    };
    template<bool x64 = default_architecture>
    using enclave_config_t = std::conditional_t<x64, enclave_config_x64_t, enclave_config_x86_t>;

    // Hot patch information
    //
    struct hotpatch_base_t
    {
        uint32_t                    sequence_number;
        uint32_t                    flags;
        uint32_t                    orginal_timedate_stamp;
        uint32_t                    orginal_checksum;
        uint32_t                    code_integrity_info;
        uint32_t                    code_integrity_size;
        uint32_t                    path_table;
        uint32_t                    buffer_offset;
    };

    struct hotpatch_info_t
    {
        uint32_t                    version;
        uint32_t                    size;
        uint32_t                    sequence_number;
        uint32_t                    base_image_list;
        uint32_t                    base_image_count;
        uint32_t                    buffer_offset; 
        uint32_t                    extra_patch_size;
    };
    
    struct hotpatch_hashes_t
    {
        uint8_t                     sha256[ 32 ];
        uint8_t                     sha1[ 20 ];
    };

    // Code integrity information
    //
    struct load_config_ci_t
    {
        uint16_t                    flags;                              // Flags to indicate if CI information is available, etc.
        uint16_t                    catalog;                            // 0xFFFF means not available
        uint32_t                    rva_catalog;
        uint32_t                    _pad0;                              // Additional bitmask to be defined later
    };

    template<bool x64 = default_architecture>
    struct load_config_directory_t
    {
        // Architecture dependent typedefs
        //
        using va_t =    std::conditional_t<x64, uint64_t, uint32_t>;
        using vsize_t = va_t;
        
        struct table_t
        { 
            va_t virtual_address; 
            vsize_t count; 
        };

        // Directory description
        //
        uint32_t                    size;
        uint32_t                    timedate_stamp;
        ex_version_t                version;
        uint32_t                    global_flags_clear;
        uint32_t                    global_flags_set;
        uint32_t                    critical_section_default_timeout;
        vsize_t                     decommit_free_block_threshold;
        vsize_t                     decommit_total_free_threshold;
        va_t                        lock_prefix_table;
        vsize_t                     maximum_allocation_size;
        vsize_t                     virtual_memory_threshold;
        vsize_t                     process_affinity_mask;
        uint32_t                    process_heap_flags;
        uint16_t                    csd_version;
        uint16_t                    dependent_load_flags;
        va_t                        edit_list;
        va_t                        security_cookie;
        table_t                     se_handler_table;
        va_t                        guard_cf_check_function_ptr;
        va_t                        guard_cf_dispatch_function_ptr;
        table_t                     guard_cf_function_table;
        uint32_t                    guard_flags;
        load_config_ci_t            code_integrity;
        table_t                     guard_address_taken_iat_entry_table;
        table_t                     guard_long_jump_target_table;
        va_t                        dynamic_value_reloc_table;
        va_t                        chpe_metadata_ptr;                      // hybrid_metadata_ptr @ v1607
        va_t                        guard_rf_failure_routine;
        va_t                        guard_rf_failure_routine_function_ptr;
        uint32_t                    dynamic_value_reloc_table_offset;
        uint16_t                    dynamic_value_reloc_table_section;
        va_t                        guard_rf_verify_stack_ptr_function_ptr;
        uint32_t                    hotpatch_table_offset;
        uint32_t                    reserved;
        va_t                        enclave_configuration_ptr;
        va_t                        volatile_metadata_ptr;
        table_t                     guard_eh_continuation_table;
    };
    using load_config_directory_x86_t = load_config_directory_t<false>;
    using load_config_directory_x64_t = load_config_directory_t<true>;
    template<bool x64> struct directory_type<directory_id::directory_entry_load_config, x64, void> { using type = load_config_directory_t<x64>; };
};
#pragma pack(pop)