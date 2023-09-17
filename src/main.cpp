#include <iostream>
#include <windows.h>
#include <zlib.h>
#include <vector>
#include <openssl/aes.h>


IMAGE_SECTION_HEADER* load_packed_section(char* section_name, IMAGE_NT_HEADERS* nt_headers);
BYTE* load_pe(BYTE *unpacked_data);
BYTE* unpack(BYTE* image_base, IMAGE_SECTION_HEADER* packed_sect);
void decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, char *iv, unsigned char *plaintext);
void load_imports(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);
void relocate(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);


int main(int argc, char *argv[])
{
    HMODULE image_base = GetModuleHandle(NULL);

    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)image_base + ((IMAGE_DOS_HEADER *)image_base)->e_lfanew);
    
    IMAGE_SECTION_HEADER *packed_sect = load_packed_section(".packed", nt_headers);

    BYTE* unpacked = unpack((BYTE*) image_base, packed_sect);

    BYTE *loaded_pe = load_pe(unpacked);
    ((void (*)())loaded_pe)();

    return 0;
}

void decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, char *iv, unsigned char *plaintext) 
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    char ivec[17];
    strcpy_s(ivec, iv);
    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, (unsigned char*)ivec, AES_DECRYPT);
}

BYTE* unpack(BYTE* image_base, IMAGE_SECTION_HEADER* packed_sect)
{
    BYTE *packed_data = (BYTE *)image_base + packed_sect->VirtualAddress;

    const char *key = "0123456789abcdef";
    char *iv = "abcdef9876543210";

    DWORD decrypted_size = *(DWORD*)packed_data;
    unsigned char *decrypted = (unsigned char *)VirtualAlloc(NULL, decrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    size_t encrypted_len = packed_sect->Misc.VirtualSize - 4;
    decrypt(packed_data + 4, encrypted_len, (const unsigned char*)key, iv, decrypted);


    DWORD unpacked_size = *(DWORD*)decrypted;
    DWORD packed_size = encrypted_len - 4;
    BYTE* unpacked = (BYTE* )VirtualAlloc(NULL, unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (uncompress(unpacked, &unpacked_size, decrypted + 4, packed_size) != Z_OK) {
        MessageBox(NULL, "Error unpacking data", "Error", MB_OK);
        ExitProcess(2);
    }
    VirtualFree(decrypted, 0, MEM_RELEASE);
    return unpacked;
}

void relocate(BYTE* image_base, IMAGE_NT_HEADERS* nt_header) 
{
   if (nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0)
   {
      std::cerr << "Error: image cannot be relocated." << std::endl;
      ExitProcess(7);
   }

   IMAGE_DATA_DIRECTORY directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

   if (directory_entry.VirtualAddress == 0) {
      std::cerr << "Error: image can be relocated, but contains no relocation directory." << std::endl;
      return;
   }

   ULONGLONG delta = (ULONGLONG)image_base - nt_header->OptionalHeader.ImageBase;

   IMAGE_BASE_RELOCATION * relocation_table = (IMAGE_BASE_RELOCATION *)(image_base + directory_entry.VirtualAddress);

   while (relocation_table->VirtualAddress != 0)
   {
      std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

      uint16_t * relocation_data = (uint16_t *)&relocation_table[1];

      for (std::size_t i=0; i<relocations; ++i)
      {
         // a relocation is an encoded 16-bit value:
         //   * the upper 4 bits are its relocation type
         //     (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format see "base relocation types")
         //   * the lower 12 bits contain the offset into the relocation entry's address base into the image
         //
         uint16_t relocation = relocation_data[i];
         std::uint16_t type = relocation >> 12;
         std::uint16_t offset = relocation & 0xFFF;
         uintptr_t *ptr = (uintptr_t *)(image_base + relocation_table->VirtualAddress + offset);

         // there are typically only two types of relocations for a 64-bit binary:
         //   * IMAGE_REL_BASED_DIR64: a 64-bit delta calculation
         //   * IMAGE_REL_BASED_ABSOLUTE: a no-op
         //
         if (type == IMAGE_REL_BASED_DIR64)
            *ptr += delta;
      }

      // the next relocation entry is at SizeOfBlock bytes after the current entry
      relocation_table = (IMAGE_BASE_RELOCATION *)(
         (std::uint8_t *)relocation_table + relocation_table->SizeOfBlock
      );
   }
}
 
BYTE* load_pe(BYTE *unpacked_data)
{
    // Extract basic information
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)unpacked_data;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(unpacked_data + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
    IMAGE_SECTION_HEADER* section_table = (IMAGE_SECTION_HEADER*)((BYTE*)optional_header + sizeof(IMAGE_OPTIONAL_HEADER));
    int number_of_sections = nt_header->FileHeader.NumberOfSections;
    
    DWORD image_size = optional_header->SizeOfImage;
    BYTE* image_base = (BYTE*)VirtualAlloc(0, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (image_base == NULL)
    {
        MessageBox(NULL, "Error allocating memory", "Error", MB_OK);
        ExitProcess(3);
    }

    std::memcpy(image_base, unpacked_data, optional_header->SizeOfHeaders);

    for (int i=0; i<number_of_sections; ++i)
      if (section_table[i].SizeOfRawData > 0)
         std::memcpy(image_base+section_table[i].VirtualAddress,
                     unpacked_data+section_table[i].PointerToRawData,
                     section_table[i].SizeOfRawData);


    // Handle Imports
    load_imports(image_base, nt_header);

    // Handle Relocations
    relocate(image_base, nt_header);
    
    BYTE* addr = image_base + optional_header->AddressOfEntryPoint;
    VirtualFree(unpacked_data, 0, MEM_RELEASE);
    return addr;
}



void load_imports(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt)
{
    IMAGE_DATA_DIRECTORY* import_dir = &unpacked_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->VirtualAddress == 0)
        return;

    IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(unpacked_data + import_dir->VirtualAddress);
    while (import_desc->Name != NULL)
    {
        char* lib_name = (char*)(unpacked_data + import_desc->Name);
        HMODULE lib = LoadLibrary(lib_name);
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(unpacked_data + import_desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* func = (IMAGE_THUNK_DATA*)(unpacked_data + import_desc->FirstThunk);

        while (thunk->u1.AddressOfData != NULL)
        {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                func->u1.Function = (ULONGLONG)GetProcAddress(lib, (char*)(thunk->u1.Ordinal & 0xFFFF));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* thunk_data = (IMAGE_IMPORT_BY_NAME*)(unpacked_data + thunk->u1.AddressOfData);
                func->u1.Function = (ULONGLONG)GetProcAddress(lib, (char*)thunk_data->Name);
            }
            thunk++;
            func++;
        }
        import_desc++;
    }

    return;
}

IMAGE_SECTION_HEADER* load_packed_section(char* section_name, IMAGE_NT_HEADERS* nt_headers) 
{
    IMAGE_OPTIONAL_HEADER *curr_opt = &nt_headers->OptionalHeader;
    IMAGE_SECTION_HEADER *curr_sect = (IMAGE_SECTION_HEADER *)((BYTE *)curr_opt + sizeof(IMAGE_OPTIONAL_HEADER));
    int number_of_sections = nt_headers->FileHeader.NumberOfSections;


    IMAGE_SECTION_HEADER *packed_sect = NULL;
    for (int i = 0; i < number_of_sections; i++)
    {
        if (strcmp((char *)curr_sect[i].Name, section_name) == 0)
        {
            packed_sect = &curr_sect[i];
            break;
        }
    }

    if (packed_sect == NULL)
    {
        MessageBox(NULL, "No packed data found", "Error", MB_OK);
        exit(1);
    }

    return packed_sect;
}
