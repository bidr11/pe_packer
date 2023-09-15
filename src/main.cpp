#include <iostream>
#include <windows.h>
#include <zlib.h>
#include <vector>

IMAGE_SECTION_HEADER* load_packed_section(char* section_name, IMAGE_NT_HEADERS* nt_headers);
BYTE* load_pe(BYTE* image_base, IMAGE_SECTION_HEADER* packed_section);
BYTE* unpack(BYTE* packed_data, DWORD packed_size, DWORD unpacked_size);
void load_imports(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);
void relocate(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);


int main(int argc, char *argv[])
{
    HMODULE image_base = GetModuleHandle(NULL);

    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)image_base + ((IMAGE_DOS_HEADER *)image_base)->e_lfanew);
    
    IMAGE_SECTION_HEADER *packed_sect = load_packed_section(".packed", nt_headers);

    BYTE *packed_data = (BYTE *)image_base + packed_sect->PointerToRawData + 4;
    DWORD unpacked_size = *(DWORD*)packed_data;
    DWORD packed_size = packed_sect->Misc.VirtualSize - 4;

    BYTE* unpacked_data = unpack(packed_data, packed_size, unpacked_size);

    BYTE *loaded_pe = load_pe(unpacked_data);
    ((void (*)())loaded_pe)();

    return 0;
}


BYTE* unpack(BYTE* packed_data, DWORD packed_size, DWORD unpacked_size)
{
    std::vector<uint8_t> unpacked = std::vector<uint8_t>(unpacked_size);
    
    if (uncompress(unpacked.data(), &unpacked_size, packed_data + 4, packed_size) != Z_OK) {
        MessageBox(NULL, "Error unpacking data", "Error", MB_OK);
        ExitProcess(2);
    }
    
    return unpacked.data();
}

void relocate(BYTE* image_base, IMAGE_NT_HEADERS* nt_header) {
   // first, check if we can even relocate the image. if the dynamic base flag isn't set,
   // then this image probably isn't prepared for relocating.

   if (nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0)
   {
      std::cerr << "Error: image cannot be relocated." << std::endl;
      ExitProcess(7);
   }

   // once we know we can relocate the image, make sure a relocation directory is present
   IMAGE_DATA_DIRECTORY directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

   if (directory_entry.VirtualAddress == 0) {
      std::cerr << "Error: image can be relocated, but contains no relocation directory." << std::endl;
      ExitProcess(8);
   }

   // calculate the difference between the image base in the compiled image
   // and the current virtually allocated image. this will be added to our
   // relocations later.
   ULONGLONG delta = *image_base - nt_header->OptionalHeader.ImageBase;

   // get the relocation table.
   IMAGE_BASE_RELOCATION * relocation_table = (IMAGE_BASE_RELOCATION *)(image_base + directory_entry.VirtualAddress);

   // when the virtual address for our relocation header is null,
   // we've reached the end of the relocation table.
   while (relocation_table->VirtualAddress != 0)
   {
      // since the SizeOfBlock value also contains the size of the relocation table header,
      // we can calculate the size of the relocation array by subtracting the size of
      // the header from the SizeOfBlock value and dividing it by its base type: a 16-bit integer.
      std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

      // additionally, the relocation array for this table entry is directly after
      // the relocation header
      auto relocation_data = reinterpret_cast<std::uint16_t *>(&relocation_table[1]);

      for (std::size_t i=0; i<relocations; ++i)
      {
         // a relocation is an encoded 16-bit value:
         //   * the upper 4 bits are its relocation type
         //     (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format see "base relocation types")
         //   * the lower 12 bits contain the offset into the relocation entry's address base into the image
         //
         auto relocation = relocation_data[i];
         std::uint16_t type = relocation >> 12;
         std::uint16_t offset = relocation & 0xFFF;
         auto ptr = reinterpret_cast<std::uintptr_t *>(image_base + relocation_table->VirtualAddress + offset);

         // there are typically only two types of relocations for a 64-bit binary:
         //   * IMAGE_REL_BASED_DIR64: a 64-bit delta calculation
         //   * IMAGE_REL_BASED_ABSOLUTE: a no-op
         //
         if (type == IMAGE_REL_BASED_DIR64)
            *ptr += delta;
      }

      // the next relocation entry is at SizeOfBlock bytes after the current entry
      relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION *>(
         reinterpret_cast<std::uint8_t *>(relocation_table) + relocation_table->SizeOfBlock
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
    
    DWORD image_size = optional_header->AddressOfEntryPoint;
    BYTE* image_base = (BYTE*)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

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
    

    return image_base + optional_header->AddressOfEntryPoint;
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
                func->u1.Function = (DWORD)GetProcAddress(lib, (char*)(thunk->u1.Ordinal & 0xFFFF));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* thunk_data = (IMAGE_IMPORT_BY_NAME*)(unpacked_data + thunk->u1.AddressOfData);
                func->u1.Function = (DWORD)GetProcAddress(lib, (char*)thunk_data->Name);
            }
            thunk++;
            func++;
        }
        import_desc++;
    }

    return;
}

IMAGE_SECTION_HEADER* load_packed_section(char* section_name, IMAGE_NT_HEADERS* nt_headers) {
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
