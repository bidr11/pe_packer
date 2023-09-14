#include <windows.h>
#include <zlib.h>

BYTE* load_pe(BYTE* imageBase, IMAGE_SECTION_HEADER* packed_section);
BYTE* unpack(BYTE* packed_data, DWORD packed_size, DWORD unpacked_size);
void load_imports(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);
void relocate(BYTE* unpacked_data, BYTE* unpacked_base, IMAGE_NT_HEADERS* unpacked_nt);

int main(int argc, char *argv[])
{
    BYTE *packed_data = NULL;
    HMODULE curr = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER *curr_dos = (IMAGE_DOS_HEADER *)curr;
    IMAGE_NT_HEADERS *curr_nt = (IMAGE_NT_HEADERS *)((BYTE *)curr + curr_dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER *curr_opt = &curr_nt->OptionalHeader;
    IMAGE_SECTION_HEADER *curr_sect = (IMAGE_SECTION_HEADER *)((BYTE *)curr_opt + sizeof(IMAGE_OPTIONAL_HEADER));
    int number_of_sections = curr_nt->FileHeader.NumberOfSections;


    for (int i = 0; i < number_of_sections; i++)
    {
        if (strcmp((char *)curr_sect->Name, ".packed") == 0)
        {
            
            break;
        }
        curr_sect++;
    }

    if (packed_data == NULL)
    {
        MessageBox(NULL, "No packed data found", "Error", MB_OK);
        return 1;
    }

    BYTE *unpacked_data = load_pe((BYTE*)curr, curr_sect);
    ((void (*)())unpacked_data)();

    return 0;
}



BYTE* load_pe(BYTE* imageBase, IMAGE_SECTION_HEADER* packed_section)
{

    BYTE *packed_data = (BYTE *)imageBase + packed_section->PointerToRawData;

    // Decompress packed data
    DWORD unpacked_size = *(DWORD*)packed_data;
    DWORD packed_size = packed_section->Misc.VirtualSize - 4;
    BYTE* unpacked_data = unpack(packed_data + 4, packed_size, unpacked_size);
    
    // Extract basic informatoin
    IMAGE_DOS_HEADER* unpacked_dos = (IMAGE_DOS_HEADER*)unpacked_data;
    IMAGE_NT_HEADERS* unpacked_nt = (IMAGE_NT_HEADERS*)(unpacked_data + unpacked_dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER* unpacked_opt = &unpacked_nt->OptionalHeader;
    IMAGE_SECTION_HEADER* unpacked_sect = (IMAGE_SECTION_HEADER*)((BYTE*)unpacked_opt + sizeof(IMAGE_OPTIONAL_HEADER));


    // Handle Imports
    load_imports(unpacked_data, unpacked_nt);

    // Hanlde Relocations
    relocate(unpacked_data, imageBase, unpacked_nt);

    // Get number of sections of unpacked PE
    // int number_of_sections = unpacked_nt->FileHeader.NumberOfSections;

    // for (int i=0; i<number_of_sections; i++)
    // {
    //     // Get name of current section
    //     char* section_name = (char*)unpacked_sect->Name;
    //     // Check if current section is .text
    //     if (strcmp(section_name, ".text") == 0)
    //     {
    //         // Get pointer to raw data of .text section
    //         BYTE* unpacked_text = (BYTE*)unpacked_data + unpacked_sect->PointerToRawData;
    //         return unpacked_text;
    //     }
    //     unpacked_sect++;
    // }

    // return unpacked_data;
}


BYTE* unpack(BYTE* packed_data, DWORD packed_size, DWORD unpacked_size)
{
    BYTE* unpacked_data = (BYTE*)VirtualAlloc(NULL, unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (uncompress(unpacked_data, &unpacked_size, packed_data, packed_size) != Z_OK) {
        MessageBox(NULL, "Error unpacking data", "Error", MB_OK);
        ExitProcess(2);
    }
    
    return unpacked_data;
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

void relocate(BYTE* unpacked_data, BYTE* unpacked_base, IMAGE_NT_HEADERS* unpacked_nt) {
    if (unpacked_nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0)
   {
      MessageBox(NULL, "Relocations not supported", "Error", MB_OK);
      ExitProcess(7);
   }
   
}