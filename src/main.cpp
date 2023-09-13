#include <windows.h>
#include <zlib.h>

BYTE *load_pe(BYTE *packed_data);

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
            BYTE *packed_data = (BYTE *)curr + curr_sect->PointerToRawData;
            break;
        }
        curr_sect++;
    }

    if (packed_data == NULL)
    {
        MessageBox(NULL, "No packed data found", "Error", MB_OK);
        return 1;
    }

    BYTE *unpacked_data = load_pe(packed_data);
    ((void (*)())unpacked_data)();

    return 0;
}


BYTE* load_pe(BYTE* packed_data)
{
    // Decompress packed data
    DWORD unpacked_size = *(DWORD*)packed_data;
    BYTE* unpacked_data = (BYTE*)VirtualAlloc(NULL, unpacked_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uncompress(unpacked_data, &unpacked_size, packed_data + 4, *(DWORD*)(packed_data + 4));
    
    // Get DOS header of unpacked PE
    IMAGE_DOS_HEADER* unpacked_dos = (IMAGE_DOS_HEADER*)unpacked_data;
    // Get NT headers of unpacked PE
    IMAGE_NT_HEADERS* unpacked_nt = (IMAGE_NT_HEADERS*)(unpacked_data + unpacked_dos->e_lfanew);
    // Get optional header of unpacked PE
    IMAGE_OPTIONAL_HEADER* unpacked_opt = &unpacked_nt->OptionalHeader;
    // Get section headers of unpacked PE
    IMAGE_SECTION_HEADER* unpacked_sect = (IMAGE_SECTION_HEADER*)((BYTE*)unpacked_opt + sizeof(IMAGE_OPTIONAL_HEADER));
    // Get number of sections of unpacked PE
    int number_of_sections = unpacked_nt->FileHeader.NumberOfSections;

    for (int i=0; i<number_of_sections; i++)
    {
        // Get name of current section
        char* section_name = (char*)unpacked_sect->Name;
        // Check if current section is .text
        if (strcmp(section_name, ".text") == 0)
        {
            // Get pointer to raw data of .text section
            BYTE* unpacked_text = (BYTE*)unpacked_data + unpacked_sect->PointerToRawData;
            return unpacked_text;
        }
        unpacked_sect++;
    }

    return unpacked_data;
}