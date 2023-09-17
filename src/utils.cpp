#include "utils.hpp"

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

    const char *key = KEY;
    char *iv = IV;

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
