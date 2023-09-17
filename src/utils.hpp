#pragma once

#include <Windows.h>
#include <zlib.h>
#include <openssl/aes.h>

#define KEY "0123456789abcdef"
#define IV "abcdef9876543210"

void decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, char *iv, unsigned char *plaintext);
BYTE* unpack(BYTE* image_base, IMAGE_SECTION_HEADER* packed_sect);
IMAGE_SECTION_HEADER* load_packed_section(char* section_name, IMAGE_NT_HEADERS* nt_headers);