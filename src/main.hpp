#pragma once

#include <iostream>
#include <windows.h>
#include <vector>

#include <utils.hpp>


BYTE* load_pe(BYTE *unpacked_data);
void load_imports(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);
void relocate(BYTE* unpacked_data, IMAGE_NT_HEADERS* unpacked_nt);