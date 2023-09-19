# Packer
This is a simple 64x Portable Executable packer that uses AES encryption and ZLIB compression.

## How it works
The unpacking stub loads a ".unpacked" section, decrypts and decompresses it, then loads it into memory and redirects execution to its entry point.

The packing process is done using python.

**Disclaimer:** Not all cases are handled. This is a very minimal packer, might not work with every executable. 

## Building the project
This packer requires an installation of OpenSSL for correct building and execution.
```powershell
cmake.exe --build ./build --config Debug --target ALL_BUILD -j 10 --
```
Make sure to install the needed python dependencies:
```powershell
pip install -r packer_executable/requirements.txt
```
## Tests
There are two tests defined in CMakeLists.txt, one is for packing the executable and the other is for running it. These tests can make sure that the project was built correctly.
```cmake
add_test(NAME test_pack
  COMMAND python "${PROJECT_SOURCE_DIR}/packer_executable/main.py" "${PROJECT_BINARY_DIR}/Debug/dummy_executable.exe" -p "${PROJECT_BINARY_DIR}/Debug/stub.exe")


add_test(NAME test_packed
  COMMAND "${PROJECT_BINARY_DIR}/packed.exe")
```
## Running the packer

Once the project is built, packing can be done through this command:
```powershell
python packer_executable/main.py <executable_to_pack> -p build/Debug/stub.exe
```