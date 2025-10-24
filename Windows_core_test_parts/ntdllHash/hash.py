
def hash_module_name_wide(name: str) -> int:
    r9d = 0
    # Encode as UTF-16LE (like Windows wchar_t*)
    data = name.encode('utf-16le') + b'\x00\x00'
    
    for b in data:
        al = b
        if 0x61 <= al <= 0x7A:
            al -= 0x20
        bl = al
        al = (al + al) & 0xFF
        al ^= bl
        r9d = (r9d + al) & 0xFFFFFFFF
        cl = bl & 0x1F
        r9d = ((r9d >> cl) | (r9d << (32 - cl))) & 0xFFFFFFFF

    return r9d

mod_name = input("ENTER module name (ntdll.dll): ").strip() or "ntdll.dll"
hash_mod_val = hash_module_name_wide(mod_name)
print(f"Hash for '{mod_name}':\nHEX: 0x{hash_mod_val:08X}\nDEC: {hash_mod_val}")

while True:
    user_mod_name = input("ENTER Function name : ")
    if user_mod_name.lower() == "exit":
        break
    hash_val = (hash_mod_val + hash_module_name_wide(user_mod_name)) & 0xFFFFFFFF
    print(f"Hash for '{mod_name}!{user_mod_name}':\nHEX: 0x{hash_val:08X}\nDEC: {hash_val}")