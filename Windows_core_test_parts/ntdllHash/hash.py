def hash(parm):
    H = 0
    hash = []
    for i in parm:
        hash.append(ord(i))
        hash.append(0)
    hash.append(0)
    hash.append(0)

    for c in hash:
        if c >= 0x61:
            c -= 0x20

        m = ((((c*2) & 0xFFFF)^c) & 0xFFFF)
        H = ((H + m) & 0xFFFFFFFF)
        rot = c & 31                                # rotate within 0–31
        H = ((H >> rot) | (H << (32 - rot))) & 0xFFFFFFFF
    return H

def hash_module_name(name: str) -> int:
    r9d = 0  # hash accumulator (32-bit)
    hash = []
    for i in name:
        hash.append(ord(i))
        hash.append(0)
    hash.append(0)
    hash.append(0)

    # Simulate the string loop (like LODSB)
    for ch in hash:
        al = ch

        # Convert to uppercase if it's lowercase ASCII
        if al >= 0x61:
            al -= 0x20

        bl = al
        al = (al + al) & 0xFF  # simulate 8-bit overflow
        al ^= bl

        r9d = (r9d + al) & 0xFFFFFFFF  # 32-bit addition

        cl = bl & 0x1F  # rotate amount (5 bits for 32-bit rotate)
        # Rotate Right (ROR)
        r9d = ((r9d >> cl) | (r9d << (32 - cl))) & 0xFFFFFFFF

    return r9d

mod_name = "ntdll.dll"
hash_val = hash_module_name(mod_name)
user_mod_name = input("ENTER NtSyscall name : ")
hash_val = (hash_val + hash_module_name(user_mod_name)) & 0xFFFFFFFF
print(f"Hash for 'ntdll.dll!{mod_name}': 0x{hash_val:08X} {hash_val}")