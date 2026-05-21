from datetime import datetime

# 32-bit unsigned arithmetic helper
def u32(x):
    return x & 0xFFFFFFFF

def generate_subdomains_by_date(count):
    now = datetime.now()

    # Seed = YYYYMMDD
    seed = (now.year * 10000) + (now.month * 100) + now.day
    seed = u32(seed)

    subdomains = []

    for _ in range(count):
        # advance seed
        seed = u32(1664525 * seed + 1013904223)

        name = []

        for _ in range(12):
            seed = u32(1664525 * seed + 1013904223)
            r = (seed >> 16) & 0x7FFF
            r %= 62

            if r < 26:
                name.append(chr(ord('A') + r))
            elif r < 52:
                name.append(chr(ord('a') + (r - 26)))
            else:
                name.append(chr(ord('0') + (r - 52)))

        subdomains.append("".join(name) + ".yourdomain.TLD")

    return subdomains


if __name__ == "__main__":
    domains = generate_subdomains_by_date(10)
    for d in domains:
        print(d)