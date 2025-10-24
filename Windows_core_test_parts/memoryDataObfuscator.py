import random
import zlib

#covert base 10 in to a another base that can represent as XX (eg: 11 22 55 AA) and return result and base
def to_base(n):
    y = n
    if n < 3:
        return f"{n}{n}",10
    
    for base in range(2,37):
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = ""
        while n > 0:
            n, r = divmod(n, base)
            result = digits[r] + result
        n = y
        if(len(result) != 2):
            continue
        if(result[0] == result[1]):
            return result,base
    
    return "11",n-1

#unique_base and bit map (dictonry)
def bitMap(unique_bit):
    bit_map = {}
    bitMapSize = len(unique_bit)

    # Find minimum bits required
    bits = 1
    while 2 ** bits < bitMapSize:
        bits += 1

    # Generate all possible bit combinations
    bit_list = [format(i, f'0{bits}b') for i in range(2 ** bits)]

    # Map each unique bit value to one binary pattern
    for i, value in enumerate(unique_bit):
        bit_map[value] = bit_list[i]

    return bit_map


#==============================
RAM = []

# Open file in binary mode ('rb' = read binary)
with open("bin/_syscallExtracter.obj", "rb") as f:
    data = f.read()  # this gives you a bytes object

# Convert bytes → list of integers
byte_list = list(data)


TEST_BYTES = byte_list[:50]
print(f"Original Bytes   ({len(TEST_BYTES)}) ->", ''.join(map(str, TEST_BYTES)))

iterates = int(input("Enter iterations: "))
compressed_bytes = []
base_array = []
unique_base = []
Original_size = len(TEST_BYTES)

# compressing real bytes and output base list 
for iterate in range(iterates):
    base_array = []
    unique_base = []
    for byte in TEST_BYTES:
        value, base = to_base(byte)
        compressed_bytes.append(value[0])
        base_array.append(base)
        if base not in unique_base:
            unique_base.append(base)
    TEST_BYTES = base_array

# # creating bitmap for unique base
# bitMapList = bitMap(unique_base)

# for i,value in enumerate(base_array):
#     base_array[i] = bitMapList[value]


#print("BitmapList            ->",bitMapList)
# print(f"Original Bytes   ({len(TEST_BYTES)}) ->", ''.join(map(str, TEST_BYTES)))
# print(f"Compressed Bytes ({len(compressed_bytes)}) ->",compressed_bytes + base_array)
# #print(f"Base Bytes       ({len(base_array)}) ->", base_array)
# #print(f"Uneque Base Bytes ({len(unique_base)}) ->",unique_base)
# print(f"({iterates}) interates Done\n")




int_list = [int(x, 16) for x in compressed_bytes]


TEST_BYTES = int_list + base_array


compressed_bytes = []
base_array = []
unique_base = []


for byte in TEST_BYTES:
    value, base = to_base(byte)
    compressed_bytes.append(value[0])
    base_array.append(base)
    if base not in unique_base:
        unique_base.append(base)

# ctemp = ""
# for cdata in compressed_bytes:

#     if cdata == "0" and ctemp != "0":
#         RAM.append(0)
#         RAM.append(0)
#     elif cdata == "1" and ctemp != "1":
#         RAM.append(0)
#         RAM.append(1)
#     elif cdata == "2" and ctemp != "2":
#         RAM.append(1)
#         RAM.append(1)
#     elif cdata != "1" and cdata != "2":
#         RAM.append(False)
#         raise ValueError("OR MY GOD, INCREASE ITERATIONS!")
#     #ctemp = cdata

# RAM.append(0)
# RAM.append(0)
# RAM.append(0)
# RAM.append(0)
# RAM.append(0)
# RAM.append(0)
# RAM.append(0)
# RAM.append(0)

# bitMapList = bitMap(unique_base)

# for i,value in enumerate(base_array):
#     base_array[i] = bitMapList[value]

# print("BitmapList            ->",bitMapList)
# print(f"Original Bytes   ({len(TEST_BYTES)}) ->", ''.join(map(str, TEST_BYTES)))
# print(f"Compressed Bytes ({len(compressed_bytes)}) ->",compressed_bytes)
# print(f"Base Bytes       ({len(base_array)}) ->", base_array)
# print(f"Uneque Base Bytes ({len(unique_base)}) ->",unique_base)


full_array = compressed_bytes + list(map(str,base_array))
nibbles = full_array

unique_list = list(set(full_array))

bitMapList = bitMap(unique_list)

for i,value in enumerate(full_array):
    full_array[i] = bitMapList[value]

#print(f"\nFull bytes ({len(full_array)/2}) ->\n",full_array)
full_size = len(full_array) *len(full_array[0])

full_array = ''.join(full_array)

print(f"\nFull bytes ({full_size/8}) ->\n",full_array)

index_arr = []
i = 0
changed_index = 1

# while i < len(full_array):
#     if full_array[i] == '1':
#         # Check if there are exactly 3 zeros before this '1'
#         if i >= 2 and full_array[i-2:i] == '00':
#             # Record the index (before removal)
#             index_arr.append(changed_index)
            
#             # Remove those 3 zeros
#             full_array = full_array[:i-2] + full_array[i:]
            
#             # After removal, move index back by 3 since string is shorter
#             i -= 2
#             continue
#         changed_index +=1
#     i += 1

full_size = len(full_array)/8

print(f"\nFull bytes ({full_size}) ->\n",full_array)
print("index array ->",index_arr)

# bit_width = len(nibbles[0])         # 2 in this case

# # Convert each string to int (fits within bit_width)
# int_array = [int(b, 2) for b in nibbles]

# # Optional: store in a bytearray (each element is 0–2**bit_width-1)
# byte_array = bytearray(int_array)



# compressed = zlib.compress(byte_array)
# #print(f"\nOriginal size: {len(byte_array)} bytes")
# print(f"\nCompressed size: {len(compressed)} bytes")

# # Optionally save to file
# with open("compressed.bin", "wb") as f:
#     f.write(compressed)


