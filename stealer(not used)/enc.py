import sys
import string

key = 0x0B00B135

def xor_enc(data):
    n = bytearray()
    k1 = key & 0xff
    k2 = (key >> 8) & 0xff
    k3 = (key >> 16) & 0xff
    k4 = (key >> 24) & 0xff

    for byte in data:
        tmp = byte ^ k1
        tmp ^= k2
        tmp ^= k3
        tmp ^= k4
        n.append(tmp)

    return bytes(n)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} [data]")
        sys.exit()

    data = sys.argv[1]#.encode()


    print("XOR'ing {} bytes of data...".format(len(data)))
    #print(data)
    xor_data = xor_enc(data.encode())
    print("".join([f"0x{byte:02X}, " for byte in xor_data]))


if __name__ == "__main__":
    main()