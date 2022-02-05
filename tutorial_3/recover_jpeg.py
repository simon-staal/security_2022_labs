from os.path import exists

INPUT='data'
OUTPUT='data.jpeg'

if exists(OUTPUT):
    print(f'File {OUTPUT} exists, clearing contents')
    open(OUTPUT, 'wb').close()

with open(INPUT, 'rb') as in_file:
    with open(OUTPUT, 'ab') as out_file:
        i = 0
        while True:
            byte = in_file.read(1)
            if not byte:
                print("Reached {INPUT} EOF without finding JPEG header")
                exit(1)
            if int.from_bytes(byte, 'big') == 0xFF:
                b_ff = byte
                byte = in_file.read(1)
                if int.from_bytes(byte, 'big') == 0xD8:
                    print(f'Found JPEG Header, writing to file {OUTPUT}')
                    out_file.write(b_ff+byte)
                    out_file.write(in_file.read())
                    exit(0)
