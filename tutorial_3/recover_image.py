with open('data', 'rb') as in_file:
    with open('data2.jpeg', 'ab') as out_file:
        i = 0
        while True:
            byte = in_file.read(1)
            if not byte:
                print("Reached EOF without finding JPEG header")
                exit(1)
            if int.from_bytes(byte, 'big') == 0xFF:
                b_ff = byte
                byte = in_file.read(1)
                if int.from_bytes(byte, 'big') == 0xD8:
                    print(f'Writing to file {b_ff}, {byte}')
                    out_file.write(b_ff)
                    out_file.write(byte)
                    out_file.write(in_file.read())
                    exit(0)
