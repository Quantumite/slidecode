import os.path
import slidecode.slide_code_constants

class SlideCode():
    """SlideCode class manages encoding process."""
    def __init__(self, infile=None, outfile=None, verbose=False, key_string=None, trailer=None, arch=32):
        #Intialize member variables
        self.infile = infile
        self.outfile = outfile
        self.verbose = verbose
        self.key_string = key_string
        self._infile_bytes = None
        self._outfile_bytes = None
        self._encoded_bytes = []
        self._header = None
        self._trailer = trailer
        self.arch = arch

        #Read in shellcode if given
        if self.infile is not None:
            with open(self.infile, "rb") as f:
                self._infile_bytes = bytearray(f.read())
            if self.verbose:
                print(f"[*] First few bytes of provided shellcode: {self._infile_bytes[:6]}")
        else:
            if self.verbose:
                print(f"[!] No shellcode provided.")

        #Read in slidecode assembly header from package
        _curdir = os.path.dirname(os.path.abspath(__file__))
        if self.arch == 32:
            if os.path.exists(f"{_curdir}\\slidecode_header.bin"):
                with open(f"{_curdir}\\slidecode_header.bin", 'rb') as h:
                    self._header = bytearray(h.read())

            if self.verbose:
                print(f"[*] First few bytes of header: {self._header[:6]}")
        elif self.arch == 64:
            if os.path.exists(f"{_curdir}\\slidecode_header64.bin"):
                with open(f"{_curdir}\\slidecode_header64.bin", 'rb') as h:
                    self._header = bytearray(h.read())

            if self.verbose:
                print(f"[*] First few bytes of header64: {self._header[:6]}")
        else:
            if self.verbose:
                print(f"[!] No shellcode header found.")


    def set_first_key(self, key_value):
        """Set new value for first shellcode key."""
        #Parses value given for first key and applies it to the correct offset.
        if self.arch == 32:
            self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+3] = int(key_value[6:8], 16)
        elif self.arch == 64:
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+3] = int(key_value[6:8], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+4] = int(key_value[8:10], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+5] = int(key_value[10:12], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+6] = int(key_value[12:14], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY+7] = int(key_value[14:16], 16)
        else:
            print(f"[!] Invalid architecture during set_first_key()")


    def set_second_key(self, key_value):
        """Set new value for second shellcode key."""
        #Parses value given for second key and applies it to the correct offset.
        if self.arch == 32:
            self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+3] = int(key_value[6:8], 16)
        elif self.arch == 64:
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+3] = int(key_value[6:8], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+4] = int(key_value[8:10], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+5] = int(key_value[10:12], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+6] = int(key_value[12:14], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY+7] = int(key_value[14:16], 16)
        else:
            print(f"[!] Invalid architecture during set_second_key()")

    def set_third_key(self, key_value):
        """Set new value for third shellcode key."""
        #Parses value given for third key and applies it to the correct offset.
        if self.arch == 32:
            self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+3] = int(key_value[6:8], 16)
        elif self.arch == 64:
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+3] = int(key_value[6:8], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+4] = int(key_value[8:10], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+5] = int(key_value[10:12], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+6] = int(key_value[12:14], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY+7] = int(key_value[14:16], 16)
        else:
            print(f"[!] Invalid architecture during set_third_key()")

    def set_fourth_key(self, key_value):
        """Set new value for fourth shellcode key."""
        #Parses value given for fourth key and applies it to the correct offset.
        if self.arch == 32:
            self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+3] = int(key_value[6:8], 16)
        elif self.arch == 64:
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY] = int(key_value[:2], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+1] = int(key_value[2:4], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+2] = int(key_value[4:6], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+3] = int(key_value[6:8], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+4] = int(key_value[8:10], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+5] = int(key_value[10:12], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+6] = int(key_value[12:14], 16)
            self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+7] = int(key_value[14:16], 16)
        else:
            print(f"[!] Invalid architecture during set_fourth_key()")

    def process_key_string(self):
        """Parse and assign key string as shellcode keys."""
        #Keys should be hexadecimal digits passed as a 
        # comma-separated string to the -k argument.
        _parsed_key_list = self.key_string.split(',')
        _length_key_list = len(_parsed_key_list)

        if _length_key_list >= 1:
            self.set_first_key(_parsed_key_list[0])
        
        if _length_key_list >= 2:
            self.set_second_key(_parsed_key_list[1])

        if _length_key_list >= 3:
            self.set_third_key(_parsed_key_list[2])

        if _length_key_list >= 4:
            self.set_fourth_key(_parsed_key_list[3])

        if _length_key_list >= 5:
            #We ignore any extra keys
            if self.verbose:
                print(slidecode.SLIDECODE_TOO_MANY_KEYS)

        if self.verbose:
            print("[*] Keys are now:")
            if self.arch == 32:
                print(f"\tKEY 1: {self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY:slidecode.SLIDECODE_OFFSET_FIRST_KEY+4]}")
                print(f"\tKEY 2: {self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY:slidecode.SLIDECODE_OFFSET_SECOND_KEY+4]}")
                print(f"\tKEY 3: {self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY:slidecode.SLIDECODE_OFFSET_THIRD_KEY+4]}")
                print(f"\tKEY 4: {self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY:slidecode.SLIDECODE_OFFSET_FOURTH_KEY+4]}")
            elif self.arch == 64:
                print(f"\tKEY 1: {self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY:slidecode.SLIDECODE_OFFSET_FIRST_KEY+8]}")
                print(f"\tKEY 2: {self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY:slidecode.SLIDECODE_OFFSET_SECOND_KEY+8]}")
                print(f"\tKEY 3: {self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY:slidecode.SLIDECODE_OFFSET_THIRD_KEY+8]}")
                print(f"\tKEY 4: {self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY:slidecode.SLIDECODE_OFFSET_FOURTH_KEY+8]}")



    def process_trailer(self, trailer_value):
        """Set new value for trailer."""
        _trailer_offset = 0
        #This loop is looking for the original trailer value in the shellcode.
        #Its part of an instruction so we need to find the correct location and repalce the value its
        #being compared to.
        for i in range(len(self._header)):
            if self._header[i] == 0xaa:
                if self._header[i+1] == 0xbb and self._header[i+2] == 0xcc and self._header[i+3] == 0xdd:
                    _trailer_offset = i
                
        #Similar parsing to key values, but only one since the trailer
        # is 4 bytes (32-bit) or 8 bytes (64-bit).
        if self.arch == 32:
            self._header[_trailer_offset] = int(trailer_value[:2], 16)
            self._header[_trailer_offset+1] = int(trailer_value[2:4], 16)
            self._header[_trailer_offset+2] = int(trailer_value[4:6], 16)
            self._header[_trailer_offset+3] = int(trailer_value[6:8], 16)
        elif self.arch == 64:
            self._header[_trailer_offset] = int(trailer_value[:2], 16)
            self._header[_trailer_offset+1] = int(trailer_value[2:4], 16)
            self._header[_trailer_offset+2] = int(trailer_value[4:6], 16)
            self._header[_trailer_offset+3] = int(trailer_value[6:8], 16)
            self._header[_trailer_offset+4] = int(trailer_value[8:10], 16)
            self._header[_trailer_offset+5] = int(trailer_value[10:12], 16)
            self._header[_trailer_offset+6] = int(trailer_value[12:14], 16)
            self._header[_trailer_offset+7] = int(trailer_value[14:16], 16)
        else:
            print(f"[!] Invalid architecture while processing trailer.")


        #Convert trailer string to bytearray for output
        if self.arch == 32:
            self._trailer = bytearray(self._header[_trailer_offset:_trailer_offset+4])
        elif self.arch == 64:
            self._trailer = bytearray(self._header[_trailer_offset:_trailer_offset+8])
        else:
            print("[!] Invalid architecture while processing trailer.")

    def encode(self):
        """Encode provided shellcode."""
        #Keys are grabbed from the header shellcode in case they
        # were modified by the user
        KEYS = [
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY:slidecode.SLIDECODE_OFFSET_FIRST_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY:slidecode.SLIDECODE_OFFSET_SECOND_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY:slidecode.SLIDECODE_OFFSET_THIRD_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY:slidecode.SLIDECODE_OFFSET_FOURTH_KEY+4]),
        ]

        #iterate through the length - 3 because operation applies to entire dword from address; address + 3 bytes more is full DWORD
        for i in range(0, len(self._infile_bytes)-3):
            #rotate through keys
            KEY = KEYS[i%4]
            if self.verbose:
                print(f'[*] KEY: {KEY}')

            for j in range(0,4):
                #encode entire dword
                if self.verbose:
                    print(f"[*] KEY[{j}]: {hex(KEY[j])}, byte[{i+j}]: {hex(self._infile_bytes[i+j])}", end=", ")
                    print(f"XOR: {hex(KEY[j] ^ self._infile_bytes[i+j])}")
                self._infile_bytes[i+j] = KEY[j] ^ self._infile_bytes[i+j]

        #Convert to bytearray for output
        self._encoded_bytes = bytearray(self._infile_bytes)

    def encode64(self):
        """Encode provided shellcode."""
        #Keys are grabbed from the header shellcode in case they
        # were modified by the user
        KEYS = [
            bytearray(self._header[slidecode.SLIDECODE64_OFFSET_FIRST_KEY:slidecode.SLIDECODE64_OFFSET_FIRST_KEY+8]),
            bytearray(self._header[slidecode.SLIDECODE64_OFFSET_SECOND_KEY:slidecode.SLIDECODE64_OFFSET_SECOND_KEY+8]),
            bytearray(self._header[slidecode.SLIDECODE64_OFFSET_THIRD_KEY:slidecode.SLIDECODE64_OFFSET_THIRD_KEY+8]),
            bytearray(self._header[slidecode.SLIDECODE64_OFFSET_FOURTH_KEY:slidecode.SLIDECODE64_OFFSET_FOURTH_KEY+8]),
        ]

        #iterate through the length - 3 because operation applies to entire dword from address; address + 3 bytes more is full DWORD
        for i in range(0, len(self._infile_bytes)-7):
            #rotate through keys
            KEY = KEYS[i%4]
            if self.verbose:
                print(f'[*] KEY: {KEY}')

            for j in range(0,8):
                #encode entire dword
                if self.verbose:
                    print(f"[*] KEY[{j}]: {hex(KEY[j])}, byte[{i+j}]: {hex(self._infile_bytes[i+j])}", end=", ")
                    print(f"XOR: {hex(KEY[j] ^ self._infile_bytes[i+j])}")
                self._infile_bytes[i+j] = KEY[j] ^ self._infile_bytes[i+j]

        #Convert to bytearray for output
        self._encoded_bytes = bytearray(self._infile_bytes)

    def run(self):
        """Process incoming shellcode and produce encoded shellcode."""
        #By default, key_string is None. If it's not None then
        # it was set by the user.
        #Default values are already in shellcode header
        if self.key_string is not None:
            self.process_key_string()

        #By default, _trailer is None. If it's not None then
        # it was set by the user.
        if self._trailer is not None:
            self.process_trailer(self._trailer)
        else:
            #Default value
            if self.arch == 32:
                self._trailer = b"\xaa\xbb\xcc\xdd"
            elif self.arch == 64:
                self._trailer = b"\xaa\xbb\xcc\xdd\xaa\xbb\xcc\xdd"
            else:
                print(f"[!] Invalid architecture while setting default trailer.")

        if self.arch == 32:
            self.encode()
        elif self.arch == 64:
            self.encode64()
        else:
            print(f"[!] Invalid architecture while encoding bytes.")

        self._outfile_bytes = self._header
        if self.verbose:
            print("[*] Writing encoded payload to file.")

        for b in self._encoded_bytes:
            self._outfile_bytes += b.to_bytes(1, 'little')
        self._outfile_bytes += self._trailer

        if self.outfile is not None:
            with open(self.outfile, 'wb') as f:
                f.write(self._outfile_bytes)
        else:
            #Default output file
            if self.arch == 32:
                with open("slidecode_output.bin", 'wb') as f:
                    f.write(self._outfile_bytes)
            elif self.arch == 64:
                with open("slidecode_output64.bin", 'wb') as f:
                    f.write(self._outfile_bytes)
            else:
                print(f"Invalid architecture while writing output file.")





    