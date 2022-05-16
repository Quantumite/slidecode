import os.path
import slidecode.slide_code_constants

class SlideCode():
    """SlideCode class manages encoding process."""
    def __init__(self, infile=None, outfile=None, verbose=False, key_string=None, trailer=None):
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
        if os.path.exists(f"{_curdir}\\slidecode_header.bin"):
            with open(f"{_curdir}\\slidecode_header.bin", 'rb') as h:
                self._header = bytearray(h.read())

            if self.verbose:
                print(f"[*] First few bytes of header: {self._header[:6]}")
        else:
            if self.verbose:
                print(f"[!] No shellcode header found.")


    def set_first_key(self, key_value):
        """Set new value for first shellcode key."""
        self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY] = int(key_value[:2], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+1] = int(key_value[2:4], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+2] = int(key_value[4:6], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY+3] = int(key_value[6:8], 16)

    def set_second_key(self, key_value):
        """Set new value for first shellcode key."""
        self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY] = int(key_value[:2], 16)
        self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+1] = int(key_value[2:4], 16)
        self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+2] = int(key_value[4:6], 16)
        self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY+3] = int(key_value[6:8], 16)

    def set_third_key(self, key_value):
        """Set new value for first shellcode key."""
        self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY] = int(key_value[:2], 16)
        self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+1] = int(key_value[2:4], 16)
        self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+2] = int(key_value[4:6], 16)
        self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY+3] = int(key_value[6:8], 16)

    def set_fourth_key(self, key_value):
        """Set new value for first shellcode key."""
        self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY] = int(key_value[:2], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+1] = int(key_value[2:4], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+2] = int(key_value[4:6], 16)
        self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY+3] = int(key_value[6:8], 16)


    def process_key_string(self):
        """Parse and assign key string as shellcode keys."""
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
            if self.verbose:
                print(slidecode.SLIDECODE_TOO_MANY_KEYS)

        if self.verbose:
            print("[*] Keys are now:")
            print(f"\tKEY 1: {self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY:slidecode.SLIDECODE_OFFSET_FIRST_KEY+4]}")
            print(f"\tKEY 2: {self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY:slidecode.SLIDECODE_OFFSET_SECOND_KEY+4]}")
            print(f"\tKEY 3: {self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY:slidecode.SLIDECODE_OFFSET_THIRD_KEY+4]}")
            print(f"\tKEY 4: {self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY:slidecode.SLIDECODE_OFFSET_FOURTH_KEY+4]}")


    def process_trailer(self, trailer_value):
        """Set new value for trailer."""
        _trailer_offset = 0
        #This loop is looking for the original trailer value in the shellcode.
        #Its part of an instruction so we need to find the correct location and repalce the value its
        #being compared to.
        for i in range(len(self._header)):
            if self._header[i] == 0xaa:
                if self._header[i+1] == 0xbb and self._header[i+2] == 0xcc and self._header[i+3] == 0xdd:
                    print("found trailer comparison")
                    _trailer_offset = i
                
        self._header[_trailer_offset] = int(trailer_value[:2], 16)
        self._header[_trailer_offset+1] = int(trailer_value[2:4], 16)
        self._header[_trailer_offset+2] = int(trailer_value[4:6], 16)
        self._header[_trailer_offset+3] = int(trailer_value[6:8], 16)

        self._trailer = bytearray(self._header[_trailer_offset:_trailer_offset+4])



    def encode(self):
        """Encode provided shellcode."""
        KEYS = [
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_FIRST_KEY:slidecode.SLIDECODE_OFFSET_FIRST_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_SECOND_KEY:slidecode.SLIDECODE_OFFSET_SECOND_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_THIRD_KEY:slidecode.SLIDECODE_OFFSET_THIRD_KEY+4]),
            bytearray(self._header[slidecode.SLIDECODE_OFFSET_FOURTH_KEY:slidecode.SLIDECODE_OFFSET_FOURTH_KEY+4]),
        ]
        

        #iterate through the length - 4 because operation applies to entire dword from address
        for i in range(0, len(self._infile_bytes)-3):
            #rotate through keys
            KEY = KEYS[i%4]
            if self.verbose:
                print(f'[*] KEY: {KEY}')

            #encode entire dword
            if self.verbose:
                print(f"[*] KEY[0]: {hex(KEY[0])}, byte[{i}]: {hex(self._infile_bytes[i])}", end=", ")
                print(f"XOR: {hex(KEY[0] ^ self._infile_bytes[i])}")
            self._infile_bytes[i] = KEY[0] ^ self._infile_bytes[i]

            if self.verbose:
                print(f"[*] KEY[1]: {hex(KEY[1])}, byte[{i+1}]: {hex(self._infile_bytes[i+1])}", end=", ")
                print(f"XOR: {hex(KEY[1] ^ self._infile_bytes[i+1])}")
            self._infile_bytes[i+1] = KEY[1] ^ self._infile_bytes[i+1]
            
            if self.verbose:
                print(f"[*] KEY[2]: {hex(KEY[2])}, byte[{i+2}]: {hex(self._infile_bytes[i+2])}", end=", ")
                print(f"XOR: {hex(KEY[2] ^ self._infile_bytes[i+2])}")
            self._infile_bytes[i+2] = KEY[2] ^ self._infile_bytes[i+2]

            if self.verbose:
                print(f"[*] KEY[3]: {hex(KEY[3])}, byte[{i+3}]: {hex(self._infile_bytes[i+3])}", end=", ")
                print(f"XOR: {hex(KEY[3] ^ self._infile_bytes[i+3])}")
            self._infile_bytes[i+3] = KEY[3] ^ self._infile_bytes[i+3]

        self._encoded_bytes = bytearray(self._infile_bytes)

    def run(self):
        """Process incoming shellcode and produce encoded shellcode."""
        if self.key_string is not None:
            self.process_key_string()

        if self._trailer is not None:
            self.process_trailer(self._trailer)
        else:
            self._trailer = b"\xaa\xbb\xcc\xdd"

        self.encode()
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
            with open("slidecode_output.bin", 'wb') as f:
                f.write(self._outfile_bytes)




    