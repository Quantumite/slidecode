# Python container for constants used in slidecode

SLIDECODE_DESCRIPTION = """
SlideCode is a shellcode wrapper that uses 4, 4-byte keys but XOR encodes each byte with the next key. In this way, most bytes are XOR encoded multiple times.
"""

SLIDECODE_IN_HELP = "Pass in the filename of the shellcode to be encoded."

SLIDECODE_OUT_HELP = "Pass in the filename for the ouput of the encoded shellcode. Default: shellcode_output.bin"

SLIDECODE_VERBOSE_HELP = "Pass in this flag for verbose information during shellcode encoding."

SLIDECODE_KEY_HELP = """Use this argument to pass in new key values. These key values should be in hexadecimal format without any prefixes.
    i.e. -k ABCDABCD and not -k \\xAB\\xCD\\xAB\\xCD and also not -k 0xABCDABCD.

    Defaults: 12233445, 9944aa72, bccddeef, aaaaaaaa

"""

SLIDECODE_TRAILER_HELP = """Use this flag to change the trailer that is appended to the encoded shellcode that is used by the decoder. Default: aabbccdd.
    i.e. -t 90909090 and not -t \\x90\\x90\\x90\\x90 and also not -t 0x90919293."""

SLIDECODE_TOO_MANY_KEYS = "[!] Too many keys provided, only the first four will be used."

SLIDECODE_SIZE_FINAL_CALL = 5
SLIDECODE_OFFSET_FOURTH_KEY = -1*(4+SLIDECODE_SIZE_FINAL_CALL)
SLIDECODE_OFFSET_THIRD_KEY = -1*(8+SLIDECODE_SIZE_FINAL_CALL)
SLIDECODE_OFFSET_SECOND_KEY = -1*(12+SLIDECODE_SIZE_FINAL_CALL)
SLIDECODE_OFFSET_FIRST_KEY = -1*(16+SLIDECODE_SIZE_FINAL_CALL)
