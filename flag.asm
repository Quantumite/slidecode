; Assembly file for CyberDawgs CTF 2023

    SECTION .text
    global main

main:
    jmp end
    db "DawgCTF{$liD3_+o_+h3_L3f+_$lid3_+o_+h3_Righ+_005}",0
end:
    ;seems to be a bug with this assembly so emitting correct bytes myself
    ;this is needed to bypass a checkESP call
    db 0x8d, 0x74, 0x24, 0x04 ;lea esi, [esp+4]
    ret