start:
    put R0,     5
    ldr r1, [r2]
str r3, [r4]
.long 20
.long start
.long 0b1101, end, 0x4, -2
add r5, r6, r7
orr RZ, r1, r2
and r3, r4, r5
not r6, r7
end:
jnz start