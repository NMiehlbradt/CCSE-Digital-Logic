start:
put r1, num_a
ldr r1, [r1]
put r2, num_b
ldr r2, [r2]
add r3, r1, r2
put r4, num_a
str r3, [r4]
not rz, rz
jnz start

num_a:
.long 10
num_b:
.long 2