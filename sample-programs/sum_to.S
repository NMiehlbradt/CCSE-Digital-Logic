    put r5, 1
    put r1, 5
    call sum_to

    not rz, rz
end:
    jnz end

sum_to:
    cmp r1, rz
    jnz recursive_case
    ret
recursive_case:
    # Push lr to stack
    sub sp, sp, r5
    str lr, [sp]
    # Push r1 to stack
    sub sp, sp, r5
    str r1, [sp]
    # Decrement r1
    sub r1, r1, r5
    call sum_to
    # Pop r2
    ldr r2, [sp]
    add sp, sp, r5
    # Do sum
    add r1, r1, r2
    # Pop lr
    ldr lr, [sp]
    add sp, sp, r5
    ret
