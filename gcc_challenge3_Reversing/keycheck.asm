movi r4, 0x41424344
and r4, r0
movi r0, 0x41404044
xor r0, r4 # r0 src
movi r4, 0x45464748
and r4, r1
movi r1, 0x41044748
xor r1, r4 # r1 src
movi r4, 0x494a4b4c
and r4, r2
movi r2, 0x494a404c
xor r2, r4 # r2 src
movi r4, 0x4d4e4f50
and r4, r3 # r4 src
movi r3, 0x4d424340 # r3 src
xor r3, r4
xor r2, r3
xor r1, r2
xor r0, r1
end
