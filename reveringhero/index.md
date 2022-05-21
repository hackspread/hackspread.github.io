# Reversing Hero


## INTRODUCTION

<div class="text">
ReversingHero is a Reverse Engineering self learning kit (x86_64 on linux) wrapped inside one binary file. It is made of 15 levels, with difficulty gradually increasing.

Created by xoprd, this course can be found here : [Reversing Hero](https://gumroad.com/l/reversinghero)


Here is just my attempt to solve  the 15 levels.
</div>

## &#9656; Reversing Hero 1

---

## &#9656; Reversing Hero 2


 The following procedure shows a simple routine where there is a bit rotation. 
Basically what happens is a permutation of the inserted value, this permutation has to give as result the following number **89349536319392163324855876422573**

Exploring the binary in IDA, we can see that the program is expecting a 64 length input.
My first lazy experiment was to insert the string : **abcdefghijklmnopqrstuvwxyz123456**

Here we get an interesting output : **lfatoi2wrd5zmgbupj3xse61nhcvqk4y**

So the permutation of **abcdefghijklmnopqrstuvwxyz123456** gives **lfatoi2wrd5zmgbupj3xse61nhcvqk4y**, we can easily assume that **lfatoi2wrd5zmgbupj3xse61nhcvqk4y** corresponds to **89349536319392163324855876422573**


|l|f|a|t|o|i|2|w|r|d|5|z|m|g|b|u|p|j|3|x|s|e|6|1|n|h|c|v|q|k|4|y|
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
|8|9|3|4|9|5|3|6|3|1|9|3|9|2|1|6|3|3|2|4|8|5|5|8|7|6|4|2|2|5|7|3|


 Reversing the order of the string to its natural order we can then get:

|a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|1|2|3|4|5|6|
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
|3|1|4|1|5|9|2|6|5|3|5|8|9|7|9|3|2|3|8|4|6|2|6|4|3|3|8|3|2|7|9|5|

So the requested input is : **31415926535897932384626433832795**


Here the commented subroutine in assembly.


```asm
 
  ext:00000000004005DC begin of pwd generator
  00000000004005DC
  00000000004005DC rdi ;--> x
  00000000004005DC
  00000000004005DC ; =============== S U B R O U T I N E ==============================
  00000000004005DC
  00000000004005DC
  00000000004005DC sub_4005DC      proc near                    ; CODE XREF: sub_400618+12↓p
  00000000004005DC                 mov     rax, rdi		          ; x = y 
  00000000004005DF                 add     rax, 1010101b        ; x = x +0x55
  00000000004005E3                 and     rax, 11111b          ; x= (x + 0x55) & 0x1f
  00000000004005E7                 shr     rax, 1               ; x= x >> 1
  00000000004005EA                 jnb     short loc_4005F0     ; Jump if Not Below (CF=0)
  00000000004005EC  
  00000000004005EC ;if CF = 1 
  00000000004005EC      or         rax, 10000b                  ;x ^ 0x10000b
  00000000004005F0 ; if CF = 0
  00000000004005F0 loc_4005F0:                                  ; CODE XREF: sub_4005DC+E↑j
  00000000004005F0                 and     rax, 11111b          ; x & 0x1F
  00000000004005F4                 shr     rax, 1               ; x >> 1
  00000000004005F7                 jnb     short loc_4005FD     ; Jump if Not Below (CF=0)
  00000000004005F9 ; if CF=1
  00000000004005F9                 or      rax, 10000
  00000000004005FD ; if CF = 0
  00000000004005FD loc_4005FD:                                  ; CODE XREF: sub_4005DC+1B↑j
  00000000004005FD                 and     rax, 11111b          ; x & 0x1f
  0000000000400601                 shr     rax, 1               ; x= x >> 1
  0000000000400604                 jnb     short loc_40060A     ; Jump if Not Below (CF=0)
  0000000000400606 ; if CF = 1
  0000000000400606                 or      rax, 10000b          ;x ^ 0x10000b
  000000000040060A ; if CF = 0
  000000000040060A loc_40060A:                                  ; CODE XREF: sub_4005DC+28↑j
  000000000040060A                 mov     rsi, rax             ;-> x = y
  000000000040060D                 add     rax, rax             ;-> x = 2y
  0000000000400610                 add     rax, rsi             ;-> x = 2y + y = 3y
  0000000000400613                 and     rax, 11111b          ;-> x & 11111
  0000000000400617                 retn
  0000000000400617 sub_4005DC      endp
  0000000000400617
  0000000000400617 end of generator
```



 Below a small python routine to get the  correct value to insert (not mine really, you can find the script @  [geeksforgeeks.org](https://www.geeksforgeeks.org/rotate-bits-of-an-integer/))


```python
#!/usr/bin/python3

#Size of the bits
BITS_SIZE = 5
#Function rotate to right
#Rotate n by d bits

def ROR5(n,d):


    #In n>>d, fist d bits are seto to 0
    #To put last 3 bits of at first :
    # do -> bitwaise OR of (n >> d) with (n << (BITS_SIZE -d)
    return ((n >> d) | (n << (BITS_SIZE -d))) & 0xFFFFFFFF

def iter_f(x):

    x = (x + 0x55) & 0x1f
    """for num in range(1,5):"""
    x = ROR5(x,3)
    x = (3*x) & 0x1f
    return x

def main():
    """
    print("Hello World!")
    """
    my_pass = "89349536319392163324855876422573"
    for num in range (32):
        print (my_pass[iter_f(num)], end="")



if __name__ == "__main__":
    main()


```


## &#9656; Reversing Hero 3

```ida

  0000000000400529 ; =============== S U B R O U T I N E =========================
  0000000000400529
  0000000000400529 ; 1st dword = edi(rdi)= a -> -8 ->hex(2^32 + (-8))  = fffffff8
  0000000000400529 ; 2nd dword = esi(rsi)= b -> -3 ->hex(2^32 + (-3))  = fffffffd
  0000000000400529 ; 3rd dword = edx(rdx)= c -> 13 ->hex(2^32 + (+13)) =(1)0000000d
  0000000000400529 ;
  0000000000400529
  0000000000400529 sub_400529 proc near       ; CODE XREF: _start+A7↑p
  0000000000400529 lea     ecx, [edi+edx]     ; a+c
  000000000040052D add     ecx, esi           ; (a+c)+b
  000000000040052F add     ecx, ecx           ; 2*((a+c)+b)
  0000000000400531 add     ecx, esi           ; (2*((a+c)+b)) + b == 1
  0000000000400533 loop    loc_400554
  0000000000400535 lea     ecx, [esi+edi*2]   ; b+(2*a)
  0000000000400539 add     ecx, edx           ; (b+(a*2))+c
  000000000040053B add     ecx, ecx           ; 2*((b+(a*2))+c)
  000000000040053D add     ecx, edx           ; (2*((b+(a*2))+c))+c
  000000000040053F loop    loc_400554
  0000000000400541 lea     ecx, [edi+edx]     ; a+c
  0000000000400545 add     ecx, esi           ; (a+c)+b
  0000000000400547 shl     ecx, 3             ; 8*((a+c)+b) --> shl,3 = 2^3
  000000000040054A add     ecx, edi           ; (8*((a+c)+b)) + a
  000000000040054C sub     ecx, edx           ; ((8*((a+c)+b)) + a ) - c
  000000000040054E sub     ecx, esi           ; (((8*((a+c)+b)) + a ) - c) - b
  0000000000400550 sub     ecx, esi           ; ((((8*((a+c)+b)) + a ) - c) - b ) - b
  0000000000400552 loop    $+2
  0000000000400554
  0000000000400554 loc_400554:                ; CODE XREF: sub_400529+A↑j
  0000000000400554                             sub_400529+16↑j ...
  0000000000400554 mov     rax, rcx
  0000000000400557 retn
  0000000000400557 sub_400529 endp
  0000000000400557
  0000000000400558
  0000000000400558 ; =============== S U B R O U T I N E =======================================

```


## &#9656; Reversing Hero 4

```asm
;here where the routine starts, magic input 00000000000000000000000000000000000000000000000000000000000000001111111211211122121112121221122211111112112111221211121212211222
f_key_generator proc near               ; CODE XREF: sub_4003E4+4A↓p
  0000000000400368                 sub     rsi, 30h
  000000000040036C                 jz      short loc_40037A ; if RSI = 0
  000000000040036E RSI > 0
  000000000040036E                 dec     rsi             ; RSI -=1
  0000000000400371                 jz      short loc_400397 ; if RSI = 1
  0000000000400373 if RSI > 1
  0000000000400373                 dec     rsi
  0000000000400376                 jz      short loc_4003B8 ;  if ((RSI > 1) - 1) - 1 = 0
  0000000000400378                 jmp     short f_exit
  000000000040037A ; ---------------------------------------------------------------------------
  000000000040037A IF RSI = 0
  000000000040037A
  000000000040037A loc_40037A:                             ; CODE XREF: f_key_generator+4↑j
.000000000040037A                 mov     ecx, [rdi+8]
  000000000040037D                 jecxz   f_exit          ; The jecxz (or jne) instruction is a conditional jump that follows a test.
  000000000040037D                                         ; It jumps to the specified location if ECX=0 (f_exit)
  0000000000400380 Sets bit in CL position to ZERO and DECREMENTS CL for reading next bit (going from 0x40f to 0)
  0000000000400380
  0000000000400380 EXC = 0x40
  0000000000400380 RSI = 0 -> read char "0"
  0000000000400380 rax = x
  0000000000400380                 mov     rax, [rdi]      ; x = DEADFACEDEADBEEF
  0000000000400383                 rol     rax, cl         ; x <<< cl -> ror rax of cl
  0000000000400386
  0000000000400386 setting the LSB to 0
  0000000000400386 eg.
  0000000000400386
  0000000000400386 01111 -> initial LSB = 1
  0000000000400386 shr 1 -> 00111
  0000000000400386 shl 1 -> 01110 -> LSB is now 0
  0000000000400386
  0000000000400386
  0000000000400386                 shr     rax, 1          ; x = x/2 -> divide rax by 2^1 -> rax/2
  0000000000400389                 shl     rax, 1          ; x = x * 2 -> multiply rax by 2^1 -> rax *2
  000000000040038C                 ror     rax, cl         ; x >>> cl -> rol rax of cl
  000000000040038F                 mov     [rdi], rax      ; copy x value at RDI memory location (RAX - 1)
  0000000000400392                 dec     dword ptr [rdi+8] ; decremente x040f value
  0000000000400395                 jmp     short loc_4003DB
  0000000000400397 ; ---------------------------------------------------------------------------
  0000000000400397 if RSI = 1
  0000000000400397
  0000000000400397 loc_400397:                             ; CODE XREF: f_key_generator+9↑j
  0000000000400397                 mov     ecx, [rdi+8]
  000000000040039A                 cmp     ecx, 40h
  000000000040039D                 jnb     short f_exit    ; if exc >= 0x40
  000000000040039F ;Sets bit in CL position to ZERO and INCREMENTS CL for reading next bit ;(going from 0 to 0x40f)
  000000000040039F
  000000000040039F RSI = 1 -> read_char ("1")
  000000000040039F ECX < 0x40
  000000000040039F                 mov     rax, [rdi]
  00000000004003A2                 inc     ecx
  00000000004003A4                 rol     rax, cl
  00000000004003A7
  00000000004003A7 setting the LSB to 0
  00000000004003A7 eg.
  00000000004003A7
  00000000004003A7 01111 -> initial LSB = 1
  00000000004003A7 shr 1 -> 00111
  00000000004003A7 shl 1 -> 01110 -> LSB is now 0
  00000000004003A7
  00000000004003A7
  00000000004003A7                 shr     rax, 1
  00000000004003AA                 shl     rax, 1
  00000000004003AD                 ror     rax, cl
  00000000004003B0                 mov     [rdi], rax
  00000000004003B3                 mov     [rdi+8], ecx
  00000000004003B6                 jmp     short loc_4003DB
  00000000004003B8 ; ---------------------------------------------------------------------------
  00000000004003B8 RSI = 2 -> read_char("2")
  00000000004003B8
  00000000004003B8 loc_4003B8:                             ; CODE XREF: f_key_generator+E↑j
  00000000004003B8                 mov     ecx, [rdi+8]
  00000000004003BB                 cmp     ecx, 40h
  00000000004003BE                 jnb     short f_exit
  00000000004003C0 Sets bit in CL position to ONE and INCREMENTS CL for reading next bit (going from 0 to 0x40f)
  00000000004003C0
  00000000004003C0 RSI = 2 -> read_char ("2")
  00000000004003C0                 mov     rax, [rdi]
  00000000004003C3                 inc     ecx
  00000000004003C5                 rol     rax, cl
  00000000004003C8 set LSB to 1
  00000000004003C8
  00000000004003C8 eg.
  00000000004003C8
  00000000004003C8 01110 -> initial LSB = 0
  00000000004003C8 shr 1 -> 00111
  00000000004003C8 shl 1 -> 01110
  00000000004003C8 or 1 ->  00001
  00000000004003C8         -------
  00000000004003C8          01111
  00000000004003C8
  00000000004003C8                 shr     rax, 1
  00000000004003CB                 shl     rax, 1
  00000000004003CE                 or      rax, 1
  00000000004003D2                 ror     rax, cl
  00000000004003D5                 mov     [rdi], rax
  00000000004003D8                 mov     [rdi+8], ecx
  00000000004003DB
  00000000004003DB loc_4003DB:                             ; CODE XREF: f_key_generator+2D↑j
  00000000004003DB                                         ; f_key_generator+4E↑j
  00000000004003DB                 xor     eax, eax
  00000000004003DD                 jmp     short locret_4003E3
  00000000004003DF ; ---------------------------------------------------------------------------
  00000000004003DF exit
  00000000004003DF
  00000000004003DF f_exit:                                 ; CODE XREF: f_key_generator+10↑j
  00000000004003DF                                         ; f_key_generator+15↑j ...
  00000000004003DF                 or      rax, 0FFFFFFFFFFFFFFFFh
  00000000004003E3
  00000000004003E3 locret_4003E3:                          ; CODE XREF: f_key_generator+75↑j
  00000000004003E3                 retn
  00000000004003E3 f_key_generator endp   
  00000000004003E3
  00000000004003E4
  00000000004003E4 ; =============== S U B R O U T I N E =======================================
  00000000004003E4
  00000000004003E4
  00000000004003E4 sub_4003E4      proc near               ; CODE XREF: _start+64↑p
  00000000004003E4
  00000000004003E4 qword_x         = qword ptr -38h
  00000000004003E4 dword_y         = dword ptr -30h
  00000000004003E4
  00000000004003E4                 push    r12
  00000000004003E6                 push    r13
  00000000004003E8                 push    r14
  00000000004003EA                 push    r15
  00000000004003EC                 push    rbp
  00000000004003ED                 sub     rsp, 10h
  00000000004003F1                 mov     [rsp+38h+qword_x], rsi ; x = 0DEADFACEDEADBEEFh (QWORD)
  00000000004003F5                 mov     [rsp+38h+dword_y], 40h ; y = 0x40(64) (DWORD)
  00000000004003FD                 mov     r12, rdi        ; r12 = a -> a = fd
  0000000000400400                 mov     r13, rdx        ; r13 = b -> b = 123456701234567h
  0000000000400403                 mov     r14, rcx        ; r14 = i -> i = 80h (for loop)
  0000000000400406                 mov     r15, r8         ; r15 = data_buff
  0000000000400409 loop for 80h(128) time
  0000000000400409
  0000000000400409 loop_for_128_decR14:                    ; CODE XREF: sub_4003E4+5F↓j
  0000000000400409                 mov     rdi, r12        ; rdi = a -> rdi = fd
  000000000040040C                 call    reads_char_file_content_
  0000000000400411                 mov     rbp, rax        ; rpb = read_char(one byte)
  0000000000400414                 or      rax, 0FFFFFFFFFFFFFFFFh ; setting RAX with 16 bits , RAX = -1
  0000000000400418                 cmp     rbp, rax        ; check if rbp is = -1 (if thechar was read)
  000000000040041B                 jz      short loc_400449 ;
  000000000040041B                                         ; cmp dst, src    ZF  CF
  000000000040041B                                         ;     dst = src   1   0
  000000000040041B                                         ;     dst < src   0   1
  000000000040041B                                         ;     dst > src   0   0
  000000000040041B                                         ;
  000000000040041B                                         ;
  000000000040041B                                         ; if (rbp != rax) then carry on ELSE exit and also return RAX = -1
  000000000040041D                 mov     rdi, r15        ; rdi = data_buff
  0000000000400420                 mov     rsi, rbp        ; rsi = x = read_char(one byte)
  0000000000400423                 call    sub_4004F0
  0000000000400428                 mov     rdi, rsp        ; rdi = buffer
  000000000040042B                 mov     rsi, rbp        ; rsi = x = read_char(one byte)
  000000000040042E                 call    f_key_generator
  0000000000400433                 test    rax, rax        ;
  0000000000400433                                         ; set ZF to 1 if rax == 0
  0000000000400433                                         ; IF rax == 0 carry on ELSE exit
  0000000000400436                 jnz     short loc_400449
  0000000000400438                 xor     eax, eax
  000000000040043A                 cmp     [rsp+38h+qword_x], r13 ;
  000000000040043A                                         ; cmp dst, src    ZF  CF
  000000000040043A                                         ;     dst = src   1   0
  000000000040043A                                         ;     dst < src   0   1
  000000000040043A                                         ;     dst > src   0   0
  000000000040043A                                         ;
  000000000040043A                                         ;
  000000000040043A                                         ; if (rsp+38h+qword_x != r13(0123456701234567)) then carry on ELSE exit
  000000000040043E                 jz      short loc_400449
  0000000000400440                 dec     r14             ; decrement i
  0000000000400443                 jnz     short loop_for_128_decR14
  0000000000400445                 or      rax, 0FFFFFFFFFFFFFFFFh
  0000000000400449
  0000000000400449 loc_400449:                             ; CODE XREF: sub_4003E4+37↑j
  0000000000400449                                         ; sub_4003E4+52↑j ...
  0000000000400449                 add     rsp, 10h
  000000000040044D                 pop     rbp
  000000000040044E                 pop     r15
  0000000000400450                 pop     r14
  0000000000400452                 pop     r13
  0000000000400454                 pop     r12
  0000000000400456                 retn
  0000000000400456 sub_4003E4      endp
  0000000000400456
  0000000000400457
  0000000000400457 ; =============== S U B R O U T I N E =======================================
  0000000000400457
  0000000000400457
  0000000000400457 xoring_32bitRAX_zero_buff proc near     ; CODE XREF: _start+37↑p
  0000000000400457                 xor     eax, eax
  0000000000400459                 mov     rcx, 20h
  0000000000400460                 rep stosb
  0000000000400462                 retn
  0000000000400462 xoring_32bitRAX_zero_buff endp
  0000000000400462
  0000000000400463
  0000000000400463 ; =============== S U B R O U T I N E =======================================
  0000000000400463
  0000000000400463
  0000000000400463 char_from_rax_dil_manipulitaion proc near
  0000000000400463                                         ; CODE XREF: rsi_bits_modification+1F↓p
  0000000000400463                                         ; rsi_bits_modification+33↓p
  0000000000400463                 movzx   rax, dil        ; movzx -> with Zero-Extend dil -> low 8 bit of RDI
  0000000000400467                 and     al, 0Fh         ; and AL with F (1111) / dil & 0x0f
  0000000000400469                 cmp     al, 0Ah         ; check if it's the end of buffer, hex value A (1010) = 10
  0000000000400469                                         ; cmp if (dil & 0x0f = 0x0a)
  0000000000400469                                         ;
  0000000000400469                                         ; cmp (dst, src)  ZF  CF
  0000000000400469                                         ; dst = src       1   0
  0000000000400469                                         ; dst < src       0   1
  0000000000400469                                         ; dst > src       0   0
  0000000000400469                                         ;
  0000000000400469                                         ; if (dil & 0x0f = 0A) -> CF 0
  0000000000400469                                         ; if (dil & 0x0f > 0A) -> CF 0
  0000000000400469                                         ; if (dil & 0x0f < 0A) -> CF 1
  000000000040046B
  000000000040046B
  000000000040046B                 sbb     dil, dil        ; Destination = Destination - (Source + CF);
  000000000040046B                                         ; dil = dil - (dil + CF)
  000000000040046B                                         ; if CF = 1 -> dil = -1
  000000000040046B                                         ; if CF = 0 -> dil = 0
  000000000040046B                                         ;
  000000000040046B                                         ; if (dil & 0x0f = 0A) -> CF 0 -> dil =  0
  000000000040046B                                         ; if (dil & 0x0f > 0A) -> CF 0 -> dil =  0
  000000000040046B                                         ; if (dil & 0x0f < 0A) -> CF 1 -> dil = -1
  000000000040046E                 not     dil             ; reverts bits in dil
  0000000000400471
  0000000000400471
  0000000000400471                 and     dil, 7          ; if dil =-1 -> dil = 7
  0000000000400471                                         ; if dil = 0 -> dil = 0
  0000000000400475                 add     al, 30h         ; add 30h(0) to al
  0000000000400477                 add     al, dil         ; Generating char -> al + 30h (48)("o") + 7
  000000000040047A                 retn
  000000000040047A char_from_rax_dil_manipulitaion endp
  000000000040047A
```



 Here were the magic happens, the rountine does these three things:

 0) with 0 
          - it sets current bit (the one correspondin cto CL) to ZERO
          - dec     dword ptr [rdi+8] ; it starts decrementing from x040f value
 1) with 1 
          - it sets current bit (the one correspondin cto CL) to ZERO
          - inc ecx , 
          - mov     [rdi+8], ecx
           it increments the value in  dword ptr [rdi+8]
 2) with 2 
          - it sets current bit (the one correspondin cto CL) to ONE
          - inc ecx , 
          - mov     [rdi+8], ecx
           it increments the value in  dword ptr [rdi+8]





> What we need to do is to run a series on 0s (64) to set the value of **[rsp+38h+qword_x]** to all 0s, then we need to start the routine for other 64 times in order to build the number  0123456701234567 --> in bits:<br>
 **000100100011010001010110011100000001001000110100010101100111** 

>Now just convert the 0 to 1 and the 1 to 2 and add that nummber to the first 64 0s:
<br> **00000000000000000000000000000000000000000000000000000000000000001111111211211122121112121221122211111112112111221211121212211222**






```NASM
 xor     eax, eax
                cmp     [rsp+38h+qword_x], r13 ; r13 = 0123456701234567
                        ; cmp dst, src    ZF  CF
                        ;     dst = src   1   0
                        ;     dst < src   0   1
                        ;     dst > src   0   0
                        ;
                        ;
                        ; if (rsp+38h+qword_x != r13(0123456701234567)) then carry on ELSE exit
                jz      short loc_400449
```


## &#9656; Reversing Hero 5

```TASM
 
 
0000000000400340 sub_400340      proc near               ; CODE XREF: _start+2A↓p
  0000000000400340                                         ; DATA XREF: _start+6D↓o ...
  0000000000400340                 push    r12
  0000000000400342                 push    r13
  0000000000400344                 push    r13
  0000000000400346                 mov     r12, rdi
  0000000000400349                 mov     r13, rsi
  000000000040034C                 xor     edx, edx        ; Logical Exclusive OR
  000000000040034E
  000000000040034E loc_40034E:                             ; CODE XREF: sub_400340+36↓j
  000000000040034E                 mov     rcx, rdx
  0000000000400351
  0000000000400351 loc_400351:                             ; CODE XREF: sub_400340+2E↓j
  0000000000400351                 mov     r8, [r12+rdx*8]
  0000000000400355                 cmp     r8, [r12+rcx*8] ; Compare Two Operands
  0000000000400359          -->    ja      short loc_400368 ; Jump if Above (CF=0 & ZF=0) 
                                                                 what if rdx=rcx ? 
  000000000040035B                 lea     rdi, [r12+rdx*8] ; Load Effective Address
  000000000040035F                 lea     rsi, [r12+rcx*8] ; Load Effective Address
  0000000000400363                 call    sub_40037F      ; Call Procedure
            
  ;========= if rdx=rcx -> the swap fuction will xor same values giving a result of 0 =======

  0000000000400368
  0000000000400368 loc_400368:                             ; CODE XREF: sub_400340+19↑j
  0000000000400368                 inc     rcx             ; Increment by 1
  000000000040036B                 cmp     rcx, r13        ; Compare Two Operands
  000000000040036E                 jb      short loc_400351 ; Jump if Below (CF=1)
  0000000000400370                 inc     rdx             ; Increment by 1
  0000000000400373                 cmp     rdx, r13        ; Compare Two Operands
  0000000000400376                 jb      short loc_40034E ; Jump if Below (CF=1)
  0000000000400378                 pop     r13
  000000000040037A                 pop     r13
  000000000040037C                 pop     r12
  000000000040037E                 retn                    ; Return Near from Procedure
  000000000040037E sub_400340      endp
  000000000040037E
  000000000040037F
  000000000040037F ; =============== S U B R O U T I N E =======================================
  000000000040037F
  000000000040037F
  000000000040037F sub_40037F      proc near               ; CODE XREF: sub_400340+23↑p
  000000000040037F                 mov     rax, [rdi]      ; eg [rdi] = a
                                                                    [rsi] = b

  0000000000400382                 xor     [rsi], rax      ; Logical Exclusive OR
  0000000000400385                 mov     rax, [rsi]
  0000000000400388                 xor     [rdi], rax      ; Logical Exclusive OR
  000000000040038B                 mov     rax, [rdi]
  000000000040038E                 xor     [rsi], rax      ; Logical Exclusive OR
  0000000000400391                 retn                    ; Return Near from Procedure
  0000000000400391 sub_40037F      endp
  0000000000400391
  0000000000400392
  0000000000400392 ; =============== S U B R O U T I N E =======================================
```


> Here the image shows that only if the result of **"cmp r8,\[r12+rcx\*8\]"** is  **r8 > \[r12+rcx\*8\]** , then **"ja"** command jumps to **loc_400368**  

 ```TASM

  0000000000400351                 mov     r8, [r12+rdx*8]
  0000000000400355                 cmp     r8, [r12+rcx*8] ; Compare Two Operands
  0000000000400359          -->    ja      short loc_400368 ; Jump if Above (CF=0 & ZF=0) 
```

{{< figure
img="rh5_1.jpg" 
alt="swap routine" 
caption="" 
command="Original" >}}

> This situation can lead to a seriuous issue when **\[r12+rdx\*8\]** is  = to **\[r12+rcx\*8\]**, the following routine will xor the values to 0 if these values are the same 




```TASM
  000000000040035B                 lea     rdi, [r12+rdx*8] ; Load Effective Address
  000000000040035F                 lea     rsi, [r12+rcx*8] ; Load Effective Address

;rdi and rsi point to the same address 


  000000000040037F sub_40037F      proc near               ; CODE XREF: sub_400340+23↑p
  000000000040037F                 mov     rax, [rdi]      ; [rdi] = a
                                                               ; [rsi] = a
                                       ;mov    rax , [a]       ;   rax = a

  0000000000400382                 xor     [rsi], rax      ; Logical Exclusive OR
                                        
                                                                ; [rdi] = 0  <--- also rdi is set to 0
                                      ;xor     [a], a  = 0      ; [rsi] = 0
                                                                ; rax = a

  0000000000400385                 mov     rax, [rsi]       
                                                                 ; [rdi] = 0
                                                                 ; [rsi] = 0
                                       ;mov     rax , [0]        ;   rax = 0

  0000000000400388                 xor     [rdi], rax      ; Logical Exclusive OR
                                      ;xor     [a], 0 =  a     ; [rdi] = 0
                                                               ; [rsi] = 0
                                                               ;   rax = 0

  000000000040038B                 mov     rax, [rdi]
                                                               ; [rdi] = 0
                                                               ; [rsi] = 0
                                       ;mov     rax , [a]      ;   rax = 0

  000000000040038E                 xor     [rsi], rax      ; Logical Exclusive OR
                                                               ; [rdi] = 0
                                      ;xor     [0],  a = a     ; [rsi] = 0
                                                               ;   rax = 0
  0000000000400391                 retn                    ; Return Near from Procedure
  0000000000400391 sub_40037F      endp
  0000000000400391
  0000000000400392
  0000000000400392 
```

 > In oder to avoid this issue we have to modify the **"ja"** (jump above) instruction into **"jae"** or **"jnb"**.

 {{< figure
img="rh5_2.jpg" 
alt="swap routine" 
caption="" 
command="Original" >}}




## &#9656; Reversing Hero 6


> Th analysis of this challange took me to function **"sub_4006AE"**

 {{< figure
img="rh6_1.jpg" 
alt="binary tree" 
caption="" 
command="Original" >}}



<nav class="recent">
  <h1>Recent Posts</h1>
  <ul>{{range first .Site.Params.SidebarRecentLimit .Site.Recent}}
    <li><a href="{{.RelPermalink}}">{{.Title}}</a></li>
  {{end}}</ul>
</nav>




