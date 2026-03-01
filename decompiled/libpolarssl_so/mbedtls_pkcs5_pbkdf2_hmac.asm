  0003012c  f04f2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, lr}
  00030130  94d04de2      sub      sp, sp, #0x94
  00030134  0050a0e1      mov      r5, r0
  00030138  000090e5      ldr      r0, [r0]
  0003013c  0280a0e1      mov      r8, r2
  00030140  0170a0e1      mov      r7, r1
  00030144  04308de5      str      r3, [sp, #4]
  00030148  bca09de5      ldr      sl, [sp, #0xbc]
  0003014c  c280ffeb      bl       #0x1045c
  00030150  c0c09de5      ldr      ip, [sp, #0xc0]
  00030154  0020a0e3      mov      r2, #0
  00030158  0c208de5      str      r2, [sp, #0xc]
  0003015c  0120a0e3      mov      r2, #1
  00030160  00005ce3      cmp      ip, #0
  00030164  0f20cde5      strb     r2, [sp, #0xf]
  00030168  00b0a0e1      mov      fp, r0
  0003016c  5800000a      beq      #0x302d4
  00030170  c4309de5      ldr      r3, [sp, #0xc4]
  00030174  50408de2      add      r4, sp, #0x50
  00030178  10908de2      add      sb, sp, #0x10
  0003017c  00308de5      str      r3, [sp]
  00030180  0500a0e1      mov      r0, r5
  00030184  0710a0e1      mov      r1, r7
  00030188  0820a0e1      mov      r2, r8
  0003018c  0c81ffeb      bl       #0x105c4
  00030190  000050e3      cmp      r0, #0
  00030194  4f00001a      bne      #0x302d8
  00030198  0500a0e1      mov      r0, r5
  0003019c  04109de5      ldr      r1, [sp, #4]
  000301a0  b8209de5      ldr      r2, [sp, #0xb8]
  000301a4  637effeb      bl       #0xfb38
  000301a8  000050e3      cmp      r0, #0
  000301ac  4900001a      bne      #0x302d8
  000301b0  0500a0e1      mov      r0, r5
  000301b4  0c108de2      add      r1, sp, #0xc
  000301b8  0420a0e3      mov      r2, #4
  000301bc  5d7effeb      bl       #0xfb38
  000301c0  000050e3      cmp      r0, #0
  000301c4  4300001a      bne      #0x302d8
  000301c8  0500a0e1      mov      r0, r5
  000301cc  0410a0e1      mov      r1, r4
  000301d0  3c7fffeb      bl       #0xfec8
  000301d4  000050e3      cmp      r0, #0
  000301d8  3e00001a      bne      #0x302d8
  000301dc  0900a0e1      mov      r0, sb
  000301e0  0410a0e1      mov      r1, r4
  000301e4  0b20a0e1      mov      r2, fp
  000301e8  a67bffeb      bl       #0xf088
  000301ec  01005ae3      cmp      sl, #1
  000301f0  0160a083      movhi    r6, #1
  000301f4  1d00009a      bls      #0x30270
  000301f8  0500a0e1      mov      r0, r5
  000301fc  0710a0e1      mov      r1, r7
  00030200  0820a0e1      mov      r2, r8
  00030204  ee80ffeb      bl       #0x105c4
  00030208  000050e3      cmp      r0, #0
  0003020c  3100001a      bne      #0x302d8
  00030210  0500a0e1      mov      r0, r5
  00030214  0910a0e1      mov      r1, sb
  00030218  0b20a0e1      mov      r2, fp
  0003021c  457effeb      bl       #0xfb38
  00030220  000050e3      cmp      r0, #0
  00030224  2b00001a      bne      #0x302d8
  00030228  0500a0e1      mov      r0, r5
  0003022c  0910a0e1      mov      r1, sb
  00030230  247fffeb      bl       #0xfec8
  00030234  000050e3      cmp      r0, #0
  00030238  2600001a      bne      #0x302d8
  0003023c  00005be3      cmp      fp, #0
  00030240  0030a011      movne    r3, r0
  00030244  0600000a      beq      #0x30264
  00030248  0320d4e7      ldrb     r2, [r4, r3]
  0003024c  0310d9e7      ldrb     r1, [sb, r3]
  00030250  022021e0      eor      r2, r1, r2
  00030254  0320c4e7      strb     r2, [r4, r3]
  00030258  013083e2      add      r3, r3, #1
  0003025c  0b0053e1      cmp      r3, fp
  00030260  f8ffff1a      bne      #0x30248
  00030264  016086e2      add      r6, r6, #1
  00030268  0a0056e1      cmp      r6, sl
  0003026c  e1ffff1a      bne      #0x301f8
  00030270  c0c09de5      ldr      ip, [sp, #0xc0]
  00030274  0410a0e1      mov      r1, r4
  00030278  00009de5      ldr      r0, [sp]
  0003027c  0b005ce1      cmp      ip, fp
  00030280  0bc0a021      movhs    ip, fp
  00030284  c0309de5      ldr      r3, [sp, #0xc0]
  00030288  0c20a0e1      mov      r2, ip
  0003028c  03306ce0      rsb      r3, ip, r3
  00030290  c0308de5      str      r3, [sp, #0xc0]
  00030294  0c3080e0      add      r3, r0, ip
  00030298  00308de5      str      r3, [sp]
  0003029c  797bffeb      bl       #0xf088
  000302a0  0f208de2      add      r2, sp, #0xf
  000302a4  0b008de2      add      r0, sp, #0xb
  000302a8  0030d2e5      ldrb     r3, [r2]
  000302ac  013083e2      add      r3, r3, #1
  000302b0  7330efe6      uxtb     r3, r3
  000302b4  013042e4      strb     r3, [r2], #-1
  000302b8  000053e3      cmp      r3, #0
  000302bc  0100001a      bne      #0x302c8
  000302c0  000052e1      cmp      r2, r0
  000302c4  f7ffff1a      bne      #0x302a8
  000302c8  c0c09de5      ldr      ip, [sp, #0xc0]
  000302cc  00005ce3      cmp      ip, #0
  000302d0  aaffff1a      bne      #0x30180
  000302d4  0000a0e3      mov      r0, #0
  000302d8  94d08de2      add      sp, sp, #0x94
  000302dc  f08fbde8      pop      {r4, r5, r6, r7, r8, sb, sl, fp, pc}
  000302e0  f0472de9      push     {r4, r5, r6, r7, r8, sb, sl, lr}
  000302e4  f8d04de2      sub      sp, sp, #0xf8
  000302e8  006090e5      ldr      r6, [r0]
  000302ec  00c0a0e3      mov      ip, #0
  000302f0  084090e5      ldr      r4, [r0, #8]
  000302f4  0450a0e3      mov      r5, #4
  000302f8  040090e5      ldr      r0, [r0, #4]
  000302fc  300056e3      cmp      r6, #0x30
  00030300  0170a0e1      mov      r7, r1
  00030304  0260a0e1      mov      r6, r2
  00030308  0380a0e1      mov      r8, r3
  0003030c  00a084e0      add      sl, r4, r0
  00030310  14c08de5      str      ip, [sp, #0x14]
  00030314  18c08de5      str      ip, [sp, #0x18]
  00030318  20508de5      str      r5, [sp, #0x20]
  0003031c  24c08de5      str      ip, [sp, #0x24]
  00030320  1c408de5      str      r4, [sp, #0x1c]
  00030324  1000001a      bne      #0x3036c
  00030328  0a10a0e1      mov      r1, sl