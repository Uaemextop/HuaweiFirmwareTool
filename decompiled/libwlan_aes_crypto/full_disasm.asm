# libwlan_aes_crypto.so  –  Full ARM32 Disassembly
# Size:      4,964 bytes
# .text:     0x00000540  size=620  (155 instructions)
# Exports:   9
# PLT imps:  8


; ─── WLAN_AES_Cbc_128_Encrypt @ 0x00000540 ───
  00000540  0f0011e3      tst      r1, #0xf                                    
  00000544  0dc0a0e1      mov      ip, sp                                      
  00000548  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000054c  0f50c113      bicne    r5, r1, #0xf                                
  00000550  10508512      addne    r5, r5, #0x10                               
  00000554  0150a001      moveq    r5, r1                                      
  00000558  04b04ce2      sub      fp, ip, #4                                  
  0000055c  4adf4de2      sub      sp, sp, #0x128                              
  00000560  0080a0e1      mov      r8, r0                                      
  00000564  0500a0e1      mov      r0, r5                                      
  00000568  0140a0e1      mov      r4, r1                                      
  0000056c  0270a0e1      mov      r7, r2                                      
  00000570  03a0a0e1      mov      sl, r3                                      
  00000574  e5ffffeb      bl       #0x510                                      
  00000578  006050e2      subs     r6, r0, #0                                  
  0000057c  3700000a      beq      #0x660                                      
  00000580  0430a0e1      mov      r3, r4                                      
  00000584  0820a0e1      mov      r2, r8                                      
  00000588  0510a0e1      mov      r1, r5                                      
  0000058c  e5ffffeb      bl       #0x528                                      
  00000590  4f0f4be2      sub      r0, fp, #0x13c                              
  00000594  d7ffffeb      bl       #0x4f8                                      
  00000598  4f0f4be2      sub      r0, fp, #0x13c                              
  0000059c  0710a0e1      mov      r1, r7                                      
  000005a0  8020a0e3      mov      r2, #0x80                                   
  000005a4  d6ffffeb      bl       #0x504                                      
  000005a8  004050e2      subs     r4, r0, #0                                  
  000005ac  1d00001a      bne      #0x628                                      
  000005b0  04309be5      ldr      r3, [fp, #4]                                
  000005b4  4f0f4be2      sub      r0, fp, #0x13c                              
  000005b8  00608de5      str      r6, [sp]                                    
  000005bc  0110a0e3      mov      r1, #1                                      
  000005c0  0520a0e1      mov      r2, r5                                      
  000005c4  04308de5      str      r3, [sp, #4]                                
  000005c8  0a30a0e1      mov      r3, sl                                      
  000005cc  d2ffffeb      bl       #0x51c                                      
  000005d0  007050e2      subs     r7, r0, #0                                  
  000005d4  0600001a      bne      #0x5f4                                      
  000005d8  08309be5      ldr      r3, [fp, #8]                                
  000005dc  0600a0e1      mov      r0, r6                                      
  000005e0  005083e5      str      r5, [r3]                                    
  000005e4  bdffffeb      bl       #0x4e0                                      
  000005e8  0700a0e1      mov      r0, r7                                      
  000005ec  24d04be2      sub      sp, fp, #0x24                               
  000005f0  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  000005f4  0600a0e1      mov      r0, r6                                      
  000005f8  b8ffffeb      bl       #0x4e0                                      
  000005fc  88009fe5      ldr      r0, [pc, #0x88]                             
  00000600  00408de5      str      r4, [sp]                                    
  00000604  4610a0e3      mov      r1, #0x46                                   
  00000608  00008fe0      add      r0, pc, r0                                  
  0000060c  04408de5      str      r4, [sp, #4]                                
  00000610  08408de5      str      r4, [sp, #8]                                
  00000614  0720a0e1      mov      r2, r7                                      
  00000618  0130a0e3      mov      r3, #1                                      
  0000061c  c4ffffeb      bl       #0x534                                      
  00000620  0100a0e3      mov      r0, #1                                      
  00000624  f0ffffea      b        #0x5ec                                      
  00000628  0600a0e1      mov      r0, r6                                      
  0000062c  abffffeb      bl       #0x4e0                                      
  00000630  58009fe5      ldr      r0, [pc, #0x58]                             
  00000634  00c0a0e3      mov      ip, #0                                      
  00000638  3d10a0e3      mov      r1, #0x3d                                   
  0000063c  00008fe0      add      r0, pc, r0                                  
  00000640  00c08de5      str      ip, [sp]                                    
  00000644  0420a0e1      mov      r2, r4                                      
  00000648  04c08de5      str      ip, [sp, #4]                                
  0000064c  0130a0e3      mov      r3, #1                                      
  00000650  08c08de5      str      ip, [sp, #8]                                
  00000654  b6ffffeb      bl       #0x534                                      
  00000658  0100a0e3      mov      r0, #1                                      
  0000065c  e2ffffea      b        #0x5ec                                      
  00000660  2c009fe5      ldr      r0, [pc, #0x2c]                             
  00000664  3110a0e3      mov      r1, #0x31                                   
  00000668  00608de5      str      r6, [sp]                                    
  0000066c  0120a0e3      mov      r2, #1                                      
  00000670  00008fe0      add      r0, pc, r0                                  
  00000674  04608de5      str      r6, [sp, #4]                                
  00000678  08608de5      str      r6, [sp, #8]                                
  0000067c  0530a0e1      mov      r3, r5                                      
  00000680  abffffeb      bl       #0x534                                      
  00000684  0100a0e3      mov      r0, #1                                      
  00000688  d7ffffea      b        #0x5ec                                      
  0000068c  9c010000      muleq    r0, ip, r1                                  
  00000690  68010000      andeq    r0, r0, r8, ror #2                          
  00000694  34010000      andeq    r0, r0, r4, lsr r1                          

; ─── WLAN_AES_Cbc_128_Decrypt @ 0x00000698 ───
  00000698  0dc0a0e1      mov      ip, sp                                      
  0000069c  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  000006a0  0f5011e2      ands     r5, r1, #0xf                                
  000006a4  04b04ce2      sub      fp, ip, #4                                  
  000006a8  4bdf4de2      sub      sp, sp, #0x12c                              
  000006ac  0140a0e1      mov      r4, r1                                      
  000006b0  0070a0e1      mov      r7, r0                                      
  000006b4  0260a0e1      mov      r6, r2                                      
  000006b8  0380a0e1      mov      r8, r3                                      
  000006bc  2100001a      bne      #0x748                                      
  000006c0  4f0f4be2      sub      r0, fp, #0x13c                              
  000006c4  8bffffeb      bl       #0x4f8                                      
  000006c8  0610a0e1      mov      r1, r6                                      
  000006cc  4f0f4be2      sub      r0, fp, #0x13c                              
  000006d0  8020a0e3      mov      r2, #0x80                                   
  000006d4  84ffffeb      bl       #0x4ec                                      
  000006d8  006050e2      subs     r6, r0, #0                                  
  000006dc  0e00001a      bne      #0x71c                                      
  000006e0  04309be5      ldr      r3, [fp, #4]                                
  000006e4  0420a0e1      mov      r2, r4                                      
  000006e8  00708de5      str      r7, [sp]                                    
  000006ec  4f0f4be2      sub      r0, fp, #0x13c                              
  000006f0  0610a0e1      mov      r1, r6                                      
  000006f4  04308de5      str      r3, [sp, #4]                                
  000006f8  0830a0e1      mov      r3, r8                                      
  000006fc  86ffffeb      bl       #0x51c                                      
  00000700  002050e2      subs     r2, r0, #0                                  
  00000704  1b00001a      bne      #0x778                                      
  00000708  08309be5      ldr      r3, [fp, #8]                                
  0000070c  0200a0e1      mov      r0, r2                                      
  00000710  004083e5      str      r4, [r3]                                    
  00000714  20d04be2      sub      sp, fp, #0x20                               
  00000718  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  0000071c  7c009fe5      ldr      r0, [pc, #0x7c]                             
  00000720  6c10a0e3      mov      r1, #0x6c                                   
  00000724  00508de5      str      r5, [sp]                                    
  00000728  0620a0e1      mov      r2, r6                                      
  0000072c  00008fe0      add      r0, pc, r0                                  
  00000730  04508de5      str      r5, [sp, #4]                                
  00000734  08508de5      str      r5, [sp, #8]                                
  00000738  0130a0e3      mov      r3, #1                                      
  0000073c  7cffffeb      bl       #0x534                                      
  00000740  0100a0e3      mov      r0, #1                                      
  00000744  f2ffffea      b        #0x714                                      
  00000748  54009fe5      ldr      r0, [pc, #0x54]                             
  0000074c  0030a0e3      mov      r3, #0                                      
  00000750  6310a0e3      mov      r1, #0x63                                   
  00000754  00308de5      str      r3, [sp]                                    
  00000758  00008fe0      add      r0, pc, r0                                  
  0000075c  04308de5      str      r3, [sp, #4]                                
  00000760  08308de5      str      r3, [sp, #8]                                
  00000764  0420a0e1      mov      r2, r4                                      
  00000768  0130a0e3      mov      r3, #1                                      
  0000076c  70ffffeb      bl       #0x534                                      
  00000770  0100a0e3      mov      r0, #1                                      
  00000774  e6ffffea      b        #0x714                                      
  00000778  28009fe5      ldr      r0, [pc, #0x28]                             
  0000077c  7410a0e3      mov      r1, #0x74                                   
  00000780  00608de5      str      r6, [sp]                                    
  00000784  0130a0e3      mov      r3, #1                                      
  00000788  00008fe0      add      r0, pc, r0                                  
  0000078c  04608de5      str      r6, [sp, #4]                                
  00000790  08608de5      str      r6, [sp, #8]                                
  00000794  66ffffeb      bl       #0x534                                      
  00000798  0100a0e3      mov      r0, #1                                      
  0000079c  dcffffea      b        #0x714                                      
  000007a0  78000000      andeq    r0, r0, r8, ror r0                          
  000007a4  4c000000      andeq    r0, r0, ip, asr #32                         
  000007a8  1c000000      andeq    r0, r0, ip, lsl r0                          