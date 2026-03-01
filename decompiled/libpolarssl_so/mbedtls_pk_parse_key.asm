
### mbedtls_pk_parse_key @ 0x31a18
  00031a18  f0452de9      push     {r4, r5, r6, r7, r8, sl, lr}              
  00031a1c  007052e2      subs     r7, r2, #0                                
  00031a20  24d04de2      sub      sp, sp, #0x24                             
  00031a24  0080a0e1      mov      r8, r0                                    
  00031a28  0150a0e1      mov      r5, r1                                    
  00031a2c  03a0a0e1      mov      sl, r3                                    
  00031a30  8300000a      beq      #0x31c44                                  
  00031a34  016047e2      sub      r6, r7, #1                                
  00031a38  14008de2      add      r0, sp, #0x14                             
  00031a3c  d774ffeb      bl       #0xeda0                                   
  00031a40  0620d5e7      ldrb     r2, [r5, r6]                              
  00031a44  000052e3      cmp      r2, #0                                    
  00031a48  1800000a      beq      #0x31ab0                                  
  00031a4c  0100a0e3      mov      r0, #1                                    
  00031a50  0710a0e1      mov      r1, r7                                    
  00031a54  f376ffeb      bl       #0xf628                                   
  00031a58  004050e2      subs     r4, r0, #0                                
  00031a5c  7b00000a      beq      #0x31c50                                  
  00031a60  0510a0e1      mov      r1, r5                                    
  00031a64  0720a0e1      mov      r2, r7                                    
  00031a68  8675ffeb      bl       #0xf088                                   
  00031a6c  40109de5      ldr      r1, [sp, #0x40]                           
  00031a70  0720a0e1      mov      r2, r7                                    
  00031a74  0a30a0e1      mov      r3, sl                                    
  00031a78  0800a0e1      mov      r0, r8                                    
  00031a7c  00108de5      str      r1, [sp]                                  
  00031a80  0410a0e1      mov      r1, r4                                    
  00031a84  cdfeffeb      bl       #0x315c0                                  
  00031a88  0710a0e1      mov      r1, r7                                    
  00031a8c  0060a0e1      mov      r6, r0                                    
  00031a90  0400a0e1      mov      r0, r4                                    
  00031a94  8577ffeb      bl       #0xf8b0                                   
  00031a98  0400a0e1      mov      r0, r4                                    
  00031a9c  3a7bffeb      bl       #0x1078c                                  
  00031aa0  000056e3      cmp      r6, #0                                    
  00031aa4  7200001a      bne      #0x31c74                                  
  00031aa8  0040a0e3      mov      r4, #0                                    
  00031aac  180000ea      b        #0x31b14                                  
  00031ab0  40109de5      ldr      r1, [sp, #0x40]                           
  00031ab4  10208de2      add      r2, sp, #0x10                             
  00031ab8  08208de5      str      r2, [sp, #8]                              
  00031abc  14008de2      add      r0, sp, #0x14                             
  00031ac0  f4229fe5      ldr      r2, [pc, #0x2f4]                          
  00031ac4  0530a0e1      mov      r3, r5                                    
  00031ac8  04108de5      str      r1, [sp, #4]                              
  00031acc  ec129fe5      ldr      r1, [pc, #0x2ec]                          
  00031ad0  02208fe0      add      r2, pc, r2                                
  00031ad4  00a08de5      str      sl, [sp]                                  
  00031ad8  01108fe0      add      r1, pc, r1                                
  00031adc  1374ffeb      bl       #0xeb30                                   
  00031ae0  004050e2      subs     r4, r0, #0                                
  00031ae4  0d00001a      bne      #0x31b20                                  
  00031ae8  0100a0e3      mov      r0, #1                                    
  00031aec  0179ffeb      bl       #0xfef8                                   
  00031af0  0010a0e1      mov      r1, r0                                    
  00031af4  0800a0e1      mov      r0, r8                                    
  00031af8  c67affeb      bl       #0x10618                                  
  00031afc  004050e2      subs     r4, r0, #0                                
  00031b00  2b00000a      beq      #0x31bb4                                  
  00031b04  0800a0e1      mov      r0, r8                                    
  00031b08  3976ffeb      bl       #0xf3f4                                   
  00031b0c  14008de2      add      r0, sp, #0x14                             
  00031b10  d676ffeb      bl       #0xf670                                   
  00031b14  0400a0e1      mov      r0, r4                                    
  00031b18  24d08de2      add      sp, sp, #0x24                             
  00031b1c  f085bde8      pop      {r4, r5, r6, r7, r8, sl, pc}              
  ; [RETURN]