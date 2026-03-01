
### polarssl_set_pub_prv_to_conf @ 0x3ee34
  0003ee34  f8402de9      push     {r3, r4, r5, r6, r7, lr}                  
  0003ee38  004050e2      subs     r4, r0, #0                                
  0003ee3c  0160a0e1      mov      r6, r1                                    
  0003ee40  0270a0e1      mov      r7, r2                                    
  0003ee44  0350a0e1      mov      r5, r3                                    
  0003ee48  2300000a      beq      #0x3eedc                                  
  0003ee4c  0100a0e3      mov      r0, #1                                    
  0003ee50  4e1fa0e3      mov      r1, #0x138                                
  0003ee54  f341ffeb      bl       #0xf628                                   
  0003ee58  000050e3      cmp      r0, #0                                    
  0003ee5c  0c0084e5      str      r0, [r4, #0xc]                            
  0003ee60  1a00000a      beq      #0x3eed0                                  
  0003ee64  0010a0e3      mov      r1, #0                                    
  0003ee68  4e2fa0e3      mov      r2, #0x138                                
  0003ee6c  c743ffeb      bl       #0xfd90                                   
  0003ee70  0100a0e3      mov      r0, #1                                    
  0003ee74  0810a0e3      mov      r1, #8                                    
  0003ee78  ea41ffeb      bl       #0xf628                                   
  0003ee7c  000050e3      cmp      r0, #0                                    
  0003ee80  100084e5      str      r0, [r4, #0x10]                           
  0003ee84  1100000a      beq      #0x3eed0                                  
  0003ee88  00c0a0e3      mov      ip, #0                                    
  0003ee8c  0710a0e1      mov      r1, r7                                    
  0003ee90  00c080e5      str      ip, [r0]                                  
  0003ee94  04c080e5      str      ip, [r0, #4]                              
  0003ee98  0c0094e5      ldr      r0, [r4, #0xc]                            
  0003ee9c  ba44ffeb      bl       #0x1018c                                  
  0003eea0  0610a0e1      mov      r1, r6                                    
  0003eea4  0520a0e1      mov      r2, r5                                    
  0003eea8  0070a0e1      mov      r7, r0                                    
  0003eeac  100094e5      ldr      r0, [r4, #0x10]                           
  0003eeb0  4845ffeb      bl       #0x103d8                                  
  0003eeb4  0c1094e5      ldr      r1, [r4, #0xc]                            
  0003eeb8  102094e5      ldr      r2, [r4, #0x10]                           
  0003eebc  075080e1      orr      r5, r0, r7                                
  0003eec0  000094e5      ldr      r0, [r4]                                  
  0003eec4  9541ffeb      bl       #0xf520                                   
  0003eec8  000085e1      orr      r0, r5, r0                                
  0003eecc  f880bde8      pop      {r3, r4, r5, r6, r7, pc}                  
  ; [RETURN]

### mbedtls_pk_parse_keyfile @ 0x31ddc
  00031ddc  70402de9      push     {r4, r5, r6, lr}                          
  00031de0  10d04de2      sub      sp, sp, #0x10                             
  00031de4  0060a0e1      mov      r6, r0                                    
  00031de8  0250a0e1      mov      r5, r2                                    
  00031dec  0100a0e1      mov      r0, r1                                    
  00031df0  08208de2      add      r2, sp, #8                                
  00031df4  0c108de2      add      r1, sp, #0xc                              
  00031df8  4574ffeb      bl       #0xef14                                   
  00031dfc  004050e2      subs     r4, r0, #0                                
  00031e00  0f00001a      bne      #0x31e44                                  
  00031e04  000055e3      cmp      r5, #0                                    
  00031e08  1000000a      beq      #0x31e50                                  
  00031e0c  0500a0e1      mov      r0, r5                                    
  00031e10  e579ffeb      bl       #0x105ac                                  
  00031e14  0530a0e1      mov      r3, r5                                    
  00031e18  0c109de5      ldr      r1, [sp, #0xc]                            
  00031e1c  08209de5      ldr      r2, [sp, #8]                              
  00031e20  00008de5      str      r0, [sp]                                  
  00031e24  0600a0e1      mov      r0, r6                                    
  00031e28  5975ffeb      bl       #0xf394                                   
  00031e2c  0040a0e1      mov      r4, r0                                    
  00031e30  0c009de5      ldr      r0, [sp, #0xc]                            
  00031e34  08109de5      ldr      r1, [sp, #8]                              
  00031e38  9c76ffeb      bl       #0xf8b0                                   
  00031e3c  0c009de5      ldr      r0, [sp, #0xc]                            
  00031e40  517affeb      bl       #0x1078c                                  
  00031e44  0400a0e1      mov      r0, r4                                    
  00031e48  10d08de2      add      sp, sp, #0x10                             
  00031e4c  7080bde8      pop      {r4, r5, r6, pc}                          
  ; [RETURN]

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