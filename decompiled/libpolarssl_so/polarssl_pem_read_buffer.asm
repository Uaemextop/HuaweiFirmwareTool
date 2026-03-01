
### polarssl_pem_read_buffer @ 0x2e630
  0002e630  f0472de9      push     {r4, r5, r6, r7, r8, sb, sl, lr}          
  0002e634  008050e2      subs     r8, r0, #0                                
  0002e638  a8d04de2      sub      sp, sp, #0xa8                             
  0002e63c  0160a0e1      mov      r6, r1                                    
  0002e640  02a0a0e1      mov      sl, r2                                    
  0002e644  0370a0e1      mov      r7, r3                                    
  0002e648  3a01000a      beq      #0x2eb38                                  
  0002e64c  0300a0e1      mov      r0, r3                                    
  0002e650  c384ffeb      bl       #0xf964                                   
  0002e654  005050e2      subs     r5, r0, #0                                
  0002e658  dc00000a      beq      #0x2e9d0                                  
  0002e65c  0700a0e1      mov      r0, r7                                    
  0002e660  0a10a0e1      mov      r1, sl                                    
  0002e664  be84ffeb      bl       #0xf964                                   
  0002e668  000050e3      cmp      r0, #0                                    
  0002e66c  05005011      cmpne    r0, r5                                    
  0002e670  0040a0e1      mov      r4, r0                                    
  0002e674  d500009a      bls      #0x2e9d0                                  
  0002e678  0600a0e1      mov      r0, r6                                    
  0002e67c  ca87ffeb      bl       #0x105ac                                  
  0002e680  00c0d5e7      ldrb     ip, [r5, r0]                              
  0002e684  006085e0      add      r6, r5, r0                                
  0002e688  20005ce3      cmp      ip, #0x20                                 
  0002e68c  01c0d605      ldrbeq   ip, [r6, #1]                              
  0002e690  01608602      addeq    r6, r6, #1                                
  0002e694  0d005ce3      cmp      ip, #0xd                                  
  0002e698  01c0d605      ldrbeq   ip, [r6, #1]                              
  0002e69c  01608602      addeq    r6, r6, #1                                
  0002e6a0  0a005ce3      cmp      ip, #0xa                                  
  0002e6a4  c900001a      bne      #0x2e9d0                                  
  0002e6a8  0a00a0e1      mov      r0, sl                                    
  0002e6ac  015086e2      add      r5, r6, #1                                
  0002e6b0  bd87ffeb      bl       #0x105ac                                  
  0002e6b4  043065e0      rsb      r3, r5, r4                                
  0002e6b8  0020d4e7      ldrb     r2, [r4, r0]                              
  0002e6bc  000084e0      add      r0, r4, r0                                
  0002e6c0  200052e3      cmp      r2, #0x20                                 
  0002e6c4  0120d005      ldrbeq   r2, [r0, #1]                              
  0002e6c8  01008002      addeq    r0, r0, #1                                
  0002e6cc  0d0052e3      cmp      r2, #0xd                                  
  0002e6d0  0120d005      ldrbeq   r2, [r0, #1]                              
  0002e6d4  01008002      addeq    r0, r0, #1                                
  0002e6d8  0a0052e3      cmp      r2, #0xa                                  
  0002e6dc  01008002      addeq    r0, r0, #1                                
  0002e6e0  150053e3      cmp      r3, #0x15                                 
  0002e6e4  d0309de5      ldr      r3, [sp, #0xd0]                           
  0002e6e8  007067e0      rsb      r7, r7, r0                                
  0002e6ec  007083e5      str      r7, [r3]                                  
  0002e6f0  3c0000ca      bgt      #0x2e7e8                                  
  0002e6f4  0060a0e3      mov      r6, #0                                    
  0002e6f8  06a0a0e1      mov      sl, r6                                    
  0002e6fc  040055e1      cmp      r5, r4                                    
  0002e700  af00002a      bhs      #0x2e9c4                                  
  0002e704  0000a0e3      mov      r0, #0                                    
  0002e708  044065e0      rsb      r4, r5, r4                                
  0002e70c  0010a0e1      mov      r1, r0                                    
  0002e710  00408de5      str      r4, [sp]                                  
  0002e714  0c208de2      add      r2, sp, #0xc                              
  0002e718  0530a0e1      mov      r3, r5                                    
  0002e71c  b886ffeb      bl       #0x10204                                  
  0002e720  2c0070e3      cmn      r0, #0x2c                                 
  0002e724  d44e0e03      movweq   r4, #0xeed4                               
  0002e728  ff4f4f03      movteq   r4, #0xffff                               
  0002e72c  2a00000a      beq      #0x2e7dc                                  
  0002e730  0c909de5      ldr      sb, [sp, #0xc]                            
  0002e734  0100a0e3      mov      r0, #1                                    
  0002e738  0910a0e1      mov      r1, sb                                    
  0002e73c  b983ffeb      bl       #0xf628                                   
  0002e740  007050e2      subs     r7, r0, #0                                
  0002e744  f800000a      beq      #0x2eb2c                                  
  0002e748  00408de5      str      r4, [sp]                                  
  0002e74c  0910a0e1      mov      r1, sb                                    
  0002e750  0c208de2      add      r2, sp, #0xc                              
  0002e754  0530a0e1      mov      r3, r5                                    
  0002e758  a986ffeb      bl       #0x10204                                  
  0002e75c  004050e2      subs     r4, r0, #0                                
  0002e760  9d00001a      bne      #0x2e9dc                                  
  0002e764  00005ae3      cmp      sl, #0                                    
  0002e768  4400000a      beq      #0x2e880                                  
  0002e76c  c8309de5      ldr      r3, [sp, #0xc8]                           
  0002e770  000053e3      cmp      r3, #0                                    
  0002e774  f200000a      beq      #0x2eb44                                  
  0002e778  250056e3      cmp      r6, #0x25                                 
  0002e77c  ad00000a      beq      #0x2ea38                                  
  0002e780  210056e3      cmp      r6, #0x21                                 
  0002e784  b600000a      beq      #0x2ea64                                  
  0002e788  050056e3      cmp      r6, #5                                    
  0002e78c  9900000a      beq      #0x2e9f8                                  
  0002e790  060056e3      cmp      r6, #6                                    
  0002e794  c400000a      beq      #0x2eaac                                  
  0002e798  070056e3      cmp      r6, #7                                    
  0002e79c  c700000a      beq      #0x2eac0                                  
  0002e7a0  0c109de5      ldr      r1, [sp, #0xc]                            
  0002e7a4  020051e3      cmp      r1, #2                                    
  0002e7a8  0500009a      bls      #0x2e7c4                                  
  0002e7ac  0030d7e5      ldrb     r3, [r7]                                  
  0002e7b0  300053e3      cmp      r3, #0x30                                 
  0002e7b4  0200001a      bne      #0x2e7c4                                  
  0002e7b8  0130d7e5      ldrb     r3, [r7, #1]                              
  0002e7bc  830053e3      cmp      r3, #0x83                                 
  0002e7c0  2f00009a      bls      #0x2e884                                  
  0002e7c4  0700a0e1      mov      r0, r7                                    
  0002e7c8  804c0ee3      movw     r4, #0xec80                               
  0002e7cc  3784ffeb      bl       #0xf8b0                                   
  0002e7d0  0700a0e1      mov      r0, r7                                    
  0002e7d4  ec87ffeb      bl       #0x1078c                                  
  0002e7d8  ff4f4fe3      movt     r4, #0xffff                               
  0002e7dc  0400a0e1      mov      r0, r4                                    
  0002e7e0  a8d08de2      add      sp, sp, #0xa8                             
  0002e7e4  f087bde8      pop      {r4, r5, r6, r7, r8, sb, sl, pc}          
  ; [RETURN]