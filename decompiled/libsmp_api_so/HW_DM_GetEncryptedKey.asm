### HW_DM_GetEncryptedKey @ 0x1c7bc
  0001c7bc  0dc0a0e1      mov      ip, sp                                      
  0001c7c0  2120a0e3      mov      r2, #0x21                                   
  0001c7c4  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  0001c7c8  04b04ce2      sub      fp, ip, #4                                  
  0001c7cc  8ddf4de2      sub      sp, sp, #0x234                              
  0001c7d0  0050a0e1      mov      r5, r0                                      
  0001c7d4  0160a0e1      mov      r6, r1                                      
  0001c7d8  0010a0e3      mov      r1, #0                                      
  0001c7dc  920f4be2      sub      r0, fp, #0x248                              
  0001c7e0  04b9ffeb      bl       #0xabf8                                     
  0001c7e4  890f4be2      sub      r0, fp, #0x224                              
  0001c7e8  0010a0e3      mov      r1, #0                                      
  0001c7ec  022ca0e3      mov      r2, #0x200                                  
  0001c7f0  00b9ffeb      bl       #0xabf8                                     
  0001c7f4  000055e3      cmp      r5, #0                                      
  0001c7f8  00005613      cmpne    r6, #0                                      
  0001c7fc  0040a013      movne    r4, #0                                      
  0001c800  0140a003      moveq    r4, #1                                      
  0001c804  0400001a      bne      #0x1c81c                                    
  0001c808  2a0900e3      movw     r0, #0x92a                                  
  0001c80c  70119fe5      ldr      r1, [pc, #0x170]                            
  0001c810  24f6ffeb      bl       #0x1a0a8                                    
  0001c814  68419fe5      ldr      r4, [pc, #0x168]                            
  0001c818  560000ea      b        #0x1c978                                    
  0001c81c  64019fe5      ldr      r0, [pc, #0x164]                            
  0001c820  00008fe0      add      r0, pc, r0                                  
  0001c824  4bbbffeb      bl       #0xb558                                     
  0001c828  000050e3      cmp      r0, #0                                      
  0001c82c  0400001a      bne      #0x1c844                                    
  0001c830  2110a0e3      mov      r1, #0x21                                   
  0001c834  922f4be2      sub      r2, fp, #0x248                              
  0001c838  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0001c83c  abb8ffeb      bl       #0xaaf0                                     
  0001c840  030000ea      b        #0x1c854                                    
  0001c844  0400a0e1      mov      r0, r4                                      
  0001c848  0510a0e1      mov      r1, r5                                      
  0001c84c  2120a0e3      mov      r2, #0x21                                   
  0001c850  26bdffeb      bl       #0xbcf0                                     
  0001c854  000050e3      cmp      r0, #0                                      
  0001c858  0a00000a      beq      #0x1c888                                    
  0001c85c  2110a0e3      mov      r1, #0x21                                   
  0001c860  0020a0e3      mov      r2, #0                                      
  0001c864  0130a0e1      mov      r3, r1                                      
  0001c868  920f4be2      sub      r0, fp, #0x248                              
  0001c86c  adb9ffeb      bl       #0xaf28                                     
  0001c870  18019fe5      ldr      r0, [pc, #0x118]                            
  0001c874  00008fe0      add      r0, pc, r0                                  
  0001c878  36bbffeb      bl       #0xb558                                     
  0001c87c  007050e2      subs     r7, r0, #0                                  
  0001c880  0600000a      beq      #0x1c8a0                                    
  0001c884  2d0000ea      b        #0x1c940                                    
  0001c888  920f4be2      sub      r0, fp, #0x248                              
  0001c88c  94bbffeb      bl       #0xb6e4                                     
  0001c890  000050e3      cmp      r0, #0                                      
  0001c894  f0ffff0a      beq      #0x1c85c                                    
  0001c898  0040a0e3      mov      r4, #0                                      
  0001c89c  300000ea      b        #0x1c964                                    
  0001c8a0  ec009fe5      ldr      r0, [pc, #0xec]                             
  0001c8a4  891f4be2      sub      r1, fp, #0x224                              
  0001c8a8  022ca0e3      mov      r2, #0x200                                  
  0001c8ac  00008fe0      add      r0, pc, r0                                  
  0001c8b0  3abeffeb      bl       #0xc1a0                                     
  0001c8b4  004050e2      subs     r4, r0, #0                                  
  0001c8b8  2900001a      bne      #0x1c964                                    
  0001c8bc  890f4be2      sub      r0, fp, #0x224                              
  0001c8c0  d0409fe5      ldr      r4, [pc, #0xd0]                             
  0001c8c4  86bbffeb      bl       #0xb6e4                                     
  0001c8c8  04408fe0      add      r4, pc, r4                                  
  0001c8cc  0080a0e1      mov      r8, r0                                      
  0001c8d0  0400a0e1      mov      r0, r4                                      
  0001c8d4  82bbffeb      bl       #0xb6e4                                     
  0001c8d8  00408de5      str      r4, [sp]                                    
  0001c8dc  0810a0e1      mov      r1, r8                                      
  0001c8e0  922f4be2      sub      r2, fp, #0x248                              
  0001c8e4  2130a0e3      mov      r3, #0x21                                   
  0001c8e8  04008de5      str      r0, [sp, #4]                                
  0001c8ec  890f4be2      sub      r0, fp, #0x224                              
  0001c8f0  4bbeffeb      bl       #0xc224                                     
  0001c8f4  004050e2      subs     r4, r0, #0                                  
  0001c8f8  e6ffff0a      beq      #0x1c898                                    
  0001c8fc  890f4be2      sub      r0, fp, #0x224                              
  0001c900  77bbffeb      bl       #0xb6e4                                     
  0001c904  0410a0e1      mov      r1, r4                                      
  0001c908  0020a0e1      mov      r2, r0                                      
  0001c90c  490900e3      movw     r0, #0x949                                  
  0001c910  bdf5ffeb      bl       #0x1a00c                                    
  0001c914  2110a0e3      mov      r1, #0x21                                   
  0001c918  0720a0e1      mov      r2, r7                                      
  0001c91c  0130a0e1      mov      r3, r1                                      
  0001c920  920f4be2      sub      r0, fp, #0x248                              
  0001c924  7fb9ffeb      bl       #0xaf28                                     
  0001c928  021ca0e3      mov      r1, #0x200                                  
  0001c92c  890f4be2      sub      r0, fp, #0x224                              
  0001c930  0720a0e1      mov      r2, r7                                      
  0001c934  0130a0e1      mov      r3, r1                                      
  0001c938  7ab9ffeb      bl       #0xaf28                                     
  0001c93c  080000ea      b        #0x1c964                                    
  0001c940  0200a0e3      mov      r0, #2                                      
  0001c944  921f4be2      sub      r1, fp, #0x248                              
  0001c948  2120a0e3      mov      r2, #0x21                                   
  0001c94c  e7bcffeb      bl       #0xbcf0                                     
  0001c950  004050e2      subs     r4, r0, #0                                  
  0001c954  cfffff0a      beq      #0x1c898                                    
  0001c958  570900e3      movw     r0, #0x957                                  
  0001c95c  0410a0e1      mov      r1, r4                                      
  0001c960  d0f5ffeb      bl       #0x1a0a8                                    
  0001c964  0500a0e1      mov      r0, r5                                      
  0001c968  0610a0e1      mov      r1, r6                                      
  0001c96c  922f4be2      sub      r2, fp, #0x248                              
  0001c970  2030a0e3      mov      r3, #0x20                                   
  0001c974  a0b7ffeb      bl       #0xa7fc                                     
  0001c978  0400a0e1      mov      r0, r4                                      
  0001c97c  20d04be2      sub      sp, fp, #0x20                               
  0001c980  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        