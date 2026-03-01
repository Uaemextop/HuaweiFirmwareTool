### HW_OS_PBKDF2_SHA256 @ 0x2f3e8
  0002f3e8  53ffffea      b        #0x2f13c                                  
  0002f3ec  0dc0a0e1      mov      ip, sp                                    
  0002f3f0  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}          
  0002f3f4  04b04ce2      sub      fp, ip, #4                                
  0002f3f8  46df4de2      sub      sp, sp, #0x118                            
  0002f3fc  0070a0e1      mov      r7, r0                                    
  0002f400  0160a0e1      mov      r6, r1                                    
  0002f404  0240a0e1      mov      r4, r2                                    
  0002f408  4d0f4be2      sub      r0, fp, #0x134                            
  0002f40c  0010a0e3      mov      r1, #0                                    
  0002f410  462fa0e3      mov      r2, #0x118                                
  0002f414  0350a0e1      mov      r5, r3                                    
  0002f418  3cc1ffeb      bl       #0x1f910                                  
  0002f41c  000057e3      cmp      r7, #0                                    
  0002f420  36030003      movweq   r0, #0x336                                
  0002f424  0600000a      beq      #0x2f444                                  
  0002f428  010000ea      b        #0x2f434                                  
  0002f42c  370300e3      movw     r0, #0x337                                
  0002f430  030000ea      b        #0x2f444                                  
  0002f434  000056e3      cmp      r6, #0                                    
  0002f438  0400001a      bne      #0x2f450                                  
  0002f43c  faffffea      b        #0x2f42c                                  
  0002f440  ce0fa0e3      mov      r0, #0x338                                
  0002f444  b6fdffeb      bl       #0x2eb24                                  
  0002f448  0000e0e3      mvn      r0, #0                                    
  0002f44c  140000ea      b        #0x2f4a4                                  
  0002f450  000054e3      cmp      r4, #0                                    
  0002f454  f9ffff0a      beq      #0x2f440                                  
  0002f458  1010a0e3      mov      r1, #0x10                                 
  0002f45c  0020a0e3      mov      r2, #0                                    
  0002f460  0130a0e1      mov      r3, r1                                    
  0002f464  0400a0e1      mov      r0, r4                                    
  0002f468  01bbffeb      bl       #0x1e074                                  
  0002f46c  000055e3      cmp      r5, #0                                    
  0002f470  4d0f4be2      sub      r0, fp, #0x134                            
  0002f474  0710a0e1      mov      r1, r7                                    
  0002f478  8020a0e3      mov      r2, #0x80                                 
  0002f47c  0100001a      bne      #0x2f488                                  
  0002f480  54bcffeb      bl       #0x1e5d8                                  
  0002f484  000000ea      b        #0x2f48c                                  
  0002f488  bfb5ffeb      bl       #0x1cb8c                                  
  0002f48c  4d0f4be2      sub      r0, fp, #0x134                            
  0002f490  0510a0e1      mov      r1, r5                                    
  0002f494  0620a0e1      mov      r2, r6                                    
  0002f498  0430a0e1      mov      r3, r4                                    
  0002f49c  35bcffeb      bl       #0x1e578                                  
  0002f4a0  0000a0e3      mov      r0, #0                                    
  0002f4a4  1cd04be2      sub      sp, fp, #0x1c                             
  0002f4a8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}          
  0002f4ac  000050e3      cmp      r0, #0                                    
  0002f4b0  0dc0a0e1      mov      ip, sp                                    
  0002f4b4  00d82de9      push     {fp, ip, lr, pc}                          
  0002f4b8  5d030003      movweq   r0, #0x35d                                
  0002f4bc  04b04ce2      sub      fp, ip, #4                                
  0002f4c0  0100000a      beq      #0x2f4cc                                  
  0002f4c4  030000ea      b        #0x2f4d8                                  
  0002f4c8  5e0300e3      movw     r0, #0x35e                                
  0002f4cc  94fdffeb      bl       #0x2eb24                                  
  0002f4d0  0000e0e3      mvn      r0, #0                                    
  0002f4d4  00a89de8      ldm      sp, {fp, sp, pc}                          