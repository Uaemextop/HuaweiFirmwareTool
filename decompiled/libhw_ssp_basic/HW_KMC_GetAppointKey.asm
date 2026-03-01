### HW_KMC_GetAppointKey @ 0x9b108
  0009b108  0dc0a0e1      mov      ip, sp                                    
  0009b10c  000050e3      cmp      r0, #0                                    
  0009b110  00005113      cmpne    r1, #0                                    
  0009b114  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}  
  0009b118  04b04ce2      sub      fp, ip, #4                                
  0009b11c  28d04de2      sub      sp, sp, #0x28                             
  0009b120  0830a0e3      mov      r3, #8                                    
  0009b124  0160a0e1      mov      r6, r1                                    
  0009b128  44300be5      str      r3, [fp, #-0x44]                          
  0009b12c  0040a0e1      mov      r4, r0                                    
  0009b130  0400001a      bne      #0x9b148                                  
  0009b134  5f0100e3      movw     r0, #0x15f                                
  0009b138  0110a0e3      mov      r1, #1                                    
  0009b13c  72feffeb      bl       #0x9ab0c                                  
  0009b140  0150a0e3      mov      r5, #1                                    
  0009b144  600000ea      b        #0x9b2cc                                  
  0009b148  88319fe5      ldr      r3, [pc, #0x188]                          
  0009b14c  03009fe7      ldr      r0, [pc, r3]                              
  0009b150  000050e3      cmp      r0, #0                                    
  0009b154  0000001a      bne      #0x9b15c                                  
  0009b158  8c0bfeeb      bl       #0x1df90                                  
  0009b15c  003094e5      ldr      r3, [r4]                                  
  0009b160  1a0200e3      movw     r0, #0x21a                                
  0009b164  70a19fe5      ldr      sl, [pc, #0x170]                          
  0009b168  652100e3      movw     r2, #0x165                                
  0009b16c  087086e2      add      r7, r6, #8                                
  0009b170  888086e2      add      r8, r6, #0x88                             
  0009b174  00308de5      str      r3, [sp]                                  
  0009b178  0aa08fe0      add      sl, pc, sl                                
  0009b17c  043094e5      ldr      r3, [r4, #4]                              
  0009b180  0a10a0e1      mov      r1, sl                                    
  0009b184  04308de5      str      r3, [sp, #4]                              
  0009b188  50319fe5      ldr      r3, [pc, #0x150]                          
  0009b18c  03308fe0      add      r3, pc, r3                                
  0009b190  e912feeb      bl       #0x1fd3c                                  
  0009b194  1c10a0e3      mov      r1, #0x1c                                 
  0009b198  0130a0e1      mov      r3, r1                                    
  0009b19c  0020a0e3      mov      r2, #0                                    
  0009b1a0  40004be2      sub      r0, fp, #0x40                             
  0009b1a4  b20bfeeb      bl       #0x1e074                                  
  0009b1a8  8030a0e3      mov      r3, #0x80                                 
  0009b1ac  0810a0e3      mov      r1, #8                                    
  0009b1b0  883086e5      str      r3, [r6, #0x88]                           
  0009b1b4  40204be2      sub      r2, fp, #0x40                             
  0009b1b8  0730a0e1      mov      r3, r7                                    
  0009b1bc  00808de5      str      r8, [sp]                                  
  0009b1c0  080084e2      add      r0, r4, #8                                
  0009b1c4  e40afeeb      bl       #0x1dd5c                                  
  0009b1c8  14319fe5      ldr      r3, [pc, #0x114]                          
  0009b1cc  0a10a0e1      mov      r1, sl                                    
  0009b1d0  6d2100e3      movw     r2, #0x16d                                
  0009b1d4  03308fe0      add      r3, pc, r3                                
  0009b1d8  0050a0e1      mov      r5, r0                                    
  0009b1dc  00008de5      str      r0, [sp]                                  
  0009b1e0  1a0200e3      movw     r0, #0x21a                                
  0009b1e4  d412feeb      bl       #0x1fd3c                                  
  0009b1e8  430f55e3      cmp      r5, #0x10c                                
  0009b1ec  1d00001a      bne      #0x9b268                                  
  0009b1f0  103094e5      ldr      r3, [r4, #0x10]                           
  0009b1f4  010053e3      cmp      r3, #1                                    