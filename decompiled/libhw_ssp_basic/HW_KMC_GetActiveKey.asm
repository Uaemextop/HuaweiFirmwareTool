### HW_KMC_GetActiveKey @ 0x9b000
  0009b000  0dc0a0e1      mov      ip, sp                                    
  0009b004  000050e3      cmp      r0, #0                                    
  0009b008  00005113      cmpne    r1, #0                                    
  0009b00c  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}              
  0009b010  04b04ce2      sub      fp, ip, #4                                
  0009b014  2cd04de2      sub      sp, sp, #0x2c                             
  0009b018  0830a0e3      mov      r3, #8                                    
  0009b01c  0140a0e1      mov      r4, r1                                    
  0009b020  3c300be5      str      r3, [fp, #-0x3c]                          
  0009b024  0060a0e1      mov      r6, r0                                    
  0009b028  0400001a      bne      #0x9b040                                  
  0009b02c  2f0100e3      movw     r0, #0x12f                                
  0009b030  0110a0e3      mov      r1, #1                                    
  0009b034  b4feffeb      bl       #0x9ab0c                                  
  0009b038  0150a0e3      mov      r5, #1                                    
  0009b03c  2b0000ea      b        #0x9b0f0                                  
  0009b040  b4309fe5      ldr      r3, [pc, #0xb4]                           
  0009b044  03009fe7      ldr      r0, [pc, r3]                              
  0009b048  000050e3      cmp      r0, #0                                    
  0009b04c  0000001a      bne      #0x9b054                                  
  0009b050  ce0bfeeb      bl       #0x1df90                                  
  0009b054  003096e5      ldr      r3, [r6]                                  
  0009b058  1a0200e3      movw     r0, #0x21a                                
  0009b05c  9c109fe5      ldr      r1, [pc, #0x9c]                           
  0009b060  362100e3      movw     r2, #0x136                                
  0009b064  00308de5      str      r3, [sp]                                  
  0009b068  01108fe0      add      r1, pc, r1                                
  0009b06c  90309fe5      ldr      r3, [pc, #0x90]                           
  0009b070  03308fe0      add      r3, pc, r3                                
  0009b074  3013feeb      bl       #0x1fd3c                                  
  0009b078  1c10a0e3      mov      r1, #0x1c                                 
  0009b07c  0130a0e1      mov      r3, r1                                    
  0009b080  0020a0e3      mov      r2, #0                                    
  0009b084  38004be2      sub      r0, fp, #0x38                             
  0009b088  f90bfeeb      bl       #0x1e074                                  
  0009b08c  8030a0e3      mov      r3, #0x80                                 
  0009b090  38104be2      sub      r1, fp, #0x38                             
  0009b094  883084e5      str      r3, [r4, #0x88]                           
  0009b098  082084e2      add      r2, r4, #8                                
  0009b09c  000096e5      ldr      r0, [r6]                                  
  0009b0a0  883084e2      add      r3, r4, #0x88                             
  0009b0a4  f514feeb      bl       #0x20480                                  
  0009b0a8  005050e2      subs     r5, r0, #0                                
  0009b0ac  3b010013      movwne   r0, #0x13b                                
  0009b0b0  0700001a      bne      #0x9b0d4                                  
  0009b0b4  38001be5      ldr      r0, [fp, #-0x38]                          
  0009b0b8  8c2084e2      add      r2, r4, #0x8c                             
  0009b0bc  34101be5      ldr      r1, [fp, #-0x34]                          
  0009b0c0  3c304be2      sub      r3, fp, #0x3c                             
  0009b0c4  3917feeb      bl       #0x20db0                                  
  0009b0c8  005050e2      subs     r5, r0, #0                                
  0009b0cc  0300000a      beq      #0x9b0e0                                  
  0009b0d0  3f0100e3      movw     r0, #0x13f                                
  0009b0d4  0510a0e1      mov      r1, r5                                    
  0009b0d8  8bfeffeb      bl       #0x9ab0c                                  
  0009b0dc  030000ea      b        #0x9b0f0                                  
  0009b0e0  003096e5      ldr      r3, [r6]                                  
  0009b0e4  003084e5      str      r3, [r4]                                  
  0009b0e8  34301be5      ldr      r3, [fp, #-0x34]                          
  0009b0ec  043084e5      str      r3, [r4, #4]                              