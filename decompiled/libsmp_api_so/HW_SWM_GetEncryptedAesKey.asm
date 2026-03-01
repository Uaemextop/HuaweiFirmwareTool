### HW_SWM_GetEncryptedAesKey @ 0x2a7c8
  0002a7c8  0dc0a0e1      mov      ip, sp                                      
  0002a7cc  2120a0e3      mov      r2, #0x21                                   
  0002a7d0  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0002a7d4  04b04ce2      sub      fp, ip, #4                                  
  0002a7d8  2cd04de2      sub      sp, sp, #0x2c                               
  0002a7dc  0060a0e1      mov      r6, r0                                      
  0002a7e0  0150a0e1      mov      r5, r1                                      
  0002a7e4  40004be2      sub      r0, fp, #0x40                               
  0002a7e8  0010a0e3      mov      r1, #0                                      
  0002a7ec  0181ffeb      bl       #0xabf8                                     
  0002a7f0  000056e3      cmp      r6, #0                                      
  0002a7f4  00005513      cmpne    r5, #0                                      
  0002a7f8  0400001a      bne      #0x2a810                                    
  0002a7fc  850300e3      movw     r0, #0x385                                  
  0002a800  b8109fe5      ldr      r1, [pc, #0xb8]                             
  0002a804  2bfcffeb      bl       #0x298b8                                    
  0002a808  b0409fe5      ldr      r4, [pc, #0xb0]                             
  0002a80c  280000ea      b        #0x2a8b4                                    
  0002a810  ac009fe5      ldr      r0, [pc, #0xac]                             
  0002a814  00008fe0      add      r0, pc, r0                                  
  0002a818  4e83ffeb      bl       #0xb558                                     
  0002a81c  000050e3      cmp      r0, #0                                      
  0002a820  1300001a      bne      #0x2a874                                    
  0002a824  9c009fe5      ldr      r0, [pc, #0x9c]                             
  0002a828  2110a0e3      mov      r1, #0x21                                   
  0002a82c  40204be2      sub      r2, fp, #0x40                               
  0002a830  ae80ffeb      bl       #0xaaf0                                     
  0002a834  004050e2      subs     r4, r0, #0                                  
  0002a838  0100000a      beq      #0x2a844                                    
  0002a83c  0140a0e3      mov      r4, #1                                      
  0002a840  1b0000ea      b        #0x2a8b4                                    
  0002a844  40004be2      sub      r0, fp, #0x40                               
  0002a848  a583ffeb      bl       #0xb6e4                                     
  0002a84c  000050e3      cmp      r0, #0                                      
  0002a850  f9ffff0a      beq      #0x2a83c                                    
  0002a854  70109fe5      ldr      r1, [pc, #0x70]                             
  0002a858  2a00a0e3      mov      r0, #0x2a                                   
  0002a85c  6c309fe5      ldr      r3, [pc, #0x6c]                             
  0002a860  8e2300e3      movw     r2, #0x38e                                  
  0002a864  01108fe0      add      r1, pc, r1                                  
  0002a868  03308fe0      add      r3, pc, r3                                  
  0002a86c  fe81ffeb      bl       #0xb06c                                     
  0002a870  050000ea      b        #0x2a88c                                    
  0002a874  0100a0e3      mov      r0, #1                                      
  0002a878  40104be2      sub      r1, fp, #0x40                               
  0002a87c  2120a0e3      mov      r2, #0x21                                   
  0002a880  1a85ffeb      bl       #0xbcf0                                     
  0002a884  004050e2      subs     r4, r0, #0                                  
  0002a888  ebffff1a      bne      #0x2a83c                                    
  0002a88c  0510a0e1      mov      r1, r5                                      
  0002a890  40204be2      sub      r2, fp, #0x40                               
  0002a894  2030a0e3      mov      r3, #0x20                                   
  0002a898  0600a0e1      mov      r0, r6                                      
  0002a89c  d67fffeb      bl       #0xa7fc                                     
  0002a8a0  2110a0e3      mov      r1, #0x21                                   
  0002a8a4  40004be2      sub      r0, fp, #0x40                               
  0002a8a8  0420a0e1      mov      r2, r4                                      
  0002a8ac  0130a0e1      mov      r3, r1                                      
  0002a8b0  9c81ffeb      bl       #0xaf28                                     
  0002a8b4  0400a0e1      mov      r0, r4                                      
  0002a8b8  18d04be2      sub      sp, fp, #0x18                               
  0002a8bc  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                