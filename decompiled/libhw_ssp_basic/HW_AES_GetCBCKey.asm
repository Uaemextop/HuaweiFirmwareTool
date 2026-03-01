### HW_AES_GetCBCKey @ 0x36e38
  00036e38  0dc0a0e1      mov      ip, sp                                    
  00036e3c  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}      
  00036e40  04b04ce2      sub      fp, ip, #4                                
  00036e44  b8404be2      sub      r4, fp, #0xb8                             
  00036e48  a4d04de2      sub      sp, sp, #0xa4                             
  00036e4c  0160a0e1      mov      r6, r1                                    
  00036e50  9410a0e3      mov      r1, #0x94                                 
  00036e54  0130a0e1      mov      r3, r1                                    
  00036e58  0070a0e1      mov      r7, r0                                    
  00036e5c  0280a0e1      mov      r8, r2                                    
  00036e60  0400a0e1      mov      r0, r4                                    
  00036e64  0020a0e3      mov      r2, #0                                    
  00036e68  819cffeb      bl       #0x1e074                                  
  00036e6c  0020a0e3      mov      r2, #0                                    
  00036e70  00408de5      str      r4, [sp]                                  
  00036e74  0100a0e3      mov      r0, #1                                    
  00036e78  0210a0e3      mov      r1, #2                                    
  00036e7c  0230a0e1      mov      r3, r2                                    
  00036e80  f9feffeb      bl       #0x36a6c                                  
  00036e84  005050e2      subs     r5, r0, #0                                
  00036e88  0600000a      beq      #0x36ea8                                  
  00036e8c  120ea0e3      mov      r0, #0x120                                
  00036e90  0510a0e1      mov      r1, r5                                    
  00036e94  e3feffeb      bl       #0x36a28                                  
  00036e98  0400a0e1      mov      r0, r4                                    
  00036e9c  9410a0e3      mov      r1, #0x94                                 
  00036ea0  0020a0e3      mov      r2, #0                                    
  00036ea4  080000ea      b        #0x36ecc                                  
  00036ea8  080084e2      add      r0, r4, #8                                
  00036eac  2010a0e3      mov      r1, #0x20                                 
  00036eb0  0720a0e1      mov      r2, r7                                    
  00036eb4  00808de5      str      r8, [sp]                                  
  00036eb8  0630a0e1      mov      r3, r6                                    
  00036ebc  17ffffeb      bl       #0x36b20                                  
  00036ec0  0400a0e1      mov      r0, r4                                    
  00036ec4  9410a0e3      mov      r1, #0x94                                 
  00036ec8  0520a0e1      mov      r2, r5                                    
  00036ecc  0130a0e1      mov      r3, r1                                    
  00036ed0  679cffeb      bl       #0x1e074                                  
  00036ed4  20d04be2      sub      sp, fp, #0x20                             
  00036ed8  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}      
  00036edc  0dc0a0e1      mov      ip, sp                                    
  00036ee0  30d82de9      push     {r4, r5, fp, ip, lr, pc}                  
  00036ee4  04b04ce2      sub      fp, ip, #4                                
  00036ee8  0040a0e1      mov      r4, r0                                    
  00036eec  015041e2      sub      r5, r1, #1                                
  00036ef0  070000ea      b        #0x36f14                                  
  00036ef4  0400a0e1      mov      r0, r4                                    
  00036ef8  5d10a0e3      mov      r1, #0x5d                                 
  00036efc  e9a5ffeb      bl       #0x206a8                                  
  00036f00  0400a0e1      mov      r0, r4                                    
  00036f04  0110e5e5      strb     r1, [r5, #1]!                             
  00036f08  5d10a0e3      mov      r1, #0x5d                                 
  00036f0c  caa2ffeb      bl       #0x1fa3c                                  
  00036f10  0040a0e1      mov      r4, r0                                    
  00036f14  000054e3      cmp      r4, #0                                    
  00036f18  f5ffff1a      bne      #0x36ef4                                  
  00036f1c  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                  
  00036f20  000050e3      cmp      r0, #0                                    
  00036f24  0dc0a0e1      mov      ip, sp                                    