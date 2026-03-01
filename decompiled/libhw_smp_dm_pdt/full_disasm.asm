# libhw_smp_dm_pdt full disassembly

; ─── HW_DM_PDT_GetInterVer_Func @ 0xb990 ───
  0000b990  000050e3      cmp      r0, #0                                      
  0000b994  00005113      cmpne    r1, #0                                      
  0000b998  0dc0a0e1      mov      ip, sp                                      
  0000b99c  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000b9a0  04b04ce2      sub      fp, ip, #4                                  
  0000b9a4  0140a0e1      mov      r4, r1                                      
  0000b9a8  0050a013      movne    r5, #0                                      
  0000b9ac  0150a003      moveq    r5, #1                                      
  0000b9b0  0200001a      bne      #0xb9c0                                     
  0000b9b4  030405e3      movw     r0, #0x5403                                 
  0000b9b8  20074fe3      movt     r0, #0xf720                                 
  0000b9bc  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000b9c0  2c209fe5      ldr      r2, [pc, #0x2c]                             
  0000b9c4  1110a0e3      mov      r1, #0x11                                   
  0000b9c8  1030a0e3      mov      r3, #0x10                                   
  0000b9cc  02208fe0      add      r2, pc, r2                                  
  0000b9d0  c4f9ffeb      bl       #0xa0e8                                     
  0000b9d4  1c209fe5      ldr      r2, [pc, #0x1c]                             
  0000b9d8  0400a0e1      mov      r0, r4                                      
  0000b9dc  1110a0e3      mov      r1, #0x11                                   
  0000b9e0  02208fe0      add      r2, pc, r2                                  
  0000b9e4  1030a0e3      mov      r3, #0x10                                   
  0000b9e8  bef9ffeb      bl       #0xa0e8                                     
  0000b9ec  0500a0e1      mov      r0, r5                                      
  0000b9f0  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000b9f4  e4440200      andeq    r4, r2, r4, ror #9                          
  0000b9f8  e0440200      andeq    r4, r2, r0, ror #9                          

; ─── HW_DM_PDT_GetBatteryInfo_Func @ 0xb9fc ───
  0000b9fc  0dc0a0e1      mov      ip, sp                                      
  0000ba00  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000ba04  005050e2      subs     r5, r0, #0                                  
  0000ba08  04b04ce2      sub      fp, ip, #4                                  
  0000ba0c  28d04de2      sub      sp, sp, #0x28                               
  0000ba10  1a00000a      beq      #0xba80                                     
  0000ba14  1410a0e3      mov      r1, #0x14                                   
  0000ba18  0020a0e3      mov      r2, #0                                      
  0000ba1c  0130a0e1      mov      r3, r1                                      
  0000ba20  28004be2      sub      r0, fp, #0x28                               
  0000ba24  2ffbffeb      bl       #0xa6e8                                     
  0000ba28  28004be2      sub      r0, fp, #0x28                               
  0000ba2c  85faffeb      bl       #0xa448                                     
  0000ba30  004050e2      subs     r4, r0, #0                                  
  0000ba34  0700001a      bne      #0xba58                                     
  0000ba38  1410a0e3      mov      r1, #0x14                                   
  0000ba3c  0500a0e1      mov      r0, r5                                      
  0000ba40  28204be2      sub      r2, fp, #0x28                               
  0000ba44  0130a0e1      mov      r3, r1                                      
  0000ba48  4cfcffeb      bl       #0xab80                                     
  0000ba4c  0400a0e1      mov      r0, r4                                      
  0000ba50  14d04be2      sub      sp, fp, #0x14                               
  0000ba54  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000ba58  54009fe5      ldr      r0, [pc, #0x54]                             
  0000ba5c  0030a0e3      mov      r3, #0                                      
  0000ba60  e210a0e3      mov      r1, #0xe2                                   
  0000ba64  00308de5      str      r3, [sp]                                    
  0000ba68  00008fe0      add      r0, pc, r0                                  
  0000ba6c  04308de5      str      r3, [sp, #4]                                
  0000ba70  0420a0e1      mov      r2, r4                                      
  0000ba74  08308de5      str      r3, [sp, #8]                                
  0000ba78  f9faffeb      bl       #0xa664                                     
  0000ba7c  f2ffffea      b        #0xba4c                                     
  0000ba80  30009fe5      ldr      r0, [pc, #0x30]                             
  0000ba84  d710a0e3      mov      r1, #0xd7                                   
  0000ba88  00508de5      str      r5, [sp]                                    
  0000ba8c  012005e3      movw     r2, #0x5001                                 
  0000ba90  04508de5      str      r5, [sp, #4]                                
  0000ba94  20274fe3      movt     r2, #0xf720                                 
  0000ba98  08508de5      str      r5, [sp, #8]                                
  0000ba9c  00008fe0      add      r0, pc, r0                                  
  0000baa0  0530a0e1      mov      r3, r5                                      
  0000baa4  014005e3      movw     r4, #0x5001                                 
  0000baa8  edfaffeb      bl       #0xa664                                     
  0000baac  20474fe3      movt     r4, #0xf720                                 
  0000bab0  e5ffffea      b        #0xba4c                                     
  0000bab4  5c440200      andeq    r4, r2, ip, asr r4                          
  0000bab8  28440200      andeq    r4, r2, r8, lsr #8                          

; ─── HW_DM_PDT_GetWIFIType_Func @ 0xbabc ───
  0000babc  000050e3      cmp      r0, #0                                      
  0000bac0  00005113      cmpne    r1, #0                                      
  0000bac4  0dc0a0e1      mov      ip, sp                                      
  0000bac8  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000bacc  04b04ce2      sub      fp, ip, #4                                  
  0000bad0  70d04de2      sub      sp, sp, #0x70                               
  0000bad4  0140a0e1      mov      r4, r1                                      
  0000bad8  0050a0e1      mov      r5, r0                                      
  0000badc  0060a013      movne    r6, #0                                      
  0000bae0  0160a003      moveq    r6, #1                                      
  0000bae4  0d00001a      bne      #0xbb20                                     
  0000bae8  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0000baec  0030a0e3      mov      r3, #0                                      
  0000baf0  3e1100e3      movw     r1, #0x13e                                  
  0000baf4  00308de5      str      r3, [sp]                                    
  0000baf8  00008fe0      add      r0, pc, r0                                  
  0000bafc  04308de5      str      r3, [sp, #4]                                
  0000bb00  032405e3      movw     r2, #0x5403                                 
  0000bb04  08308de5      str      r3, [sp, #8]                                
  0000bb08  20274fe3      movt     r2, #0xf720                                 
  0000bb0c  d4faffeb      bl       #0xa664                                     
  0000bb10  030405e3      movw     r0, #0x5403                                 
  0000bb14  20074fe3      movt     r0, #0xf720                                 
  0000bb18  1cd04be2      sub      sp, fp, #0x1c                               
  0000bb1c  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000bb20  78704be2      sub      r7, fp, #0x78                               
  0000bb24  0810a0e3      mov      r1, #8                                      
  0000bb28  0130a0e1      mov      r3, r1                                      
  0000bb2c  0620a0e1      mov      r2, r6                                      
  0000bb30  0700a0e1      mov      r0, r7                                      
  0000bb34  ebfaffeb      bl       #0xa6e8                                     
  0000bb38  5410a0e3      mov      r1, #0x54                                   
  0000bb3c  0130a0e1      mov      r3, r1                                      
  0000bb40  0620a0e1      mov      r2, r6                                      
  0000bb44  70004be2      sub      r0, fp, #0x70                               
  0000bb48  e6faffeb      bl       #0xa6e8                                     
  0000bb4c  ac209fe5      ldr      r2, [pc, #0xac]                             
  0000bb50  2010a0e3      mov      r1, #0x20                                   
  0000bb54  1f30a0e3      mov      r3, #0x1f                                   
  0000bb58  02208fe0      add      r2, pc, r2                                  
  0000bb5c  6c004be2      sub      r0, fp, #0x6c                               
  0000bb60  60f9ffeb      bl       #0xa0e8                                     
  0000bb64  98209fe5      ldr      r2, [pc, #0x98]                             
  0000bb68  2010a0e3      mov      r1, #0x20                                   
  0000bb6c  1f30a0e3      mov      r3, #0x1f                                   
  0000bb70  02208fe0      add      r2, pc, r2                                  
  0000bb74  48004be2      sub      r0, fp, #0x48                               
  0000bb78  5af9ffeb      bl       #0xa0e8                                     
  0000bb7c  15c0a0e3      mov      ip, #0x15                                   
  0000bb80  0830a0e3      mov      r3, #8                                      
  0000bb84  0c20a0e1      mov      r2, ip                                      
  0000bb88  88008de8      stm      sp, {r3, r7}                                
  0000bb8c  70004be2      sub      r0, fp, #0x70                               
  0000bb90  08308de5      str      r3, [sp, #8]                                
  0000bb94  331003e3      movw     r1, #0x3033                                 
  0000bb98  4e3d83e2      add      r3, r3, #0x1380                             
  0000bb9c  601744e3      movt     r1, #0x4760                                 
  0000bba0  0c308de5      str      r3, [sp, #0xc]                              
  0000bba4  0730a0e1      mov      r3, r7                                      
  0000bba8  4cc00be5      str      ip, [fp, #-0x4c]                            
  0000bbac  8ac0a0e3      mov      ip, #0x8a                                   
  0000bbb0  28c00be5      str      ip, [fp, #-0x28]                            
  0000bbb4  69fcffeb      bl       #0xad60                                     
  0000bbb8  002050e2      subs     r2, r0, #0                                  
  0000bbbc  0500001a      bne      #0xbbd8                                     
  0000bbc0  78301be5      ldr      r3, [fp, #-0x78]                            
  0000bbc4  003085e5      str      r3, [r5]                                    
  0000bbc8  74301be5      ldr      r3, [fp, #-0x74]                            
  0000bbcc  003084e5      str      r3, [r4]                                    
  0000bbd0  0000a0e3      mov      r0, #0                                      
  0000bbd4  cfffffea      b        #0xbb18                                     
  0000bbd8  28009fe5      ldr      r0, [pc, #0x28]                             
  0000bbdc  571100e3      movw     r1, #0x157                                  
  0000bbe0  00608de5      str      r6, [sp]                                    
  0000bbe4  0630a0e1      mov      r3, r6                                      
  0000bbe8  04608de5      str      r6, [sp, #4]                                
  0000bbec  00008fe0      add      r0, pc, r0                                  
  0000bbf0  08608de5      str      r6, [sp, #8]                                
  0000bbf4  9afaffeb      bl       #0xa664                                     
  0000bbf8  f4ffffea      b        #0xbbd0                                     
  0000bbfc  cc430200      andeq    r4, r2, ip, asr #7                          
  0000bc00  7c430200      andeq    r4, r2, ip, ror r3                          
  0000bc04  6c430200      andeq    r4, r2, ip, ror #6                          
  0000bc08  d8420200      ldrdeq   r4, r5, [r2], -r8                           

; ─── HW_DM_PDT_CheckAlarmForPonAlarm @ 0xbc0c ───
  0000bc0c  0dc0a0e1      mov      ip, sp                                      
  0000bc10  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  0000bc14  04b04ce2      sub      fp, ip, #4                                  
  0000bc18  083090e5      ldr      r3, [r0, #8]                                
  0000bc1c  0040a0e1      mov      r4, r0                                      
  0000bc20  010053e3      cmp      r3, #1                                      
  0000bc24  0b00000a      beq      #0xbc58                                     
  0000bc28  88309fe5      ldr      r3, [pc, #0x88]                             
  0000bc2c  03308fe0      add      r3, pc, r3                                  
  0000bc30  002093e5      ldr      r2, [r3]                                    
  0000bc34  000052e3      cmp      r2, #0                                      
  0000bc38  0400001a      bne      #0xbc50                                     
  0000bc3c  042094e5      ldr      r2, [r4, #4]                                
  0000bc40  010052e3      cmp      r2, #1                                      
  0000bc44  1100000a      beq      #0xbc90                                     
  0000bc48  0120a0e3      mov      r2, #1                                      
  0000bc4c  002083e5      str      r2, [r3]                                    
  0000bc50  0000a0e3      mov      r0, #0                                      
  0000bc54  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    
  0000bc58  0c3090e5      ldr      r3, [r0, #0xc]                              
  0000bc5c  010053e3      cmp      r3, #1                                      
  0000bc60  f0ffff1a      bne      #0xbc28                                     
  0000bc64  043090e5      ldr      r3, [r0, #4]                                
  0000bc68  010053e3      cmp      r3, #1                                      
  0000bc6c  edffff1a      bne      #0xbc28                                     
  0000bc70  003090e5      ldr      r3, [r0]                                    
  0000bc74  010053e3      cmp      r3, #1                                      
  0000bc78  eaffff1a      bne      #0xbc28                                     
  0000bc7c  1010a0e3      mov      r1, #0x10                                   
  0000bc80  0020a0e3      mov      r2, #0                                      
  0000bc84  0130a0e1      mov      r3, r1                                      
  0000bc88  96faffeb      bl       #0xa6e8                                     
  0000bc8c  efffffea      b        #0xbc50                                     
  0000bc90  24009fe5      ldr      r0, [pc, #0x24]                             
  0000bc94  00008fe0      add      r0, pc, r0                                  
  0000bc98  36fcffeb      bl       #0xad78                                     
  0000bc9c  002050e2      subs     r2, r0, #0                                  
  0000bca0  eaffff1a      bne      #0xbc50                                     
  0000bca4  1010a0e3      mov      r1, #0x10                                   
  0000bca8  0400a0e1      mov      r0, r4                                      
  0000bcac  0130a0e1      mov      r3, r1                                      
  0000bcb0  8cfaffeb      bl       #0xa6e8                                     
  0000bcb4  e5ffffea      b        #0xbc50                                     
  0000bcb8  e4410300      andeq    r4, r3, r4, ror #3                          
  0000bcbc  50420200      andeq    r4, r2, r0, asr r2                          

; ─── HW_DM_PDT_GetBatteryAlarm @ 0xbcc0 ───
  0000bcc0  0dc0a0e1      mov      ip, sp                                      
  0000bcc4  0030e0e3      mvn      r3, #0                                      
  0000bcc8  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000bccc  04b04ce2      sub      fp, ip, #4                                  
  0000bcd0  005050e2      subs     r5, r0, #0                                  
  0000bcd4  28d04de2      sub      sp, sp, #0x28                               
  0000bcd8  28300be5      str      r3, [fp, #-0x28]                            
  0000bcdc  1900000a      beq      #0xbd48                                     
  0000bce0  1010a0e3      mov      r1, #0x10                                   
  0000bce4  0020a0e3      mov      r2, #0                                      
  0000bce8  0130a0e1      mov      r3, r1                                      
  0000bcec  24004be2      sub      r0, fp, #0x24                               
  0000bcf0  7cfaffeb      bl       #0xa6e8                                     
  0000bcf4  1700a0e3      mov      r0, #0x17                                   
  0000bcf8  0410a0e3      mov      r1, #4                                      
  0000bcfc  28204be2      sub      r2, fp, #0x28                               
  0000bd00  91f9ffeb      bl       #0xa34c                                     
  0000bd04  004050e2      subs     r4, r0, #0                                  
  0000bd08  1b00001a      bne      #0xbd7c                                     
  0000bd0c  28301be5      ldr      r3, [fp, #-0x28]                            
  0000bd10  000053e3      cmp      r3, #0                                      
  0000bd14  0300000a      beq      #0xbd28                                     
  0000bd18  24004be2      sub      r0, fp, #0x24                               
  0000bd1c  68faffeb      bl       #0xa6c4                                     
  0000bd20  00c050e2      subs     ip, r0, #0                                  
  0000bd24  1e00001a      bne      #0xbda4                                     
  0000bd28  1010a0e3      mov      r1, #0x10                                   
  0000bd2c  0500a0e1      mov      r0, r5                                      
  0000bd30  24204be2      sub      r2, fp, #0x24                               
  0000bd34  0130a0e1      mov      r3, r1                                      
  0000bd38  90fbffeb      bl       #0xab80                                     
  0000bd3c  0400a0e1      mov      r0, r4                                      
  0000bd40  14d04be2      sub      sp, fp, #0x14                               
  0000bd44  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000bd48  80009fe5      ldr      r0, [pc, #0x80]                             
  0000bd4c  7810a0e3      mov      r1, #0x78                                   
  0000bd50  00508de5      str      r5, [sp]                                    
  0000bd54  012005e3      movw     r2, #0x5001                                 
  0000bd58  04508de5      str      r5, [sp, #4]                                
  0000bd5c  20274fe3      movt     r2, #0xf720                                 
  0000bd60  08508de5      str      r5, [sp, #8]                                
  0000bd64  00008fe0      add      r0, pc, r0                                  
  0000bd68  0530a0e1      mov      r3, r5                                      
  0000bd6c  014005e3      movw     r4, #0x5001                                 
  0000bd70  3bfaffeb      bl       #0xa664                                     
  0000bd74  20474fe3      movt     r4, #0xf720                                 
  0000bd78  efffffea      b        #0xbd3c                                     
  0000bd7c  50009fe5      ldr      r0, [pc, #0x50]                             
  0000bd80  0030a0e3      mov      r3, #0                                      
  0000bd84  8210a0e3      mov      r1, #0x82                                   
  0000bd88  00308de5      str      r3, [sp]                                    
  0000bd8c  00008fe0      add      r0, pc, r0                                  
  0000bd90  04308de5      str      r3, [sp, #4]                                
  0000bd94  0420a0e1      mov      r2, r4                                      
  0000bd98  08308de5      str      r3, [sp, #8]                                
  0000bd9c  30faffeb      bl       #0xa664                                     
  0000bda0  e5ffffea      b        #0xbd3c                                     
  0000bda4  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000bda8  0430a0e1      mov      r3, r4                                      
  0000bdac  00408de5      str      r4, [sp]                                    
  0000bdb0  9210a0e3      mov      r1, #0x92                                   
  0000bdb4  04408de5      str      r4, [sp, #4]                                
  0000bdb8  0c20a0e1      mov      r2, ip                                      
  0000bdbc  08408de5      str      r4, [sp, #8]                                
  0000bdc0  00008fe0      add      r0, pc, r0                                  
  0000bdc4  0c40a0e1      mov      r4, ip                                      
  0000bdc8  25faffeb      bl       #0xa664                                     
  0000bdcc  daffffea      b        #0xbd3c                                     
  0000bdd0  60410200      andeq    r4, r2, r0, ror #2                          
  0000bdd4  38410200      andeq    r4, r2, r8, lsr r1                          
  0000bdd8  04410200      andeq    r4, r2, r4, lsl #2                          

; ─── HW_DM_PDT_GetBatteryAlarm_Func @ 0xbddc ───
  0000bddc  0dc0a0e1      mov      ip, sp                                      
  0000bde0  1010a0e3      mov      r1, #0x10                                   
  0000bde4  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000bde8  04b04ce2      sub      fp, ip, #4                                  
  0000bdec  20d04de2      sub      sp, sp, #0x20                               
  0000bdf0  0020a0e3      mov      r2, #0                                      
  0000bdf4  0130a0e1      mov      r3, r1                                      
  0000bdf8  0050a0e1      mov      r5, r0                                      
  0000bdfc  24004be2      sub      r0, fp, #0x24                               
  0000be00  38faffeb      bl       #0xa6e8                                     
  0000be04  24004be2      sub      r0, fp, #0x24                               
  0000be08  50fbffeb      bl       #0xab50                                     
  0000be0c  004050e2      subs     r4, r0, #0                                  
  0000be10  1500001a      bne      #0xbe6c                                     
  0000be14  24004be2      sub      r0, fp, #0x24                               
  0000be18  67feffeb      bl       #0xb7bc                                     
  0000be1c  004050e2      subs     r4, r0, #0                                  
  0000be20  0700001a      bne      #0xbe44                                     
  0000be24  1010a0e3      mov      r1, #0x10                                   
  0000be28  0500a0e1      mov      r0, r5                                      
  0000be2c  24204be2      sub      r2, fp, #0x24                               
  0000be30  0130a0e1      mov      r3, r1                                      
  0000be34  51fbffeb      bl       #0xab80                                     
  0000be38  0400a0e1      mov      r0, r4                                      
  0000be3c  14d04be2      sub      sp, fp, #0x14                               
  0000be40  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000be44  48009fe5      ldr      r0, [pc, #0x48]                             
  0000be48  0030a0e3      mov      r3, #0                                      
  0000be4c  ba10a0e3      mov      r1, #0xba                                   
  0000be50  00308de5      str      r3, [sp]                                    
  0000be54  00008fe0      add      r0, pc, r0                                  
  0000be58  04308de5      str      r3, [sp, #4]                                
  0000be5c  0420a0e1      mov      r2, r4                                      
  0000be60  08308de5      str      r3, [sp, #8]                                
  0000be64  fef9ffeb      bl       #0xa664                                     
  0000be68  f2ffffea      b        #0xbe38                                     
  0000be6c  24009fe5      ldr      r0, [pc, #0x24]                             
  0000be70  0030a0e3      mov      r3, #0                                      
  0000be74  b210a0e3      mov      r1, #0xb2                                   
  0000be78  00308de5      str      r3, [sp]                                    
  0000be7c  00008fe0      add      r0, pc, r0                                  
  0000be80  04308de5      str      r3, [sp, #4]                                
  0000be84  0420a0e1      mov      r2, r4                                      
  0000be88  08308de5      str      r3, [sp, #8]                                
  0000be8c  f4f9ffeb      bl       #0xa664                                     
  0000be90  e8ffffea      b        #0xbe38                                     
  0000be94  70400200      andeq    r4, r2, r0, ror r0                          
  0000be98  48400200      andeq    r4, r2, r8, asr #32                         

; ─── HW_DM_PDT_GetWifiInfoForDes @ 0xbe9c ───
  0000be9c  0dc0a0e1      mov      ip, sp                                      
  0000bea0  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000bea4  04b04ce2      sub      fp, ip, #4                                  
  0000bea8  006050e2      subs     r6, r0, #0                                  
  0000beac  1cd04de2      sub      sp, sp, #0x1c                               
  0000beb0  0040a0e3      mov      r4, #0                                      
  0000beb4  b4424be1      strh     r4, [fp, #-0x24]                            
  0000beb8  20400be5      str      r4, [fp, #-0x20]                            
  0000bebc  1e00000a      beq      #0xbf3c                                     
  0000bec0  4200a0e3      mov      r0, #0x42                                   
  0000bec4  0210a0e3      mov      r1, #2                                      
  0000bec8  000141e3      movt     r0, #0x1100                                 
  0000becc  24204be2      sub      r2, fp, #0x24                               
  0000bed0  1df9ffeb      bl       #0xa34c                                     
  0000bed4  005050e2      subs     r5, r0, #0                                  
  0000bed8  0d00001a      bne      #0xbf14                                     
  0000bedc  28019fe5      ldr      r0, [pc, #0x128]                            
  0000bee0  00008fe0      add      r0, pc, r0                                  
  0000bee4  a3fbffeb      bl       #0xad78                                     
  0000bee8  010050e3      cmp      r0, #1                                      
  0000beec  2f00000a      beq      #0xbfb0                                     
  0000bef0  18119fe5      ldr      r1, [pc, #0x118]                            
  0000bef4  0600a0e1      mov      r0, r6                                      
  0000bef8  01108fe0      add      r1, pc, r1                                  
  0000befc  aafaffeb      bl       #0xa9ac                                     
  0000bf00  000050e3      cmp      r0, #0                                      
  0000bf04  1900001a      bne      #0xbf70                                     
  0000bf08  0500a0e1      mov      r0, r5                                      
  0000bf0c  18d04be2      sub      sp, fp, #0x18                               
  0000bf10  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  0000bf14  f8009fe5      ldr      r0, [pc, #0xf8]                             
  0000bf18  0b1100e3      movw     r1, #0x10b                                  
  0000bf1c  00408de5      str      r4, [sp]                                    
  0000bf20  0520a0e1      mov      r2, r5                                      
  0000bf24  04408de5      str      r4, [sp, #4]                                
  0000bf28  0430a0e1      mov      r3, r4                                      
  0000bf2c  08408de5      str      r4, [sp, #8]                                
  0000bf30  00008fe0      add      r0, pc, r0                                  
  0000bf34  caf9ffeb      bl       #0xa664                                     
  0000bf38  f2ffffea      b        #0xbf08                                     
  0000bf3c  d4009fe5      ldr      r0, [pc, #0xd4]                             
  0000bf40  031100e3      movw     r1, #0x103                                  
  0000bf44  00608de5      str      r6, [sp]                                    
  0000bf48  032405e3      movw     r2, #0x5403                                 
  0000bf4c  04608de5      str      r6, [sp, #4]                                
  0000bf50  20274fe3      movt     r2, #0xf720                                 
  0000bf54  08608de5      str      r6, [sp, #8]                                
  0000bf58  00008fe0      add      r0, pc, r0                                  
  0000bf5c  0630a0e1      mov      r3, r6                                      
  0000bf60  035405e3      movw     r5, #0x5403                                 
  0000bf64  bef9ffeb      bl       #0xa664                                     
  0000bf68  20574fe3      movt     r5, #0xf720                                 
  0000bf6c  e5ffffea      b        #0xbf08                                     
  0000bf70  a4009fe5      ldr      r0, [pc, #0xa4]                             
  0000bf74  20104be2      sub      r1, fp, #0x20                               
  0000bf78  00008fe0      add      r0, pc, r0                                  
  0000bf7c  cffdffeb      bl       #0xb6c0                                     
  0000bf80  005050e2      subs     r5, r0, #0                                  
  0000bf84  1600001a      bne      #0xbfe4                                     
  0000bf88  20301be5      ldr      r3, [fp, #-0x20]                            
  0000bf8c  050053e3      cmp      r3, #5                                      
  0000bf90  dcffff1a      bne      #0xbf08                                     
  0000bf94  84209fe5      ldr      r2, [pc, #0x84]                             
  0000bf98  0600a0e1      mov      r0, r6                                      
  0000bf9c  1910a0e3      mov      r1, #0x19                                   
  0000bfa0  1830a0e3      mov      r3, #0x18                                   
  0000bfa4  02208fe0      add      r2, pc, r2                                  
  0000bfa8  4ef8ffeb      bl       #0xa0e8                                     
  0000bfac  d5ffffea      b        #0xbf08                                     
  0000bfb0  6c109fe5      ldr      r1, [pc, #0x6c]                             
  0000bfb4  24004be2      sub      r0, fp, #0x24                               
  0000bfb8  01108fe0      add      r1, pc, r1                                  
  0000bfbc  7afaffeb      bl       #0xa9ac                                     
  0000bfc0  000050e3      cmp      r0, #0                                      
  0000bfc4  c9ffff1a      bne      #0xbef0                                     
  0000bfc8  58209fe5      ldr      r2, [pc, #0x58]                             
  0000bfcc  0600a0e1      mov      r0, r6                                      
  0000bfd0  1910a0e3      mov      r1, #0x19                                   
  0000bfd4  1830a0e3      mov      r3, #0x18                                   
  0000bfd8  02208fe0      add      r2, pc, r2                                  
  0000bfdc  41f8ffeb      bl       #0xa0e8                                     
  0000bfe0  c2ffffea      b        #0xbef0                                     
  0000bfe4  40009fe5      ldr      r0, [pc, #0x40]                             
  0000bfe8  0030a0e3      mov      r3, #0                                      
  0000bfec  471fa0e3      mov      r1, #0x11c                                  
  0000bff0  00308de5      str      r3, [sp]                                    
  0000bff4  00008fe0      add      r0, pc, r0                                  
  0000bff8  04308de5      str      r3, [sp, #4]                                
  0000bffc  0520a0e1      mov      r2, r5                                      
  0000c000  08308de5      str      r3, [sp, #8]                                
  0000c004  96f9ffeb      bl       #0xa664                                     
  0000c008  deffffea      b        #0xbf88                                     
  0000c00c  24400200      andeq    r4, r2, r4, lsr #32                         
  0000c010  2c400200      andeq    r4, r2, ip, lsr #32                         
  0000c014  943f0200      muleq    r2, r4, pc                                  
  0000c018  6c3f0200      andeq    r3, r2, ip, ror #30                         
  0000c01c  b43f0200      strheq   r3, [r2], -r4                               
  0000c020  803f0200      andeq    r3, r2, r0, lsl #31                         
  0000c024  683f0200      andeq    r3, r2, r8, ror #30                         
  0000c028  4c3f0200      andeq    r3, r2, ip, asr #30                         
  0000c02c  d03e0200      ldrdeq   r3, r4, [r2], -r0                           

; ─── HW_DM_ProcBatter_WhenLossExtPwr @ 0xc030 ───
  0000c030  0dc0a0e1      mov      ip, sp                                      
  0000c034  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000c038  04b04ce2      sub      fp, ip, #4                                  
  0000c03c  46df4de2      sub      sp, sp, #0x118                              
  0000c040  49cf4be2      sub      ip, fp, #0x124                              
  0000c044  1c519fe5      ldr      r5, [pc, #0x11c]                            
  0000c048  0f008ce8      stm      ip, {r0, r1, r2, r3}                        
  0000c04c  450f4be2      sub      r0, fp, #0x114                              
  0000c050  24411be5      ldr      r4, [fp, #-0x124]                           
  0000c054  0010a0e3      mov      r1, #0                                      
  0000c058  012ca0e3      mov      r2, #0x100                                  
  0000c05c  05508fe0      add      r5, pc, r5                                  
  0000c060  fbf8ffeb      bl       #0xa454                                     
  0000c064  010054e3      cmp      r4, #1                                      
  0000c068  0000a0e3      mov      r0, #0                                      
  0000c06c  2000000a      beq      #0xc0f4                                     
  0000c070  0010a0e1      mov      r1, r0                                      
  0000c074  0020a0e1      mov      r2, r0                                      
  0000c078  fcfdffeb      bl       #0xb870                                     
  0000c07c  e8309fe5      ldr      r3, [pc, #0xe8]                             
  0000c080  e8c09fe5      ldr      ip, [pc, #0xe8]                             
  0000c084  011ca0e3      mov      r1, #0x100                                  
  0000c088  ff20a0e3      mov      r2, #0xff                                   
  0000c08c  03308fe0      add      r3, pc, r3                                  
  0000c090  0cc08fe0      add      ip, pc, ip                                  
  0000c094  450f4be2      sub      r0, fp, #0x114                              
  0000c098  00c08de5      str      ip, [sp]                                    
  0000c09c  54faffeb      bl       #0xa9f4                                     
  0000c0a0  cc109fe5      ldr      r1, [pc, #0xcc]                             
  0000c0a4  cc309fe5      ldr      r3, [pc, #0xcc]                             
  0000c0a8  45cf4be2      sub      ip, fp, #0x114                              
  0000c0ac  01108fe0      add      r1, pc, r1                                  
  0000c0b0  1600a0e3      mov      r0, #0x16                                   
  0000c0b4  a22100e3      movw     r2, #0x1a2                                  
  0000c0b8  03308fe0      add      r3, pc, r3                                  
  0000c0bc  00c08de5      str      ip, [sp]                                    
  0000c0c0  f4f9ffeb      bl       #0xa898                                     
  0000c0c4  010500e3      movw     r0, #0x501                                  
  0000c0c8  500040e3      movt     r0, #0x50                                   
  0000c0cc  c2f8ffeb      bl       #0xa3dc                                     
  0000c0d0  0010a0e1      mov      r1, r0                                      
  0000c0d4  010500e3      movw     r0, #0x501                                  
  0000c0d8  500040e3      movt     r0, #0x50                                   
  0000c0dc  fff9ffeb      bl       #0xa8e0                                     
  0000c0e0  94309fe5      ldr      r3, [pc, #0x94]                             
  0000c0e4  033095e7      ldr      r3, [r5, r3]                                
  0000c0e8  e04083e5      str      r4, [r3, #0xe0]                             
  0000c0ec  14d04be2      sub      sp, fp, #0x14                               
  0000c0f0  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000c0f4  0020e0e3      mvn      r2, #0                                      
  0000c0f8  0010a0e1      mov      r1, r0                                      
  0000c0fc  dbfdffeb      bl       #0xb870                                     
  0000c100  78309fe5      ldr      r3, [pc, #0x78]                             
  0000c104  78c09fe5      ldr      ip, [pc, #0x78]                             
  0000c108  450f4be2      sub      r0, fp, #0x114                              
  0000c10c  011ca0e3      mov      r1, #0x100                                  
  0000c110  ff20a0e3      mov      r2, #0xff                                   
  0000c114  0cc08fe0      add      ip, pc, ip                                  
  0000c118  03308fe0      add      r3, pc, r3                                  
  0000c11c  00c08de5      str      ip, [sp]                                    
  0000c120  33faffeb      bl       #0xa9f4                                     
  0000c124  5c109fe5      ldr      r1, [pc, #0x5c]                             
  0000c128  5c309fe5      ldr      r3, [pc, #0x5c]                             
  0000c12c  662fa0e3      mov      r2, #0x198                                  
  0000c130  01108fe0      add      r1, pc, r1                                  
  0000c134  450f4be2      sub      r0, fp, #0x114                              
  0000c138  03308fe0      add      r3, pc, r3                                  
  0000c13c  00008de5      str      r0, [sp]                                    
  0000c140  1600a0e3      mov      r0, #0x16                                   
  0000c144  d3f9ffeb      bl       #0xa898                                     
  0000c148  050ca0e3      mov      r0, #0x500                                  
  0000c14c  500040e3      movt     r0, #0x50                                   
  0000c150  a1f8ffeb      bl       #0xa3dc                                     
  0000c154  0010a0e1      mov      r1, r0                                      
  0000c158  050ca0e3      mov      r0, #0x500                                  
  0000c15c  500040e3      movt     r0, #0x50                                   
  0000c160  def9ffeb      bl       #0xa8e0                                     
  0000c164  ddffffea      b        #0xc0e0                                     
  0000c168  9c2f0300      muleq    r3, ip, pc                                  
  0000c16c  14540200      andeq    r5, r2, r4, lsl r4                          
  0000c170  003f0200      andeq    r3, r2, r0, lsl #30                         
  0000c174  183e0200      andeq    r3, r2, r8, lsl lr                          
  0000c178  bc3e0200      strheq   r3, [r2], -ip                               
  0000c17c  b8080000      strheq   r0, [r0], -r8                               
  0000c180  88530200      andeq    r5, r2, r8, lsl #7                          
  0000c184  2c3e0200      andeq    r3, r2, ip, lsr #28                         
  0000c188  943d0200      muleq    r2, r4, sp                                  
  0000c18c  3c3e0200      andeq    r3, r2, ip, lsr lr                          

; ─── HW_DM_ProcBatter_WhenBatteryMiss @ 0xc190 ───
  0000c190  0dc0a0e1      mov      ip, sp                                      
  0000c194  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000c198  04b04ce2      sub      fp, ip, #4                                  
  0000c19c  46df4de2      sub      sp, sp, #0x118                              
  0000c1a0  4dcf4be2      sub      ip, fp, #0x134                              
  0000c1a4  494f4be2      sub      r4, fp, #0x124                              
  0000c1a8  0f008ce8      stm      ip, {r0, r1, r2, r3}                        
  0000c1ac  0400a0e1      mov      r0, r4                                      
  0000c1b0  30511be5      ldr      r5, [fp, #-0x130]                           
  0000c1b4  0010a0e3      mov      r1, #0                                      
  0000c1b8  012ca0e3      mov      r2, #0x100                                  
  0000c1bc  04709be5      ldr      r7, [fp, #4]                                
  0000c1c0  2c811be5      ldr      r8, [fp, #-0x12c]                           
  0000c1c4  28a11be5      ldr      sl, [fp, #-0x128]                           
  0000c1c8  a1f8ffeb      bl       #0xa454                                     
  0000c1cc  54619fe5      ldr      r6, [pc, #0x154]                            
  0000c1d0  010055e3      cmp      r5, #1                                      
  0000c1d4  06608fe0      add      r6, pc, r6                                  
  0000c1d8  2200000a      beq      #0xc268                                     
  0000c1dc  010057e3      cmp      r7, #1                                      
  0000c1e0  4200000a      beq      #0xc2f0                                     
  0000c1e4  40319fe5      ldr      r3, [pc, #0x140]                            
  0000c1e8  011ca0e3      mov      r1, #0x100                                  
  0000c1ec  3cc19fe5      ldr      ip, [pc, #0x13c]                            
  0000c1f0  ff20a0e3      mov      r2, #0xff                                   
  0000c1f4  03308fe0      add      r3, pc, r3                                  
  0000c1f8  0400a0e1      mov      r0, r4                                      
  0000c1fc  0cc08fe0      add      ip, pc, ip                                  
  0000c200  00c08de5      str      ip, [sp]                                    
  0000c204  faf9ffeb      bl       #0xa9f4                                     
  0000c208  24119fe5      ldr      r1, [pc, #0x124]                            
  0000c20c  24319fe5      ldr      r3, [pc, #0x124]                            
  0000c210  e52100e3      movw     r2, #0x1e5                                  
  0000c214  01108fe0      add      r1, pc, r1                                  
  0000c218  1600a0e3      mov      r0, #0x16                                   
  0000c21c  03308fe0      add      r3, pc, r3                                  
  0000c220  00408de5      str      r4, [sp]                                    
  0000c224  9bf9ffeb      bl       #0xa898                                     
  0000c228  070500e3      movw     r0, #0x507                                  
  0000c22c  500040e3      movt     r0, #0x50                                   
  0000c230  69f8ffeb      bl       #0xa3dc                                     
  0000c234  0010a0e1      mov      r1, r0                                      
  0000c238  070500e3      movw     r0, #0x507                                  
  0000c23c  500040e3      movt     r0, #0x50                                   
  0000c240  a6f9ffeb      bl       #0xa8e0                                     
  0000c244  f0309fe5      ldr      r3, [pc, #0xf0]                             
  0000c248  0120a0e3      mov      r2, #1                                      
  0000c24c  03308fe0      add      r3, pc, r3                                  
  0000c250  002083e5      str      r2, [r3]                                    
  0000c254  e4309fe5      ldr      r3, [pc, #0xe4]                             
  0000c258  033096e7      ldr      r3, [r6, r3]                                
  0000c25c  e45083e5      str      r5, [r3, #0xe4]                             
  0000c260  24d04be2      sub      sp, fp, #0x24                               
  0000c264  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000c268  010057e3      cmp      r7, #1                                      
  0000c26c  2800000a      beq      #0xc314                                     
  0000c270  cc309fe5      ldr      r3, [pc, #0xcc]                             
  0000c274  011ca0e3      mov      r1, #0x100                                  
  0000c278  c8c09fe5      ldr      ip, [pc, #0xc8]                             
  0000c27c  ff20a0e3      mov      r2, #0xff                                   
  0000c280  03308fe0      add      r3, pc, r3                                  
  0000c284  c0709fe5      ldr      r7, [pc, #0xc0]                             
  0000c288  0cc08fe0      add      ip, pc, ip                                  
  0000c28c  0400a0e1      mov      r0, r4                                      
  0000c290  00c08de5      str      ip, [sp]                                    
  0000c294  07708fe0      add      r7, pc, r7                                  
  0000c298  d5f9ffeb      bl       #0xa9f4                                     
  0000c29c  ac109fe5      ldr      r1, [pc, #0xac]                             
  0000c2a0  ac309fe5      ldr      r3, [pc, #0xac]                             
  0000c2a4  1600a0e3      mov      r0, #0x16                                   
  0000c2a8  00408de5      str      r4, [sp]                                    
  0000c2ac  01108fe0      add      r1, pc, r1                                  
  0000c2b0  03308fe0      add      r3, pc, r3                                  
  0000c2b4  ce2100e3      movw     r2, #0x1ce                                  
  0000c2b8  76f9ffeb      bl       #0xa898                                     
  0000c2bc  003097e5      ldr      r3, [r7]                                    
  0000c2c0  010053e3      cmp      r3, #1                                      
  0000c2c4  e2ffff1a      bne      #0xc254                                     
  0000c2c8  060500e3      movw     r0, #0x506                                  
  0000c2cc  500040e3      movt     r0, #0x50                                   
  0000c2d0  41f8ffeb      bl       #0xa3dc                                     
  0000c2d4  0010a0e1      mov      r1, r0                                      
  0000c2d8  060500e3      movw     r0, #0x506                                  
  0000c2dc  500040e3      movt     r0, #0x50                                   
  0000c2e0  7ef9ffeb      bl       #0xa8e0                                     
  0000c2e4  0030a0e3      mov      r3, #0                                      
  0000c2e8  003087e5      str      r3, [r7]                                    
  0000c2ec  d8ffffea      b        #0xc254                                     
  0000c2f0  000058e3      cmp      r8, #0                                      
  0000c2f4  baffff1a      bne      #0xc1e4                                     
  0000c2f8  00005ae3      cmp      sl, #0                                      
  0000c2fc  b8ffff1a      bne      #0xc1e4                                     
  0000c300  0710a0e1      mov      r1, r7                                      
  0000c304  0020e0e3      mvn      r2, #0                                      
  0000c308  0d00a0e3      mov      r0, #0xd                                    
  0000c30c  57fdffeb      bl       #0xb870                                     
  0000c310  b3ffffea      b        #0xc1e4                                     
  0000c314  0510a0e1      mov      r1, r5                                      
  0000c318  0020a0e3      mov      r2, #0                                      
  0000c31c  0d00a0e3      mov      r0, #0xd                                    
  0000c320  52fdffeb      bl       #0xb870                                     
  0000c324  d1ffffea      b        #0xc270                                     
  0000c328  242e0300      andeq    r2, r3, r4, lsr #28                         
  0000c32c  ac520200      andeq    r5, r2, ip, lsr #5                          
  0000c330  f43d0200      strdeq   r3, r4, [r2], -r4                           
  0000c334  b03c0200      strheq   r3, [r2], -r0                               
  0000c338  583d0200      andeq    r3, r2, r8, asr sp                          
  0000c33c  c83b0300      andeq    r3, r3, r8, asr #23                         
  0000c340  b8080000      strheq   r0, [r0], -r8                               
  0000c344  20520200      andeq    r5, r2, r0, lsr #4                          
  0000c348  3c3d0200      andeq    r3, r2, ip, lsr sp                          
  0000c34c  803b0300      andeq    r3, r3, r0, lsl #23                         
  0000c350  183c0200      andeq    r3, r2, r8, lsl ip                          
  0000c354  c43c0200      andeq    r3, r2, r4, asr #25                         

; ─── HW_DM_ProcBatter_WhenBatteryFail @ 0xc358 ───
  0000c358  0dc0a0e1      mov      ip, sp                                      
  0000c35c  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000c360  04b04ce2      sub      fp, ip, #4                                  
  0000c364  46df4de2      sub      sp, sp, #0x118                              
  0000c368  4dcf4be2      sub      ip, fp, #0x134                              
  0000c36c  494f4be2      sub      r4, fp, #0x124                              
  0000c370  0f008ce8      stm      ip, {r0, r1, r2, r3}                        
  0000c374  0400a0e1      mov      r0, r4                                      
  0000c378  2c511be5      ldr      r5, [fp, #-0x12c]                           
  0000c37c  0010a0e3      mov      r1, #0                                      
  0000c380  012ca0e3      mov      r2, #0x100                                  
  0000c384  04709be5      ldr      r7, [fp, #4]                                
  0000c388  30a11be5      ldr      sl, [fp, #-0x130]                           
  0000c38c  28811be5      ldr      r8, [fp, #-0x128]                           
  0000c390  2ff8ffeb      bl       #0xa454                                     
  0000c394  28619fe5      ldr      r6, [pc, #0x128]                              ; r6='eratureConfig.xml /var/HighTmperatureConfig.xml.bak'
  0000c398  010055e3      cmp      r5, #1                                      
  0000c39c  06608fe0      add      r6, pc, r6                                  
  0000c3a0  1e00000a      beq      #0xc420                                     
  0000c3a4  010057e3      cmp      r7, #1                                      
  0000c3a8  3700000a      beq      #0xc48c                                     
  0000c3ac  14319fe5      ldr      r3, [pc, #0x114]                            
  0000c3b0  011ca0e3      mov      r1, #0x100                                  
  0000c3b4  10c19fe5      ldr      ip, [pc, #0x110]                            
  0000c3b8  ff20a0e3      mov      r2, #0xff                                   
  0000c3bc  03308fe0      add      r3, pc, r3                                  
  0000c3c0  0400a0e1      mov      r0, r4                                      
  0000c3c4  0cc08fe0      add      ip, pc, ip                                  
  0000c3c8  00c08de5      str      ip, [sp]                                    
  0000c3cc  88f9ffeb      bl       #0xa9f4                                     
  0000c3d0  f8109fe5      ldr      r1, [pc, #0xf8]                             
  0000c3d4  f8309fe5      ldr      r3, [pc, #0xf8]                             
  0000c3d8  1600a0e3      mov      r0, #0x16                                   
  0000c3dc  01108fe0      add      r1, pc, r1                                  
  0000c3e0  212200e3      movw     r2, #0x221                                  
  0000c3e4  03308fe0      add      r3, pc, r3                                  
  0000c3e8  00408de5      str      r4, [sp]                                    
  0000c3ec  29f9ffeb      bl       #0xa898                                     
  0000c3f0  050500e3      movw     r0, #0x505                                  
  0000c3f4  500040e3      movt     r0, #0x50                                   
  0000c3f8  f7f7ffeb      bl       #0xa3dc                                     
  0000c3fc  0010a0e1      mov      r1, r0                                      
  0000c400  050500e3      movw     r0, #0x505                                  
  0000c404  500040e3      movt     r0, #0x50                                   
  0000c408  34f9ffeb      bl       #0xa8e0                                     
  0000c40c  c4309fe5      ldr      r3, [pc, #0xc4]                             
  0000c410  033096e7      ldr      r3, [r6, r3]                                
  0000c414  e85083e5      str      r5, [r3, #0xe8]                             
  0000c418  24d04be2      sub      sp, fp, #0x24                               
  0000c41c  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000c420  010057e3      cmp      r7, #1                                      
  0000c424  2100000a      beq      #0xc4b0                                     
  0000c428  ac309fe5      ldr      r3, [pc, #0xac]                             
  0000c42c  0400a0e1      mov      r0, r4                                      
  0000c430  a8c09fe5      ldr      ip, [pc, #0xa8]                             
  0000c434  011ca0e3      mov      r1, #0x100                                  
  0000c438  ff20a0e3      mov      r2, #0xff                                   
  0000c43c  03308fe0      add      r3, pc, r3                                  
  0000c440  0cc08fe0      add      ip, pc, ip                                  
  0000c444  00c08de5      str      ip, [sp]                                    
  0000c448  69f9ffeb      bl       #0xa9f4                                     
  0000c44c  90109fe5      ldr      r1, [pc, #0x90]                             
  0000c450  90309fe5      ldr      r3, [pc, #0x90]                             
  0000c454  212ea0e3      mov      r2, #0x210                                  
  0000c458  01108fe0      add      r1, pc, r1                                  
  0000c45c  00408de5      str      r4, [sp]                                    
  0000c460  03308fe0      add      r3, pc, r3                                  
  0000c464  1600a0e3      mov      r0, #0x16                                   
  0000c468  0af9ffeb      bl       #0xa898                                     
  0000c46c  040500e3      movw     r0, #0x504                                  
  0000c470  500040e3      movt     r0, #0x50                                   
  0000c474  d8f7ffeb      bl       #0xa3dc                                     
  0000c478  0010a0e1      mov      r1, r0                                      
  0000c47c  040500e3      movw     r0, #0x504                                  
  0000c480  500040e3      movt     r0, #0x50                                   
  0000c484  15f9ffeb      bl       #0xa8e0                                     
  0000c488  dfffffea      b        #0xc40c                                     
  0000c48c  000058e3      cmp      r8, #0                                      
  0000c490  c5ffff1a      bne      #0xc3ac                                     
  0000c494  00005ae3      cmp      sl, #0                                      
  0000c498  c3ffff1a      bne      #0xc3ac                                     
  0000c49c  0710a0e1      mov      r1, r7                                      
  0000c4a0  0020e0e3      mvn      r2, #0                                      
  0000c4a4  0d00a0e3      mov      r0, #0xd                                    
  0000c4a8  f0fcffeb      bl       #0xb870                                     
  0000c4ac  beffffea      b        #0xc3ac                                     
  0000c4b0  0510a0e1      mov      r1, r5                                      
  0000c4b4  0020a0e3      mov      r2, #0                                      
  0000c4b8  0d00a0e3      mov      r0, #0xd                                    
  0000c4bc  ebfcffeb      bl       #0xb870                                     
  0000c4c0  d8ffffea      b        #0xc428                                     
  0000c4c4  5c2c0300      andeq    r2, r3, ip, asr ip                          
  0000c4c8  e4500200      andeq    r5, r2, r4, ror #1                          
  0000c4cc  8c3c0200      andeq    r3, r2, ip, lsl #25                         
  0000c4d0  e83a0200      andeq    r3, r2, r8, ror #21                         
  0000c4d4  903b0200      muleq    r2, r0, fp                                  
  0000c4d8  b8080000      strheq   r0, [r0], -r8                               
  0000c4dc  64500200      andeq    r5, r2, r4, rrx                             
  0000c4e0  e03b0200      andeq    r3, r2, r0, ror #23                         
  0000c4e4  6c3a0200      andeq    r3, r2, ip, ror #20                         
  0000c4e8  143b0200      andeq    r3, r2, r4, lsl fp                          

; ─── HW_DM_ProcBatter_WhenBatteryLow @ 0xc4ec ───
  0000c4ec  0dc0a0e1      mov      ip, sp                                      
  0000c4f0  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000c4f4  04b04ce2      sub      fp, ip, #4                                  
  0000c4f8  46df4de2      sub      sp, sp, #0x118                              
  0000c4fc  4dcf4be2      sub      ip, fp, #0x134                              
  0000c500  494f4be2      sub      r4, fp, #0x124                              
  0000c504  0f008ce8      stm      ip, {r0, r1, r2, r3}                        
  0000c508  0400a0e1      mov      r0, r4                                      
  0000c50c  28511be5      ldr      r5, [fp, #-0x128]                           
  0000c510  0010a0e3      mov      r1, #0                                      
  0000c514  012ca0e3      mov      r2, #0x100                                  
  0000c518  04709be5      ldr      r7, [fp, #4]                                
  0000c51c  30a11be5      ldr      sl, [fp, #-0x130]                           
  0000c520  2c811be5      ldr      r8, [fp, #-0x12c]                           
  0000c524  caf7ffeb      bl       #0xa454                                     
  0000c528  28619fe5      ldr      r6, [pc, #0x128]                            
  0000c52c  010055e3      cmp      r5, #1                                      
  0000c530  06608fe0      add      r6, pc, r6                                  
  0000c534  1e00000a      beq      #0xc5b4                                     
  0000c538  010057e3      cmp      r7, #1                                      
  0000c53c  3700000a      beq      #0xc620                                     
  0000c540  14319fe5      ldr      r3, [pc, #0x114]                            
  0000c544  011ca0e3      mov      r1, #0x100                                  
  0000c548  10c19fe5      ldr      ip, [pc, #0x110]                            
  0000c54c  ff20a0e3      mov      r2, #0xff                                   
  0000c550  03308fe0      add      r3, pc, r3                                  
  0000c554  0400a0e1      mov      r0, r4                                      
  0000c558  0cc08fe0      add      ip, pc, ip                                  
  0000c55c  00c08de5      str      ip, [sp]                                    
  0000c560  23f9ffeb      bl       #0xa9f4                                     
  0000c564  f8109fe5      ldr      r1, [pc, #0xf8]                             
  0000c568  f8309fe5      ldr      r3, [pc, #0xf8]                             
  0000c56c  1600a0e3      mov      r0, #0x16                                   
  0000c570  01108fe0      add      r1, pc, r1                                  
  0000c574  5b2200e3      movw     r2, #0x25b                                  
  0000c578  03308fe0      add      r3, pc, r3                                  
  0000c57c  00408de5      str      r4, [sp]                                    
  0000c580  c4f8ffeb      bl       #0xa898                                     
  0000c584  030500e3      movw     r0, #0x503                                  
  0000c588  500040e3      movt     r0, #0x50                                   
  0000c58c  92f7ffeb      bl       #0xa3dc                                     
  0000c590  0010a0e1      mov      r1, r0                                      
  0000c594  030500e3      movw     r0, #0x503                                  
  0000c598  500040e3      movt     r0, #0x50                                   
  0000c59c  cff8ffeb      bl       #0xa8e0                                     
  0000c5a0  c4309fe5      ldr      r3, [pc, #0xc4]                             
  0000c5a4  033096e7      ldr      r3, [r6, r3]                                
  0000c5a8  ec5083e5      str      r5, [r3, #0xec]                             
  0000c5ac  24d04be2      sub      sp, fp, #0x24                               
  0000c5b0  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000c5b4  010057e3      cmp      r7, #1                                      
  0000c5b8  2100000a      beq      #0xc644                                     
  0000c5bc  ac309fe5      ldr      r3, [pc, #0xac]                             
  0000c5c0  0400a0e1      mov      r0, r4                                      
  0000c5c4  a8c09fe5      ldr      ip, [pc, #0xa8]                             
  0000c5c8  011ca0e3      mov      r1, #0x100                                  
  0000c5cc  ff20a0e3      mov      r2, #0xff                                   
  0000c5d0  03308fe0      add      r3, pc, r3                                  
  0000c5d4  0cc08fe0      add      ip, pc, ip                                  
  0000c5d8  00c08de5      str      ip, [sp]                                    
  0000c5dc  04f9ffeb      bl       #0xa9f4                                     
  0000c5e0  90109fe5      ldr      r1, [pc, #0x90]                             
  0000c5e4  90309fe5      ldr      r3, [pc, #0x90]                             
  0000c5e8  4a2200e3      movw     r2, #0x24a                                  
  0000c5ec  01108fe0      add      r1, pc, r1                                  
  0000c5f0  00408de5      str      r4, [sp]                                    
  0000c5f4  03308fe0      add      r3, pc, r3                                  
  0000c5f8  1600a0e3      mov      r0, #0x16                                   
  0000c5fc  a5f8ffeb      bl       #0xa898                                     
  0000c600  020500e3      movw     r0, #0x502                                  
  0000c604  500040e3      movt     r0, #0x50                                   
  0000c608  73f7ffeb      bl       #0xa3dc                                     
  0000c60c  0010a0e1      mov      r1, r0                                      
  0000c610  020500e3      movw     r0, #0x502                                  
  0000c614  500040e3      movt     r0, #0x50                                   
  0000c618  b0f8ffeb      bl       #0xa8e0                                     
  0000c61c  dfffffea      b        #0xc5a0                                     
  0000c620  000058e3      cmp      r8, #0                                      
  0000c624  c5ffff1a      bne      #0xc540                                     
  0000c628  00005ae3      cmp      sl, #0                                      
  0000c62c  c3ffff1a      bne      #0xc540                                     
  0000c630  0710a0e1      mov      r1, r7                                      
  0000c634  0020e0e3      mvn      r2, #0                                      
  0000c638  0d00a0e3      mov      r0, #0xd                                    
  0000c63c  8bfcffeb      bl       #0xb870                                     
  0000c640  beffffea      b        #0xc540                                     
  0000c644  0510a0e1      mov      r1, r5                                      
  0000c648  0020a0e3      mov      r2, #0                                      
  0000c64c  0d00a0e3      mov      r0, #0xd                                    
  0000c650  86fcffeb      bl       #0xb870                                     
  0000c654  d8ffffea      b        #0xc5bc                                     
  0000c658  c82a0300      andeq    r2, r3, r8, asr #21                         
  0000c65c  504f0200      andeq    r4, r2, r0, asr pc                          
  0000c660  543b0200      andeq    r3, r2, r4, asr fp                          
  0000c664  54390200      andeq    r3, r2, r4, asr sb                          
  0000c668  fc390200      strdeq   r3, r4, [r2], -ip                           
  0000c66c  b8080000      strheq   r0, [r0], -r8                               
  0000c670  d04e0200      ldrdeq   r4, r5, [r2], -r0                           
  0000c674  ac3a0200      andeq    r3, r2, ip, lsr #21                         
  0000c678  d8380200      ldrdeq   r3, r4, [r2], -r8                           
  0000c67c  80390200      andeq    r3, r2, r0, lsl #19                         

; ─── HW_DM_IsStauesChang @ 0xc680 ───
  0000c680  04402de5      str      r4, [sp, #-4]!                              
  0000c684  14d04de2      sub      sp, sp, #0x14                               
  0000c688  10408de2      add      r4, sp, #0x10                               
  0000c68c  60c09fe5      ldr      ip, [pc, #0x60]                               ; ip='ST_PATH'
  0000c690  0f0004e9      stmdb    r4, {r0, r1, r2, r3}                        
  0000c694  0cc08fe0      add      ip, pc, ip                                  
  0000c698  58309fe5      ldr      r3, [pc, #0x58]                             
  0000c69c  00209de5      ldr      r2, [sp]                                    
  0000c6a0  04009de5      ldr      r0, [sp, #4]                                
  0000c6a4  03309ce7      ldr      r3, [ip, r3]                                
  0000c6a8  08c09de5      ldr      ip, [sp, #8]                                
  0000c6ac  e01093e5      ldr      r1, [r3, #0xe0]                             
  0000c6b0  020051e1      cmp      r1, r2                                      
  0000c6b4  0c209de5      ldr      r2, [sp, #0xc]                              
  0000c6b8  0300000a      beq      #0xc6cc                                     
  0000c6bc  0100a0e3      mov      r0, #1                                      
  0000c6c0  14d08de2      add      sp, sp, #0x14                               
  0000c6c4  1000bde8      ldm      sp!, {r4}                                   
  0000c6c8  1eff2fe1      bx       lr                                          
  0000c6cc  ec1093e5      ldr      r1, [r3, #0xec]                             
  0000c6d0  020051e1      cmp      r1, r2                                      
  0000c6d4  f8ffff1a      bne      #0xc6bc                                     
  0000c6d8  e82093e5      ldr      r2, [r3, #0xe8]                             
  0000c6dc  0c0052e1      cmp      r2, ip                                      
  0000c6e0  f5ffff1a      bne      #0xc6bc                                     
  0000c6e4  e43093e5      ldr      r3, [r3, #0xe4]                             
  0000c6e8  000053e0      subs     r0, r3, r0                                  
  0000c6ec  0100a013      movne    r0, #1                                      
  0000c6f0  f2ffffea      b        #0xc6c0                                     
  0000c6f4  64290300      andeq    r2, r3, r4, ror #18                         
  0000c6f8  b8080000      strheq   r0, [r0], -r8                               

; ─── HW_DM_ProcBatteryNetlinkMsg @ 0xc6fc ───
  0000c6fc  0dc0a0e1      mov      ip, sp                                      
  0000c700  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000c704  04b04ce2      sub      fp, ip, #4                                  
  0000c708  2c504be2      sub      r5, fp, #0x2c                               
  0000c70c  28d04de2      sub      sp, sp, #0x28                               
  0000c710  0040a0e3      mov      r4, #0                                      
  0000c714  0500a0e1      mov      r0, r5                                      
  0000c718  2c400be5      str      r4, [fp, #-0x2c]                            
  0000c71c  28400be5      str      r4, [fp, #-0x28]                            
  0000c720  24400be5      str      r4, [fp, #-0x24]                            
  0000c724  20400be5      str      r4, [fp, #-0x20]                            
  0000c728  30400be5      str      r4, [fp, #-0x30]                            
  0000c72c  07f9ffeb      bl       #0xab50                                     
  0000c730  d0719fe5      ldr      r7, [pc, #0x1d0]                              ; r7='URL2'
  0000c734  07708fe0      add      r7, pc, r7                                  
  0000c738  006050e2      subs     r6, r0, #0                                  
  0000c73c  3e00001a      bne      #0xc83c                                     
  0000c740  3000a0e3      mov      r0, #0x30                                   
  0000c744  0410a0e3      mov      r1, #4                                      
  0000c748  000041e3      movt     r0, #0x1000                                 
  0000c74c  34204be2      sub      r2, fp, #0x34                               
  0000c750  fdf6ffeb      bl       #0xa34c                                     
  0000c754  006050e2      subs     r6, r0, #0                                  
  0000c758  2a00001a      bne      #0xc808                                     
  0000c75c  0f0095e8      ldm      r5, {r0, r1, r2, r3}                        
  0000c760  46f8ffeb      bl       #0xa880                                     
  0000c764  2c301be5      ldr      r3, [fp, #-0x2c]                            
  0000c768  010050e3      cmp      r0, #1                                      
  0000c76c  3c00000a      beq      #0xc864                                     
  0000c770  94219fe5      ldr      r2, [pc, #0x194]                            
  0000c774  024097e7      ldr      r4, [r7, r2]                                
  0000c778  e02094e5      ldr      r2, [r4, #0xe0]                             
  0000c77c  030052e1      cmp      r2, r3                                      
  0000c780  0100000a      beq      #0xc78c                                     
  0000c784  0f0095e8      ldm      r5, {r0, r1, r2, r3}                        
  0000c788  eefaffeb      bl       #0xb348                                     
  0000c78c  1500a0e3      mov      r0, #0x15                                   
  0000c790  0410a0e3      mov      r1, #4                                      
  0000c794  30204be2      sub      r2, fp, #0x30                               
  0000c798  ebf6ffeb      bl       #0xa34c                                     
  0000c79c  006050e2      subs     r6, r0, #0                                  
  0000c7a0  4d00001a      bne      #0xc8dc                                     
  0000c7a4  ec3094e5      ldr      r3, [r4, #0xec]                             
  0000c7a8  20201be5      ldr      r2, [fp, #-0x20]                            
  0000c7ac  030052e1      cmp      r2, r3                                      
  0000c7b0  0300000a      beq      #0xc7c4                                     
  0000c7b4  30c01be5      ldr      ip, [fp, #-0x30]                            
  0000c7b8  0f0095e8      ldm      r5, {r0, r1, r2, r3}                        
  0000c7bc  00c08de5      str      ip, [sp]                                    
  0000c7c0  63f9ffeb      bl       #0xad54                                     
  0000c7c4  e83094e5      ldr      r3, [r4, #0xe8]                             
  0000c7c8  24201be5      ldr      r2, [fp, #-0x24]                            
  0000c7cc  030052e1      cmp      r2, r3                                      
  0000c7d0  0300000a      beq      #0xc7e4                                     
  0000c7d4  30c01be5      ldr      ip, [fp, #-0x30]                            
  0000c7d8  0f0095e8      ldm      r5, {r0, r1, r2, r3}                        
  0000c7dc  00c08de5      str      ip, [sp]                                    
  0000c7e0  ecf8ffeb      bl       #0xab98                                     
  0000c7e4  e43094e5      ldr      r3, [r4, #0xe4]                             
  0000c7e8  28201be5      ldr      r2, [fp, #-0x28]                            
  0000c7ec  030052e1      cmp      r2, r3                                      
  0000c7f0  0e00000a      beq      #0xc830                                     
  0000c7f4  30c01be5      ldr      ip, [fp, #-0x30]                            
  0000c7f8  0f0095e8      ldm      r5, {r0, r1, r2, r3}                        
  0000c7fc  00c08de5      str      ip, [sp]                                    
  0000c800  c6fbffeb      bl       #0xb720                                     
  0000c804  090000ea      b        #0xc830                                     
  0000c808  00019fe5      ldr      r0, [pc, #0x100]                            
  0000c80c  3030a0e3      mov      r3, #0x30                                   
  0000c810  00408de5      str      r4, [sp]                                    
  0000c814  a71200e3      movw     r1, #0x2a7                                  
  0000c818  04408de5      str      r4, [sp, #4]                                
  0000c81c  0620a0e1      mov      r2, r6                                      
  0000c820  08408de5      str      r4, [sp, #8]                                
  0000c824  00008fe0      add      r0, pc, r0                                  
  0000c828  003041e3      movt     r3, #0x1000                                 
  0000c82c  8cf7ffeb      bl       #0xa664                                     
  0000c830  0600a0e1      mov      r0, r6                                      
  0000c834  1cd04be2      sub      sp, fp, #0x1c                               
  0000c838  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000c83c  d0009fe5      ldr      r0, [pc, #0xd0]                             
  0000c840  9f1200e3      movw     r1, #0x29f                                  
  0000c844  00408de5      str      r4, [sp]                                    
  0000c848  0620a0e1      mov      r2, r6                                      
  0000c84c  04408de5      str      r4, [sp, #4]                                
  0000c850  0430a0e1      mov      r3, r4                                      
  0000c854  08408de5      str      r4, [sp, #8]                                
  0000c858  00008fe0      add      r0, pc, r0                                  
  0000c85c  80f7ffeb      bl       #0xa664                                     
  0000c860  f2ffffea      b        #0xc830                                     
  0000c864  010053e3      cmp      r3, #1                                      
  0000c868  c0ffff1a      bne      #0xc770                                     
  0000c86c  20201be5      ldr      r2, [fp, #-0x20]                            
  0000c870  010052e3      cmp      r2, #1                                      
  0000c874  bdffff1a      bne      #0xc770                                     
  0000c878  24201be5      ldr      r2, [fp, #-0x24]                            
  0000c87c  010052e3      cmp      r2, #1                                      
  0000c880  baffff1a      bne      #0xc770                                     
  0000c884  28401be5      ldr      r4, [fp, #-0x28]                            
  0000c888  010054e3      cmp      r4, #1                                      
  0000c88c  b7ffff1a      bne      #0xc770                                     
  0000c890  0610a0e1      mov      r1, r6                                      
  0000c894  0620a0e1      mov      r2, r6                                      
  0000c898  0600a0e1      mov      r0, r6                                      
  0000c89c  f3fbffeb      bl       #0xb870                                     
  0000c8a0  0620a0e1      mov      r2, r6                                      
  0000c8a4  0d00a0e3      mov      r0, #0xd                                    
  0000c8a8  0410a0e1      mov      r1, r4                                      
  0000c8ac  effbffeb      bl       #0xb870                                     
  0000c8b0  54309fe5      ldr      r3, [pc, #0x54]                             
  0000c8b4  2c201be5      ldr      r2, [fp, #-0x2c]                            
  0000c8b8  033097e7      ldr      r3, [r7, r3]                                
  0000c8bc  ec2083e5      str      r2, [r3, #0xec]                             
  0000c8c0  20201be5      ldr      r2, [fp, #-0x20]                            
  0000c8c4  e02083e5      str      r2, [r3, #0xe0]                             
  0000c8c8  24201be5      ldr      r2, [fp, #-0x24]                            
  0000c8cc  e82083e5      str      r2, [r3, #0xe8]                             
  0000c8d0  28201be5      ldr      r2, [fp, #-0x28]                            
  0000c8d4  e42083e5      str      r2, [r3, #0xe4]                             
  0000c8d8  d4ffffea      b        #0xc830                                     
  0000c8dc  34009fe5      ldr      r0, [pc, #0x34]                             
  0000c8e0  0030a0e3      mov      r3, #0                                      
  0000c8e4  c71200e3      movw     r1, #0x2c7                                  
  0000c8e8  00308de5      str      r3, [sp]                                    
  0000c8ec  04308de5      str      r3, [sp, #4]                                
  0000c8f0  00008fe0      add      r0, pc, r0                                  
  0000c8f4  08308de5      str      r3, [sp, #8]                                
  0000c8f8  0620a0e1      mov      r2, r6                                      
  0000c8fc  1530a0e3      mov      r3, #0x15                                   
  0000c900  57f7ffeb      bl       #0xa664                                     
  0000c904  c9ffffea      b        #0xc830                                     
  0000c908  c4280300      andeq    r2, r3, r4, asr #17                         
  0000c90c  b8080000      strheq   r0, [r0], -r8                               
  0000c910  a0360200      andeq    r3, r2, r0, lsr #13                         
  0000c914  6c360200      andeq    r3, r2, ip, ror #12                         
  0000c918  d4350200      ldrdeq   r3, r4, [r2], -r4                           
  0000c91c  0dc0a0e1      mov      ip, sp                                      
  0000c920  0d00a0e3      mov      r0, #0xd                                    
  0000c924  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000c928  04b04ce2      sub      fp, ip, #4                                  
  0000c92c  8adf4de2      sub      sp, sp, #0x228                              
  0000c930  a4409fe5      ldr      r4, [pc, #0xa4]                               ; r4='10G EPON'
  0000c934  a4709fe5      ldr      r7, [pc, #0xa4]                             
  0000c938  0110a0e3      mov      r1, #1                                      
  0000c93c  0020e0e3      mvn      r2, #0                                      
  0000c940  0050a0e3      mov      r5, #0                                      
  0000c944  04408fe0      add      r4, pc, r4                                  
  0000c948  c8fbffeb      bl       #0xb870                                     
  0000c94c  0560a0e1      mov      r6, r5                                      
  0000c950  07708fe0      add      r7, pc, r7                                  
  0000c954  090000ea      b        #0xc980                                     
  0000c958  62f7ffeb      bl       #0xa6e8                                     
  0000c95c  80c09fe5      ldr      ip, [pc, #0x80]                             
  0000c960  8d1f4be2      sub      r1, fp, #0x234                              
  0000c964  862fa0e3      mov      r2, #0x218                                  
  0000c968  0030a0e3      mov      r3, #0                                      
  0000c96c  0cc094e7      ldr      ip, [r4, ip]                                
  0000c970  dc009ce5      ldr      r0, [ip, #0xdc]                             
  0000c974  28f7ffeb      bl       #0xa61c                                     
  0000c978  000050e3      cmp      r0, #0                                      
  0000c97c  090000ca      bgt      #0xc9a8                                     
  0000c980  c6fbffeb      bl       #0xb8a0                                     
  0000c984  861fa0e3      mov      r1, #0x218                                  
  0000c988  0130a0e1      mov      r3, r1                                      
  0000c98c  0020a0e3      mov      r2, #0                                      
  0000c990  010050e3      cmp      r0, #1                                      
  0000c994  8d0f4be2      sub      r0, fp, #0x234                              
  0000c998  eeffff0a      beq      #0xc958                                     
  0000c99c  0500a0e1      mov      r0, r5                                      
  0000c9a0  1cd04be2      sub      sp, fp, #0x1c                               
  0000c9a4  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000c9a8  870f4be2      sub      r0, fp, #0x21c                              
  0000c9ac  20faffeb      bl       #0xb234                                     
  0000c9b0  005050e2      subs     r5, r0, #0                                  
  0000c9b4  f1ffff0a      beq      #0xc980                                     
  0000c9b8  00608de5      str      r6, [sp]                                    
  0000c9bc  0700a0e1      mov      r0, r7                                      
  0000c9c0  04608de5      str      r6, [sp, #4]                                
  0000c9c4  1b1300e3      movw     r1, #0x31b                                  
  0000c9c8  08608de5      str      r6, [sp, #8]                                
  0000c9cc  0520a0e1      mov      r2, r5                                      
  0000c9d0  0030a0e3      mov      r3, #0                                      
  0000c9d4  22f7ffeb      bl       #0xa664                                     
  0000c9d8  e8ffffea      b        #0xc980                                     
  0000c9dc  b4260300      strheq   r2, [r3], -r4                               
  0000c9e0  74350200      andeq    r3, r2, r4, ror r5                          
  0000c9e4  b8080000      strheq   r0, [r0], -r8                               

; ─── HW_DM_BatteryNetlinkRoutine @ 0xc9e8 ───
  0000c9e8  c8009fe5      ldr      r0, [pc, #0xc8]                             
  0000c9ec  0dc0a0e1      mov      ip, sp                                      
  0000c9f0  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000c9f4  04b04ce2      sub      fp, ip, #4                                  
  0000c9f8  14d04de2      sub      sp, sp, #0x14                               
  0000c9fc  00008fe0      add      r0, pc, r0                                  
  0000ca00  b4409fe5      ldr      r4, [pc, #0xb4]                               ; r4='[mtd]Flash Check Result=[success].'
  0000ca04  aef8ffeb      bl       #0xacc4                                     
  0000ca08  3cfaffeb      bl       #0xb300                                     
  0000ca0c  ac209fe5      ldr      r2, [pc, #0xac]                             
  0000ca10  04408fe0      add      r4, pc, r4                                  
  0000ca14  024094e7      ldr      r4, [r4, r2]                                
  0000ca18  000050e3      cmp      r0, #0                                      
  0000ca1c  dc0084e5      str      r0, [r4, #0xdc]                             
  0000ca20  070000ba      blt      #0xca44                                     
  0000ca24  0a1aa0e3      mov      r1, #0xa000                                 
  0000ca28  001042e3      movt     r1, #0x2000                                 
  0000ca2c  0ff7ffeb      bl       #0xa670                                     
  0000ca30  010070e3      cmn      r0, #1                                      
  0000ca34  1000000a      beq      #0xca7c                                     
  0000ca38  10d04be2      sub      sp, fp, #0x10                               
  0000ca3c  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000ca40  b5ffffea      b        #0xc91c                                     
  0000ca44  78009fe5      ldr      r0, [pc, #0x78]                             
  0000ca48  0030a0e3      mov      r3, #0                                      
  0000ca4c  fa1200e3      movw     r1, #0x2fa                                  
  0000ca50  00308de5      str      r3, [sp]                                    
  0000ca54  00008fe0      add      r0, pc, r0                                  
  0000ca58  04308de5      str      r3, [sp, #4]                                
  0000ca5c  052aa0e3      mov      r2, #0x5000                                 
  0000ca60  08308de5      str      r3, [sp, #8]                                
  0000ca64  20274fe3      movt     r2, #0xf720                                 
  0000ca68  fdf6ffeb      bl       #0xa664                                     
  0000ca6c  050aa0e3      mov      r0, #0x5000                                 
  0000ca70  20074fe3      movt     r0, #0xf720                                 
  0000ca74  10d04be2      sub      sp, fp, #0x10                               
  0000ca78  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000ca7c  dc0094e5      ldr      r0, [r4, #0xdc]                             
  0000ca80  65f8ffeb      bl       #0xac1c                                     
  0000ca84  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0000ca88  0030a0e3      mov      r3, #0                                      
  0000ca8c  051300e3      movw     r1, #0x305                                  
  0000ca90  00008fe0      add      r0, pc, r0                                  
  0000ca94  00308de5      str      r3, [sp]                                    
  0000ca98  0c2005e3      movw     r2, #0x500c                                 
  0000ca9c  04308de5      str      r3, [sp, #4]                                
  0000caa0  20274fe3      movt     r2, #0xf720                                 
  0000caa4  08308de5      str      r3, [sp, #8]                                
  0000caa8  edf6ffeb      bl       #0xa664                                     
  0000caac  0c0005e3      movw     r0, #0x500c                                 
  0000cab0  20074fe3      movt     r0, #0xf720                                 
  0000cab4  eeffffea      b        #0xca74                                     
  0000cab8  dc360200      ldrdeq   r3, r4, [r2], -ip                           
  0000cabc  e8250300      andeq    r2, r3, r8, ror #11                         
  0000cac0  b8080000      strheq   r0, [r0], -r8                               
  0000cac4  70340200      andeq    r3, r2, r0, ror r4                          
  0000cac8  34340200      andeq    r3, r2, r4, lsr r4                          

; ─── HW_DM_InitBattery @ 0xcacc ───
  0000cacc  0dc0a0e1      mov      ip, sp                                      
  0000cad0  0030e0e3      mvn      r3, #0                                      
  0000cad4  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000cad8  04b04ce2      sub      fp, ip, #4                                  
  0000cadc  14204be2      sub      r2, fp, #0x14                               
  0000cae0  1cd04de2      sub      sp, sp, #0x1c                               
  0000cae4  1700a0e3      mov      r0, #0x17                                   
  0000cae8  043022e5      str      r3, [r2, #-4]!                              
  0000caec  0410a0e3      mov      r1, #4                                      
  0000caf0  15f6ffeb      bl       #0xa34c                                     
  0000caf4  74c09fe5      ldr      ip, [pc, #0x74]                             
  0000caf8  0cc08fe0      add      ip, pc, ip                                  
  0000cafc  004050e2      subs     r4, r0, #0                                  
  0000cb00  0f00001a      bne      #0xcb44                                     
  0000cb04  18301be5      ldr      r3, [fp, #-0x18]                            
  0000cb08  000053e3      cmp      r3, #0                                      
  0000cb0c  0200001a      bne      #0xcb1c                                     
  0000cb10  0400a0e1      mov      r0, r4                                      
  0000cb14  10d04be2      sub      sp, fp, #0x10                               
  0000cb18  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000cb1c  50009fe5      ldr      r0, [pc, #0x50]                             
  0000cb20  0410a0e1      mov      r1, r4                                      
  0000cb24  4c209fe5      ldr      r2, [pc, #0x4c]                             
  0000cb28  0430a0e1      mov      r3, r4                                      
  0000cb2c  00009ce7      ldr      r0, [ip, r0]                                
  0000cb30  02209ce7      ldr      r2, [ip, r2]                                
  0000cb34  d80080e2      add      r0, r0, #0xd8                               
  0000cb38  93f9ffeb      bl       #0xb18c                                     
  0000cb3c  0040a0e1      mov      r4, r0                                      
  0000cb40  f2ffffea      b        #0xcb10                                     
  0000cb44  30009fe5      ldr      r0, [pc, #0x30]                             
  0000cb48  0030a0e3      mov      r3, #0                                      
  0000cb4c  cf1fa0e3      mov      r1, #0x33c                                  
  0000cb50  00308de5      str      r3, [sp]                                    
  0000cb54  04308de5      str      r3, [sp, #4]                                
  0000cb58  00008fe0      add      r0, pc, r0                                  
  0000cb5c  08308de5      str      r3, [sp, #8]                                
  0000cb60  0420a0e1      mov      r2, r4                                      
  0000cb64  1730a0e3      mov      r3, #0x17                                   
  0000cb68  bdf6ffeb      bl       #0xa664                                     
  0000cb6c  e7ffffea      b        #0xcb10                                     
  0000cb70  00250300      andeq    r2, r3, r0, lsl #10                         
  0000cb74  b8080000      strheq   r0, [r0], -r8                               
  0000cb78  80080000      andeq    r0, r0, r0, lsl #17                         
  0000cb7c  6c330200      andeq    r3, r2, ip, ror #6                          

; ─── HW_DM_DeInitBattery @ 0xcb80 ───
  0000cb80  0dc0a0e1      mov      ip, sp                                      
  0000cb84  34209fe5      ldr      r2, [pc, #0x34]                             
  0000cb88  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  0000cb8c  04b04ce2      sub      fp, ip, #4                                  
  0000cb90  2c309fe5      ldr      r3, [pc, #0x2c]                               ; r3='esult=[fail].'
  0000cb94  03308fe0      add      r3, pc, r3                                  
  0000cb98  024093e7      ldr      r4, [r3, r2]                                
  0000cb9c  dc0094e5      ldr      r0, [r4, #0xdc]                             
  0000cba0  010070e3      cmn      r0, #1                                      
  0000cba4  0000000a      beq      #0xcbac                                     
  0000cba8  1bf8ffeb      bl       #0xac1c                                     
  0000cbac  d80094e5      ldr      r0, [r4, #0xd8]                             
  0000cbb0  010070e3      cmn      r0, #1                                      
  0000cbb4  18a89d08      ldmeq    sp, {r3, r4, fp, sp, pc}                    
  0000cbb8  18689de8      ldm      sp, {r3, r4, fp, sp, lr}                    
  0000cbbc  4cf5ffea      b        #0xa0f4                                     
  0000cbc0  b8080000      strheq   r0, [r0], -r8                               
  0000cbc4  64240300      andeq    r2, r3, r4, ror #8                          

; ─── HW_DM_PDT_InitFunc_Cut @ 0xcbc8 ───
  0000cbc8  1c309fe5      ldr      r3, [pc, #0x1c]                             
  0000cbcc  1c209fe5      ldr      r2, [pc, #0x1c]                             
  0000cbd0  03308fe0      add      r3, pc, r3                                  
  0000cbd4  022093e7      ldr      r2, [r3, r2]                                
  0000cbd8  042080e5      str      r2, [r0, #4]                                
  0000cbdc  10209fe5      ldr      r2, [pc, #0x10]                             
  0000cbe0  023093e7      ldr      r3, [r3, r2]                                
  0000cbe4  0c3080e5      str      r3, [r0, #0xc]                              
  0000cbe8  1eff2fe1      bx       lr                                          
  0000cbec  28240300      andeq    r2, r3, r8, lsr #8                          
  0000cbf0  4c090000      andeq    r0, r0, ip, asr #18                         
  0000cbf4  7c090000      andeq    r0, r0, ip, ror sb                          

; ─── HW_DM_PDT_InitShareFunc_Cut @ 0xcbf8 ───
  0000cbf8  0dc0a0e1      mov      ip, sp                                      
  0000cbfc  0030a0e3      mov      r3, #0                                      
  0000cc00  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000cc04  04b04ce2      sub      fp, ip, #4                                  
  0000cc08  14204be2      sub      r2, fp, #0x14                               
  0000cc0c  08d04de2      sub      sp, sp, #8                                  
  0000cc10  78409fe5      ldr      r4, [pc, #0x78]                             
  0000cc14  043022e5      str      r3, [r2, #-4]!                              
  0000cc18  0050a0e1      mov      r5, r0                                      
  0000cc1c  70309fe5      ldr      r3, [pc, #0x70]                             
  0000cc20  04408fe0      add      r4, pc, r4                                  
  0000cc24  0300a0e3      mov      r0, #3                                      
  0000cc28  0410a0e3      mov      r1, #4                                      
  0000cc2c  033094e7      ldr      r3, [r4, r3]                                
  0000cc30  043085e5      str      r3, [r5, #4]                                
  0000cc34  5c309fe5      ldr      r3, [pc, #0x5c]                             
  0000cc38  033094e7      ldr      r3, [r4, r3]                                
  0000cc3c  083085e5      str      r3, [r5, #8]                                
  0000cc40  54309fe5      ldr      r3, [pc, #0x54]                             
  0000cc44  033094e7      ldr      r3, [r4, r3]                                
  0000cc48  0c3085e5      str      r3, [r5, #0xc]                              
  0000cc4c  bef5ffeb      bl       #0xa34c                                     
  0000cc50  000050e3      cmp      r0, #0                                      
  0000cc54  0200001a      bne      #0xcc64                                     
  0000cc58  18301be5      ldr      r3, [fp, #-0x18]                            
  0000cc5c  000053e3      cmp      r3, #0                                      
  0000cc60  0600001a      bne      #0xcc80                                     
  0000cc64  0030a0e3      mov      r3, #0                                      
  0000cc68  283085e5      str      r3, [r5, #0x28]                             
  0000cc6c  2c309fe5      ldr      r3, [pc, #0x2c]                             
  0000cc70  033094e7      ldr      r3, [r4, r3]                                
  0000cc74  2c3085e5      str      r3, [r5, #0x2c]                             
  0000cc78  14d04be2      sub      sp, fp, #0x14                               
  0000cc7c  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000cc80  1c309fe5      ldr      r3, [pc, #0x1c]                             
  0000cc84  033094e7      ldr      r3, [r4, r3]                                
  0000cc88  283085e5      str      r3, [r5, #0x28]                             
  0000cc8c  f6ffffea      b        #0xcc6c                                     
  0000cc90  d8230300      ldrdeq   r2, r3, [r3], -r8                           
  0000cc94  88080000      andeq    r0, r0, r8, lsl #17                         
  0000cc98  dc080000      ldrdeq   r0, r1, [r0], -ip                           
  0000cc9c  5c090000      andeq    r0, r0, ip, asr sb                          
  0000cca0  64090000      andeq    r0, r0, r4, ror #18                         
  0000cca4  30090000      andeq    r0, r0, r0, lsr sb                          

; ─── HW_DM_RPC_GetSimCardStatus @ 0xcca8 ───
  0000cca8  000053e2      subs     r0, r3, #0                                  
  0000ccac  0dc0a0e1      mov      ip, sp                                      
  0000ccb0  00d82de9      push     {fp, ip, lr, pc}                            
  0000ccb4  04b04ce2      sub      fp, ip, #4                                  
  0000ccb8  10d04de2      sub      sp, sp, #0x10                               
  0000ccbc  0700000a      beq      #0xcce0                                     
  0000ccc0  48209fe5      ldr      r2, [pc, #0x48]                             
  0000ccc4  4010a0e3      mov      r1, #0x40                                   
  0000ccc8  3f30a0e3      mov      r3, #0x3f                                   
  0000cccc  02208fe0      add      r2, pc, r2                                  
  0000ccd0  04f5ffeb      bl       #0xa0e8                                     
  0000ccd4  0000a0e3      mov      r0, #0                                      
  0000ccd8  0cd04be2      sub      sp, fp, #0xc                                
  0000ccdc  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000cce0  00008de5      str      r0, [sp]                                    
  0000cce4  ce1300e3      movw     r1, #0x3ce                                  
  0000cce8  04008de5      str      r0, [sp, #4]                                
  0000ccec  012005e3      movw     r2, #0x5001                                 
  0000ccf0  08008de5      str      r0, [sp, #8]                                
  0000ccf4  20274fe3      movt     r2, #0xf720                                 
  0000ccf8  14009fe5      ldr      r0, [pc, #0x14]                             
  0000ccfc  00008fe0      add      r0, pc, r0                                  
  0000cd00  57f6ffeb      bl       #0xa664                                     
  0000cd04  010005e3      movw     r0, #0x5001                                 
  0000cd08  20074fe3      movt     r0, #0xf720                                 
  0000cd0c  f1ffffea      b        #0xccd8                                     
  0000cd10  18340200      andeq    r3, r2, r8, lsl r4                          
  0000cd14  c8310200      andeq    r3, r2, r8, asr #3                          

; ─── HW_DM_PDT_FormatBatteryChipStatus @ 0xcd18 ───
  0000cd18  0dc0a0e1      mov      ip, sp                                      
  0000cd1c  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000cd20  0140a0e1      mov      r4, r1                                      
  0000cd24  c4119fe5      ldr      r1, [pc, #0x1c4]                            
  0000cd28  04b04ce2      sub      fp, ip, #4                                  
  0000cd2c  90d04de2      sub      sp, sp, #0x90                               
  0000cd30  0060a0e1      mov      r6, r0                                      
  0000cd34  0250a0e1      mov      r5, r2                                      
  0000cd38  a4004be2      sub      r0, fp, #0xa4                               
  0000cd3c  01108fe0      add      r1, pc, r1                                  
  0000cd40  4020a0e3      mov      r2, #0x40                                   
  0000cd44  0370a0e1      mov      r7, r3                                      
  0000cd48  98faffeb      bl       #0xb7b0                                     
  0000cd4c  000056e3      cmp      r6, #0                                      
  0000cd50  00005413      cmpne    r4, #0                                      
  0000cd54  0400000a      beq      #0xcd6c                                     
  0000cd58  000055e3      cmp      r5, #0                                      
  0000cd5c  00005713      cmpne    r7, #0                                      
  0000cd60  0020a013      movne    r2, #0                                      
  0000cd64  0120a003      moveq    r2, #1                                      
  0000cd68  0100001a      bne      #0xcd74                                     
  0000cd6c  1cd04be2      sub      sp, fp, #0x1c                               
  0000cd70  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000cd74  4810a0e3      mov      r1, #0x48                                   
  0000cd78  64004be2      sub      r0, fp, #0x64                               
  0000cd7c  0130a0e1      mov      r3, r1                                      
  0000cd80  58f6ffeb      bl       #0xa6e8                                     
  0000cd84  1010a0e3      mov      r1, #0x10                                   
  0000cd88  0620a0e1      mov      r2, r6                                      
  0000cd8c  0130a0e1      mov      r3, r1                                      
  0000cd90  64004be2      sub      r0, fp, #0x64                               
  0000cd94  79f7ffeb      bl       #0xab80                                     
  0000cd98  003096e5      ldr      r3, [r6]                                    
  0000cd9c  28604be2      sub      r6, fp, #0x28                               
  0000cda0  0810a0e3      mov      r1, #8                                      
  0000cda4  000053e3      cmp      r3, #0                                      
  0000cda8  0720a0e3      mov      r2, #7                                      
  0000cdac  0600a0e1      mov      r0, r6                                      
  0000cdb0  3900000a      beq      #0xce9c                                     
  0000cdb4  38319fe5      ldr      r3, [pc, #0x138]                            
  0000cdb8  38c19fe5      ldr      ip, [pc, #0x138]                            
  0000cdbc  03308fe0      add      r3, pc, r3                                  
  0000cdc0  0cc08fe0      add      ip, pc, ip                                  
  0000cdc4  00c08de5      str      ip, [sp]                                    
  0000cdc8  09f7ffeb      bl       #0xa9f4                                     
  0000cdcc  083094e5      ldr      r3, [r4, #8]                                
  0000cdd0  012043e2      sub      r2, r3, #1                                  
  0000cdd4  020052e3      cmp      r2, #2                                      
  0000cdd8  3900009a      bls      #0xcec4                                     
  0000cddc  18319fe5      ldr      r3, [pc, #0x118]                            
  0000cde0  a4c04be2      sub      ip, fp, #0xa4                               
  0000cde4  1c10a0e3      mov      r1, #0x1c                                   
  0000cde8  00c08de5      str      ip, [sp]                                    
  0000cdec  1b20a0e3      mov      r2, #0x1b                                   
  0000cdf0  03308fe0      add      r3, pc, r3                                  
  0000cdf4  54004be2      sub      r0, fp, #0x54                               
  0000cdf8  fdf6ffeb      bl       #0xa9f4                                     
  0000cdfc  1410a0e3      mov      r1, #0x14                                   
  0000ce00  0130a0e1      mov      r3, r1                                      
  0000ce04  0020a0e3      mov      r2, #0                                      
  0000ce08  0400a0e1      mov      r0, r4                                      
  0000ce0c  35f6ffeb      bl       #0xa6e8                                     
  0000ce10  e8309fe5      ldr      r3, [pc, #0xe8]                             
  0000ce14  e8c09fe5      ldr      ip, [pc, #0xe8]                             
  0000ce18  0600a0e1      mov      r0, r6                                      
  0000ce1c  03308fe0      add      r3, pc, r3                                  
  0000ce20  0810a0e3      mov      r1, #8                                      
  0000ce24  0cc08fe0      add      ip, pc, ip                                  
  0000ce28  0720a0e3      mov      r2, #7                                      
  0000ce2c  00c08de5      str      ip, [sp]                                    
  0000ce30  eff6ffeb      bl       #0xa9f4                                     
  0000ce34  0030a0e3      mov      r3, #0                                      
  0000ce38  083085e5      str      r3, [r5, #8]                                
  0000ce3c  c4609fe5      ldr      r6, [pc, #0xc4]                             
  0000ce40  0810a0e3      mov      r1, #8                                      
  0000ce44  10c094e5      ldr      ip, [r4, #0x10]                             
  0000ce48  0720a0e3      mov      r2, #7                                      
  0000ce4c  06608fe0      add      r6, pc, r6                                  
  0000ce50  38004be2      sub      r0, fp, #0x38                               
  0000ce54  0630a0e1      mov      r3, r6                                      
  0000ce58  00c08de5      str      ip, [sp]                                    
  0000ce5c  e4f6ffeb      bl       #0xa9f4                                     
  0000ce60  0cc094e5      ldr      ip, [r4, #0xc]                              
  0000ce64  0630a0e1      mov      r3, r6                                      
  0000ce68  0810a0e3      mov      r1, #8                                      
  0000ce6c  0720a0e3      mov      r2, #7                                      
  0000ce70  30004be2      sub      r0, fp, #0x30                               
  0000ce74  00c08de5      str      ip, [sp]                                    
  0000ce78  ddf6ffeb      bl       #0xa9f4                                     
  0000ce7c  08c095e5      ldr      ip, [r5, #8]                                
  0000ce80  4810a0e3      mov      r1, #0x48                                   
  0000ce84  000097e5      ldr      r0, [r7]                                    
  0000ce88  64204be2      sub      r2, fp, #0x64                               
  0000ce8c  0130a0e1      mov      r3, r1                                      
  0000ce90  20c00be5      str      ip, [fp, #-0x20]                            
  0000ce94  39f7ffeb      bl       #0xab80                                     
  0000ce98  b3ffffea      b        #0xcd6c                                     
  0000ce9c  68309fe5      ldr      r3, [pc, #0x68]                             
  0000cea0  68c09fe5      ldr      ip, [pc, #0x68]                             
  0000cea4  03308fe0      add      r3, pc, r3                                  
  0000cea8  0cc08fe0      add      ip, pc, ip                                  
  0000ceac  00c08de5      str      ip, [sp]                                    
  0000ceb0  cff6ffeb      bl       #0xa9f4                                     
  0000ceb4  083094e5      ldr      r3, [r4, #8]                                
  0000ceb8  012043e2      sub      r2, r3, #1                                  
  0000cebc  020052e3      cmp      r2, #2                                      
  0000cec0  c5ffff8a      bhi      #0xcddc                                     
  0000cec4  a4204be2      sub      r2, fp, #0xa4                               
  0000cec8  00408de5      str      r4, [sp]                                    
  0000cecc  033282e0      add      r3, r2, r3, lsl #4                          
  0000ced0  04308de5      str      r3, [sp, #4]                                
  0000ced4  38309fe5      ldr      r3, [pc, #0x38]                             
  0000ced8  54004be2      sub      r0, fp, #0x54                               
  0000cedc  1c10a0e3      mov      r1, #0x1c                                   
  0000cee0  1b20a0e3      mov      r2, #0x1b                                   
  0000cee4  03308fe0      add      r3, pc, r3                                  
  0000cee8  c1f6ffeb      bl       #0xa9f4                                     
  0000ceec  d2ffffea      b        #0xce3c                                     
  0000cef0  34310200      andeq    r3, r2, r4, lsr r1                          
  0000cef4  e4460200      andeq    r4, r2, r4, ror #13                         
  0000cef8  34330200      andeq    r3, r2, r4, lsr r3                          
  0000cefc  08330200      andeq    r3, r2, r8, lsl #6                          
  0000cf00  84460200      andeq    r4, r2, r4, lsl #13                         
  0000cf04  cc320200      andeq    r3, r2, ip, asr #5                          
  0000cf08  bc320200      strheq   r3, [r2], -ip                               
  0000cf0c  fc450200      strdeq   r4, r5, [r2], -ip                           
  0000cf10  48320200      andeq    r3, r2, r8, asr #4                          
  0000cf14  1c320200      andeq    r3, r2, ip, lsl r2                          

; ─── HW_DM_RPC_GetBatteryChipStatus @ 0xcf18 ───
  0000cf18  0dc0a0e1      mov      ip, sp                                      
  0000cf1c  000053e3      cmp      r3, #0                                      
  0000cf20  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000cf24  04b04ce2      sub      fp, ip, #4                                  
  0000cf28  50d04de2      sub      sp, sp, #0x50                               
  0000cf2c  0040a0e3      mov      r4, #0                                      
  0000cf30  03540503      movweq   r5, #0x5403                                 
  0000cf34  50300be5      str      r3, [fp, #-0x50]                            
  0000cf38  20574f03      movteq   r5, #0xf720                                 
  0000cf3c  38400be5      str      r4, [fp, #-0x38]                            
  0000cf40  34400be5      str      r4, [fp, #-0x34]                            
  0000cf44  30400be5      str      r4, [fp, #-0x30]                            
  0000cf48  2c400be5      str      r4, [fp, #-0x2c]                            
  0000cf4c  4c400be5      str      r4, [fp, #-0x4c]                            
  0000cf50  48400be5      str      r4, [fp, #-0x48]                            
  0000cf54  2c00000a      beq      #0xd00c                                     
  0000cf58  1410a0e3      mov      r1, #0x14                                   
  0000cf5c  0420a0e1      mov      r2, r4                                      
  0000cf60  0130a0e1      mov      r3, r1                                      
  0000cf64  28004be2      sub      r0, fp, #0x28                               
  0000cf68  def5ffeb      bl       #0xa6e8                                     
  0000cf6c  0c10a0e3      mov      r1, #0xc                                    
  0000cf70  0420a0e1      mov      r2, r4                                      
  0000cf74  0130a0e1      mov      r3, r1                                      
  0000cf78  44004be2      sub      r0, fp, #0x44                               
  0000cf7c  d9f5ffeb      bl       #0xa6e8                                     
  0000cf80  38004be2      sub      r0, fp, #0x38                               
  0000cf84  f1f6ffeb      bl       #0xab50                                     
  0000cf88  005050e2      subs     r5, r0, #0                                  
  0000cf8c  2100001a      bne      #0xd018                                     
  0000cf90  1700a0e3      mov      r0, #0x17                                   
  0000cf94  0410a0e3      mov      r1, #4                                      
  0000cf98  4c204be2      sub      r2, fp, #0x4c                               
  0000cf9c  eaf4ffeb      bl       #0xa34c                                     
  0000cfa0  005050e2      subs     r5, r0, #0                                  
  0000cfa4  2500001a      bne      #0xd040                                     
  0000cfa8  4c301be5      ldr      r3, [fp, #-0x4c]                            
  0000cfac  000053e3      cmp      r3, #0                                      
  0000cfb0  3600000a      beq      #0xd090                                     
  0000cfb4  34301be5      ldr      r3, [fp, #-0x34]                            
  0000cfb8  010053e3      cmp      r3, #1                                      
  0000cfbc  4200000a      beq      #0xd0cc                                     
  0000cfc0  28004be2      sub      r0, fp, #0x28                               
  0000cfc4  aef6ffeb      bl       #0xaa84                                     
  0000cfc8  005050e2      subs     r5, r0, #0                                  
  0000cfcc  0300001a      bne      #0xcfe0                                     
  0000cfd0  20301be5      ldr      r3, [fp, #-0x20]                            
  0000cfd4  013043e2      sub      r3, r3, #1                                  
  0000cfd8  020053e3      cmp      r3, #2                                      
  0000cfdc  4900008a      bhi      #0xd108                                     
  0000cfe0  48004be2      sub      r0, fp, #0x48                               
  0000cfe4  25f9ffeb      bl       #0xb480                                     
  0000cfe8  005050e2      subs     r5, r0, #0                                  
  0000cfec  1d00001a      bne      #0xd068                                     
  0000cff0  48c01be5      ldr      ip, [fp, #-0x48]                            
  0000cff4  38004be2      sub      r0, fp, #0x38                               
  0000cff8  28104be2      sub      r1, fp, #0x28                               
  0000cffc  44204be2      sub      r2, fp, #0x44                               
  0000d000  50304be2      sub      r3, fp, #0x50                               
  0000d004  3cc00be5      str      ip, [fp, #-0x3c]                            
  0000d008  50f5ffeb      bl       #0xa550                                     
  0000d00c  0500a0e1      mov      r0, r5                                      
  0000d010  14d04be2      sub      sp, fp, #0x14                               
  0000d014  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000d018  14019fe5      ldr      r0, [pc, #0x114]                            
  0000d01c  481400e3      movw     r1, #0x448                                  
  0000d020  00408de5      str      r4, [sp]                                    
  0000d024  0520a0e1      mov      r2, r5                                      
  0000d028  04408de5      str      r4, [sp, #4]                                
  0000d02c  0430a0e1      mov      r3, r4                                      
  0000d030  08408de5      str      r4, [sp, #8]                                
  0000d034  00008fe0      add      r0, pc, r0                                  
  0000d038  89f5ffeb      bl       #0xa664                                     
  0000d03c  f2ffffea      b        #0xd00c                                     
  0000d040  f0009fe5      ldr      r0, [pc, #0xf0]                             
  0000d044  451ea0e3      mov      r1, #0x450                                  
  0000d048  00408de5      str      r4, [sp]                                    
  0000d04c  0520a0e1      mov      r2, r5                                      
  0000d050  04408de5      str      r4, [sp, #4]                                
  0000d054  1730a0e3      mov      r3, #0x17                                   
  0000d058  08408de5      str      r4, [sp, #8]                                
  0000d05c  00008fe0      add      r0, pc, r0                                  
  0000d060  7ff5ffeb      bl       #0xa664                                     
  0000d064  e8ffffea      b        #0xd00c                                     
  0000d068  cc009fe5      ldr      r0, [pc, #0xcc]                             
  0000d06c  0030a0e3      mov      r3, #0                                      
  0000d070  751400e3      movw     r1, #0x475                                  
  0000d074  00308de5      str      r3, [sp]                                    
  0000d078  00008fe0      add      r0, pc, r0                                  
  0000d07c  04308de5      str      r3, [sp, #4]                                
  0000d080  0520a0e1      mov      r2, r5                                      
  0000d084  08308de5      str      r3, [sp, #8]                                
  0000d088  75f5ffeb      bl       #0xa664                                     
  0000d08c  deffffea      b        #0xd00c                                     
  0000d090  38004be2      sub      r0, fp, #0x38                               
  0000d094  28104be2      sub      r1, fp, #0x28                               
  0000d098  44204be2      sub      r2, fp, #0x44                               
  0000d09c  50304be2      sub      r3, fp, #0x50                               
  0000d0a0  2af5ffeb      bl       #0xa550                                     
  0000d0a4  94009fe5      ldr      r0, [pc, #0x94]                             
  0000d0a8  00508de5      str      r5, [sp]                                    
  0000d0ac  581400e3      movw     r1, #0x458                                  
  0000d0b0  04508de5      str      r5, [sp, #4]                                
  0000d0b4  0520a0e1      mov      r2, r5                                      
  0000d0b8  08508de5      str      r5, [sp, #8]                                
  0000d0bc  00008fe0      add      r0, pc, r0                                  
  0000d0c0  0530a0e1      mov      r3, r5                                      
  0000d0c4  66f5ffeb      bl       #0xa664                                     
  0000d0c8  cfffffea      b        #0xd00c                                     
  0000d0cc  38004be2      sub      r0, fp, #0x38                               
  0000d0d0  28104be2      sub      r1, fp, #0x28                               
  0000d0d4  44204be2      sub      r2, fp, #0x44                               
  0000d0d8  50304be2      sub      r3, fp, #0x50                               
  0000d0dc  1bf5ffeb      bl       #0xa550                                     
  0000d0e0  5c009fe5      ldr      r0, [pc, #0x5c]                             
  0000d0e4  00508de5      str      r5, [sp]                                    
  0000d0e8  461ea0e3      mov      r1, #0x460                                  
  0000d0ec  04508de5      str      r5, [sp, #4]                                
  0000d0f0  0520a0e1      mov      r2, r5                                      
  0000d0f4  08508de5      str      r5, [sp, #8]                                
  0000d0f8  00008fe0      add      r0, pc, r0                                  
  0000d0fc  0530a0e1      mov      r3, r5                                      
  0000d100  57f5ffeb      bl       #0xa664                                     
  0000d104  c0ffffea      b        #0xd00c                                     
  0000d108  1410a0e3      mov      r1, #0x14                                   
  0000d10c  0520a0e1      mov      r2, r5                                      
  0000d110  0130a0e1      mov      r3, r1                                      
  0000d114  28004be2      sub      r0, fp, #0x28                               
  0000d118  72f5ffeb      bl       #0xa6e8                                     
  0000d11c  38004be2      sub      r0, fp, #0x38                               
  0000d120  28104be2      sub      r1, fp, #0x28                               
  0000d124  44204be2      sub      r2, fp, #0x44                               
  0000d128  50304be2      sub      r3, fp, #0x50                               
  0000d12c  07f5ffeb      bl       #0xa550                                     
  0000d130  b5ffffea      b        #0xd00c                                     
  0000d134  902e0200      muleq    r2, r0, lr                                  
  0000d138  682e0200      andeq    r2, r2, r8, ror #28                         
  0000d13c  4c2e0200      andeq    r2, r2, ip, asr #28                         
  0000d140  082e0200      andeq    r2, r2, r8, lsl #28                         
  0000d144  cc2d0200      andeq    r2, r2, ip, asr #27                         

; ─── HW_DM_RPC_GetSpecialFwVersion @ 0xd148 ───
  0000d148  0dc0a0e1      mov      ip, sp                                      
  0000d14c  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000d150  04b04ce2      sub      fp, ip, #4                                  
  0000d154  006053e2      subs     r6, r3, #0                                  
  0000d158  1cd04de2      sub      sp, sp, #0x1c                               
  0000d15c  0040a0e3      mov      r4, #0                                      
  0000d160  20400be5      str      r4, [fp, #-0x20]                            
  0000d164  1f00000a      beq      #0xd1e8                                     
  0000d168  d0009fe5      ldr      r0, [pc, #0xd0]                             
  0000d16c  20104be2      sub      r1, fp, #0x20                               
  0000d170  0420a0e1      mov      r2, r4                                      
  0000d174  00008fe0      add      r0, pc, r0                                  
  0000d178  a3f4ffeb      bl       #0xa40c                                     
  0000d17c  005050e2      subs     r5, r0, #0                                  
  0000d180  0e00001a      bne      #0xd1c0                                     
  0000d184  20501be5      ldr      r5, [fp, #-0x20]                            
  0000d188  0500a0e1      mov      r0, r5                                      
  0000d18c  5ff7ffeb      bl       #0xaf10                                     
  0000d190  0520a0e1      mov      r2, r5                                      
  0000d194  04109be5      ldr      r1, [fp, #4]                                
  0000d198  0030a0e1      mov      r3, r0                                      
  0000d19c  0600a0e1      mov      r0, r6                                      
  0000d1a0  d0f3ffeb      bl       #0xa0e8                                     
  0000d1a4  005050e2      subs     r5, r0, #0                                  
  0000d1a8  1a00001a      bne      #0xd218                                     
  0000d1ac  20001be5      ldr      r0, [fp, #-0x20]                            
  0000d1b0  b5f5ffeb      bl       #0xa88c                                     
  0000d1b4  0500a0e1      mov      r0, r5                                      
  0000d1b8  18d04be2      sub      sp, fp, #0x18                               
  0000d1bc  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  0000d1c0  7c009fe5      ldr      r0, [pc, #0x7c]                             
  0000d1c4  a11400e3      movw     r1, #0x4a1                                  
  0000d1c8  00408de5      str      r4, [sp]                                    
  0000d1cc  0520a0e1      mov      r2, r5                                      
  0000d1d0  04408de5      str      r4, [sp, #4]                                
  0000d1d4  0430a0e1      mov      r3, r4                                      
  0000d1d8  08408de5      str      r4, [sp, #8]                                
  0000d1dc  00008fe0      add      r0, pc, r0                                  
  0000d1e0  1ff5ffeb      bl       #0xa664                                     
  0000d1e4  f2ffffea      b        #0xd1b4                                     
  0000d1e8  58009fe5      ldr      r0, [pc, #0x58]                             
  0000d1ec  991400e3      movw     r1, #0x499                                  
  0000d1f0  00608de5      str      r6, [sp]                                    
  0000d1f4  032405e3      movw     r2, #0x5403                                 
  0000d1f8  04608de5      str      r6, [sp, #4]                                
  0000d1fc  20274fe3      movt     r2, #0xf720                                 
  0000d200  08608de5      str      r6, [sp, #8]                                
  0000d204  00008fe0      add      r0, pc, r0                                  
  0000d208  035405e3      movw     r5, #0x5403                                 
  0000d20c  14f5ffeb      bl       #0xa664                                     
  0000d210  20574fe3      movt     r5, #0xf720                                 
  0000d214  e6ffffea      b        #0xd1b4                                     
  0000d218  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000d21c  a81400e3      movw     r1, #0x4a8                                  
  0000d220  00408de5      str      r4, [sp]                                    
  0000d224  0520a0e1      mov      r2, r5                                      
  0000d228  04408de5      str      r4, [sp, #4]                                
  0000d22c  0430a0e1      mov      r3, r4                                      
  0000d230  08408de5      str      r4, [sp, #8]                                
  0000d234  00008fe0      add      r0, pc, r0                                  
  0000d238  09f5ffeb      bl       #0xa664                                     
  0000d23c  daffffea      b        #0xd1ac                                     
  0000d240  9c2f0200      muleq    r2, ip, pc                                  
  0000d244  e82c0200      andeq    r2, r2, r8, ror #25                         
  0000d248  c02c0200      andeq    r2, r2, r0, asr #25                         
  0000d24c  902c0200      muleq    r2, r0, ip                                  

; ─── HW_DM_PDT_GetStringClassInXGponMode @ 0xd250 ───
  0000d250  20209fe5      ldr      r2, [pc, #0x20]                             
  0000d254  0dc0a0e1      mov      ip, sp                                      
  0000d258  011100e3      movw     r1, #0x101                                  
  0000d25c  013ca0e3      mov      r3, #0x100                                  
  0000d260  00d82de9      push     {fp, ip, lr, pc}                            
  0000d264  02208fe0      add      r2, pc, r2                                  
  0000d268  04b04ce2      sub      fp, ip, #4                                  
  0000d26c  9df3ffeb      bl       #0xa0e8                                     
  0000d270  0000a0e3      mov      r0, #0                                      
  0000d274  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000d278  c02e0200      andeq    r2, r2, r0, asr #29                         

; ─── HW_DM_PDT_GetStringClassInEponAMode @ 0xd27c ───
  0000d27c  20209fe5      ldr      r2, [pc, #0x20]                             
  0000d280  0dc0a0e1      mov      ip, sp                                      
  0000d284  011100e3      movw     r1, #0x101                                  
  0000d288  013ca0e3      mov      r3, #0x100                                  
  0000d28c  00d82de9      push     {fp, ip, lr, pc}                            
  0000d290  02208fe0      add      r2, pc, r2                                  
  0000d294  04b04ce2      sub      fp, ip, #4                                  
  0000d298  92f3ffeb      bl       #0xa0e8                                     
  0000d29c  0000a0e3      mov      r0, #0                                      
  0000d2a0  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000d2a4  982e0200      muleq    r2, r8, lr                                  

; ─── HW_DM_PDT_GetStringClassInEponSMode @ 0xd2a8 ───
  0000d2a8  20209fe5      ldr      r2, [pc, #0x20]                             
  0000d2ac  0dc0a0e1      mov      ip, sp                                      
  0000d2b0  011100e3      movw     r1, #0x101                                  
  0000d2b4  013ca0e3      mov      r3, #0x100                                  
  0000d2b8  00d82de9      push     {fp, ip, lr, pc}                            
  0000d2bc  02208fe0      add      r2, pc, r2                                  
  0000d2c0  04b04ce2      sub      fp, ip, #4                                  
  0000d2c4  87f3ffeb      bl       #0xa0e8                                     
  0000d2c8  0000a0e3      mov      r0, #0                                      
  0000d2cc  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000d2d0  702e0200      andeq    r2, r2, r0, ror lr                          

; ─── HW_DM_PDT_DistributeDevicePara_Func @ 0xd2d4 ───
  0000d2d4  0000a0e3      mov      r0, #0                                      
  0000d2d8  1eff2fe1      bx       lr                                          

; ─── HW_DM_PDT_DataModelGetFeatures @ 0xd2dc ───
  0000d2dc  0dc0a0e1      mov      ip, sp                                      
  0000d2e0  b8319fe5      ldr      r3, [pc, #0x1b8]                            
  0000d2e4  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000d2e8  04b04ce2      sub      fp, ip, #4                                  
  0000d2ec  10d04de2      sub      sp, sp, #0x10                               
  0000d2f0  1c504be2      sub      r5, fp, #0x1c                               
  0000d2f4  0160a0e1      mov      r6, r1                                      
  0000d2f8  a4119fe5      ldr      r1, [pc, #0x1a4]                            
  0000d2fc  03308fe0      add      r3, pc, r3                                  
  0000d300  00c0a0e3      mov      ip, #0                                      
  0000d304  0040a0e1      mov      r4, r0                                      
  0000d308  8320a0e3      mov      r2, #0x83                                   
  0000d30c  8e0100e3      movw     r0, #0x18e                                  
  0000d310  00408de5      str      r4, [sp]                                    
  0000d314  01108fe0      add      r1, pc, r1                                  
  0000d318  08c025e5      str      ip, [r5, #-8]!                              
  0000d31c  5df5ffeb      bl       #0xa898                                     
  0000d320  0400a0e3      mov      r0, #4                                      
  0000d324  0520a0e1      mov      r2, r5                                      
  0000d328  0010a0e1      mov      r1, r0                                      
  0000d32c  06f4ffeb      bl       #0xa34c                                     
  0000d330  24301be5      ldr      r3, [fp, #-0x24]                            
  0000d334  000053e3      cmp      r3, #0                                      
  0000d338  3100001a      bne      #0xd404                                     
  0000d33c  64119fe5      ldr      r1, [pc, #0x164]                            
  0000d340  8e0100e3      movw     r0, #0x18e                                  
  0000d344  60319fe5      ldr      r3, [pc, #0x160]                            
  0000d348  8e20a0e3      mov      r2, #0x8e                                   
  0000d34c  01108fe0      add      r1, pc, r1                                  
  0000d350  00408de5      str      r4, [sp]                                    
  0000d354  03308fe0      add      r3, pc, r3                                  
  0000d358  4ef5ffeb      bl       #0xa898                                     
  0000d35c  1c204be2      sub      r2, fp, #0x1c                               
  0000d360  0030a0e3      mov      r3, #0                                      
  0000d364  0300a0e3      mov      r0, #3                                      
  0000d368  043022e5      str      r3, [r2, #-4]!                              
  0000d36c  0410a0e3      mov      r1, #4                                      
  0000d370  f5f3ffeb      bl       #0xa34c                                     
  0000d374  20301be5      ldr      r3, [fp, #-0x20]                            
  0000d378  000053e3      cmp      r3, #0                                      
  0000d37c  2d00001a      bne      #0xd438                                     
  0000d380  28119fe5      ldr      r1, [pc, #0x128]                            
  0000d384  8e0100e3      movw     r0, #0x18e                                  
  0000d388  24319fe5      ldr      r3, [pc, #0x124]                            
  0000d38c  9d20a0e3      mov      r2, #0x9d                                   
  0000d390  01108fe0      add      r1, pc, r1                                  
  0000d394  00408de5      str      r4, [sp]                                    
  0000d398  03308fe0      add      r3, pc, r3                                  
  0000d39c  3df5ffeb      bl       #0xa898                                     
  0000d3a0  10019fe5      ldr      r0, [pc, #0x110]                            
  0000d3a4  00008fe0      add      r0, pc, r0                                  
  0000d3a8  72f6ffeb      bl       #0xad78                                     
  0000d3ac  010050e3      cmp      r0, #1                                      
  0000d3b0  2d00000a      beq      #0xd46c                                     
  0000d3b4  0400a0e1      mov      r0, r4                                      
  0000d3b8  d4f6ffeb      bl       #0xaf10                                     
  0000d3bc  000056e1      cmp      r6, r0                                      
  0000d3c0  0400003a      blo      #0xd3d8                                     
  0000d3c4  010040e2      sub      r0, r0, #1                                  
  0000d3c8  0030d4e7      ldrb     r3, [r4, r0]                                
  0000d3cc  2c0053e3      cmp      r3, #0x2c                                   
  0000d3d0  0030a003      moveq    r3, #0                                      
  0000d3d4  0030c407      strbeq   r3, [r4, r0]                                
  0000d3d8  dc109fe5      ldr      r1, [pc, #0xdc]                             
  0000d3dc  8e0100e3      movw     r0, #0x18e                                  
  0000d3e0  d8309fe5      ldr      r3, [pc, #0xd8]                             
  0000d3e4  ac20a0e3      mov      r2, #0xac                                   
  0000d3e8  00408de5      str      r4, [sp]                                    
  0000d3ec  01108fe0      add      r1, pc, r1                                  
  0000d3f0  03308fe0      add      r3, pc, r3                                  
  0000d3f4  27f5ffeb      bl       #0xa898                                     
  0000d3f8  0000a0e3      mov      r0, #0                                      
  0000d3fc  1cd04be2      sub      sp, fp, #0x1c                               
  0000d400  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000d404  0400a0e1      mov      r0, r4                                      
  0000d408  b4509fe5      ldr      r5, [pc, #0xb4]                             
  0000d40c  bff6ffeb      bl       #0xaf10                                     
  0000d410  05508fe0      add      r5, pc, r5                                  
  0000d414  067060e0      rsb      r7, r0, r6                                  
  0000d418  0500a0e1      mov      r0, r5                                      
  0000d41c  bbf6ffeb      bl       #0xaf10                                     
  0000d420  0520a0e1      mov      r2, r5                                      
  0000d424  0710a0e1      mov      r1, r7                                      
  0000d428  0030a0e1      mov      r3, r0                                      
  0000d42c  0400a0e1      mov      r0, r4                                      
  0000d430  72f5ffeb      bl       #0xaa00                                     
  0000d434  c0ffffea      b        #0xd33c                                     
  0000d438  0400a0e1      mov      r0, r4                                      
  0000d43c  84509fe5      ldr      r5, [pc, #0x84]                             
  0000d440  b2f6ffeb      bl       #0xaf10                                     
  0000d444  05508fe0      add      r5, pc, r5                                  
  0000d448  067060e0      rsb      r7, r0, r6                                  
  0000d44c  0500a0e1      mov      r0, r5                                      
  0000d450  aef6ffeb      bl       #0xaf10                                     
  0000d454  0520a0e1      mov      r2, r5                                      
  0000d458  0710a0e1      mov      r1, r7                                      
  0000d45c  0030a0e1      mov      r3, r0                                      
  0000d460  0400a0e1      mov      r0, r4                                      
  0000d464  65f5ffeb      bl       #0xaa00                                     
  0000d468  c4ffffea      b        #0xd380                                     
  0000d46c  0400a0e1      mov      r0, r4                                      
  0000d470  54509fe5      ldr      r5, [pc, #0x54]                             
  0000d474  a5f6ffeb      bl       #0xaf10                                     
  0000d478  05508fe0      add      r5, pc, r5                                  
  0000d47c  067060e0      rsb      r7, r0, r6                                  
  0000d480  0500a0e1      mov      r0, r5                                      
  0000d484  a1f6ffeb      bl       #0xaf10                                     
  0000d488  0520a0e1      mov      r2, r5                                      
  0000d48c  0710a0e1      mov      r1, r7                                      
  0000d490  0030a0e1      mov      r3, r0                                      
  0000d494  0400a0e1      mov      r0, r4                                      
  0000d498  58f5ffeb      bl       #0xaa00                                     
  0000d49c  c4ffffea      b        #0xd3b4                                     
  0000d4a0  4c2e0200      andeq    r2, r2, ip, asr #28                         
  0000d4a4  202e0200      andeq    r2, r2, r0, lsr #28                         
  0000d4a8  e82d0200      andeq    r2, r2, r8, ror #27                         
  0000d4ac  f42d0200      strdeq   r2, r3, [r2], -r4                           
  0000d4b0  a42d0200      andeq    r2, r2, r4, lsr #27                         
  0000d4b4  b02d0200      strheq   r2, [r2], -r0                               
  0000d4b8  e42d0200      andeq    r2, r2, r4, ror #27                         
  0000d4bc  482d0200      andeq    r2, r2, r8, asr #26                         
  0000d4c0  582d0200      andeq    r2, r2, r8, asr sp                          
  0000d4c4  682d0200      andeq    r2, r2, r8, ror #26                         
  0000d4c8  3c2d0200      andeq    r2, r2, ip, lsr sp                          
  0000d4cc  202d0200      andeq    r2, r2, r0, lsr #26                         

; ─── HW_DM_PDT_GetApSerialNumber_Func @ 0xd4d0 ───
  0000d4d0  0dc0a0e1      mov      ip, sp                                      
  0000d4d4  4120a0e3      mov      r2, #0x41                                   
  0000d4d8  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  0000d4dc  04b04ce2      sub      fp, ip, #4                                  
  0000d4e0  5cd04de2      sub      sp, sp, #0x5c                               
  0000d4e4  5c519fe5      ldr      r5, [pc, #0x15c]                            
  0000d4e8  0060a0e1      mov      r6, r0                                      
  0000d4ec  0170a0e1      mov      r7, r1                                      
  0000d4f0  68004be2      sub      r0, fp, #0x68                               
  0000d4f4  0010a0e3      mov      r1, #0                                      
  0000d4f8  05508fe0      add      r5, pc, r5                                  
  0000d4fc  d4f3ffeb      bl       #0xa454                                     
  0000d500  44319fe5      ldr      r3, [pc, #0x144]                            
  0000d504  1600a0e3      mov      r0, #0x16                                   
  0000d508  0510a0e1      mov      r1, r5                                      
  0000d50c  482800e3      movw     r2, #0x848                                  
  0000d510  03308fe0      add      r3, pc, r3                                  
  0000d514  00608de5      str      r6, [sp]                                    
  0000d518  def4ffeb      bl       #0xa898                                     
  0000d51c  2c019fe5      ldr      r0, [pc, #0x12c]                            
  0000d520  0010a0e3      mov      r1, #0                                      
  0000d524  00008fe0      add      r0, pc, r0                                  
  0000d528  c8f4ffeb      bl       #0xa850                                     
  0000d52c  008050e2      subs     r8, r0, #0                                  
  0000d530  0f00001a      bne      #0xd574                                     
  0000d534  3500a0e3      mov      r0, #0x35                                   
  0000d538  4110a0e3      mov      r1, #0x41                                   
  0000d53c  000141e3      movt     r0, #0x1100                                 
  0000d540  68204be2      sub      r2, fp, #0x68                               
  0000d544  80f3ffeb      bl       #0xa34c                                     
  0000d548  004050e2      subs     r4, r0, #0                                  
  0000d54c  1e00000a      beq      #0xd5cc                                     
  0000d550  00808de5      str      r8, [sp]                                    
  0000d554  0500a0e1      mov      r0, r5                                      
  0000d558  04808de5      str      r8, [sp, #4]                                
  0000d55c  4e1800e3      movw     r1, #0x84e                                  
  0000d560  08808de5      str      r8, [sp, #8]                                
  0000d564  0420a0e1      mov      r2, r4                                      
  0000d568  0630a0e1      mov      r3, r6                                      
  0000d56c  3cf4ffeb      bl       #0xa664                                     
  0000d570  120000ea      b        #0xd5c0                                     
  0000d574  3b00a0e3      mov      r0, #0x3b                                   
  0000d578  4110a0e3      mov      r1, #0x41                                   
  0000d57c  000141e3      movt     r0, #0x1100                                 
  0000d580  68204be2      sub      r2, fp, #0x68                               
  0000d584  70f3ffeb      bl       #0xa34c                                     
  0000d588  004050e2      subs     r4, r0, #0                                  
  0000d58c  2300001a      bne      #0xd620                                     
  0000d590  4110a0e3      mov      r1, #0x41                                   
  0000d594  68204be2      sub      r2, fp, #0x68                               
  0000d598  4030a0e3      mov      r3, #0x40                                   
  0000d59c  0700a0e1      mov      r0, r7                                      
  0000d5a0  d0f2ffeb      bl       #0xa0e8                                     
  0000d5a4  a8309fe5      ldr      r3, [pc, #0xa8]                             
  0000d5a8  00708de5      str      r7, [sp]                                    
  0000d5ac  1600a0e3      mov      r0, #0x16                                   
  0000d5b0  0510a0e1      mov      r1, r5                                      
  0000d5b4  5d2800e3      movw     r2, #0x85d                                  
  0000d5b8  03308fe0      add      r3, pc, r3                                  
  0000d5bc  b5f4ffeb      bl       #0xa898                                     
  0000d5c0  0400a0e1      mov      r0, r4                                      
  0000d5c4  20d04be2      sub      sp, fp, #0x20                               
  0000d5c8  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  0000d5cc  68204be2      sub      r2, fp, #0x68                               
  0000d5d0  0700a0e1      mov      r0, r7                                      
  0000d5d4  4110a0e3      mov      r1, #0x41                                   
  0000d5d8  4030a0e3      mov      r3, #0x40                                   
  0000d5dc  c1f2ffeb      bl       #0xa0e8                                     
  0000d5e0  70309fe5      ldr      r3, [pc, #0x70]                             
  0000d5e4  0510a0e1      mov      r1, r5                                      
  0000d5e8  00708de5      str      r7, [sp]                                    
  0000d5ec  1600a0e3      mov      r0, #0x16                                   
  0000d5f0  522800e3      movw     r2, #0x852                                  
  0000d5f4  03308fe0      add      r3, pc, r3                                  
  0000d5f8  a6f4ffeb      bl       #0xa898                                     
  0000d5fc  00408de5      str      r4, [sp]                                    
  0000d600  04408de5      str      r4, [sp, #4]                                
  0000d604  0500a0e1      mov      r0, r5                                      
  0000d608  08408de5      str      r4, [sp, #8]                                
  0000d60c  531800e3      movw     r1, #0x853                                  
  0000d610  0620a0e1      mov      r2, r6                                      
  0000d614  0430a0e1      mov      r3, r4                                      
  0000d618  11f4ffeb      bl       #0xa664                                     
  0000d61c  e7ffffea      b        #0xd5c0                                     
  0000d620  0030a0e3      mov      r3, #0                                      
  0000d624  0500a0e1      mov      r0, r5                                      
  0000d628  00308de5      str      r3, [sp]                                    
  0000d62c  591800e3      movw     r1, #0x859                                  
  0000d630  04308de5      str      r3, [sp, #4]                                
  0000d634  0420a0e1      mov      r2, r4                                      
  0000d638  08308de5      str      r3, [sp, #8]                                
  0000d63c  0630a0e1      mov      r3, r6                                      
  0000d640  07f4ffeb      bl       #0xa664                                     
  0000d644  ddffffea      b        #0xd5c0                                     
  0000d648  3c2c0200      andeq    r2, r2, ip, lsr ip                          
  0000d64c  902c0200      muleq    r2, r0, ip                                  
  0000d650  882c0200      andeq    r2, r2, r8, lsl #25                         
  0000d654  302c0200      andeq    r2, r2, r0, lsr ip                          
  0000d658  d02b0200      ldrdeq   r2, r3, [r2], -r0                           

; ─── HW_DM_RPC_SetAduitEnable @ 0xd65c ───
  0000d65c  0dc0a0e1      mov      ip, sp                                      
  0000d660  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000d664  005051e2      subs     r5, r1, #0                                  
  0000d668  04b04ce2      sub      fp, ip, #4                                  
  0000d66c  20d04de2      sub      sp, sp, #0x20                               
  0000d670  0240a0e1      mov      r4, r2                                      
  0000d674  2700000a      beq      #0xd718                                     
  0000d678  003095e5      ldr      r3, [r5]                                    
  0000d67c  010053e3      cmp      r3, #1                                      
  0000d680  0e00009a      bls      #0xd6c0                                     
  0000d684  20019fe5      ldr      r0, [pc, #0x120]                            
  0000d688  0030a0e3      mov      r3, #0                                      
  0000d68c  a41700e3      movw     r1, #0x7a4                                  
  0000d690  00308de5      str      r3, [sp]                                    
  0000d694  00008fe0      add      r0, pc, r0                                  
  0000d698  04308de5      str      r3, [sp, #4]                                
  0000d69c  012005e3      movw     r2, #0x5001                                 
  0000d6a0  08308de5      str      r3, [sp, #8]                                
  0000d6a4  20274fe3      movt     r2, #0xf720                                 
  0000d6a8  014005e3      movw     r4, #0x5001                                 
  0000d6ac  ecf3ffeb      bl       #0xa664                                     
  0000d6b0  20474fe3      movt     r4, #0xf720                                 
  0000d6b4  0400a0e1      mov      r0, r4                                      
  0000d6b8  14d04be2      sub      sp, fp, #0x14                               
  0000d6bc  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000d6c0  1010a0e3      mov      r1, #0x10                                   
  0000d6c4  0020a0e3      mov      r2, #0                                      
  0000d6c8  0130a0e1      mov      r3, r1                                      
  0000d6cc  24004be2      sub      r0, fp, #0x24                               
  0000d6d0  04f4ffeb      bl       #0xa6e8                                     
  0000d6d4  0410a0e1      mov      r1, r4                                      
  0000d6d8  0500a0e1      mov      r0, r5                                      
  0000d6dc  be2ca0e3      mov      r2, #0xbe00                                 
  0000d6e0  24304be2      sub      r3, fp, #0x24                               
  0000d6e4  012642e3      movt     r2, #0x2601                                 
  0000d6e8  35f3ffeb      bl       #0xa3c4                                     
  0000d6ec  004050e2      subs     r4, r0, #0                                  
  0000d6f0  1500001a      bne      #0xd74c                                     
  0000d6f4  be0ca0e3      mov      r0, #0xbe00                                 
  0000d6f8  24104be2      sub      r1, fp, #0x24                               
  0000d6fc  010642e3      movt     r0, #0x2601                                 
  0000d700  aff7ffeb      bl       #0xb5c4                                     
  0000d704  004050e2      subs     r4, r0, #0                                  
  0000d708  1a00001a      bne      #0xd778                                     
  0000d70c  24004be2      sub      r0, fp, #0x24                               
  0000d710  86f8ffeb      bl       #0xb930                                     
  0000d714  e6ffffea      b        #0xd6b4                                     
  0000d718  90009fe5      ldr      r0, [pc, #0x90]                             
  0000d71c  9b1700e3      movw     r1, #0x79b                                  
  0000d720  00508de5      str      r5, [sp]                                    
  0000d724  012005e3      movw     r2, #0x5001                                 
  0000d728  04508de5      str      r5, [sp, #4]                                
  0000d72c  20274fe3      movt     r2, #0xf720                                 
  0000d730  08508de5      str      r5, [sp, #8]                                
  0000d734  00008fe0      add      r0, pc, r0                                  
  0000d738  0530a0e1      mov      r3, r5                                      
  0000d73c  014005e3      movw     r4, #0x5001                                 
  0000d740  c7f3ffeb      bl       #0xa664                                     
  0000d744  20474fe3      movt     r4, #0xf720                                 
  0000d748  d9ffffea      b        #0xd6b4                                     
  0000d74c  60009fe5      ldr      r0, [pc, #0x60]                             
  0000d750  00c0a0e3      mov      ip, #0                                      
  0000d754  003095e5      ldr      r3, [r5]                                    
  0000d758  b11700e3      movw     r1, #0x7b1                                  
  0000d75c  00008fe0      add      r0, pc, r0                                  
  0000d760  00c08de5      str      ip, [sp]                                    
  0000d764  0420a0e1      mov      r2, r4                                      
  0000d768  04c08de5      str      ip, [sp, #4]                                
  0000d76c  08c08de5      str      ip, [sp, #8]                                
  0000d770  bbf3ffeb      bl       #0xa664                                     
  0000d774  ceffffea      b        #0xd6b4                                     
  0000d778  0000a0e3      mov      r0, #0                                      
  0000d77c  00008de5      str      r0, [sp]                                    
  0000d780  04008de5      str      r0, [sp, #4]                                
  0000d784  0030a0e1      mov      r3, r0                                      
  0000d788  08008de5      str      r0, [sp, #8]                                
  0000d78c  b91700e3      movw     r1, #0x7b9                                  
  0000d790  20009fe5      ldr      r0, [pc, #0x20]                             
  0000d794  0420a0e1      mov      r2, r4                                      
  0000d798  00008fe0      add      r0, pc, r0                                  
  0000d79c  b0f3ffeb      bl       #0xa664                                     
  0000d7a0  24004be2      sub      r0, fp, #0x24                               
  0000d7a4  61f8ffeb      bl       #0xb930                                     
  0000d7a8  c1ffffea      b        #0xd6b4                                     
  0000d7ac  a02a0200      andeq    r2, r2, r0, lsr #21                         
  0000d7b0  002a0200      andeq    r2, r2, r0, lsl #20                         
  0000d7b4  d8290200      ldrdeq   r2, r3, [r2], -r8                           
  0000d7b8  9c290200      muleq    r2, ip, sb                                  

; ─── HW_DM_GetFlashInfo_Func @ 0xd7bc ───
  0000d7bc  0dc0a0e1      mov      ip, sp                                      
  0000d7c0  1c10a0e3      mov      r1, #0x1c                                   
  0000d7c4  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000d7c8  04b04ce2      sub      fp, ip, #4                                  
  0000d7cc  30d04de2      sub      sp, sp, #0x30                               
  0000d7d0  0130a0e1      mov      r3, r1                                      
  0000d7d4  0020a0e3      mov      r2, #0                                      
  0000d7d8  0040a0e1      mov      r4, r0                                      
  0000d7dc  30004be2      sub      r0, fp, #0x30                               
  0000d7e0  c0f3ffeb      bl       #0xa6e8                                     
  0000d7e4  0200a0e3      mov      r0, #2                                      
  0000d7e8  30104be2      sub      r1, fp, #0x30                               
  0000d7ec  d4f7ffeb      bl       #0xb744                                     
  0000d7f0  005050e2      subs     r5, r0, #0                                  
  0000d7f4  0d00001a      bne      #0xd830                                     
  0000d7f8  1c301be5      ldr      r3, [fp, #-0x1c]                            
  0000d7fc  033aa0e1      lsl      r3, r3, #0x14                               
  0000d800  2314a0e1      lsr      r1, r3, #8                                  
  0000d804  7300efe6      uxtb     r0, r3                                      
  0000d808  2328a0e1      lsr      r2, r3, #0x10                               
  0000d80c  0000c4e5      strb     r0, [r4]                                    
  0000d810  233ca0e1      lsr      r3, r3, #0x18                               
  0000d814  7110efe6      uxtb     r1, r1                                      
  0000d818  0220c4e5      strb     r2, [r4, #2]                                
  0000d81c  0110c4e5      strb     r1, [r4, #1]                                
  0000d820  0330c4e5      strb     r3, [r4, #3]                                
  0000d824  0500a0e1      mov      r0, r5                                      
  0000d828  14d04be2      sub      sp, fp, #0x14                               
  0000d82c  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000d830  20009fe5      ldr      r0, [pc, #0x20]                             
  0000d834  0030a0e3      mov      r3, #0                                      
  0000d838  341a00e3      movw     r1, #0xa34                                  
  0000d83c  00308de5      str      r3, [sp]                                    
  0000d840  00008fe0      add      r0, pc, r0                                  
  0000d844  04308de5      str      r3, [sp, #4]                                
  0000d848  0520a0e1      mov      r2, r5                                      
  0000d84c  08308de5      str      r3, [sp, #8]                                
  0000d850  83f3ffeb      bl       #0xa664                                     
  0000d854  f2ffffea      b        #0xd824                                     
  0000d858  f4280200      strdeq   r2, r3, [r2], -r4                           

; ─── HW_DM_RPC_HardWareSelfTest @ 0xd85c ───
  0000d85c  0dc0a0e1      mov      ip, sp                                      
  0000d860  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000d864  004053e2      subs     r4, r3, #0                                  
  0000d868  04b04ce2      sub      fp, ip, #4                                  
  0000d86c  10d04de2      sub      sp, sp, #0x10                               
  0000d870  0e00000a      beq      #0xd8b0                                     
  0000d874  88509fe5      ldr      r5, [pc, #0x88]                             
  0000d878  082800e3      movw     r2, #0x808                                  
  0000d87c  84309fe5      ldr      r3, [pc, #0x84]                             
  0000d880  8e0100e3      movw     r0, #0x18e                                  
  0000d884  05508fe0      add      r5, pc, r5                                  
  0000d888  03308fe0      add      r3, pc, r3                                  
  0000d88c  0510a0e1      mov      r1, r5                                      
  0000d890  00f4ffeb      bl       #0xa898                                     
  0000d894  0400a0e1      mov      r0, r4                                      
  0000d898  6bf6ffeb      bl       #0xb24c                                     
  0000d89c  004050e2      subs     r4, r0, #0                                  
  0000d8a0  0e00001a      bne      #0xd8e0                                     
  0000d8a4  0400a0e1      mov      r0, r4                                      
  0000d8a8  14d04be2      sub      sp, fp, #0x14                               
  0000d8ac  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000d8b0  54009fe5      ldr      r0, [pc, #0x54]                             
  0000d8b4  041800e3      movw     r1, #0x804                                  
  0000d8b8  00408de5      str      r4, [sp]                                    
  0000d8bc  032405e3      movw     r2, #0x5403                                 
  0000d8c0  04408de5      str      r4, [sp, #4]                                
  0000d8c4  20274fe3      movt     r2, #0xf720                                 
  0000d8c8  08408de5      str      r4, [sp, #8]                                
  0000d8cc  00008fe0      add      r0, pc, r0                                  
  0000d8d0  034405e3      movw     r4, #0x5403                                 
  0000d8d4  62f3ffeb      bl       #0xa664                                     
  0000d8d8  20474fe3      movt     r4, #0xf720                                 
  0000d8dc  f0ffffea      b        #0xd8a4                                     
  0000d8e0  0030a0e3      mov      r3, #0                                      
  0000d8e4  0500a0e1      mov      r0, r5                                      
  0000d8e8  00308de5      str      r3, [sp]                                    
  0000d8ec  811ea0e3      mov      r1, #0x810                                  
  0000d8f0  04308de5      str      r3, [sp, #4]                                
  0000d8f4  0420a0e1      mov      r2, r4                                      
  0000d8f8  08308de5      str      r3, [sp, #8]                                
  0000d8fc  58f3ffeb      bl       #0xa664                                     
  0000d900  e7ffffea      b        #0xd8a4                                     
  0000d904  b0280200      strheq   r2, [r2], -r0                               
  0000d908  8c290200      andeq    r2, r2, ip, lsl #19                         
  0000d90c  68280200      andeq    r2, r2, r8, ror #16                         

; ─── HW_DM_RPC_GetAduitEnable @ 0xd910 ───
  0000d910  0dc0a0e1      mov      ip, sp                                      
  0000d914  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000d918  005053e2      subs     r5, r3, #0                                  
  0000d91c  04b04ce2      sub      fp, ip, #4                                  
  0000d920  20d04de2      sub      sp, sp, #0x20                               
  0000d924  2000000a      beq      #0xd9ac                                     
  0000d928  0100a0e1      mov      r0, r1                                      
  0000d92c  24304be2      sub      r3, fp, #0x24                               
  0000d930  0210a0e1      mov      r1, r2                                      
  0000d934  be2ca0e3      mov      r2, #0xbe00                                 
  0000d938  012642e3      movt     r2, #0x2601                                 
  0000d93c  a1f4ffeb      bl       #0xabc8                                     
  0000d940  004050e2      subs     r4, r0, #0                                  
  0000d944  0c00001a      bne      #0xd97c                                     
  0000d948  24004be2      sub      r0, fp, #0x24                               
  0000d94c  be1ca0e3      mov      r1, #0xbe00                                 
  0000d950  0520a0e1      mov      r2, r5                                      
  0000d954  011642e3      movt     r1, #0x2601                                 
  0000d958  04309be5      ldr      r3, [fp, #4]                                
  0000d95c  5cf2ffeb      bl       #0xa2d4                                     
  0000d960  004050e2      subs     r4, r0, #0                                  
  0000d964  1c00001a      bne      #0xd9dc                                     
  0000d968  24004be2      sub      r0, fp, #0x24                               
  0000d96c  eff7ffeb      bl       #0xb930                                     
  0000d970  0400a0e1      mov      r0, r4                                      
  0000d974  14d04be2      sub      sp, fp, #0x14                               
  0000d978  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000d97c  88009fe5      ldr      r0, [pc, #0x88]                             
  0000d980  0030a0e3      mov      r3, #0                                      
  0000d984  e11700e3      movw     r1, #0x7e1                                  
  0000d988  00308de5      str      r3, [sp]                                    
  0000d98c  04308de5      str      r3, [sp, #4]                                
  0000d990  00008fe0      add      r0, pc, r0                                  
  0000d994  08308de5      str      r3, [sp, #8]                                
  0000d998  0420a0e1      mov      r2, r4                                      
  0000d99c  be3ca0e3      mov      r3, #0xbe00                                 
  0000d9a0  013642e3      movt     r3, #0x2601                                 
  0000d9a4  2ef3ffeb      bl       #0xa664                                     
  0000d9a8  f0ffffea      b        #0xd970                                     
  0000d9ac  5c009fe5      ldr      r0, [pc, #0x5c]                             
  0000d9b0  d61700e3      movw     r1, #0x7d6                                  
  0000d9b4  00508de5      str      r5, [sp]                                    
  0000d9b8  032405e3      movw     r2, #0x5403                                 
  0000d9bc  04508de5      str      r5, [sp, #4]                                
  0000d9c0  20274fe3      movt     r2, #0xf720                                 
  0000d9c4  08508de5      str      r5, [sp, #8]                                
  0000d9c8  00008fe0      add      r0, pc, r0                                  
  0000d9cc  034405e3      movw     r4, #0x5403                                 
  0000d9d0  23f3ffeb      bl       #0xa664                                     
  0000d9d4  20474fe3      movt     r4, #0xf720                                 
  0000d9d8  e4ffffea      b        #0xd970                                     
  0000d9dc  0000a0e3      mov      r0, #0                                      
  0000d9e0  00008de5      str      r0, [sp]                                    
  0000d9e4  04008de5      str      r0, [sp, #4]                                
  0000d9e8  be3ca0e3      mov      r3, #0xbe00                                 
  0000d9ec  08008de5      str      r0, [sp, #8]                                
  0000d9f0  eb1700e3      movw     r1, #0x7eb                                  
  0000d9f4  18009fe5      ldr      r0, [pc, #0x18]                             
  0000d9f8  0420a0e1      mov      r2, r4                                      
  0000d9fc  013642e3      movt     r3, #0x2601                                 
  0000da00  00008fe0      add      r0, pc, r0                                  
  0000da04  16f3ffeb      bl       #0xa664                                     
  0000da08  d6ffffea      b        #0xd968                                     
  0000da0c  a4270200      andeq    r2, r2, r4, lsr #15                         
  0000da10  6c270200      andeq    r2, r2, ip, ror #14                         
  0000da14  34270200      andeq    r2, r2, r4, lsr r7                          

; ─── HW_DM_PDT_GetManufactureOUI_Func @ 0xda18 ───
  0000da18  0dc0a0e1      mov      ip, sp                                      
  0000da1c  022ca0e3      mov      r2, #0x200                                  
  0000da20  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000da24  04b04ce2      sub      fp, ip, #4                                  
  0000da28  86df4de2      sub      sp, sp, #0x218                              
  0000da2c  8acf4be2      sub      ip, fp, #0x228                              
  0000da30  0040a0e3      mov      r4, #0                                      
  0000da34  78a19fe5      ldr      sl, [pc, #0x178]                            
  0000da38  0060a0e1      mov      r6, r0                                      
  0000da3c  0150a0e1      mov      r5, r1                                      
  0000da40  890f4be2      sub      r0, fp, #0x224                              
  0000da44  0410a0e1      mov      r1, r4                                      
  0000da48  b240cce0      strh     r4, [ip], #2                                
  0000da4c  0aa08fe0      add      sl, pc, sl                                  
  0000da50  0040cce5      strb     r4, [ip]                                    
  0000da54  2c420be5      str      r4, [fp, #-0x22c]                           
  0000da58  7df2ffeb      bl       #0xa454                                     
  0000da5c  54319fe5      ldr      r3, [pc, #0x154]                            
  0000da60  1600a0e3      mov      r0, #0x16                                   
  0000da64  0a10a0e1      mov      r1, sl                                      
  0000da68  ac2800e3      movw     r2, #0x8ac                                  
  0000da6c  03308fe0      add      r3, pc, r3                                  
  0000da70  00608de5      str      r6, [sp]                                    
  0000da74  04508de5      str      r5, [sp, #4]                                
  0000da78  86f3ffeb      bl       #0xa898                                     
  0000da7c  38019fe5      ldr      r0, [pc, #0x138]                            
  0000da80  00008fe0      add      r0, pc, r0                                  
  0000da84  bbf4ffeb      bl       #0xad78                                     
  0000da88  010050e3      cmp      r0, #1                                      
  0000da8c  1900000a      beq      #0xdaf8                                     
  0000da90  8b8f4be2      sub      r8, fp, #0x22c                              
  0000da94  4600a0e3      mov      r0, #0x46                                   
  0000da98  0710a0e3      mov      r1, #7                                      
  0000da9c  000041e3      movt     r0, #0x1000                                 
  0000daa0  0820a0e1      mov      r2, r8                                      
  0000daa4  28f2ffeb      bl       #0xa34c                                     
  0000daa8  007050e2      subs     r7, r0, #0                                  
  0000daac  3700001a      bne      #0xdb90                                     
  0000dab0  0710a0e3      mov      r1, #7                                      
  0000dab4  0820a0e1      mov      r2, r8                                      
  0000dab8  0630a0e3      mov      r3, #6                                      
  0000dabc  0500a0e1      mov      r0, r5                                      
  0000dac0  88f1ffeb      bl       #0xa0e8                                     
  0000dac4  f4109fe5      ldr      r1, [pc, #0xf4]                             
  0000dac8  f4309fe5      ldr      r3, [pc, #0xf4]                             
  0000dacc  1600a0e3      mov      r0, #0x16                                   
  0000dad0  00608de5      str      r6, [sp]                                    
  0000dad4  01108fe0      add      r1, pc, r1                                  
  0000dad8  04508de5      str      r5, [sp, #4]                                
  0000dadc  c62800e3      movw     r2, #0x8c6                                  
  0000dae0  03308fe0      add      r3, pc, r3                                  
  0000dae4  0070a0e3      mov      r7, #0                                      
  0000dae8  6af3ffeb      bl       #0xa898                                     
  0000daec  0700a0e1      mov      r0, r7                                      
  0000daf0  24d04be2      sub      sp, fp, #0x24                               
  0000daf4  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000daf8  3f00a0e3      mov      r0, #0x3f                                   
  0000dafc  021ca0e3      mov      r1, #0x200                                  
  0000db00  000141e3      movt     r0, #0x1100                                 
  0000db04  892f4be2      sub      r2, fp, #0x224                              
  0000db08  0ff2ffeb      bl       #0xa34c                                     
  0000db0c  007050e2      subs     r7, r0, #0                                  
  0000db10  1500001a      bne      #0xdb6c                                     
  0000db14  891f4be2      sub      r1, fp, #0x224                              
  0000db18  8b8f4be2      sub      r8, fp, #0x22c                              
  0000db1c  063081e2      add      r3, r1, #6                                  
  0000db20  08308de5      str      r3, [sp, #8]                                
  0000db24  9c309fe5      ldr      r3, [pc, #0x9c]                             
  0000db28  032081e2      add      r2, r1, #3                                  
  0000db2c  00108de5      str      r1, [sp]                                    
  0000db30  0800a0e1      mov      r0, r8                                      
  0000db34  04208de5      str      r2, [sp, #4]                                
  0000db38  0710a0e3      mov      r1, #7                                      
  0000db3c  0620a0e3      mov      r2, #6                                      
  0000db40  03308fe0      add      r3, pc, r3                                  
  0000db44  aaf3ffeb      bl       #0xa9f4                                     
  0000db48  893f4be2      sub      r3, fp, #0x224                              
  0000db4c  08018de8      stm      sp, {r3, r8}                                
  0000db50  1600a0e3      mov      r0, #0x16                                   
  0000db54  70309fe5      ldr      r3, [pc, #0x70]                             
  0000db58  0a10a0e1      mov      r1, sl                                      
  0000db5c  b92800e3      movw     r2, #0x8b9                                  
  0000db60  03308fe0      add      r3, pc, r3                                  
  0000db64  4bf3ffeb      bl       #0xa898                                     
  0000db68  d0ffffea      b        #0xdab0                                     
  0000db6c  00408de5      str      r4, [sp]                                    
  0000db70  0a00a0e1      mov      r0, sl                                      
  0000db74  04408de5      str      r4, [sp, #4]                                
  0000db78  b31800e3      movw     r1, #0x8b3                                  
  0000db7c  08408de5      str      r4, [sp, #8]                                
  0000db80  0720a0e1      mov      r2, r7                                      
  0000db84  0630a0e1      mov      r3, r6                                      
  0000db88  b5f2ffeb      bl       #0xa664                                     
  0000db8c  d6ffffea      b        #0xdaec                                     
  0000db90  00408de5      str      r4, [sp]                                    
  0000db94  0a00a0e1      mov      r0, sl                                      
  0000db98  04408de5      str      r4, [sp, #4]                                
  0000db9c  231da0e3      mov      r1, #0x8c0                                  
  0000dba0  08408de5      str      r4, [sp, #8]                                
  0000dba4  0720a0e1      mov      r2, r7                                      
  0000dba8  0630a0e1      mov      r3, r6                                      
  0000dbac  acf2ffeb      bl       #0xa664                                     
  0000dbb0  cdffffea      b        #0xdaec                                     
  0000dbb4  e8260200      andeq    r2, r2, r8, ror #13                         
  0000dbb8  cc270200      andeq    r2, r2, ip, asr #15                         
  0000dbbc  d4270200      ldrdeq   r2, r3, [r2], -r4                           
  0000dbc0  60260200      andeq    r2, r2, r0, ror #12                         
  0000dbc4  b4270200      strheq   r2, [r2], -r4                               
  0000dbc8  28270200      andeq    r2, r2, r8, lsr #14                         
  0000dbcc  18270200      andeq    r2, r2, r8, lsl r7                          

; ─── HW_SSMP_AP_ConsultSwitch @ 0xdbd0 ───
  0000dbd0  0dc0a0e1      mov      ip, sp                                      
  0000dbd4  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000dbd8  04b04ce2      sub      fp, ip, #4                                  
  0000dbdc  006050e2      subs     r6, r0, #0                                  
  0000dbe0  70d04de2      sub      sp, sp, #0x70                               
  0000dbe4  0040a0e3      mov      r4, #0                                      
  0000dbe8  0370a0e3      mov      r7, #3                                      
  0000dbec  6c400be5      str      r4, [fp, #-0x6c]                            
  0000dbf0  68400be5      str      r4, [fp, #-0x68]                            
  0000dbf4  b4464be1      strh     r4, [fp, #-0x64]                            
  0000dbf8  78700be5      str      r7, [fp, #-0x78]                            
  0000dbfc  74400be5      str      r4, [fp, #-0x74]                            
  0000dc00  70400be5      str      r4, [fp, #-0x70]                            
  0000dc04  3500000a      beq      #0xdce0                                     
  0000dc08  0100a0e3      mov      r0, #1                                      
  0000dc0c  0410a0e3      mov      r1, #4                                      
  0000dc10  70204be2      sub      r2, fp, #0x70                               
  0000dc14  ccf1ffeb      bl       #0xa34c                                     
  0000dc18  005050e2      subs     r5, r0, #0                                  
  0000dc1c  2500001a      bne      #0xdcb8                                     
  0000dc20  003096e5      ldr      r3, [r6]                                    
  0000dc24  60004be2      sub      r0, fp, #0x60                               
  0000dc28  7c300be5      str      r3, [fp, #-0x7c]                            
  0000dc2c  2cf5ffeb      bl       #0xb0e4                                     
  0000dc30  7c301be5      ldr      r3, [fp, #-0x7c]                            
  0000dc34  010053e3      cmp      r3, #1                                      
  0000dc38  3f00000a      beq      #0xdd3c                                     
  0000dc3c  030053e3      cmp      r3, #3                                      
  0000dc40  6c404be2      sub      r4, fp, #0x6c                               
  0000dc44  4b00000a      beq      #0xdd78                                     
  0000dc48  0410a0e3      mov      r1, #4                                      
  0000dc4c  78204be2      sub      r2, fp, #0x78                               
  0000dc50  3300a0e3      mov      r0, #0x33                                   
  0000dc54  000141e3      movt     r0, #0x1100                                 
  0000dc58  95f6ffeb      bl       #0xb6b4                                     
  0000dc5c  0410a0e3      mov      r1, #4                                      
  0000dc60  7c204be2      sub      r2, fp, #0x7c                               
  0000dc64  0050a0e1      mov      r5, r0                                      
  0000dc68  9200a0e3      mov      r0, #0x92                                   
  0000dc6c  000141e3      movt     r0, #0x1100                                 
  0000dc70  8ff6ffeb      bl       #0xb6b4                                     
  0000dc74  0410a0e3      mov      r1, #4                                      
  0000dc78  70204be2      sub      r2, fp, #0x70                               
  0000dc7c  055080e1      orr      r5, r0, r5                                  
  0000dc80  6200a0e3      mov      r0, #0x62                                   
  0000dc84  000141e3      movt     r0, #0x1100                                 
  0000dc88  89f6ffeb      bl       #0xb6b4                                     
  0000dc8c  005085e1      orr      r5, r5, r0                                  
  0000dc90  0400a0e1      mov      r0, r4                                      
  0000dc94  0bf3ffeb      bl       #0xa8c8                                     
  0000dc98  005095e1      orrs     r5, r5, r0                                  
  0000dc9c  1c00001a      bne      #0xdd14                                     
  0000dca0  0100a0e3      mov      r0, #1                                      
  0000dca4  68f2ffeb      bl       #0xa64c                                     
  0000dca8  9df5ffeb      bl       #0xb324                                     
  0000dcac  0500a0e1      mov      r0, r5                                      
  0000dcb0  1cd04be2      sub      sp, fp, #0x1c                               
  0000dcb4  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000dcb8  30019fe5      ldr      r0, [pc, #0x130]                            
  0000dcbc  111c00e3      movw     r1, #0xc11                                  
  0000dcc0  00408de5      str      r4, [sp]                                    
  0000dcc4  0520a0e1      mov      r2, r5                                      
  0000dcc8  04408de5      str      r4, [sp, #4]                                
  0000dccc  0430a0e1      mov      r3, r4                                      
  0000dcd0  08408de5      str      r4, [sp, #8]                                
  0000dcd4  00008fe0      add      r0, pc, r0                                  
  0000dcd8  61f2ffeb      bl       #0xa664                                     
  0000dcdc  f2ffffea      b        #0xdcac                                     
  0000dce0  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0000dce4  0a1c00e3      movw     r1, #0xc0a                                  
  0000dce8  00608de5      str      r6, [sp]                                    
  0000dcec  032405e3      movw     r2, #0x5403                                 
  0000dcf0  04608de5      str      r6, [sp, #4]                                
  0000dcf4  20274fe3      movt     r2, #0xf720                                 
  0000dcf8  08608de5      str      r6, [sp, #8]                                
  0000dcfc  00008fe0      add      r0, pc, r0                                  
  0000dd00  0630a0e1      mov      r3, r6                                      
  0000dd04  035405e3      movw     r5, #0x5403                                 
  0000dd08  55f2ffeb      bl       #0xa664                                     
  0000dd0c  20574fe3      movt     r5, #0xf720                                 
  0000dd10  e5ffffea      b        #0xdcac                                     
  0000dd14  dc009fe5      ldr      r0, [pc, #0xdc]                             
  0000dd18  0030a0e3      mov      r3, #0                                      
  0000dd1c  391c00e3      movw     r1, #0xc39                                  
  0000dd20  00308de5      str      r3, [sp]                                    
  0000dd24  00008fe0      add      r0, pc, r0                                  
  0000dd28  04308de5      str      r3, [sp, #4]                                
  0000dd2c  0520a0e1      mov      r2, r5                                      
  0000dd30  08308de5      str      r3, [sp, #8]                                
  0000dd34  4af2ffeb      bl       #0xa664                                     
  0000dd38  dbffffea      b        #0xdcac                                     
  0000dd3c  b8509fe5      ldr      r5, [pc, #0xb8]                             
  0000dd40  60004be2      sub      r0, fp, #0x60                               
  0000dd44  6c404be2      sub      r4, fp, #0x6c                               
  0000dd48  05508fe0      add      r5, pc, r5                                  
  0000dd4c  0510a0e1      mov      r1, r5                                      
  0000dd50  b2f5ffeb      bl       #0xb420                                     
  0000dd54  0a10a0e3      mov      r1, #0xa                                    
  0000dd58  000050e3      cmp      r0, #0                                      
  0000dd5c  1c00000a      beq      #0xddd4                                     
  0000dd60  0520a0e1      mov      r2, r5                                      
  0000dd64  0830a0e3      mov      r3, #8                                      
  0000dd68  0400a0e1      mov      r0, r4                                      
  0000dd6c  78700be5      str      r7, [fp, #-0x78]                            
  0000dd70  dcf0ffeb      bl       #0xa0e8                                     
  0000dd74  b3ffffea      b        #0xdc48                                     
  0000dd78  80209fe5      ldr      r2, [pc, #0x80]                             
  0000dd7c  0530a0e3      mov      r3, #5                                      
  0000dd80  0a10a0e3      mov      r1, #0xa                                    
  0000dd84  0400a0e1      mov      r0, r4                                      
  0000dd88  02208fe0      add      r2, pc, r2                                  
  0000dd8c  0850a0e3      mov      r5, #8                                      
  0000dd90  78500be5      str      r5, [fp, #-0x78]                            
  0000dd94  d3f0ffeb      bl       #0xa0e8                                     
  0000dd98  0410a0e3      mov      r1, #4                                      
  0000dd9c  74204be2      sub      r2, fp, #0x74                               
  0000dda0  0200a0e3      mov      r0, #2                                      
  0000dda4  68f1ffeb      bl       #0xa34c                                     
  0000dda8  54009fe5      ldr      r0, [pc, #0x54]                             
  0000ddac  00008fe0      add      r0, pc, r0                                  
  0000ddb0  f0f3ffeb      bl       #0xad78                                     
  0000ddb4  010050e3      cmp      r0, #1                                      
  0000ddb8  74500b05      streq    r5, [fp, #-0x74]                            
  0000ddbc  74301b15      ldrne    r3, [fp, #-0x74]                            
  0000ddc0  08300403      movweq   r3, #0x4008                                 
  0000ddc4  30304003      movteq   r3, #0x30                                   
  0000ddc8  c1398312      addne    r3, r3, #0x304000                           
  0000ddcc  70300be5      str      r3, [fp, #-0x70]                            
  0000ddd0  9cffffea      b        #0xdc48                                     
  0000ddd4  2c209fe5      ldr      r2, [pc, #0x2c]                             
  0000ddd8  0230a0e3      mov      r3, #2                                      
  0000dddc  0400a0e1      mov      r0, r4                                      
  0000dde0  78700be5      str      r7, [fp, #-0x78]                            
  0000dde4  02208fe0      add      r2, pc, r2                                  
  0000dde8  bef0ffeb      bl       #0xa0e8                                     
  0000ddec  95ffffea      b        #0xdc48                                     
  0000ddf0  60240200      andeq    r2, r2, r0, ror #8                          
  0000ddf4  38240200      andeq    r2, r2, r8, lsr r4                          
  0000ddf8  10240200      andeq    r2, r2, r0, lsl r4                          
  0000ddfc  68250200      andeq    r2, r2, r8, ror #10                         
  0000de00  38250200      andeq    r2, r2, r8, lsr r5                          
  0000de04  1c250200      andeq    r2, r2, ip, lsl r5                          
  0000de08  d8240200      ldrdeq   r2, r3, [r2], -r8                           

; ─── HW_DM_ReplaceStringSpace @ 0xde0c ───
  0000de0c  000050e3      cmp      r0, #0                                      
  0000de10  00005113      cmpne    r1, #0                                      
  0000de14  0dc0a0e1      mov      ip, sp                                      
  0000de18  00d82de9      push     {fp, ip, lr, pc}                            
  0000de1c  04b04ce2      sub      fp, ip, #4                                  
  0000de20  10d04de2      sub      sp, sp, #0x10                               
  0000de24  0020a013      movne    r2, #0                                      
  0000de28  0120a003      moveq    r2, #1                                      
  0000de2c  1a00000a      beq      #0xde9c                                     
  0000de30  0030d0e5      ldrb     r3, [r0]                                    
  0000de34  000053e3      cmp      r3, #0                                      
  0000de38  1100000a      beq      #0xde84                                     
  0000de3c  011080e0      add      r1, r0, r1                                  
  0000de40  010050e1      cmp      r0, r1                                      
  0000de44  1f00002a      bhs      #0xdec8                                     
  0000de48  200053e3      cmp      r3, #0x20                                   
  0000de4c  01308012      addne    r3, r0, #1                                  
  0000de50  01208112      addne    r2, r1, #1                                  
  0000de54  0400001a      bne      #0xde6c                                     
  0000de58  0b0000ea      b        #0xde8c                                     
  0000de5c  020053e1      cmp      r3, r2                                      
  0000de60  0700000a      beq      #0xde84                                     
  0000de64  200050e3      cmp      r0, #0x20                                   
  0000de68  0800000a      beq      #0xde90                                     
  0000de6c  0310a0e1      mov      r1, r3                                      
  0000de70  0100d3e4      ldrb     r0, [r3], #1                                
  0000de74  000050e3      cmp      r0, #0                                      
  0000de78  f7ffff1a      bne      #0xde5c                                     
  0000de7c  0cd04be2      sub      sp, fp, #0xc                                
  0000de80  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000de84  0000a0e3      mov      r0, #0                                      
  0000de88  fbffffea      b        #0xde7c                                     
  0000de8c  0010a0e1      mov      r1, r0                                      
  0000de90  0000a0e3      mov      r0, #0                                      
  0000de94  0000c1e5      strb     r0, [r1]                                    
  0000de98  f7ffffea      b        #0xde7c                                     
  0000de9c  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000dea0  0030a0e3      mov      r3, #0                                      
  0000dea4  5d10a0e3      mov      r1, #0x5d                                   
  0000dea8  00308de5      str      r3, [sp]                                    
  0000deac  00008fe0      add      r0, pc, r0                                  
  0000deb0  04308de5      str      r3, [sp, #4]                                
  0000deb4  0120a0e3      mov      r2, #1                                      
  0000deb8  08308de5      str      r3, [sp, #8]                                
  0000debc  e8f1ffeb      bl       #0xa664                                     
  0000dec0  0100a0e3      mov      r0, #1                                      
  0000dec4  ecffffea      b        #0xde7c                                     
  0000dec8  0200a0e1      mov      r0, r2                                      
  0000decc  eaffffea      b        #0xde7c                                     
  0000ded0  88220200      andeq    r2, r2, r8, lsl #5                          

; ─── HW_DM_AdditionalHardwareVersion @ 0xded4 ───
  0000ded4  0dc0a0e1      mov      ip, sp                                      
  0000ded8  000051e3      cmp      r1, #0                                      
  0000dedc  00005213      cmpne    r2, #0                                      
  0000dee0  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  0000dee4  04b04ce2      sub      fp, ip, #4                                  
  0000dee8  57df4de2      sub      sp, sp, #0x15c                              
  0000deec  0030a0e3      mov      r3, #0                                      
  0000def0  0250a0e1      mov      r5, r2                                      
  0000def4  0140a0e1      mov      r4, r1                                      
  0000def8  0070a013      movne    r7, #0                                      
  0000defc  0170a003      moveq    r7, #1                                      
  0000df00  6c310be5      str      r3, [fp, #-0x16c]                           
  0000df04  0800000a      beq      #0xdf2c                                     
  0000df08  a4019fe5      ldr      r0, [pc, #0x1a4]                            
  0000df0c  00008fe0      add      r0, pc, r0                                  
  0000df10  98f3ffeb      bl       #0xad78                                     
  0000df14  010050e3      cmp      r0, #1                                      
  0000df18  0760a011      movne    r6, r7                                      
  0000df1c  0c00000a      beq      #0xdf54                                     
  0000df20  0600a0e1      mov      r0, r6                                      
  0000df24  20d04be2      sub      sp, fp, #0x20                               
  0000df28  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  0000df2c  84019fe5      ldr      r0, [pc, #0x184]                            
  0000df30  0120a0e3      mov      r2, #1                                      
  0000df34  00308de5      str      r3, [sp]                                    
  0000df38  cc10a0e3      mov      r1, #0xcc                                   
  0000df3c  04308de5      str      r3, [sp, #4]                                
  0000df40  00008fe0      add      r0, pc, r0                                  
  0000df44  08308de5      str      r3, [sp, #8]                                
  0000df48  0260a0e1      mov      r6, r2                                      
  0000df4c  c4f1ffeb      bl       #0xa664                                     
  0000df50  f2ffffea      b        #0xdf20                                     
  0000df54  60219fe5      ldr      r2, [pc, #0x160]                            
  0000df58  2010a0e3      mov      r1, #0x20                                   
  0000df5c  1f30a0e3      mov      r3, #0x1f                                   
  0000df60  590f4be2      sub      r0, fp, #0x164                              
  0000df64  02208fe0      add      r2, pc, r2                                  
  0000df68  8ac0a0e3      mov      ip, #0x8a                                   
  0000df6c  44710be5      str      r7, [fp, #-0x144]                           
  0000df70  20c10be5      str      ip, [fp, #-0x120]                           
  0000df74  5bf0ffeb      bl       #0xa0e8                                     
  0000df78  40219fe5      ldr      r2, [pc, #0x140]                            
  0000df7c  2010a0e3      mov      r1, #0x20                                   
  0000df80  1f30a0e3      mov      r3, #0x1f                                   
  0000df84  050d4be2      sub      r0, fp, #0x140                              
  0000df88  02208fe0      add      r2, pc, r2                                  
  0000df8c  55f0ffeb      bl       #0xa0e8                                     
  0000df90  0430a0e3      mov      r3, #4                                      
  0000df94  5a0f4be2      sub      r0, fp, #0x168                              
  0000df98  00308de5      str      r3, [sp]                                    
  0000df9c  0310a0e3      mov      r1, #3                                      
  0000dfa0  453f4be2      sub      r3, fp, #0x114                              
  0000dfa4  0720a0e1      mov      r2, r7                                      
  0000dfa8  04308de5      str      r3, [sp, #4]                                
  0000dfac  601744e3      movt     r1, #0x4760                                 
  0000dfb0  ef30a0e3      mov      r3, #0xef                                   
  0000dfb4  08308de5      str      r3, [sp, #8]                                
  0000dfb8  e03e02e3      movw     r3, #0x2ee0                                 
  0000dfbc  0c308de5      str      r3, [sp, #0xc]                              
  0000dfc0  5b3f4be2      sub      r3, fp, #0x16c                              
  0000dfc4  65f3ffeb      bl       #0xad60                                     
  0000dfc8  006050e2      subs     r6, r0, #0                                  
  0000dfcc  2400001a      bne      #0xe064                                     
  0000dfd0  1110a0e3      mov      r1, #0x11                                   
  0000dfd4  84004be2      sub      r0, fp, #0x84                               
  0000dfd8  74604be5      strb     r6, [fp, #-0x74]                            
  0000dfdc  0680a0e1      mov      r8, r6                                      
  0000dfe0  3d604be5      strb     r6, [fp, #-0x3d]                            
  0000dfe4  36604be5      strb     r6, [fp, #-0x36]                            
  0000dfe8  92f3ffeb      bl       #0xae38                                     
  0000dfec  006050e2      subs     r6, r0, #0                                  
  0000dff0  1100001a      bne      #0xe03c                                     
  0000dff4  1110a0e3      mov      r1, #0x11                                   
  0000dff8  4d004be2      sub      r0, fp, #0x4d                               
  0000dffc  8df3ffeb      bl       #0xae38                                     
  0000e000  006050e2      subs     r6, r0, #0                                  
  0000e004  2000001a      bne      #0xe08c                                     
  0000e008  84304be2      sub      r3, fp, #0x84                               
  0000e00c  00308de5      str      r3, [sp]                                    
  0000e010  3c304be2      sub      r3, fp, #0x3c                               
  0000e014  04308de5      str      r3, [sp, #4]                                
  0000e018  4d304be2      sub      r3, fp, #0x4d                               
  0000e01c  08308de5      str      r3, [sp, #8]                                
  0000e020  9c309fe5      ldr      r3, [pc, #0x9c]                             
  0000e024  0510a0e1      mov      r1, r5                                      
  0000e028  0400a0e1      mov      r0, r4                                      
  0000e02c  0520a0e1      mov      r2, r5                                      
  0000e030  03308fe0      add      r3, pc, r3                                  
  0000e034  6ef2ffeb      bl       #0xa9f4                                     
  0000e038  b8ffffea      b        #0xdf20                                     
  0000e03c  84009fe5      ldr      r0, [pc, #0x84]                             
  0000e040  f010a0e3      mov      r1, #0xf0                                   
  0000e044  00708de5      str      r7, [sp]                                    
  0000e048  0620a0e1      mov      r2, r6                                      
  0000e04c  04708de5      str      r7, [sp, #4]                                
  0000e050  0730a0e1      mov      r3, r7                                      
  0000e054  08708de5      str      r7, [sp, #8]                                
  0000e058  00008fe0      add      r0, pc, r0                                  
  0000e05c  80f1ffeb      bl       #0xa664                                     
  0000e060  aeffffea      b        #0xdf20                                     
  0000e064  60009fe5      ldr      r0, [pc, #0x60]                             
  0000e068  e410a0e3      mov      r1, #0xe4                                   
  0000e06c  00708de5      str      r7, [sp]                                    
  0000e070  0620a0e1      mov      r2, r6                                      
  0000e074  04708de5      str      r7, [sp, #4]                                
  0000e078  0730a0e1      mov      r3, r7                                      
  0000e07c  08708de5      str      r7, [sp, #8]                                
  0000e080  00008fe0      add      r0, pc, r0                                  
  0000e084  76f1ffeb      bl       #0xa664                                     
  0000e088  a4ffffea      b        #0xdf20                                     
  0000e08c  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0000e090  f810a0e3      mov      r1, #0xf8                                   
  0000e094  00808de5      str      r8, [sp]                                    
  0000e098  0620a0e1      mov      r2, r6                                      
  0000e09c  04808de5      str      r8, [sp, #4]                                
  0000e0a0  0830a0e1      mov      r3, r8                                      
  0000e0a4  08808de5      str      r8, [sp, #8]                                
  0000e0a8  00008fe0      add      r0, pc, r0                                  
  0000e0ac  6cf1ffeb      bl       #0xa664                                     
  0000e0b0  9affffea      b        #0xdf20                                     
  0000e0b4  d0230200      ldrdeq   r2, r3, [r2], -r0                           
  0000e0b8  f4210200      strdeq   r2, r3, [r2], -r4                           
  0000e0bc  701f0200      andeq    r1, r2, r0, ror pc                          
  0000e0c0  68230200      andeq    r2, r2, r8, ror #6                          
  0000e0c4  c4220200      andeq    r2, r2, r4, asr #5                          
  0000e0c8  dc200200      ldrdeq   r2, r3, [r2], -ip                           
  0000e0cc  b4200200      strheq   r2, [r2], -r4                               
  0000e0d0  8c200200      andeq    r2, r2, ip, lsl #1                          

; ─── HW_DM_PDT_GetResetFlag_From_SDK @ 0xe0d4 ───
  0000e0d4  0dc0a0e1      mov      ip, sp                                      
  0000e0d8  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000e0dc  04b04ce2      sub      fp, ip, #4                                  
  0000e0e0  14d04de2      sub      sp, sp, #0x14                               
  0000e0e4  48f2ffeb      bl       #0xaa0c                                     
  0000e0e8  004050e2      subs     r4, r0, #0                                  
  0000e0ec  0800000a      beq      #0xe114                                     
  0000e0f0  28009fe5      ldr      r0, [pc, #0x28]                             
  0000e0f4  0030a0e3      mov      r3, #0                                      
  0000e0f8  1a1100e3      movw     r1, #0x11a                                  
  0000e0fc  00308de5      str      r3, [sp]                                    
  0000e100  00008fe0      add      r0, pc, r0                                  
  0000e104  04308de5      str      r3, [sp, #4]                                
  0000e108  0420a0e1      mov      r2, r4                                      
  0000e10c  08308de5      str      r3, [sp, #8]                                
  0000e110  53f1ffeb      bl       #0xa664                                     
  0000e114  0400a0e1      mov      r0, r4                                      
  0000e118  10d04be2      sub      sp, fp, #0x10                               
  0000e11c  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000e120  34200200      andeq    r2, r2, r4, lsr r0                          

; ─── HW_DM_PDT_SetResetFlag @ 0xe124 ───
  0000e124  0dc0a0e1      mov      ip, sp                                      
  0000e128  00d82de9      push     {fp, ip, lr, pc}                            
  0000e12c  04b04ce2      sub      fp, ip, #4                                  
  0000e130  10d04de2      sub      sp, sp, #0x10                               
  0000e134  18204be2      sub      r2, fp, #0x18                               
  0000e138  1c100be5      str      r1, [fp, #-0x1c]                            
  0000e13c  0410a0e3      mov      r1, #4                                      
  0000e140  18000be5      str      r0, [fp, #-0x18]                            
  0000e144  0130a0e1      mov      r3, r1                                      
  0000e148  14004be2      sub      r0, fp, #0x14                               
  0000e14c  00c0a0e3      mov      ip, #0                                      
  0000e150  14c00be5      str      ip, [fp, #-0x14]                            
  0000e154  10c00be5      str      ip, [fp, #-0x10]                            
  0000e158  88f2ffeb      bl       #0xab80                                     
  0000e15c  0410a0e3      mov      r1, #4                                      
  0000e160  10004be2      sub      r0, fp, #0x10                               
  0000e164  0130a0e1      mov      r3, r1                                      
  0000e168  1c204be2      sub      r2, fp, #0x1c                               
  0000e16c  83f2ffeb      bl       #0xab80                                     
  0000e170  14004be2      sub      r0, fp, #0x14                               
  0000e174  0810a0e3      mov      r1, #8                                      
  0000e178  ecefffeb      bl       #0xa130                                     
  0000e17c  0cd04be2      sub      sp, fp, #0xc                                
  0000e180  00a89de8      ldm      sp, {fp, sp, pc}                            

; ─── HW_DM_PDT_SetLossPowerResetFlag @ 0xe184 ───
  0000e184  0dc0a0e1      mov      ip, sp                                      
  0000e188  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000e18c  04b04ce2      sub      fp, ip, #4                                  
  0000e190  14004be2      sub      r0, fp, #0x14                               
  0000e194  18d04de2      sub      sp, sp, #0x18                               
  0000e198  0040a0e3      mov      r4, #0                                      
  0000e19c  044020e5      str      r4, [r0, #-4]!                              
  0000e1a0  6ef1ffeb      bl       #0xa760                                     
  0000e1a4  005050e2      subs     r5, r0, #0                                  
  0000e1a8  0a00001a      bne      #0xe1d8                                     
  0000e1ac  18301be5      ldr      r3, [fp, #-0x18]                            
  0000e1b0  000053e3      cmp      r3, #0                                      
  0000e1b4  0200000a      beq      #0xe1c4                                     
  0000e1b8  0500a0e1      mov      r0, r5                                      
  0000e1bc  14d04be2      sub      sp, fp, #0x14                               
  0000e1c0  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000e1c4  aa0505e3      movw     r0, #0x55aa                                 
  0000e1c8  0210a0e3      mov      r1, #2                                      
  0000e1cc  550a4ae3      movt     r0, #0xaa55                                 
  0000e1d0  eeefffeb      bl       #0xa190                                     
  0000e1d4  f7ffffea      b        #0xe1b8                                     
  0000e1d8  20009fe5      ldr      r0, [pc, #0x20]                             
  0000e1dc  4e1100e3      movw     r1, #0x14e                                  
  0000e1e0  00408de5      str      r4, [sp]                                    
  0000e1e4  0520a0e1      mov      r2, r5                                      
  0000e1e8  04408de5      str      r4, [sp, #4]                                
  0000e1ec  0430a0e1      mov      r3, r4                                      
  0000e1f0  08408de5      str      r4, [sp, #8]                                
  0000e1f4  00008fe0      add      r0, pc, r0                                  
  0000e1f8  19f1ffeb      bl       #0xa664                                     
  0000e1fc  edffffea      b        #0xe1b8                                     
  0000e200  401f0200      andeq    r1, r2, r0, asr #30                         

; ─── HW_DM_CloseUsbPower @ 0xe204 ───
  0000e204  c8009fe5      ldr      r0, [pc, #0xc8]                             
  0000e208  0dc0a0e1      mov      ip, sp                                      
  0000e20c  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000e210  04b04ce2      sub      fp, ip, #4                                  
  0000e214  18d04de2      sub      sp, sp, #0x18                               
  0000e218  00008fe0      add      r0, pc, r0                                  
  0000e21c  0050a0e3      mov      r5, #0                                      
  0000e220  18500be5      str      r5, [fp, #-0x18]                            
  0000e224  d5f0ffeb      bl       #0xa580                                     
  0000e228  a8009fe5      ldr      r0, [pc, #0xa8]                             
  0000e22c  00008fe0      add      r0, pc, r0                                  
  0000e230  d0f2ffeb      bl       #0xad78                                     
  0000e234  010050e3      cmp      r0, #1                                      
  0000e238  0300000a      beq      #0xe24c                                     
  0000e23c  0040a0e3      mov      r4, #0                                      
  0000e240  0400a0e1      mov      r0, r4                                      
  0000e244  14d04be2      sub      sp, fp, #0x14                               
  0000e248  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000e24c  0600a0e3      mov      r0, #6                                      
  0000e250  0410a0e3      mov      r1, #4                                      
  0000e254  18204be2      sub      r2, fp, #0x18                               
  0000e258  3bf0ffeb      bl       #0xa34c                                     
  0000e25c  004050e2      subs     r4, r0, #0                                  
  0000e260  1100001a      bne      #0xe2ac                                     
  0000e264  18301be5      ldr      r3, [fp, #-0x18]                            
  0000e268  000053e3      cmp      r3, #0                                      
  0000e26c  f2ffff0a      beq      #0xe23c                                     
  0000e270  0410a0e1      mov      r1, r4                                      
  0000e274  0200a0e3      mov      r0, #2                                      
  0000e278  b3f4ffeb      bl       #0xb54c                                     
  0000e27c  004050e2      subs     r4, r0, #0                                  
  0000e280  edffff0a      beq      #0xe23c                                     
  0000e284  50009fe5      ldr      r0, [pc, #0x50]                             
  0000e288  5f1fa0e3      mov      r1, #0x17c                                  
  0000e28c  00508de5      str      r5, [sp]                                    
  0000e290  0420a0e1      mov      r2, r4                                      
  0000e294  04508de5      str      r5, [sp, #4]                                
  0000e298  00008fe0      add      r0, pc, r0                                  
  0000e29c  08508de5      str      r5, [sp, #8]                                
  0000e2a0  18301be5      ldr      r3, [fp, #-0x18]                            
  0000e2a4  eef0ffeb      bl       #0xa664                                     
  0000e2a8  e4ffffea      b        #0xe240                                     
  0000e2ac  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000e2b0  6f1100e3      movw     r1, #0x16f                                  
  0000e2b4  00508de5      str      r5, [sp]                                    
  0000e2b8  0420a0e1      mov      r2, r4                                      
  0000e2bc  04508de5      str      r5, [sp, #4]                                
  0000e2c0  00008fe0      add      r0, pc, r0                                  
  0000e2c4  08508de5      str      r5, [sp, #8]                                
  0000e2c8  18301be5      ldr      r3, [fp, #-0x18]                            
  0000e2cc  e4f0ffeb      bl       #0xa664                                     
  0000e2d0  daffffea      b        #0xe240                                     
  0000e2d4  00210200      andeq    r2, r2, r0, lsl #2                          
  0000e2d8  04210200      andeq    r2, r2, r4, lsl #2                          
  0000e2dc  9c1e0200      muleq    r2, ip, lr                                  
  0000e2e0  741e0200      andeq    r1, r2, r4, ror lr                          

; ─── HW_DM_PDT_Wan_NetAddressReleasePktProc @ 0xe2e4 ───
  0000e2e4  0dc0a0e1      mov      ip, sp                                      
  0000e2e8  011ca0e3      mov      r1, #0x100                                  
  0000e2ec  00d82de9      push     {fp, ip, lr, pc}                            
  0000e2f0  04b04ce2      sub      fp, ip, #4                                  
  0000e2f4  01dc4de2      sub      sp, sp, #0x100                              
  0000e2f8  0130a0e1      mov      r3, r1                                      
  0000e2fc  0020a0e3      mov      r2, #0                                      
  0000e300  430f4be2      sub      r0, fp, #0x10c                              
  0000e304  f7f0ffeb      bl       #0xa6e8                                     
  0000e308  24309fe5      ldr      r3, [pc, #0x24]                             
  0000e30c  011ca0e3      mov      r1, #0x100                                  
  0000e310  ff20a0e3      mov      r2, #0xff                                   
  0000e314  03308fe0      add      r3, pc, r3                                  
  0000e318  430f4be2      sub      r0, fp, #0x10c                              
  0000e31c  b4f1ffeb      bl       #0xa9f4                                     
  0000e320  430f4be2      sub      r0, fp, #0x10c                              
  0000e324  90f2ffeb      bl       #0xad6c                                     
  0000e328  0000a0e3      mov      r0, #0                                      
  0000e32c  0cd04be2      sub      sp, fp, #0xc                                
  0000e330  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000e334  30200200      andeq    r2, r2, r0, lsr r0                          

; ─── HW_DM_PDT_Reset_Func @ 0xe338 ───
  0000e338  0dc0a0e1      mov      ip, sp                                      
  0000e33c  0030e0e3      mvn      r3, #0                                      
  0000e340  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000e344  04b04ce2      sub      fp, ip, #4                                  
  0000e348  28d04de2      sub      sp, sp, #0x28                               
  0000e34c  0050a0e1      mov      r5, r0                                      
  0000e350  2c004be2      sub      r0, fp, #0x2c                               
  0000e354  28300be5      str      r3, [fp, #-0x28]                            
  0000e358  0160a0e1      mov      r6, r1                                      
  0000e35c  0040a0e3      mov      r4, #0                                      
  0000e360  24400be5      str      r4, [fp, #-0x24]                            
  0000e364  e5f0ffeb      bl       #0xa700                                     
  0000e368  2c301be5      ldr      r3, [fp, #-0x2c]                            
  0000e36c  010053e3      cmp      r3, #1                                      
  0000e370  5900000a      beq      #0xe4dc                                     
  0000e374  def3ffeb      bl       #0xb2f4                                     
  0000e378  00029fe5      ldr      r0, [pc, #0x200]                            
  0000e37c  00008fe0      add      r0, pc, r0                                  
  0000e380  dcf2ffeb      bl       #0xaef8                                     
  0000e384  010050e3      cmp      r0, #1                                      
  0000e388  6000000a      beq      #0xe510                                     
  0000e38c  020056e3      cmp      r6, #2                                      
  0000e390  02005503      cmpeq    r5, #2                                      
  0000e394  1400001a      bne      #0xe3ec                                     
  0000e398  e4719fe5      ldr      r7, [pc, #0x1e4]                            
  0000e39c  0540a0e3      mov      r4, #5                                      
  0000e3a0  e0619fe5      ldr      r6, [pc, #0x1e0]                            
  0000e3a4  07708fe0      add      r7, pc, r7                                  
  0000e3a8  06608fe0      add      r6, pc, r6                                  
  0000e3ac  0700a0e1      mov      r0, r7                                      
  0000e3b0  d0f2ffeb      bl       #0xaef8                                     
  0000e3b4  010050e3      cmp      r0, #1                                      
  0000e3b8  0600a0e1      mov      r0, r6                                      
  0000e3bc  0400001a      bne      #0xe3d4                                     
  0000e3c0  6ef0ffeb      bl       #0xa580                                     
  0000e3c4  0500a0e3      mov      r0, #5                                      
  0000e3c8  9ff0ffeb      bl       #0xa64c                                     
  0000e3cc  014054e2      subs     r4, r4, #1                                  
  0000e3d0  f5ffff1a      bne      #0xe3ac                                     
  0000e3d4  b0419fe5      ldr      r4, [pc, #0x1b0]                            
  0000e3d8  04408fe0      add      r4, pc, r4                                  
  0000e3dc  0400a0e1      mov      r0, r4                                      
  0000e3e0  c4f2ffeb      bl       #0xaef8                                     
  0000e3e4  010050e3      cmp      r0, #1                                      
  0000e3e8  5b00000a      beq      #0xe55c                                     
  0000e3ec  86f4ffeb      bl       #0xb60c                                     
  0000e3f0  70f1ffeb      bl       #0xa9b8                                     
  0000e3f4  8000a0e3      mov      r0, #0x80                                   
  0000e3f8  0130a0e3      mov      r3, #1                                      
  0000e3fc  20300be5      str      r3, [fp, #-0x20]                            
  0000e400  b6efffeb      bl       #0xa2e0                                     
  0000e404  010050e3      cmp      r0, #1                                      
  0000e408  4e00000a      beq      #0xe548                                     
  0000e40c  08f5ffeb      bl       #0xb834                                     
  0000e410  61efffeb      bl       #0xa19c                                     
  0000e414  001050e2      subs     r1, r0, #0                                  
  0000e418  0700000a      beq      #0xe43c                                     
  0000e41c  6c019fe5      ldr      r0, [pc, #0x16c]                            
  0000e420  00008fe0      add      r0, pc, r0                                  
  0000e424  55f0ffeb      bl       #0xa580                                     
  0000e428  44f4ffeb      bl       #0xb540                                     
  0000e42c  000050e3      cmp      r0, #0                                      
  0000e430  0020a0e1      mov      r2, r0                                      
  0000e434  30000be5      str      r0, [fp, #-0x30]                            
  0000e438  3900001a      bne      #0xe524                                     
  0000e43c  083045e2      sub      r3, r5, #8                                  
  0000e440  aa0505e3      movw     r0, #0x55aa                                 
  0000e444  030053e3      cmp      r3, #3                                      
  0000e448  550a4ae3      movt     r0, #0xaa55                                 
  0000e44c  0510a091      movls    r1, r5                                      
  0000e450  0110a083      movhi    r1, #1                                      
  0000e454  4defffeb      bl       #0xa190                                     
  0000e458  61f2ffeb      bl       #0xade4                                     
  0000e45c  0010a0e1      mov      r1, r0                                      
  0000e460  2c019fe5      ldr      r0, [pc, #0x12c]                            
  0000e464  00008fe0      add      r0, pc, r0                                  
  0000e468  44f0ffeb      bl       #0xa580                                     
  0000e46c  24019fe5      ldr      r0, [pc, #0x124]                            
  0000e470  00008fe0      add      r0, pc, r0                                  
  0000e474  3cf2ffeb      bl       #0xad6c                                     
  0000e478  30104be2      sub      r1, fp, #0x30                               
  0000e47c  0420a0e3      mov      r2, #4                                      
  0000e480  140407e3      movw     r0, #0x7414                                 
  0000e484  04f3ffeb      bl       #0xb09c                                     
  0000e488  24004be2      sub      r0, fp, #0x24                               
  0000e48c  07f1ffeb      bl       #0xa8b0                                     
  0000e490  000050e3      cmp      r0, #0                                      
  0000e494  30000be5      str      r0, [fp, #-0x30]                            
  0000e498  0200001a      bne      #0xe4a8                                     
  0000e49c  24301be5      ldr      r3, [fp, #-0x24]                            
  0000e4a0  010053e3      cmp      r3, #1                                      
  0000e4a4  3200000a      beq      #0xe574                                     
  0000e4a8  28104be2      sub      r1, fp, #0x28                               
  0000e4ac  0420a0e3      mov      r2, #4                                      
  0000e4b0  130407e3      movw     r0, #0x7413                                 
  0000e4b4  f8f2ffeb      bl       #0xb09c                                     
  0000e4b8  11f4ffeb      bl       #0xb504                                     
  0000e4bc  0100a0e3      mov      r0, #1                                      
  0000e4c0  61f0ffeb      bl       #0xa64c                                     
  0000e4c4  670504e3      movw     r0, #0x4567                                 
  0000e4c8  230140e3      movt     r0, #0x123                                  
  0000e4cc  dcf0ffeb      bl       #0xa844                                     
  0000e4d0  0000a0e3      mov      r0, #0                                      
  0000e4d4  1cd04be2      sub      sp, fp, #0x1c                               
  0000e4d8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000e4dc  b8009fe5      ldr      r0, [pc, #0xb8]                             
  0000e4e0  d31100e3      movw     r1, #0x1d3                                  
  0000e4e4  00408de5      str      r4, [sp]                                    
  0000e4e8  0a2005e3      movw     r2, #0x500a                                 
  0000e4ec  00008fe0      add      r0, pc, r0                                  
  0000e4f0  04408de5      str      r4, [sp, #4]                                
  0000e4f4  08408de5      str      r4, [sp, #8]                                
  0000e4f8  20274fe3      movt     r2, #0xf720                                 
  0000e4fc  0430a0e1      mov      r3, r4                                      
  0000e500  57f0ffeb      bl       #0xa664                                     
  0000e504  0a0005e3      movw     r0, #0x500a                                 
  0000e508  20074fe3      movt     r0, #0xf720                                 
  0000e50c  f0ffffea      b        #0xe4d4                                     
  0000e510  020056e3      cmp      r6, #2                                      
  0000e514  b4ffff1a      bne      #0xe3ec                                     
  0000e518  0c00a0e3      mov      r0, #0xc                                    
  0000e51c  4af0ffeb      bl       #0xa64c                                     
  0000e520  99ffffea      b        #0xe38c                                     
  0000e524  74009fe5      ldr      r0, [pc, #0x74]                             
  0000e528  0030a0e3      mov      r3, #0                                      
  0000e52c  131200e3      movw     r1, #0x213                                  
  0000e530  00308de5      str      r3, [sp]                                    
  0000e534  00008fe0      add      r0, pc, r0                                  
  0000e538  04308de5      str      r3, [sp, #4]                                
  0000e53c  08308de5      str      r3, [sp, #8]                                
  0000e540  47f0ffeb      bl       #0xa664                                     
  0000e544  bcffffea      b        #0xe43c                                     
  0000e548  20104be2      sub      r1, fp, #0x20                               
  0000e54c  0420a0e3      mov      r2, #4                                      
  0000e550  100407e3      movw     r0, #0x7410                                 
  0000e554  d0f2ffeb      bl       #0xb09c                                     
  0000e558  abffffea      b        #0xe40c                                     
  0000e55c  40009fe5      ldr      r0, [pc, #0x40]                             
  0000e560  00008fe0      add      r0, pc, r0                                  
  0000e564  05f0ffeb      bl       #0xa580                                     
  0000e568  0400a0e1      mov      r0, r4                                      
  0000e56c  93f0ffeb      bl       #0xa7c0                                     
  0000e570  9dffffea      b        #0xe3ec                                     
  0000e574  0200a0e3      mov      r0, #2                                      
  0000e578  33f0ffeb      bl       #0xa64c                                     
  0000e57c  c9ffffea      b        #0xe4a8                                     
  0000e580  dc1f0200      ldrdeq   r1, r2, [r2], -ip                           
  0000e584  c81f0200      andeq    r1, r2, r8, asr #31                         
  0000e588  dc1f0200      ldrdeq   r1, r2, [r2], -ip                           
  0000e58c  941f0200      muleq    r2, r4, pc                                  
  0000e590  b01f0200      strheq   r1, [r2], -r0                               
  0000e594  881f0200      andeq    r1, r2, r8, lsl #31                         
  0000e598  9c1f0200      muleq    r2, ip, pc                                  
  0000e59c  481c0200      andeq    r1, r2, r8, asr #24                         
  0000e5a0  001c0200      andeq    r1, r2, r0, lsl #24                         
  0000e5a4  441e0200      andeq    r1, r2, r4, asr #28                         

; ─── HW_DM_PDT_GetDeviceType_YNCT @ 0xe5a8 ───
  0000e5a8  0dc0a0e1      mov      ip, sp                                      
  0000e5ac  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000e5b0  04b04ce2      sub      fp, ip, #4                                  
  0000e5b4  78d04de2      sub      sp, sp, #0x78                               
  0000e5b8  0060a0e1      mov      r6, r0                                      
  0000e5bc  0150a0e1      mov      r5, r1                                      
  0000e5c0  0270a0e1      mov      r7, r2                                      
  0000e5c4  0010a0e3      mov      r1, #0                                      
  0000e5c8  4120a0e3      mov      r2, #0x41                                   
  0000e5cc  68004be2      sub      r0, fp, #0x68                               
  0000e5d0  0380a0e1      mov      r8, r3                                      
  0000e5d4  9eefffeb      bl       #0xa454                                     
  0000e5d8  48029fe5      ldr      r0, [pc, #0x248]                            
  0000e5dc  0040a0e3      mov      r4, #0                                      
  0000e5e0  88400be5      str      r4, [fp, #-0x88]                            
  0000e5e4  00008fe0      add      r0, pc, r0                                  
  0000e5e8  84400be5      str      r4, [fp, #-0x84]                            
  0000e5ec  80400be5      str      r4, [fp, #-0x80]                            
  0000e5f0  7c400be5      str      r4, [fp, #-0x7c]                            
  0000e5f4  78400be5      str      r4, [fp, #-0x78]                            
  0000e5f8  74400be5      str      r4, [fp, #-0x74]                            
  0000e5fc  70400be5      str      r4, [fp, #-0x70]                            
  0000e600  6c400be5      str      r4, [fp, #-0x6c]                            
  0000e604  8c400be5      str      r4, [fp, #-0x8c]                            
  0000e608  daf1ffeb      bl       #0xad78                                     
  0000e60c  010050e3      cmp      r0, #1                                      
  0000e610  2a00000a      beq      #0xe6c0                                     
  0000e614  000055e3      cmp      r5, #0                                      
  0000e618  1700000a      beq      #0xe67c                                     
  0000e61c  08c29fe5      ldr      ip, [pc, #0x208]                            
  0000e620  000058e3      cmp      r8, #0                                      
  0000e624  0cc08fe0      add      ip, pc, ip                                  
  0000e628  00c29f05      ldreq    ip, [pc, #0x200]                            
  0000e62c  0cc08f00      addeq    ip, pc, ip                                  
  0000e630  fc319fe5      ldr      r3, [pc, #0x1fc]                            
  0000e634  68004be2      sub      r0, fp, #0x68                               
  0000e638  04708de5      str      r7, [sp, #4]                                
  0000e63c  4110a0e3      mov      r1, #0x41                                   
  0000e640  03308fe0      add      r3, pc, r3                                  
  0000e644  00308de5      str      r3, [sp]                                    
  0000e648  e8319fe5      ldr      r3, [pc, #0x1e8]                            
  0000e64c  4020a0e3      mov      r2, #0x40                                   
  0000e650  08508de5      str      r5, [sp, #8]                                
  0000e654  0cc08de5      str      ip, [sp, #0xc]                              
  0000e658  03308fe0      add      r3, pc, r3                                  
  0000e65c  e4f0ffeb      bl       #0xa9f4                                     
  0000e660  0600a0e1      mov      r0, r6                                      
  0000e664  4110a0e3      mov      r1, #0x41                                   
  0000e668  68204be2      sub      r2, fp, #0x68                               
  0000e66c  4030a0e3      mov      r3, #0x40                                   
  0000e670  9ceeffeb      bl       #0xa0e8                                     
  0000e674  24d04be2      sub      sp, fp, #0x24                               
  0000e678  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000e67c  b8319fe5      ldr      r3, [pc, #0x1b8]                            
  0000e680  000058e3      cmp      r8, #0                                      
  0000e684  03308fe0      add      r3, pc, r3                                  
  0000e688  b0319f05      ldreq    r3, [pc, #0x1b0]                            
  0000e68c  03308f00      addeq    r3, pc, r3                                  
  0000e690  08308de5      str      r3, [sp, #8]                                
  0000e694  68004be2      sub      r0, fp, #0x68                               
  0000e698  a4319fe5      ldr      r3, [pc, #0x1a4]                            
  0000e69c  4110a0e3      mov      r1, #0x41                                   
  0000e6a0  04708de5      str      r7, [sp, #4]                                
  0000e6a4  4020a0e3      mov      r2, #0x40                                   
  0000e6a8  03308fe0      add      r3, pc, r3                                  
  0000e6ac  00308de5      str      r3, [sp]                                    
  0000e6b0  90319fe5      ldr      r3, [pc, #0x190]                            
  0000e6b4  03308fe0      add      r3, pc, r3                                  
  0000e6b8  cdf0ffeb      bl       #0xa9f4                                     
  0000e6bc  e7ffffea      b        #0xe660                                     
  0000e6c0  88a04be2      sub      sl, fp, #0x88                               
  0000e6c4  0410a0e1      mov      r1, r4                                      
  0000e6c8  2030a0e3      mov      r3, #0x20                                   
  0000e6cc  8c204be2      sub      r2, fp, #0x8c                               
  0000e6d0  00a08de5      str      sl, [sp]                                    
  0000e6d4  2a00a0e3      mov      r0, #0x2a                                   
  0000e6d8  04208de5      str      r2, [sp, #4]                                
  0000e6dc  062100e3      movw     r2, #0x106                                  
  0000e6e0  502442e3      movt     r2, #0x2450                                 
  0000e6e4  94eeffeb      bl       #0xa13c                                     
  0000e6e8  5c019fe5      ldr      r0, [pc, #0x15c]                            
  0000e6ec  0a10a0e1      mov      r1, sl                                      
  0000e6f0  00008fe0      add      r0, pc, r0                                  
  0000e6f4  acf0ffeb      bl       #0xa9ac                                     
  0000e6f8  040050e1      cmp      r0, r4                                      
  0000e6fc  1200001a      bne      #0xe74c                                     
  0000e700  040055e1      cmp      r5, r4                                      
  0000e704  3500001a      bne      #0xe7e0                                     
  0000e708  40319fe5      ldr      r3, [pc, #0x140]                            
  0000e70c  040058e1      cmp      r8, r4                                      
  0000e710  03308fe0      add      r3, pc, r3                                  
  0000e714  38319f05      ldreq    r3, [pc, #0x138]                            
  0000e718  03308f00      addeq    r3, pc, r3                                  
  0000e71c  08308de5      str      r3, [sp, #8]                                
  0000e720  68004be2      sub      r0, fp, #0x68                               
  0000e724  2c319fe5      ldr      r3, [pc, #0x12c]                            
  0000e728  4110a0e3      mov      r1, #0x41                                   
  0000e72c  04708de5      str      r7, [sp, #4]                                
  0000e730  4020a0e3      mov      r2, #0x40                                   
  0000e734  03308fe0      add      r3, pc, r3                                  
  0000e738  00308de5      str      r3, [sp]                                    
  0000e73c  18319fe5      ldr      r3, [pc, #0x118]                            
  0000e740  03308fe0      add      r3, pc, r3                                  
  0000e744  aaf0ffeb      bl       #0xa9f4                                     
  0000e748  c4ffffea      b        #0xe660                                     
  0000e74c  000055e3      cmp      r5, #0                                      
  0000e750  1000001a      bne      #0xe798                                     
  0000e754  04319fe5      ldr      r3, [pc, #0x104]                            
  0000e758  000058e3      cmp      r8, #0                                      
  0000e75c  03308fe0      add      r3, pc, r3                                  
  0000e760  fc309f05      ldreq    r3, [pc, #0xfc]                             
  0000e764  03308f00      addeq    r3, pc, r3                                  
  0000e768  08308de5      str      r3, [sp, #8]                                
  0000e76c  68004be2      sub      r0, fp, #0x68                               
  0000e770  f0309fe5      ldr      r3, [pc, #0xf0]                             
  0000e774  4110a0e3      mov      r1, #0x41                                   
  0000e778  04708de5      str      r7, [sp, #4]                                
  0000e77c  4020a0e3      mov      r2, #0x40                                   
  0000e780  03308fe0      add      r3, pc, r3                                  
  0000e784  00308de5      str      r3, [sp]                                    
  0000e788  dc309fe5      ldr      r3, [pc, #0xdc]                             
  0000e78c  03308fe0      add      r3, pc, r3                                  
  0000e790  97f0ffeb      bl       #0xa9f4                                     
  0000e794  b1ffffea      b        #0xe660                                     
  0000e798  d0c09fe5      ldr      ip, [pc, #0xd0]                             
  0000e79c  000058e3      cmp      r8, #0                                      
  0000e7a0  0cc08fe0      add      ip, pc, ip                                  
  0000e7a4  c8c09f05      ldreq    ip, [pc, #0xc8]                             
  0000e7a8  0cc08f00      addeq    ip, pc, ip                                  
  0000e7ac  c4309fe5      ldr      r3, [pc, #0xc4]                             
  0000e7b0  68004be2      sub      r0, fp, #0x68                               
  0000e7b4  04708de5      str      r7, [sp, #4]                                
  0000e7b8  4110a0e3      mov      r1, #0x41                                   
  0000e7bc  03308fe0      add      r3, pc, r3                                  
  0000e7c0  00308de5      str      r3, [sp]                                    
  0000e7c4  b0309fe5      ldr      r3, [pc, #0xb0]                             
  0000e7c8  4020a0e3      mov      r2, #0x40                                   
  0000e7cc  08508de5      str      r5, [sp, #8]                                
  0000e7d0  0cc08de5      str      ip, [sp, #0xc]                              
  0000e7d4  03308fe0      add      r3, pc, r3                                  
  0000e7d8  85f0ffeb      bl       #0xa9f4                                     
  0000e7dc  9fffffea      b        #0xe660                                     
  0000e7e0  98c09fe5      ldr      ip, [pc, #0x98]                             
  0000e7e4  000058e3      cmp      r8, #0                                      
  0000e7e8  0cc08fe0      add      ip, pc, ip                                  
  0000e7ec  90c09f05      ldreq    ip, [pc, #0x90]                             
  0000e7f0  0cc08f00      addeq    ip, pc, ip                                  
  0000e7f4  8c309fe5      ldr      r3, [pc, #0x8c]                             
  0000e7f8  68004be2      sub      r0, fp, #0x68                               
  0000e7fc  04708de5      str      r7, [sp, #4]                                
  0000e800  4110a0e3      mov      r1, #0x41                                   
  0000e804  03308fe0      add      r3, pc, r3                                  
  0000e808  00308de5      str      r3, [sp]                                    
  0000e80c  78309fe5      ldr      r3, [pc, #0x78]                             
  0000e810  4020a0e3      mov      r2, #0x40                                   
  0000e814  08508de5      str      r5, [sp, #8]                                
  0000e818  0cc08de5      str      ip, [sp, #0xc]                              
  0000e81c  03308fe0      add      r3, pc, r3                                  
  0000e820  73f0ffeb      bl       #0xa9f4                                     
  0000e824  8dffffea      b        #0xe660                                     
  0000e828  381e0200      andeq    r1, r2, r8, lsr lr                          
  0000e82c  b41c0200      strheq   r1, [r2], -r4                               
  0000e830  e81d0200      andeq    r1, r2, r8, ror #27                         
  0000e834  201e0200      andeq    r1, r2, r0, lsr #28                         
  0000e838  f41d0200      strdeq   r1, r2, [r2], -r4                           
  0000e83c  541c0200      andeq    r1, r2, r4, asr ip                          
  0000e840  881d0200      andeq    r1, r2, r8, lsl #27                         
  0000e844  b81d0200      strheq   r1, [r2], -r8                               
  0000e848  841d0200      andeq    r1, r2, r4, lsl #27                         
  0000e84c  441d0200      andeq    r1, r2, r4, asr #26                         
  0000e850  c81b0200      andeq    r1, r2, r8, asr #23                         
  0000e854  fc1c0200      strdeq   r1, r2, [r2], -ip                           
  0000e858  101d0200      andeq    r1, r2, r0, lsl sp                          
  0000e85c  f81c0200      strdeq   r1, r2, [r2], -r8                           
  0000e860  7c1b0200      andeq    r1, r2, ip, ror fp                          
  0000e864  b01c0200      strheq   r1, [r2], -r0                               
  0000e868  d81c0200      ldrdeq   r1, r2, [r2], -r8                           
  0000e86c  ac1c0200      andeq    r1, r2, ip, lsr #25                         
  0000e870  381b0200      andeq    r1, r2, r8, lsr fp                          
  0000e874  6c1c0200      andeq    r1, r2, ip, ror #24                         
  0000e878  9c1c0200      muleq    r2, ip, ip                                  
  0000e87c  781c0200      andeq    r1, r2, r8, ror ip                          
  0000e880  f01a0200      strdeq   r1, r2, [r2], -r0                           
  0000e884  241c0200      andeq    r1, r2, r4, lsr #24                         
  0000e888  401c0200      andeq    r1, r2, r0, asr #24                         
  0000e88c  301c0200      andeq    r1, r2, r0, lsr ip                          

; ─── HW_DM_PDT_GetDeviceType_Func @ 0xe890 ───
  0000e890  0dc0a0e1      mov      ip, sp                                      
  0000e894  4120a0e3      mov      r2, #0x41                                   
  0000e898  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000e89c  04b04ce2      sub      fp, ip, #4                                  
  0000e8a0  0040a0e3      mov      r4, #0                                      
  0000e8a4  a0d04de2      sub      sp, sp, #0xa0                               
  0000e8a8  0060a0e1      mov      r6, r0                                      
  0000e8ac  0410a0e1      mov      r1, r4                                      
  0000e8b0  60004be2      sub      r0, fp, #0x60                               
  0000e8b4  ac400be5      str      r4, [fp, #-0xac]                            
  0000e8b8  a8400be5      str      r4, [fp, #-0xa8]                            
  0000e8bc  a4400be5      str      r4, [fp, #-0xa4]                            
  0000e8c0  e3eeffeb      bl       #0xa454                                     
  0000e8c4  040056e1      cmp      r6, r4                                      
  0000e8c8  a0400be5      str      r4, [fp, #-0xa0]                            
  0000e8cc  9c400be5      str      r4, [fp, #-0x9c]                            
  0000e8d0  03540503      movweq   r5, #0x5403                                 
  0000e8d4  98400be5      str      r4, [fp, #-0x98]                            
  0000e8d8  94400be5      str      r4, [fp, #-0x94]                            
  0000e8dc  20574f03      movteq   r5, #0xf720                                 
  0000e8e0  90400be5      str      r4, [fp, #-0x90]                            
  0000e8e4  8c400be5      str      r4, [fp, #-0x8c]                            
  0000e8e8  88400be5      str      r4, [fp, #-0x88]                            
  0000e8ec  84400be5      str      r4, [fp, #-0x84]                            
  0000e8f0  80404be5      strb     r4, [fp, #-0x80]                            
  0000e8f4  7c400be5      str      r4, [fp, #-0x7c]                            
  0000e8f8  78400be5      str      r4, [fp, #-0x78]                            
  0000e8fc  74400be5      str      r4, [fp, #-0x74]                            
  0000e900  70400be5      str      r4, [fp, #-0x70]                            
  0000e904  6c400be5      str      r4, [fp, #-0x6c]                            
  0000e908  68400be5      str      r4, [fp, #-0x68]                            
  0000e90c  64404be5      strb     r4, [fp, #-0x64]                            
  0000e910  4300000a      beq      #0xea24                                     
  0000e914  0400a0e3      mov      r0, #4                                      
  0000e918  ac204be2      sub      r2, fp, #0xac                               
  0000e91c  0010a0e1      mov      r1, r0                                      
  0000e920  89eeffeb      bl       #0xa34c                                     
  0000e924  0410a0e3      mov      r1, #4                                      
  0000e928  a8204be2      sub      r2, fp, #0xa8                               
  0000e92c  0050a0e1      mov      r5, r0                                      
  0000e930  0100a0e3      mov      r0, #1                                      
  0000e934  84eeffeb      bl       #0xa34c                                     
  0000e938  0410a0e3      mov      r1, #4                                      
  0000e93c  a4204be2      sub      r2, fp, #0xa4                               
  0000e940  055080e1      orr      r5, r0, r5                                  
  0000e944  0300a0e3      mov      r0, #3                                      
  0000e948  7feeffeb      bl       #0xa34c                                     
  0000e94c  1910a0e3      mov      r1, #0x19                                   
  0000e950  98204be2      sub      r2, fp, #0x98                               
  0000e954  005085e1      orr      r5, r5, r0                                  
  0000e958  4400a0e3      mov      r0, #0x44                                   
  0000e95c  000141e3      movt     r0, #0x1100                                 
  0000e960  79eeffeb      bl       #0xa34c                                     
  0000e964  1910a0e3      mov      r1, #0x19                                   
  0000e968  7c204be2      sub      r2, fp, #0x7c                               
  0000e96c  005085e1      orr      r5, r5, r0                                  
  0000e970  4500a0e3      mov      r0, #0x45                                   
  0000e974  000141e3      movt     r0, #0x1100                                 
  0000e978  73eeffeb      bl       #0xa34c                                     
  0000e97c  005095e1      orrs     r5, r5, r0                                  
  0000e980  2a00001a      bne      #0xea30                                     
  0000e984  54029fe5      ldr      r0, [pc, #0x254]                            
  0000e988  00008fe0      add      r0, pc, r0                                  
  0000e98c  f9f0ffeb      bl       #0xad78                                     
  0000e990  4c129fe5      ldr      r1, [pc, #0x24c]                            
  0000e994  01108fe0      add      r1, pc, r1                                  
  0000e998  010050e3      cmp      r0, #1                                      
  0000e99c  7c004be2      sub      r0, fp, #0x7c                               
  0000e9a0  a8301b05      ldreq    r3, [fp, #-0xa8]                            
  0000e9a4  01304302      subeq    r3, r3, #1                                  
  0000e9a8  a8300b05      streq    r3, [fp, #-0xa8]                            
  0000e9ac  feefffeb      bl       #0xa9ac                                     
  0000e9b0  000050e3      cmp      r0, #0                                      
  0000e9b4  2700001a      bne      #0xea58                                     
  0000e9b8  c4edffeb      bl       #0xa0d0                                     
  0000e9bc  24129fe5      ldr      r1, [pc, #0x224]                            
  0000e9c0  01108fe0      add      r1, pc, r1                                  
  0000e9c4  000050e3      cmp      r0, #0                                      
  0000e9c8  4600000a      beq      #0xeae8                                     
  0000e9cc  a4301be5      ldr      r3, [fp, #-0xa4]                            
  0000e9d0  a8201be5      ldr      r2, [fp, #-0xa8]                            
  0000e9d4  000053e3      cmp      r3, #0                                      
  0000e9d8  ac301be5      ldr      r3, [fp, #-0xac]                            
  0000e9dc  4300001a      bne      #0xeaf0                                     
  0000e9e0  04c29fe5      ldr      ip, [pc, #0x204]                            
  0000e9e4  0cc08fe0      add      ip, pc, ip                                  
  0000e9e8  08308de5      str      r3, [sp, #8]                                
  0000e9ec  60004be2      sub      r0, fp, #0x60                               
  0000e9f0  f8319fe5      ldr      r3, [pc, #0x1f8]                            
  0000e9f4  00108de5      str      r1, [sp]                                    
  0000e9f8  4110a0e3      mov      r1, #0x41                                   
  0000e9fc  04208de5      str      r2, [sp, #4]                                
  0000ea00  03308fe0      add      r3, pc, r3                                  
  0000ea04  4020a0e3      mov      r2, #0x40                                   
  0000ea08  0cc08de5      str      ip, [sp, #0xc]                              
  0000ea0c  f8efffeb      bl       #0xa9f4                                     
  0000ea10  0600a0e1      mov      r0, r6                                      
  0000ea14  4110a0e3      mov      r1, #0x41                                   
  0000ea18  60204be2      sub      r2, fp, #0x60                               
  0000ea1c  4030a0e3      mov      r3, #0x40                                   
  0000ea20  b0edffeb      bl       #0xa0e8                                     
  0000ea24  0500a0e1      mov      r0, r5                                      
  0000ea28  1cd04be2      sub      sp, fp, #0x1c                               
  0000ea2c  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000ea30  bc019fe5      ldr      r0, [pc, #0x1bc]                            
  0000ea34  aa1200e3      movw     r1, #0x2aa                                  
  0000ea38  00408de5      str      r4, [sp]                                    
  0000ea3c  0520a0e1      mov      r2, r5                                      
  0000ea40  04408de5      str      r4, [sp, #4]                                
  0000ea44  0430a0e1      mov      r3, r4                                      
  0000ea48  08408de5      str      r4, [sp, #8]                                
  0000ea4c  00008fe0      add      r0, pc, r0                                  
  0000ea50  03efffeb      bl       #0xa664                                     
  0000ea54  f2ffffea      b        #0xea24                                     
  0000ea58  98119fe5      ldr      r1, [pc, #0x198]                            
  0000ea5c  7c004be2      sub      r0, fp, #0x7c                               
  0000ea60  01108fe0      add      r1, pc, r1                                  
  0000ea64  d0efffeb      bl       #0xa9ac                                     
  0000ea68  000050e3      cmp      r0, #0                                      
  0000ea6c  d1ffff0a      beq      #0xe9b8                                     
  0000ea70  84019fe5      ldr      r0, [pc, #0x184]                            
  0000ea74  00008fe0      add      r0, pc, r0                                  
  0000ea78  bef0ffeb      bl       #0xad78                                     
  0000ea7c  000050e3      cmp      r0, #0                                      
  0000ea80  1d00000a      beq      #0xeafc                                     
  0000ea84  a0404be2      sub      r4, fp, #0xa0                               
  0000ea88  0e00a0e3      mov      r0, #0xe                                    
  0000ea8c  0810a0e3      mov      r1, #8                                      
  0000ea90  0420a0e1      mov      r2, r4                                      
  0000ea94  2ceeffeb      bl       #0xa34c                                     
  0000ea98  007050e2      subs     r7, r0, #0                                  
  0000ea9c  3400001a      bne      #0xeb74                                     
  0000eaa0  a4301be5      ldr      r3, [fp, #-0xa4]                            
  0000eaa4  a8201be5      ldr      r2, [fp, #-0xa8]                            
  0000eaa8  000053e3      cmp      r3, #0                                      
  0000eaac  ac301be5      ldr      r3, [fp, #-0xac]                            
  0000eab0  2900000a      beq      #0xeb5c                                     
  0000eab4  44c19fe5      ldr      ip, [pc, #0x144]                            
  0000eab8  0cc08fe0      add      ip, pc, ip                                  
  0000eabc  08308de5      str      r3, [sp, #8]                                
  0000eac0  60004be2      sub      r0, fp, #0x60                               
  0000eac4  38319fe5      ldr      r3, [pc, #0x138]                            
  0000eac8  4110a0e3      mov      r1, #0x41                                   
  0000eacc  04208de5      str      r2, [sp, #4]                                
  0000ead0  4020a0e3      mov      r2, #0x40                                   
  0000ead4  00408de5      str      r4, [sp]                                    
  0000ead8  03308fe0      add      r3, pc, r3                                  
  0000eadc  0cc08de5      str      ip, [sp, #0xc]                              
  0000eae0  c3efffeb      bl       #0xa9f4                                     
  0000eae4  c9ffffea      b        #0xea10                                     
  0000eae8  98104be2      sub      r1, fp, #0x98                               
  0000eaec  b6ffffea      b        #0xe9cc                                     
  0000eaf0  10c19fe5      ldr      ip, [pc, #0x110]                            
  0000eaf4  0cc08fe0      add      ip, pc, ip                                  
  0000eaf8  baffffea      b        #0xe9e8                                     
  0000eafc  08019fe5      ldr      r0, [pc, #0x108]                            
  0000eb00  00008fe0      add      r0, pc, r0                                  
  0000eb04  9bf0ffeb      bl       #0xad78                                     
  0000eb08  010050e3      cmp      r0, #1                                      
  0000eb0c  2900000a      beq      #0xebb8                                     
  0000eb10  a4301be5      ldr      r3, [fp, #-0xa4]                            
  0000eb14  a8201be5      ldr      r2, [fp, #-0xa8]                            
  0000eb18  000053e3      cmp      r3, #0                                      
  0000eb1c  ac301be5      ldr      r3, [fp, #-0xac]                            
  0000eb20  1000000a      beq      #0xeb68                                     
  0000eb24  e4c09fe5      ldr      ip, [pc, #0xe4]                             
  0000eb28  0cc08fe0      add      ip, pc, ip                                  
  0000eb2c  08308de5      str      r3, [sp, #8]                                
  0000eb30  98104be2      sub      r1, fp, #0x98                               
  0000eb34  d8309fe5      ldr      r3, [pc, #0xd8]                             
  0000eb38  60004be2      sub      r0, fp, #0x60                               
  0000eb3c  00108de5      str      r1, [sp]                                    
  0000eb40  4110a0e3      mov      r1, #0x41                                   
  0000eb44  04208de5      str      r2, [sp, #4]                                
  0000eb48  03308fe0      add      r3, pc, r3                                  
  0000eb4c  4020a0e3      mov      r2, #0x40                                   
  0000eb50  0cc08de5      str      ip, [sp, #0xc]                              
  0000eb54  a6efffeb      bl       #0xa9f4                                     
  0000eb58  acffffea      b        #0xea10                                     
  0000eb5c  b4c09fe5      ldr      ip, [pc, #0xb4]                             
  0000eb60  0cc08fe0      add      ip, pc, ip                                  
  0000eb64  d4ffffea      b        #0xeabc                                     
  0000eb68  acc09fe5      ldr      ip, [pc, #0xac]                             
  0000eb6c  0cc08fe0      add      ip, pc, ip                                  
  0000eb70  edffffea      b        #0xeb2c                                     
  0000eb74  a4309fe5      ldr      r3, [pc, #0xa4]                             
  0000eb78  4110a0e3      mov      r1, #0x41                                   
  0000eb7c  4020a0e3      mov      r2, #0x40                                   
  0000eb80  60004be2      sub      r0, fp, #0x60                               
  0000eb84  03308fe0      add      r3, pc, r3                                  
  0000eb88  99efffeb      bl       #0xa9f4                                     
  0000eb8c  90009fe5      ldr      r0, [pc, #0x90]                             
  0000eb90  00c0a0e3      mov      ip, #0                                      
  0000eb94  c21200e3      movw     r1, #0x2c2                                  
  0000eb98  00008fe0      add      r0, pc, r0                                  
  0000eb9c  00c08de5      str      ip, [sp]                                    
  0000eba0  0720a0e1      mov      r2, r7                                      
  0000eba4  04c08de5      str      ip, [sp, #4]                                
  0000eba8  0c30a0e1      mov      r3, ip                                      
  0000ebac  08c08de5      str      ip, [sp, #8]                                
  0000ebb0  abeeffeb      bl       #0xa664                                     
  0000ebb4  b9ffffea      b        #0xeaa0                                     
  0000ebb8  68009fe5      ldr      r0, [pc, #0x68]                             
  0000ebbc  00008fe0      add      r0, pc, r0                                  
  0000ebc0  6cf0ffeb      bl       #0xad78                                     
  0000ebc4  010050e3      cmp      r0, #1                                      
  0000ebc8  d0ffff1a      bne      #0xeb10                                     
  0000ebcc  ac104be2      sub      r1, fp, #0xac                               
  0000ebd0  60004be2      sub      r0, fp, #0x60                               
  0000ebd4  0e0091e8      ldm      r1, {r1, r2, r3}                            
  0000ebd8  b7f0ffeb      bl       #0xaebc                                     
  0000ebdc  8bffffea      b        #0xea10                                     
  0000ebe0  e81a0200      andeq    r1, r2, r8, ror #21                         
  0000ebe4  f41a0200      strdeq   r1, r2, [r2], -r4                           
  0000ebe8  a41a0200      andeq    r1, r2, r4, lsr #21                         
  0000ebec  841a0200      andeq    r1, r2, r4, lsl #21                         
  0000ebf0  4c1a0200      andeq    r1, r2, ip, asr #20                         
  0000ebf4  e8160200      andeq    r1, r2, r8, ror #13                         
  0000ebf8  301a0200      andeq    r1, r2, r0, lsr sl                          
  0000ebfc  241a0200      andeq    r1, r2, r4, lsr #20                         
  0000ec00  24140200      andeq    r1, r2, r4, lsr #8                          
  0000ec04  74190200      andeq    r1, r2, r4, ror sb                          
  0000ec08  e8130200      andeq    r1, r2, r8, ror #7                          
  0000ec0c  b8190200      strheq   r1, [r2], -r8                               
  0000ec10  b0170200      strheq   r1, [r2], -r0                               
  0000ec14  04190200      andeq    r1, r2, r4, lsl #18                         
  0000ec18  08190200      andeq    r1, r2, r8, lsl #18                         
  0000ec1c  a8180200      andeq    r1, r2, r8, lsr #17                         
  0000ec20  30190200      andeq    r1, r2, r0, lsr sb                          
  0000ec24  9c150200      muleq    r2, ip, r5                                  
  0000ec28  14190200      andeq    r1, r2, r4, lsl sb                          

; ─── HW_DM_PDT_GetHWDeviceTypeSmartE8C @ 0xec2c ───
  0000ec2c  020051e3      cmp      r1, #2                                      
  0000ec30  0c00000a      beq      #0xec68                                     
  0000ec34  040051e3      cmp      r1, #4                                      
  0000ec38  0200000a      beq      #0xec48                                     
  0000ec3c  6420a0e3      mov      r2, #0x64                                   
  0000ec40  002080e5      str      r2, [r0]                                    
  0000ec44  1eff2fe1      bx       lr                                          
  0000ec48  010053e3      cmp      r3, #1                                      
  0000ec4c  0820a003      moveq    r2, #8                                      
  0000ec50  faffff0a      beq      #0xec40                                     
  0000ec54  020053e3      cmp      r3, #2                                      
  0000ec58  6420a013      movne    r2, #0x64                                   
  0000ec5c  0920a003      moveq    r2, #9                                      
  0000ec60  002080e5      str      r2, [r0]                                    
  0000ec64  1eff2fe1      bx       lr                                          
  0000ec68  010052e3      cmp      r2, #1                                      
  0000ec6c  0620a003      moveq    r2, #6                                      
  0000ec70  f2ffff0a      beq      #0xec40                                     
  0000ec74  011072e2      rsbs     r1, r2, #1                                  
  0000ec78  0010a033      movlo    r1, #0                                      
  0000ec7c  010053e3      cmp      r3, #1                                      
  0000ec80  00005203      cmpeq    r2, #0                                      
  0000ec84  0800000a      beq      #0xecac                                     
  0000ec88  000051e3      cmp      r1, #0                                      
  0000ec8c  6420a013      movne    r2, #0x64                                   
  0000ec90  e9ffff0a      beq      #0xec3c                                     
  0000ec94  00109de5      ldr      r1, [sp]                                    
  0000ec98  010051e3      cmp      r1, #1                                      
  0000ec9c  02005303      cmpeq    r3, #2                                      
  0000eca0  0a20a003      moveq    r2, #0xa                                    
  0000eca4  002080e5      str      r2, [r0]                                    
  0000eca8  1eff2fe1      bx       lr                                          
  0000ecac  0720a0e3      mov      r2, #7                                      
  0000ecb0  f7ffffea      b        #0xec94                                     

; ─── HW_DM_PDT_GetHWDeviceTypeE8C @ 0xecb4 ───
  0000ecb4  000052e3      cmp      r2, #0                                      
  0000ecb8  0130a003      moveq    r3, #1                                      
  0000ecbc  00308005      streq    r3, [r0]                                    
  0000ecc0  1eff2f01      bxeq     lr                                          
  0000ecc4  000053e3      cmp      r3, #0                                      
  0000ecc8  0900001a      bne      #0xecf4                                     
  0000eccc  020051e3      cmp      r1, #2                                      
  0000ecd0  04005113      cmpne    r1, #4                                      
  0000ecd4  0430a003      moveq    r3, #4                                      
  0000ecd8  00308005      streq    r3, [r0]                                    
  0000ecdc  1eff2f01      bxeq     lr                                          
  0000ece0  010052e3      cmp      r2, #1                                      
  0000ece4  01005103      cmpeq    r1, #1                                      
  0000ece8  0530a003      moveq    r3, #5                                      
  0000ecec  00308005      streq    r3, [r0]                                    
  0000ecf0  1eff2f01      bxeq     lr                                          
  0000ecf4  0330a0e3      mov      r3, #3                                      
  0000ecf8  003080e5      str      r3, [r0]                                    
  0000ecfc  1eff2fe1      bx       lr                                          

; ─── HW_DM_PDT_GetHWDeviceType_Func @ 0xed00 ───
  0000ed00  0dc0a0e1      mov      ip, sp                                      
  0000ed04  1910a0e3      mov      r1, #0x19                                   
  0000ed08  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000ed0c  04b04ce2      sub      fp, ip, #4                                  
  0000ed10  40d04de2      sub      sp, sp, #0x40                               
  0000ed14  30204be2      sub      r2, fp, #0x30                               
  0000ed18  4500a0e3      mov      r0, #0x45                                   
  0000ed1c  000141e3      movt     r0, #0x1100                                 
  0000ed20  0030a0e3      mov      r3, #0                                      
  0000ed24  0340a0e3      mov      r4, #3                                      
  0000ed28  48300be5      str      r3, [fp, #-0x48]                            
  0000ed2c  44300be5      str      r3, [fp, #-0x44]                            
  0000ed30  40300be5      str      r3, [fp, #-0x40]                            
  0000ed34  3c300be5      str      r3, [fp, #-0x3c]                            
  0000ed38  30300be5      str      r3, [fp, #-0x30]                            
  0000ed3c  2c300be5      str      r3, [fp, #-0x2c]                            
  0000ed40  28300be5      str      r3, [fp, #-0x28]                            
  0000ed44  24300be5      str      r3, [fp, #-0x24]                            
  0000ed48  20300be5      str      r3, [fp, #-0x20]                            
  0000ed4c  1c300be5      str      r3, [fp, #-0x1c]                            
  0000ed50  18304be5      strb     r3, [fp, #-0x18]                            
  0000ed54  38300be5      str      r3, [fp, #-0x38]                            
  0000ed58  34300be5      str      r3, [fp, #-0x34]                            
  0000ed5c  4c400be5      str      r4, [fp, #-0x4c]                            
  0000ed60  79edffeb      bl       #0xa34c                                     
  0000ed64  0400a0e3      mov      r0, #4                                      
  0000ed68  48204be2      sub      r2, fp, #0x48                               
  0000ed6c  0010a0e1      mov      r1, r0                                      
  0000ed70  75edffeb      bl       #0xa34c                                     
  0000ed74  0410a0e3      mov      r1, #4                                      
  0000ed78  44204be2      sub      r2, fp, #0x44                               
  0000ed7c  0050a0e1      mov      r5, r0                                      
  0000ed80  0400a0e1      mov      r0, r4                                      
  0000ed84  70edffeb      bl       #0xa34c                                     
  0000ed88  0410a0e3      mov      r1, #4                                      
  0000ed8c  40204be2      sub      r2, fp, #0x40                               
  0000ed90  055080e1      orr      r5, r0, r5                                  
  0000ed94  0100a0e3      mov      r0, #1                                      
  0000ed98  6bedffeb      bl       #0xa34c                                     
  0000ed9c  0410a0e3      mov      r1, #4                                      
  0000eda0  3c204be2      sub      r2, fp, #0x3c                               
  0000eda4  005085e1      orr      r5, r5, r0                                  
  0000eda8  0600a0e3      mov      r0, #6                                      
  0000edac  66edffeb      bl       #0xa34c                                     
  0000edb0  005095e1      orrs     r5, r5, r0                                  
  0000edb4  0400a011      movne    r0, r4                                      
  0000edb8  0100000a      beq      #0xedc4                                     
  0000edbc  14d04be2      sub      sp, fp, #0x14                               
  0000edc0  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000edc4  c8109fe5      ldr      r1, [pc, #0xc8]                             
  0000edc8  30004be2      sub      r0, fp, #0x30                               
  0000edcc  01108fe0      add      r1, pc, r1                                  
  0000edd0  f5eeffeb      bl       #0xa9ac                                     
  0000edd4  000050e3      cmp      r0, #0                                      
  0000edd8  0900001a      bne      #0xee04                                     
  0000eddc  38004be2      sub      r0, fp, #0x38                               
  0000ede0  34104be2      sub      r1, fp, #0x34                               
  0000ede4  41efffeb      bl       #0xaaf0                                     
  0000ede8  34301be5      ldr      r3, [fp, #-0x34]                            
  0000edec  040053e3      cmp      r3, #4                                      
  0000edf0  1e00000a      beq      #0xee70                                     
  0000edf4  030053e3      cmp      r3, #3                                      
  0000edf8  1400000a      beq      #0xee50                                     
  0000edfc  2200a0e3      mov      r0, #0x22                                   
  0000ee00  edffffea      b        #0xedbc                                     
  0000ee04  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0000ee08  00008fe0      add      r0, pc, r0                                  
  0000ee0c  d9efffeb      bl       #0xad78                                     
  0000ee10  010050e3      cmp      r0, #1                                      
  0000ee14  80009fe5      ldr      r0, [pc, #0x80]                             
  0000ee18  40301b05      ldreq    r3, [fp, #-0x40]                            
  0000ee1c  00008fe0      add      r0, pc, r0                                  
  0000ee20  01304302      subeq    r3, r3, #1                                  
  0000ee24  40300b05      streq    r3, [fp, #-0x40]                            
  0000ee28  d2efffeb      bl       #0xad78                                     
  0000ee2c  40101be5      ldr      r1, [fp, #-0x40]                            
  0000ee30  48201be5      ldr      r2, [fp, #-0x48]                            
  0000ee34  44301be5      ldr      r3, [fp, #-0x44]                            
  0000ee38  010050e3      cmp      r0, #1                                      
  0000ee3c  4c004be2      sub      r0, fp, #0x4c                               
  0000ee40  0f00000a      beq      #0xee84                                     
  0000ee44  17efffeb      bl       #0xaaa8                                     
  0000ee48  4c001be5      ldr      r0, [fp, #-0x4c]                            
  0000ee4c  daffffea      b        #0xedbc                                     
  0000ee50  38301be5      ldr      r3, [fp, #-0x38]                            
  0000ee54  010053e3      cmp      r3, #1                                      
  0000ee58  e7ffff1a      bne      #0xedfc                                     
  0000ee5c  44301be5      ldr      r3, [fp, #-0x44]                            
  0000ee60  000053e3      cmp      r3, #0                                      
  0000ee64  2100a013      movne    r0, #0x21                                   
  0000ee68  d3ffff1a      bne      #0xedbc                                     
  0000ee6c  e2ffffea      b        #0xedfc                                     
  0000ee70  44001be5      ldr      r0, [fp, #-0x44]                            
  0000ee74  000050e3      cmp      r0, #0                                      
  0000ee78  2200a003      moveq    r0, #0x22                                   
  0000ee7c  2000a013      movne    r0, #0x20                                   
  0000ee80  cdffffea      b        #0xedbc                                     
  0000ee84  3cc01be5      ldr      ip, [fp, #-0x3c]                            
  0000ee88  00c08de5      str      ip, [sp]                                    
  0000ee8c  f8ecffeb      bl       #0xa274                                     
  0000ee90  ecffffea      b        #0xee48                                     
  0000ee94  20170200      andeq    r1, r2, r0, lsr #14                         
  0000ee98  68160200      andeq    r1, r2, r8, ror #12                         
  0000ee9c  9c160200      muleq    r2, ip, r6                                  

; ─── HW_DM_PDT_GetStringClassInGponMode @ 0xeea0 ───
  0000eea0  0dc0a0e1      mov      ip, sp                                      
  0000eea4  0030a0e1      mov      r3, r0                                      
  0000eea8  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000eeac  04b04ce2      sub      fp, ip, #4                                  
  0000eeb0  14d04de2      sub      sp, sp, #0x14                               
  0000eeb4  0140a0e1      mov      r4, r1                                      
  0000eeb8  060050e3      cmp      r0, #6                                      
  0000eebc  00f18f90      addls    pc, pc, r0, lsl #2                          
  0000eec0  180000ea      b        #0xef28                                     
  0000eec4  140000ea      b        #0xef1c                                     
  0000eec8  100000ea      b        #0xef10                                     
  0000eecc  0c0000ea      b        #0xef04                                     
  0000eed0  140000ea      b        #0xef28                                     
  0000eed4  130000ea      b        #0xef28                                     
  0000eed8  120000ea      b        #0xef28                                     
  0000eedc  ffffffea      b        #0xeee0                                     
  0000eee0  74209fe5      ldr      r2, [pc, #0x74]                             
  0000eee4  02208fe0      add      r2, pc, r2                                  
  0000eee8  0400a0e1      mov      r0, r4                                      
  0000eeec  011100e3      movw     r1, #0x101                                  
  0000eef0  013ca0e3      mov      r3, #0x100                                  
  0000eef4  7becffeb      bl       #0xa0e8                                     
  0000eef8  0000a0e3      mov      r0, #0                                      
  0000eefc  10d04be2      sub      sp, fp, #0x10                               
  0000ef00  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000ef04  54209fe5      ldr      r2, [pc, #0x54]                             
  0000ef08  02208fe0      add      r2, pc, r2                                  
  0000ef0c  f5ffffea      b        #0xeee8                                     
  0000ef10  4c209fe5      ldr      r2, [pc, #0x4c]                             
  0000ef14  02208fe0      add      r2, pc, r2                                  
  0000ef18  f2ffffea      b        #0xeee8                                     
  0000ef1c  44209fe5      ldr      r2, [pc, #0x44]                             
  0000ef20  02208fe0      add      r2, pc, r2                                  
  0000ef24  efffffea      b        #0xeee8                                     
  0000ef28  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0000ef2c  00c0a0e3      mov      ip, #0                                      
  0000ef30  d11300e3      movw     r1, #0x3d1                                  
  0000ef34  00c08de5      str      ip, [sp]                                    
  0000ef38  00008fe0      add      r0, pc, r0                                  
  0000ef3c  04c08de5      str      ip, [sp, #4]                                
  0000ef40  012805e3      movw     r2, #0x5801                                 
  0000ef44  08c08de5      str      ip, [sp, #8]                                
  0000ef48  20274fe3      movt     r2, #0xf720                                 
  0000ef4c  c4edffeb      bl       #0xa664                                     
  0000ef50  18209fe5      ldr      r2, [pc, #0x18]                             
  0000ef54  02208fe0      add      r2, pc, r2                                  
  0000ef58  e2ffffea      b        #0xeee8                                     
  0000ef5c  34160200      andeq    r1, r2, r4, lsr r6                          
  0000ef60  f0150200      strdeq   r1, r2, [r2], -r0                           
  0000ef64  f0150200      strdeq   r1, r2, [r2], -r0                           
  0000ef68  f0150200      strdeq   r1, r2, [r2], -r0                           
  0000ef6c  fc110200      strdeq   r1, r2, [r2], -ip                           
  0000ef70  bc150200      strheq   r1, [r2], -ip                               

; ─── HW_DM_PDT_GetStringClassInEponMode @ 0xef74 ───
  0000ef74  78209fe5      ldr      r2, [pc, #0x78]                             
  0000ef78  003050e2      subs     r3, r0, #0                                  
  0000ef7c  0dc0a0e1      mov      ip, sp                                      
  0000ef80  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000ef84  04b04ce2      sub      fp, ip, #4                                  
  0000ef88  14d04de2      sub      sp, sp, #0x14                               
  0000ef8c  02208fe0      add      r2, pc, r2                                  
  0000ef90  0140a0e1      mov      r4, r1                                      
  0000ef94  0f00000a      beq      #0xefd8                                     
  0000ef98  58209fe5      ldr      r2, [pc, #0x58]                             
  0000ef9c  010053e3      cmp      r3, #1                                      
  0000efa0  02208fe0      add      r2, pc, r2                                  
  0000efa4  0b00000a      beq      #0xefd8                                     
  0000efa8  4c009fe5      ldr      r0, [pc, #0x4c]                             
  0000efac  00c0a0e3      mov      ip, #0                                      
  0000efb0  fb1300e3      movw     r1, #0x3fb                                  
  0000efb4  00c08de5      str      ip, [sp]                                    
  0000efb8  00008fe0      add      r0, pc, r0                                  
  0000efbc  04c08de5      str      ip, [sp, #4]                                
  0000efc0  012805e3      movw     r2, #0x5801                                 
  0000efc4  08c08de5      str      ip, [sp, #8]                                
  0000efc8  20274fe3      movt     r2, #0xf720                                 
  0000efcc  a4edffeb      bl       #0xa664                                     
  0000efd0  28209fe5      ldr      r2, [pc, #0x28]                             
  0000efd4  02208fe0      add      r2, pc, r2                                  
  0000efd8  0400a0e1      mov      r0, r4                                      
  0000efdc  011100e3      movw     r1, #0x101                                  
  0000efe0  013ca0e3      mov      r3, #0x100                                  
  0000efe4  3fecffeb      bl       #0xa0e8                                     
  0000efe8  0000a0e3      mov      r0, #0                                      
  0000efec  10d04be2      sub      sp, fp, #0x10                               
  0000eff0  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000eff4  b8150200      strheq   r1, [r2], -r8                               
  0000eff8  84150200      andeq    r1, r2, r4, lsl #11                         
  0000effc  7c110200      andeq    r1, r2, ip, ror r1                          
  0000f000  70150200      andeq    r1, r2, r0, ror r5                          

; ─── HW_DM_PDT_GetStringClassInAutoMode @ 0xf004 ───
  0000f004  010050e3      cmp      r0, #1                                      
  0000f008  0dc0a0e1      mov      ip, sp                                      
  0000f00c  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000f010  04b04ce2      sub      fp, ip, #4                                  
  0000f014  14d04de2      sub      sp, sp, #0x14                               
  0000f018  0030a0e1      mov      r3, r0                                      
  0000f01c  0140a0e1      mov      r4, r1                                      
  0000f020  1800000a      beq      #0xf088                                     
  0000f024  1400003a      blo      #0xf07c                                     
  0000f028  020050e3      cmp      r0, #2                                      
  0000f02c  1800000a      beq      #0xf094                                     
  0000f030  68009fe5      ldr      r0, [pc, #0x68]                             
  0000f034  00c0a0e3      mov      ip, #0                                      
  0000f038  281400e3      movw     r1, #0x428                                  
  0000f03c  00c08de5      str      ip, [sp]                                    
  0000f040  00008fe0      add      r0, pc, r0                                  
  0000f044  04c08de5      str      ip, [sp, #4]                                
  0000f048  012805e3      movw     r2, #0x5801                                 
  0000f04c  08c08de5      str      ip, [sp, #8]                                
  0000f050  20274fe3      movt     r2, #0xf720                                 
  0000f054  82edffeb      bl       #0xa664                                     
  0000f058  44209fe5      ldr      r2, [pc, #0x44]                             
  0000f05c  02208fe0      add      r2, pc, r2                                  
  0000f060  0400a0e1      mov      r0, r4                                      
  0000f064  011100e3      movw     r1, #0x101                                  
  0000f068  013ca0e3      mov      r3, #0x100                                  
  0000f06c  1decffeb      bl       #0xa0e8                                     
  0000f070  0000a0e3      mov      r0, #0                                      
  0000f074  10d04be2      sub      sp, fp, #0x10                               
  0000f078  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000f07c  24209fe5      ldr      r2, [pc, #0x24]                             
  0000f080  02208fe0      add      r2, pc, r2                                  
  0000f084  f5ffffea      b        #0xf060                                     
  0000f088  1c209fe5      ldr      r2, [pc, #0x1c]                             
  0000f08c  02208fe0      add      r2, pc, r2                                  
  0000f090  f2ffffea      b        #0xf060                                     
  0000f094  14209fe5      ldr      r2, [pc, #0x14]                             
  0000f098  02208fe0      add      r2, pc, r2                                  
  0000f09c  efffffea      b        #0xf060                                     
  0000f0a0  f4100200      strdeq   r1, r2, [r2], -r4                           
  0000f0a4  e0140200      andeq    r1, r2, r0, ror #9                          
  0000f0a8  bc140200      strheq   r1, [r2], -ip                               
  0000f0ac  a0140200      andeq    r1, r2, r0, lsr #9                          
  0000f0b0  b4140200      strheq   r1, [r2], -r4                               

; ─── HW_DM_PDT_GetClassInfoAndModeInfoByUpMode @ 0xf0b4 ───
  0000f0b4  000052e3      cmp      r2, #0                                      
  0000f0b8  00005313      cmpne    r3, #0                                      
  0000f0bc  0dc0a0e1      mov      ip, sp                                      
  0000f0c0  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000f0c4  04b04ce2      sub      fp, ip, #4                                  
  0000f0c8  14d04de2      sub      sp, sp, #0x14                               
  0000f0cc  02c0a0e1      mov      ip, r2                                      
  0000f0d0  0020a0e1      mov      r2, r0                                      
  0000f0d4  0d00000a      beq      #0xf110                                     
  0000f0d8  014040e2      sub      r4, r0, #1                                  
  0000f0dc  090054e3      cmp      r4, #9                                      
  0000f0e0  04f18f90      addls    pc, pc, r4, lsl #2                          
  0000f0e4  220000ea      b        #0xf174                                     
  0000f0e8  2c0000ea      b        #0xf1a0                                     
  0000f0ec  330000ea      b        #0xf1c0                                     
  0000f0f0  3a0000ea      b        #0xf1e0                                     
  0000f0f4  3e0000ea      b        #0xf1f4                                     
  0000f0f8  450000ea      b        #0xf214                                     
  0000f0fc  4b0000ea      b        #0xf230                                     
  0000f100  510000ea      b        #0xf24c                                     
  0000f104  570000ea      b        #0xf268                                     
  0000f108  190000ea      b        #0xf174                                     
  0000f10c  0d0000ea      b        #0xf148                                     
  0000f110  64019fe5      ldr      r0, [pc, #0x164]                            
  0000f114  0030a0e3      mov      r3, #0                                      
  0000f118  4a1400e3      movw     r1, #0x44a                                  
  0000f11c  00308de5      str      r3, [sp]                                    
  0000f120  00008fe0      add      r0, pc, r0                                  
  0000f124  04308de5      str      r3, [sp, #4]                                
  0000f128  012005e3      movw     r2, #0x5001                                 
  0000f12c  08308de5      str      r3, [sp, #8]                                
  0000f130  20274fe3      movt     r2, #0xf720                                 
  0000f134  4aedffeb      bl       #0xa664                                     
  0000f138  010005e3      movw     r0, #0x5001                                 
  0000f13c  20074fe3      movt     r0, #0xf720                                 
  0000f140  10d04be2      sub      sp, fp, #0x10                               
  0000f144  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000f148  30219fe5      ldr      r2, [pc, #0x130]                            
  0000f14c  0300a0e1      mov      r0, r3                                      
  0000f150  2ce19fe5      ldr      lr, [pc, #0x12c]                            
  0000f154  011100e3      movw     r1, #0x101                                  
  0000f158  02208fe0      add      r2, pc, r2                                  
  0000f15c  013ca0e3      mov      r3, #0x100                                  
  0000f160  0ee08fe0      add      lr, pc, lr                                  
  0000f164  00e08ce5      str      lr, [ip]                                    
  0000f168  deebffeb      bl       #0xa0e8                                     
  0000f16c  0000a0e3      mov      r0, #0                                      
  0000f170  f2ffffea      b        #0xf140                                     
  0000f174  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0000f178  0040a0e3      mov      r4, #0                                      
  0000f17c  8e1400e3      movw     r1, #0x48e                                  
  0000f180  00408de5      str      r4, [sp]                                    
  0000f184  00008fe0      add      r0, pc, r0                                  
  0000f188  04408de5      str      r4, [sp, #4]                                
  0000f18c  08408de5      str      r4, [sp, #8]                                
  0000f190  0430a0e1      mov      r3, r4                                      
  0000f194  32edffeb      bl       #0xa664                                     
  0000f198  0400a0e1      mov      r0, r4                                      
  0000f19c  e7ffffea      b        #0xf140                                     
  0000f1a0  0100a0e1      mov      r0, r1                                      
  0000f1a4  0310a0e1      mov      r1, r3                                      
  0000f1a8  dc309fe5      ldr      r3, [pc, #0xdc]                             
  0000f1ac  03308fe0      add      r3, pc, r3                                  
  0000f1b0  00308ce5      str      r3, [ip]                                    
  0000f1b4  10d04be2      sub      sp, fp, #0x10                               
  0000f1b8  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f1bc  8fefffea      b        #0xb000                                     
  0000f1c0  0100a0e1      mov      r0, r1                                      
  0000f1c4  0310a0e1      mov      r1, r3                                      
  0000f1c8  c0309fe5      ldr      r3, [pc, #0xc0]                             
  0000f1cc  03308fe0      add      r3, pc, r3                                  
  0000f1d0  00308ce5      str      r3, [ip]                                    
  0000f1d4  10d04be2      sub      sp, fp, #0x10                               
  0000f1d8  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f1dc  bef1ffea      b        #0xb8dc                                     
  0000f1e0  ac309fe5      ldr      r3, [pc, #0xac]                             
  0000f1e4  0000a0e3      mov      r0, #0                                      
  0000f1e8  03308fe0      add      r3, pc, r3                                  
  0000f1ec  00308ce5      str      r3, [ip]                                    
  0000f1f0  d2ffffea      b        #0xf140                                     
  0000f1f4  0100a0e1      mov      r0, r1                                      
  0000f1f8  0310a0e1      mov      r1, r3                                      
  0000f1fc  94309fe5      ldr      r3, [pc, #0x94]                             
  0000f200  03308fe0      add      r3, pc, r3                                  
  0000f204  00308ce5      str      r3, [ip]                                    
  0000f208  10d04be2      sub      sp, fp, #0x10                               
  0000f20c  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f210  c3ebffea      b        #0xa124                                     
  0000f214  0300a0e1      mov      r0, r3                                      
  0000f218  7c309fe5      ldr      r3, [pc, #0x7c]                             
  0000f21c  03308fe0      add      r3, pc, r3                                  
  0000f220  00308ce5      str      r3, [ip]                                    
  0000f224  10d04be2      sub      sp, fp, #0x10                               
  0000f228  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f22c  66f0ffea      b        #0xb3cc                                     
  0000f230  0300a0e1      mov      r0, r3                                      
  0000f234  64309fe5      ldr      r3, [pc, #0x64]                             
  0000f238  03308fe0      add      r3, pc, r3                                  
  0000f23c  00308ce5      str      r3, [ip]                                    
  0000f240  10d04be2      sub      sp, fp, #0x10                               
  0000f244  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f248  0df1ffea      b        #0xb684                                     
  0000f24c  0300a0e1      mov      r0, r3                                      
  0000f250  4c309fe5      ldr      r3, [pc, #0x4c]                             
  0000f254  03308fe0      add      r3, pc, r3                                  
  0000f258  00308ce5      str      r3, [ip]                                    
  0000f25c  10d04be2      sub      sp, fp, #0x10                               
  0000f260  10689de8      ldm      sp, {r4, fp, sp, lr}                        
  0000f264  13f0ffea      b        #0xb2b8                                     
  0000f268  38309fe5      ldr      r3, [pc, #0x38]                             
  0000f26c  0000a0e3      mov      r0, #0                                      
  0000f270  03308fe0      add      r3, pc, r3                                  
  0000f274  00308ce5      str      r3, [ip]                                    
  0000f278  b0ffffea      b        #0xf140                                     
  0000f27c  14100200      andeq    r1, r2, r4, lsl r0                          
  0000f280  60140200      andeq    r1, r2, r0, ror #8                          
  0000f284  50140200      andeq    r1, r2, r0, asr r4                          
  0000f288  b00f0200      strheq   r0, [r2], -r0                               
  0000f28c  f8340200      strdeq   r3, r4, [r2], -r8                           
  0000f290  e4340200      andeq    r3, r2, r4, ror #9                          
  0000f294  80130200      andeq    r1, r2, r0, lsl #7                          
  0000f298  5c130200      andeq    r1, r2, ip, asr r3                          
  0000f29c  58130200      andeq    r1, r2, r8, asr r3                          
  0000f2a0  44130200      andeq    r1, r2, r4, asr #6                          
  0000f2a4  3c130200      andeq    r1, r2, ip, lsr r3                          
  0000f2a8  34130200      andeq    r1, r2, r4, lsr r3                          

; ─── HW_DM_PDT_GetOpticInfo @ 0xf2ac ───
  0000f2ac  0dc0a0e1      mov      ip, sp                                      
  0000f2b0  0030a0e3      mov      r3, #0                                      
  0000f2b4  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0000f2b8  04b04ce2      sub      fp, ip, #4                                  
  0000f2bc  005050e2      subs     r5, r0, #0                                  
  0000f2c0  5cd04de2      sub      sp, sp, #0x5c                               
  0000f2c4  38300be5      str      r3, [fp, #-0x38]                            
  0000f2c8  03440503      movweq   r4, #0x5403                                 
  0000f2cc  34300be5      str      r3, [fp, #-0x34]                            
  0000f2d0  30304be5      strb     r3, [fp, #-0x30]                            
  0000f2d4  20474f03      movteq   r4, #0xf720                                 
  0000f2d8  3c300be5      str      r3, [fp, #-0x3c]                            
  0000f2dc  5500000a      beq      #0xf438                                     
  0000f2e0  0410a0e3      mov      r1, #4                                      
  0000f2e4  4c204be2      sub      r2, fp, #0x4c                               
  0000f2e8  4700a0e3      mov      r0, #0x47                                   
  0000f2ec  000141e3      movt     r0, #0x1100                                 
  0000f2f0  15ecffeb      bl       #0xa34c                                     
  0000f2f4  0410a0e3      mov      r1, #4                                      
  0000f2f8  48204be2      sub      r2, fp, #0x48                               
  0000f2fc  0040a0e1      mov      r4, r0                                      
  0000f300  4800a0e3      mov      r0, #0x48                                   
  0000f304  000141e3      movt     r0, #0x1100                                 
  0000f308  0fecffeb      bl       #0xa34c                                     
  0000f30c  0410a0e3      mov      r1, #4                                      
  0000f310  44204be2      sub      r2, fp, #0x44                               
  0000f314  044080e1      orr      r4, r0, r4                                  
  0000f318  4900a0e3      mov      r0, #0x49                                   
  0000f31c  000141e3      movt     r0, #0x1100                                 
  0000f320  09ecffeb      bl       #0xa34c                                     
  0000f324  0410a0e3      mov      r1, #4                                      
  0000f328  40204be2      sub      r2, fp, #0x40                               
  0000f32c  004084e1      orr      r4, r4, r0                                  
  0000f330  4a00a0e3      mov      r0, #0x4a                                   
  0000f334  000141e3      movt     r0, #0x1100                                 
  0000f338  03ecffeb      bl       #0xa34c                                     
  0000f33c  004094e1      orrs     r4, r4, r0                                  
  0000f340  3f00001a      bne      #0xf444                                     
  0000f344  0910a0e3      mov      r1, #9                                      
  0000f348  3020a0e3      mov      r2, #0x30                                   
  0000f34c  0130a0e1      mov      r3, r1                                      
  0000f350  38004be2      sub      r0, fp, #0x38                               
  0000f354  e3ecffeb      bl       #0xa6e8                                     
  0000f358  48301be5      ldr      r3, [fp, #-0x48]                            
  0000f35c  4c801be5      ldr      r8, [fp, #-0x4c]                            
  0000f360  38004be2      sub      r0, fp, #0x38                               
  0000f364  016003e2      and      r6, r3, #1                                  
  0000f368  d3c0e0e7      ubfx     ip, r3, #1, #1                              
  0000f36c  5331e0e7      ubfx     r3, r3, #2, #1                              
  0000f370  58300be5      str      r3, [fp, #-0x58]                            
  0000f374  34305be5      ldrb     r3, [fp, #-0x34]                            
  0000f378  019008e2      and      sb, r8, #1                                  
  0000f37c  50c00be5      str      ip, [fp, #-0x50]                            
  0000f380  d880e0e7      ubfx     r8, r8, #1, #1                              
  0000f384  44c01be5      ldr      ip, [fp, #-0x44]                            
  0000f388  3c104be2      sub      r1, fp, #0x3c                               
  0000f38c  54300be5      str      r3, [fp, #-0x54]                            
  0000f390  0220a0e3      mov      r2, #2                                      
  0000f394  40301be5      ldr      r3, [fp, #-0x40]                            
  0000f398  01c00ce2      and      ip, ip, #1                                  
  0000f39c  60c00be5      str      ip, [fp, #-0x60]                            
  0000f3a0  35c05be5      ldrb     ip, [fp, #-0x35]                            
  0000f3a4  013003e2      and      r3, r3, #1                                  
  0000f3a8  64300be5      str      r3, [fp, #-0x64]                            
  0000f3ac  37305be5      ldrb     r3, [fp, #-0x37]                            
  0000f3b0  31a05be5      ldrb     sl, [fp, #-0x31]                            
  0000f3b4  32705be5      ldrb     r7, [fp, #-0x32]                            
  0000f3b8  5cc00be5      str      ip, [fp, #-0x5c]                            
  0000f3bc  0aa089e0      add      sl, sb, sl                                  
  0000f3c0  33e05be5      ldrb     lr, [fp, #-0x33]                            
  0000f3c4  077088e0      add      r7, r8, r7                                  
  0000f3c8  68300be5      str      r3, [fp, #-0x68]                            
  0000f3cc  38c05be5      ldrb     ip, [fp, #-0x38]                            
  0000f3d0  0ee086e0      add      lr, r6, lr                                  
  0000f3d4  70a00be5      str      sl, [fp, #-0x70]                            
  0000f3d8  50301be5      ldr      r3, [fp, #-0x50]                            
  0000f3dc  54801be5      ldr      r8, [fp, #-0x54]                            
  0000f3e0  58901be5      ldr      sb, [fp, #-0x58]                            
  0000f3e4  5ca01be5      ldr      sl, [fp, #-0x5c]                            
  0000f3e8  086083e0      add      r6, r3, r8                                  
  0000f3ec  60301be5      ldr      r3, [fp, #-0x60]                            
  0000f3f0  0a8089e0      add      r8, sb, sl                                  
  0000f3f4  68901be5      ldr      sb, [fp, #-0x68]                            
  0000f3f8  6cc00be5      str      ip, [fp, #-0x6c]                            
  0000f3fc  64a01be5      ldr      sl, [fp, #-0x64]                            
  0000f400  09c083e0      add      ip, r3, sb                                  
  0000f404  6c901be5      ldr      sb, [fp, #-0x6c]                            
  0000f408  33e04be5      strb     lr, [fp, #-0x33]                            
  0000f40c  09308ae0      add      r3, sl, sb                                  
  0000f410  70a01be5      ldr      sl, [fp, #-0x70]                            
  0000f414  32704be5      strb     r7, [fp, #-0x32]                            
  0000f418  34604be5      strb     r6, [fp, #-0x34]                            
  0000f41c  31a04be5      strb     sl, [fp, #-0x31]                            
  0000f420  35804be5      strb     r8, [fp, #-0x35]                            
  0000f424  37c04be5      strb     ip, [fp, #-0x37]                            
  0000f428  38304be5      strb     r3, [fp, #-0x38]                            
  0000f42c  30404be5      strb     r4, [fp, #-0x30]                            
  0000f430  adeeffeb      bl       #0xaeec                                     
  0000f434  000085e5      str      r0, [r5]                                    
  0000f438  0400a0e1      mov      r0, r4                                      
  0000f43c  28d04be2      sub      sp, fp, #0x28                               
  0000f440  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  0000f444  4c001be5      ldr      r0, [fp, #-0x4c]                            
  0000f448  131da0e3      mov      r1, #0x4c0                                  
  0000f44c  0420a0e1      mov      r2, r4                                      
  0000f450  40301be5      ldr      r3, [fp, #-0x40]                            
  0000f454  00008de5      str      r0, [sp]                                    
  0000f458  48001be5      ldr      r0, [fp, #-0x48]                            
  0000f45c  04008de5      str      r0, [sp, #4]                                
  0000f460  44001be5      ldr      r0, [fp, #-0x44]                            
  0000f464  08008de5      str      r0, [sp, #8]                                
  0000f468  08009fe5      ldr      r0, [pc, #8]                                
  0000f46c  00008fe0      add      r0, pc, r0                                  
  0000f470  7becffeb      bl       #0xa664                                     
  0000f474  efffffea      b        #0xf438                                     
  0000f478  c80c0200      andeq    r0, r2, r8, asr #25                         

; ─── HW_DM_PDT_GetManufactureInfo_Func @ 0xf47c ───
  0000f47c  0dc0a0e1      mov      ip, sp                                      
  0000f480  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000f484  04b04ce2      sub      fp, ip, #4                                  
  0000f488  006050e2      subs     r6, r0, #0                                  
  0000f48c  34d04de2      sub      sp, sp, #0x34                               
  0000f490  0040a0e3      mov      r4, #0                                      
  0000f494  34400be5      str      r4, [fp, #-0x34]                            
  0000f498  30400be5      str      r4, [fp, #-0x30]                            
  0000f49c  2c400be5      str      r4, [fp, #-0x2c]                            
  0000f4a0  28400be5      str      r4, [fp, #-0x28]                            
  0000f4a4  24400be5      str      r4, [fp, #-0x24]                            
  0000f4a8  20404be5      strb     r4, [fp, #-0x20]                            
  0000f4ac  bc434be1      strh     r4, [fp, #-0x3c]                            
  0000f4b0  38400be5      str      r4, [fp, #-0x38]                            
  0000f4b4  3300000a      beq      #0xf588                                     
  0000f4b8  3b00a0e3      mov      r0, #0x3b                                   
  0000f4bc  1510a0e3      mov      r1, #0x15                                   
  0000f4c0  000141e3      movt     r0, #0x1100                                 
  0000f4c4  34204be2      sub      r2, fp, #0x34                               
  0000f4c8  9febffeb      bl       #0xa34c                                     
  0000f4cc  005050e2      subs     r5, r0, #0                                  
  0000f4d0  2200001a      bne      #0xf560                                     
  0000f4d4  38004be2      sub      r0, fp, #0x38                               
  0000f4d8  30f0ffeb      bl       #0xb5a0                                     
  0000f4dc  0210a0e3      mov      r1, #2                                      
  0000f4e0  3c204be2      sub      r2, fp, #0x3c                               
  0000f4e4  0050a0e1      mov      r5, r0                                      
  0000f4e8  4200a0e3      mov      r0, #0x42                                   
  0000f4ec  000141e3      movt     r0, #0x1100                                 
  0000f4f0  95ebffeb      bl       #0xa34c                                     
  0000f4f4  055090e1      orrs     r5, r0, r5                                  
  0000f4f8  2f00001a      bne      #0xf5bc                                     
  0000f4fc  3c305be5      ldrb     r3, [fp, #-0x3c]                            
  0000f500  32c0a0e3      mov      ip, #0x32                                   
  0000f504  0600a0e1      mov      r0, r6                                      
  0000f508  0cc08de5      str      ip, [sp, #0xc]                              
  0000f50c  411043e2      sub      r1, r3, #0x41                               
  0000f510  302043e2      sub      r2, r3, #0x30                               
  0000f514  190051e3      cmp      r1, #0x19                                   
  0000f518  09005283      cmphi    r2, #9                                      
  0000f51c  34204be2      sub      r2, fp, #0x34                               
  0000f520  00208de5      str      r2, [sp]                                    
  0000f524  4110a0e3      mov      r1, #0x41                                   
  0000f528  3030a083      movhi    r3, #0x30                                   
  0000f52c  3b304be5      strb     r3, [fp, #-0x3b]                            
  0000f530  3b305be5      ldrb     r3, [fp, #-0x3b]                            
  0000f534  38201be5      ldr      r2, [fp, #-0x38]                            
  0000f538  3cc04be5      strb     ip, [fp, #-0x3c]                            
  0000f53c  08308de5      str      r3, [sp, #8]                                
  0000f540  9c309fe5      ldr      r3, [pc, #0x9c]                             
  0000f544  04208de5      str      r2, [sp, #4]                                
  0000f548  4020a0e3      mov      r2, #0x40                                   
  0000f54c  03308fe0      add      r3, pc, r3                                  
  0000f550  27edffeb      bl       #0xa9f4                                     
  0000f554  0500a0e1      mov      r0, r5                                      
  0000f558  18d04be2      sub      sp, fp, #0x18                               
  0000f55c  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  0000f560  80009fe5      ldr      r0, [pc, #0x80]                             
  0000f564  fa1400e3      movw     r1, #0x4fa                                  
  0000f568  00408de5      str      r4, [sp]                                    
  0000f56c  0520a0e1      mov      r2, r5                                      
  0000f570  04408de5      str      r4, [sp, #4]                                
  0000f574  0430a0e1      mov      r3, r4                                      
  0000f578  08408de5      str      r4, [sp, #8]                                
  0000f57c  00008fe0      add      r0, pc, r0                                  
  0000f580  37ecffeb      bl       #0xa664                                     
  0000f584  f2ffffea      b        #0xf554                                     
  0000f588  5c009fe5      ldr      r0, [pc, #0x5c]                             
  0000f58c  f11400e3      movw     r1, #0x4f1                                  
  0000f590  00608de5      str      r6, [sp]                                    
  0000f594  032405e3      movw     r2, #0x5403                                 
  0000f598  04608de5      str      r6, [sp, #4]                                
  0000f59c  20274fe3      movt     r2, #0xf720                                 
  0000f5a0  08608de5      str      r6, [sp, #8]                                
  0000f5a4  00008fe0      add      r0, pc, r0                                  
  0000f5a8  0630a0e1      mov      r3, r6                                      
  0000f5ac  035405e3      movw     r5, #0x5403                                 
  0000f5b0  2becffeb      bl       #0xa664                                     
  0000f5b4  20574fe3      movt     r5, #0xf720                                 
  0000f5b8  e5ffffea      b        #0xf554                                     
  0000f5bc  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000f5c0  061500e3      movw     r1, #0x506                                  
  0000f5c4  00408de5      str      r4, [sp]                                    
  0000f5c8  0520a0e1      mov      r2, r5                                      
  0000f5cc  04408de5      str      r4, [sp, #4]                                
  0000f5d0  00008fe0      add      r0, pc, r0                                  
  0000f5d4  08408de5      str      r4, [sp, #8]                                
  0000f5d8  38301be5      ldr      r3, [fp, #-0x38]                            
  0000f5dc  20ecffeb      bl       #0xa664                                     
  0000f5e0  dbffffea      b        #0xf554                                     
  0000f5e4  74100200      andeq    r1, r2, r4, ror r0                          
  0000f5e8  b80b0200      strheq   r0, [r2], -r8                               
  0000f5ec  900b0200      muleq    r2, r0, fp                                  
  0000f5f0  640b0200      andeq    r0, r2, r4, ror #22                         

; ─── HW_DM_GetHtmlSpecFtResVersion @ 0xf5f4 ───
  0000f5f4  0dc0a0e1      mov      ip, sp                                      
  0000f5f8  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0000f5fc  04b04ce2      sub      fp, ip, #4                                  
  0000f600  bc529fe5      ldr      r5, [pc, #0x2bc]                            
  0000f604  48d04de2      sub      sp, sp, #0x48                               
  0000f608  0070a0e1      mov      r7, r0                                      
  0000f60c  05508fe0      add      r5, pc, r5                                  
  0000f610  0040a0e3      mov      r4, #0                                      
  0000f614  0160a0e1      mov      r6, r1                                      
  0000f618  0280a0e1      mov      r8, r2                                      
  0000f61c  0500a0e1      mov      r0, r5                                      
  0000f620  48400be5      str      r4, [fp, #-0x48]                            
  0000f624  44400be5      str      r4, [fp, #-0x44]                            
  0000f628  04a0a0e1      mov      sl, r4                                      
  0000f62c  40400be5      str      r4, [fp, #-0x40]                            
  0000f630  3c400be5      str      r4, [fp, #-0x3c]                            
  0000f634  38400be5      str      r4, [fp, #-0x38]                            
  0000f638  34400be5      str      r4, [fp, #-0x34]                            
  0000f63c  30400be5      str      r4, [fp, #-0x30]                            
  0000f640  2c400be5      str      r4, [fp, #-0x2c]                            
  0000f644  b8424be1      strh     r4, [fp, #-0x28]                            
  0000f648  58400be5      str      r4, [fp, #-0x58]                            
  0000f64c  54400be5      str      r4, [fp, #-0x54]                            
  0000f650  50400be5      str      r4, [fp, #-0x50]                            
  0000f654  4c400be5      str      r4, [fp, #-0x4c]                            
  0000f658  26eeffeb      bl       #0xaef8                                     
  0000f65c  010050e3      cmp      r0, #1                                      
  0000f660  1200000a      beq      #0xf6b0                                     
  0000f664  5c529fe5      ldr      r5, [pc, #0x25c]                            
  0000f668  2110a0e3      mov      r1, #0x21                                   
  0000f66c  58c29fe5      ldr      ip, [pc, #0x258]                            
  0000f670  2020a0e3      mov      r2, #0x20                                   
  0000f674  05508fe0      add      r5, pc, r5                                  
  0000f678  0700a0e1      mov      r0, r7                                      
  0000f67c  0cc08fe0      add      ip, pc, ip                                  
  0000f680  00c08de5      str      ip, [sp]                                    
  0000f684  0530a0e1      mov      r3, r5                                      
  0000f688  d9ecffeb      bl       #0xa9f4                                     
  0000f68c  00808de5      str      r8, [sp]                                    
  0000f690  0600a0e1      mov      r0, r6                                      
  0000f694  2110a0e3      mov      r1, #0x21                                   
  0000f698  2020a0e3      mov      r2, #0x20                                   
  0000f69c  0530a0e1      mov      r3, r5                                      
  0000f6a0  d3ecffeb      bl       #0xa9f4                                     
  0000f6a4  0400a0e1      mov      r0, r4                                      
  0000f6a8  24d04be2      sub      sp, fp, #0x24                               
  0000f6ac  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0000f6b0  18829fe5      ldr      r8, [pc, #0x218]                            
  0000f6b4  2110a0e3      mov      r1, #0x21                                   
  0000f6b8  14c29fe5      ldr      ip, [pc, #0x214]                            
  0000f6bc  2020a0e3      mov      r2, #0x20                                   
  0000f6c0  08808fe0      add      r8, pc, r8                                  
  0000f6c4  0700a0e1      mov      r0, r7                                      
  0000f6c8  0cc08fe0      add      ip, pc, ip                                  
  0000f6cc  00c08de5      str      ip, [sp]                                    
  0000f6d0  0830a0e1      mov      r3, r8                                      
  0000f6d4  c6ecffeb      bl       #0xa9f4                                     
  0000f6d8  f8c19fe5      ldr      ip, [pc, #0x1f8]                            
  0000f6dc  2020a0e3      mov      r2, #0x20                                   
  0000f6e0  0830a0e1      mov      r3, r8                                      
  0000f6e4  0cc08fe0      add      ip, pc, ip                                  
  0000f6e8  2110a0e3      mov      r1, #0x21                                   
  0000f6ec  00c08de5      str      ip, [sp]                                    
  0000f6f0  0600a0e1      mov      r0, r6                                      
  0000f6f4  beecffeb      bl       #0xa9f4                                     
  0000f6f8  0500a0e1      mov      r0, r5                                      
  0000f6fc  0410a0e1      mov      r1, r4                                      
  0000f700  ff2100e3      movw     r2, #0x1ff                                  
  0000f704  3bedffeb      bl       #0xabf8                                     
  0000f708  010070e3      cmn      r0, #1                                      
  0000f70c  0050a0e1      mov      r5, r0                                      
  0000f710  0200001a      bne      #0xf720                                     
  0000f714  024405e3      movw     r4, #0x5402                                 
  0000f718  20474fe3      movt     r4, #0xf720                                 
  0000f71c  e0ffffea      b        #0xf6a4                                     
  0000f720  2120a0e3      mov      r2, #0x21                                   
  0000f724  48104be2      sub      r1, fp, #0x48                               
  0000f728  68f0ffeb      bl       #0xb8d0                                     
  0000f72c  27a04be5      strb     sl, [fp, #-0x27]                            
  0000f730  010070e3      cmn      r0, #1                                      
  0000f734  0040a0e1      mov      r4, r0                                      
  0000f738  0300000a      beq      #0xf74c                                     
  0000f73c  48004be2      sub      r0, fp, #0x48                               
  0000f740  f2edffeb      bl       #0xaf10                                     
  0000f744  000050e3      cmp      r0, #0                                      
  0000f748  0400001a      bne      #0xf760                                     
  0000f74c  0500a0e1      mov      r0, r5                                      
  0000f750  024405e3      movw     r4, #0x5402                                 
  0000f754  34ecffeb      bl       #0xa82c                                     
  0000f758  20474fe3      movt     r4, #0xf720                                 
  0000f75c  d0ffffea      b        #0xf6a4                                     
  0000f760  0500a0e1      mov      r0, r5                                      
  0000f764  30ecffeb      bl       #0xa82c                                     
  0000f768  6c119fe5      ldr      r1, [pc, #0x16c]                            
  0000f76c  48004be2      sub      r0, fp, #0x48                               
  0000f770  01108fe0      add      r1, pc, r1                                  
  0000f774  29efffeb      bl       #0xb420                                     
  0000f778  005050e2      subs     r5, r0, #0                                  
  0000f77c  e4ffff0a      beq      #0xf714                                     
  0000f780  e2edffeb      bl       #0xaf10                                     
  0000f784  010050e3      cmp      r0, #1                                      
  0000f788  e1ffff9a      bls      #0xf714                                     
  0000f78c  012085e2      add      r2, r5, #1                                  
  0000f790  0410a0e3      mov      r1, #4                                      
  0000f794  0330a0e3      mov      r3, #3                                      
  0000f798  58004be2      sub      r0, fp, #0x58                               
  0000f79c  51eaffeb      bl       #0xa0e8                                     
  0000f7a0  38119fe5      ldr      r1, [pc, #0x138]                            
  0000f7a4  0500a0e1      mov      r0, r5                                      
  0000f7a8  01108fe0      add      r1, pc, r1                                  
  0000f7ac  1befffeb      bl       #0xb420                                     
  0000f7b0  005050e2      subs     r5, r0, #0                                  
  0000f7b4  d6ffff0a      beq      #0xf714                                     
  0000f7b8  d4edffeb      bl       #0xaf10                                     
  0000f7bc  010050e3      cmp      r0, #1                                      
  0000f7c0  d3ffff9a      bls      #0xf714                                     
  0000f7c4  0410a0e3      mov      r1, #4                                      
  0000f7c8  012085e2      add      r2, r5, #1                                  
  0000f7cc  0330a0e3      mov      r3, #3                                      
  0000f7d0  54004be2      sub      r0, fp, #0x54                               
  0000f7d4  43eaffeb      bl       #0xa0e8                                     
  0000f7d8  04119fe5      ldr      r1, [pc, #0x104]                            
  0000f7dc  0500a0e1      mov      r0, r5                                      
  0000f7e0  01108fe0      add      r1, pc, r1                                  
  0000f7e4  0defffeb      bl       #0xb420                                     
  0000f7e8  007050e2      subs     r7, r0, #0                                  
  0000f7ec  c8ffff0a      beq      #0xf714                                     
  0000f7f0  c6edffeb      bl       #0xaf10                                     
  0000f7f4  010050e3      cmp      r0, #1                                      
  0000f7f8  c5ffff9a      bls      #0xf714                                     
  0000f7fc  50504be2      sub      r5, fp, #0x50                               
  0000f800  0410a0e3      mov      r1, #4                                      
  0000f804  012087e2      add      r2, r7, #1                                  
  0000f808  0230a0e3      mov      r3, #2                                      
  0000f80c  0500a0e1      mov      r0, r5                                      
  0000f810  34eaffeb      bl       #0xa0e8                                     
  0000f814  cc109fe5      ldr      r1, [pc, #0xcc]                             
  0000f818  0700a0e1      mov      r0, r7                                      
  0000f81c  01108fe0      add      r1, pc, r1                                  
  0000f820  feeeffeb      bl       #0xb420                                     
  0000f824  008050e2      subs     r8, r0, #0                                  
  0000f828  b9ffff0a      beq      #0xf714                                     
  0000f82c  b7edffeb      bl       #0xaf10                                     
  0000f830  030050e3      cmp      r0, #3                                      
  0000f834  b6ffff9a      bls      #0xf714                                     
  0000f838  4c704be2      sub      r7, fp, #0x4c                               
  0000f83c  0330a0e3      mov      r3, #3                                      
  0000f840  0410a0e3      mov      r1, #4                                      
  0000f844  032088e0      add      r2, r8, r3                                  
  0000f848  0700a0e1      mov      r0, r7                                      
  0000f84c  25eaffeb      bl       #0xa0e8                                     
  0000f850  58004be2      sub      r0, fp, #0x58                               
  0000f854  0010a0e3      mov      r1, #0                                      
  0000f858  0a20a0e3      mov      r2, #0xa                                    
  0000f85c  7eeaffeb      bl       #0xa25c                                     
  0000f860  0010a0e3      mov      r1, #0                                      
  0000f864  0a20a0e3      mov      r2, #0xa                                    
  0000f868  00a0a0e1      mov      sl, r0                                      
  0000f86c  54004be2      sub      r0, fp, #0x54                               
  0000f870  79eaffeb      bl       #0xa25c                                     
  0000f874  0020a0e3      mov      r2, #0                                      
  0000f878  2030a0e3      mov      r3, #0x20                                   
  0000f87c  2110a0e3      mov      r1, #0x21                                   
  0000f880  0080a0e1      mov      r8, r0                                      
  0000f884  0600a0e1      mov      r0, r6                                      
  0000f888  96ebffeb      bl       #0xa6e8                                     
  0000f88c  6410a0e3      mov      r1, #0x64                                   
  0000f890  0a00a0e1      mov      r0, sl                                      
  0000f894  fbefffeb      bl       #0xb888                                     
  0000f898  4c309fe5      ldr      r3, [pc, #0x4c]                             
  0000f89c  04808de5      str      r8, [sp, #4]                                
  0000f8a0  2110a0e3      mov      r1, #0x21                                   
  0000f8a4  08508de5      str      r5, [sp, #8]                                
  0000f8a8  2020a0e3      mov      r2, #0x20                                   
  0000f8ac  0c708de5      str      r7, [sp, #0xc]                              
  0000f8b0  03308fe0      add      r3, pc, r3                                  
  0000f8b4  00008de5      str      r0, [sp]                                    
  0000f8b8  0600a0e1      mov      r0, r6                                      
  0000f8bc  4cecffeb      bl       #0xa9f4                                     
  0000f8c0  77ffffea      b        #0xf6a4                                     
  0000f8c4  c00f0200      andeq    r0, r2, r0, asr #31                         
  0000f8c8  2c1e0200      andeq    r1, r2, ip, lsr #28                         
  0000f8cc  740f0200      andeq    r0, r2, r4, ror pc                          
  0000f8d0  e01d0200      andeq    r1, r2, r0, ror #27                         
  0000f8d4  340f0200      andeq    r0, r2, r4, lsr pc                          
  0000f8d8  200f0200      andeq    r0, r2, r0, lsr #30                         
  0000f8dc  840d0200      andeq    r0, r2, r4, lsl #27                         
  0000f8e0  600e0200      andeq    r0, r2, r0, ror #28                         
  0000f8e4  541c0200      andeq    r1, r2, r4, asr ip                          
  0000f8e8  f00d0200      strdeq   r0, r1, [r2], -r0                           
  0000f8ec  600d0200      andeq    r0, r2, r0, ror #26                         

; ─── HW_DM_PDT_GetAPDescriptionInfo @ 0xf8f0 ───
  0000f8f0  010050e3      cmp      r0, #1                                      
  0000f8f4  0dc0a0e1      mov      ip, sp                                      
  0000f8f8  00d82de9      push     {fp, ip, lr, pc}                            
  0000f8fc  04b04ce2      sub      fp, ip, #4                                  
  0000f900  30d04de2      sub      sp, sp, #0x30                               
  0000f904  02c0a0e1      mov      ip, r2                                      
  0000f908  2500000a      beq      #0xf9a4                                     
  0000f90c  020050e3      cmp      r0, #2                                      
  0000f910  4200000a      beq      #0xfa20                                     
  0000f914  030050e3      cmp      r0, #3                                      
  0000f918  0200000a      beq      #0xf928                                     
  0000f91c  0000a0e3      mov      r0, #0                                      
  0000f920  0cd04be2      sub      sp, fp, #0xc                                
  0000f924  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000f928  6ce19fe5      ldr      lr, [pc, #0x16c]                            
  0000f92c  0100a0e1      mov      r0, r1                                      
  0000f930  20308de5      str      r3, [sp, #0x20]                             
  0000f934  011100e3      movw     r1, #0x101                                  
  0000f938  0ee08fe0      add      lr, pc, lr                                  
  0000f93c  00508de8      stm      sp, {ip, lr}                                
  0000f940  58c19fe5      ldr      ip, [pc, #0x158]                            
  0000f944  012ca0e3      mov      r2, #0x100                                  
  0000f948  04309be5      ldr      r3, [fp, #4]                                
  0000f94c  0cc08fe0      add      ip, pc, ip                                  
  0000f950  08c08de5      str      ip, [sp, #8]                                
  0000f954  48c19fe5      ldr      ip, [pc, #0x148]                            
  0000f958  24308de5      str      r3, [sp, #0x24]                             
  0000f95c  0cc08fe0      add      ip, pc, ip                                  
  0000f960  10c08de5      str      ip, [sp, #0x10]                             
  0000f964  3cc19fe5      ldr      ip, [pc, #0x13c]                            
  0000f968  08309be5      ldr      r3, [fp, #8]                                
  0000f96c  0cc08fe0      add      ip, pc, ip                                  
  0000f970  14c08de5      str      ip, [sp, #0x14]                             
  0000f974  30c19fe5      ldr      ip, [pc, #0x130]                            
  0000f978  28308de5      str      r3, [sp, #0x28]                             
  0000f97c  0cc08fe0      add      ip, pc, ip                                  
  0000f980  28319fe5      ldr      r3, [pc, #0x128]                            
  0000f984  18c08de5      str      ip, [sp, #0x18]                             
  0000f988  24c19fe5      ldr      ip, [pc, #0x124]                            
  0000f98c  03308fe0      add      r3, pc, r3                                  
  0000f990  0ce08de5      str      lr, [sp, #0xc]                              
  0000f994  0cc08fe0      add      ip, pc, ip                                  
  0000f998  1cc08de5      str      ip, [sp, #0x1c]                             
  0000f99c  14ecffeb      bl       #0xa9f4                                     
  0000f9a0  ddffffea      b        #0xf91c                                     
  0000f9a4  00c08de5      str      ip, [sp]                                    
  0000f9a8  0100a0e1      mov      r0, r1                                      
  0000f9ac  04c19fe5      ldr      ip, [pc, #0x104]                            
  0000f9b0  011100e3      movw     r1, #0x101                                  
  0000f9b4  1c308de5      str      r3, [sp, #0x1c]                             
  0000f9b8  012ca0e3      mov      r2, #0x100                                  
  0000f9bc  0cc08fe0      add      ip, pc, ip                                  
  0000f9c0  04c08de5      str      ip, [sp, #4]                                
  0000f9c4  f0c09fe5      ldr      ip, [pc, #0xf0]                             
  0000f9c8  04309be5      ldr      r3, [fp, #4]                                
  0000f9cc  0cc08fe0      add      ip, pc, ip                                  
  0000f9d0  08c08de5      str      ip, [sp, #8]                                
  0000f9d4  e4c09fe5      ldr      ip, [pc, #0xe4]                             
  0000f9d8  20308de5      str      r3, [sp, #0x20]                             
  0000f9dc  0cc08fe0      add      ip, pc, ip                                  
  0000f9e0  0cc08de5      str      ip, [sp, #0xc]                              
  0000f9e4  d8c09fe5      ldr      ip, [pc, #0xd8]                             
  0000f9e8  08309be5      ldr      r3, [fp, #8]                                
  0000f9ec  0cc08fe0      add      ip, pc, ip                                  
  0000f9f0  10c08de5      str      ip, [sp, #0x10]                             
  0000f9f4  ccc09fe5      ldr      ip, [pc, #0xcc]                             
  0000f9f8  24308de5      str      r3, [sp, #0x24]                             
  0000f9fc  0cc08fe0      add      ip, pc, ip                                  
  0000fa00  c4309fe5      ldr      r3, [pc, #0xc4]                             
  0000fa04  14c08de5      str      ip, [sp, #0x14]                             
  0000fa08  c0c09fe5      ldr      ip, [pc, #0xc0]                             
  0000fa0c  03308fe0      add      r3, pc, r3                                  
  0000fa10  0cc08fe0      add      ip, pc, ip                                  
  0000fa14  18c08de5      str      ip, [sp, #0x18]                             
  0000fa18  f5ebffeb      bl       #0xa9f4                                     
  0000fa1c  beffffea      b        #0xf91c                                     
  0000fa20  ace09fe5      ldr      lr, [pc, #0xac]                             
  0000fa24  0100a0e1      mov      r0, r1                                      
  0000fa28  20308de5      str      r3, [sp, #0x20]                             
  0000fa2c  011100e3      movw     r1, #0x101                                  
  0000fa30  0ee08fe0      add      lr, pc, lr                                  
  0000fa34  00508de8      stm      sp, {ip, lr}                                
  0000fa38  98c09fe5      ldr      ip, [pc, #0x98]                             
  0000fa3c  012ca0e3      mov      r2, #0x100                                  
  0000fa40  04309be5      ldr      r3, [fp, #4]                                
  0000fa44  0cc08fe0      add      ip, pc, ip                                  
  0000fa48  08c08de5      str      ip, [sp, #8]                                
  0000fa4c  88c09fe5      ldr      ip, [pc, #0x88]                             
  0000fa50  24308de5      str      r3, [sp, #0x24]                             
  0000fa54  0cc08fe0      add      ip, pc, ip                                  
  0000fa58  10c08de5      str      ip, [sp, #0x10]                             
  0000fa5c  7cc09fe5      ldr      ip, [pc, #0x7c]                             
  0000fa60  08309be5      ldr      r3, [fp, #8]                                
  0000fa64  0cc08fe0      add      ip, pc, ip                                  
  0000fa68  14c08de5      str      ip, [sp, #0x14]                             
  0000fa6c  70c09fe5      ldr      ip, [pc, #0x70]                             
  0000fa70  28308de5      str      r3, [sp, #0x28]                             
  0000fa74  0cc08fe0      add      ip, pc, ip                                  
  0000fa78  68309fe5      ldr      r3, [pc, #0x68]                             
  0000fa7c  18c08de5      str      ip, [sp, #0x18]                             
  0000fa80  64c09fe5      ldr      ip, [pc, #0x64]                             
  0000fa84  03308fe0      add      r3, pc, r3                                  
  0000fa88  0ce08de5      str      lr, [sp, #0xc]                              
  0000fa8c  0cc08fe0      add      ip, pc, ip                                  
  0000fa90  1cc08de5      str      ip, [sp, #0x1c]                             
  0000fa94  d6ebffeb      bl       #0xa9f4                                     
  0000fa98  9fffffea      b        #0xf91c                                     
  0000fa9c  680d0200      andeq    r0, r2, r8, ror #26                         
  0000faa0  000d0200      andeq    r0, r2, r0, lsl #26                         
  0000faa4  140d0200      andeq    r0, r2, r4, lsl sp                          
  0000faa8  480d0200      andeq    r0, r2, r8, asr #26                         
  0000faac  e40c0200      andeq    r0, r2, r4, ror #25                         
  0000fab0  ec0c0200      andeq    r0, r2, ip, ror #25                         
  0000fab4  44090200      andeq    r0, r2, r4, asr #18                         
  0000fab8  880c0200      andeq    r0, r2, r8, lsl #25                         
  0000fabc  800c0200      andeq    r0, r2, r0, lsl #25                         
  0000fac0  7c0c0200      andeq    r0, r2, ip, ror ip                          
  0000fac4  740c0200      andeq    r0, r2, r4, ror ip                          
  0000fac8  740c0200      andeq    r0, r2, r4, ror ip                          
  0000facc  100c0200      andeq    r0, r2, r0, lsl ip                          
  0000fad0  c8080200      andeq    r0, r2, r8, asr #17                         
  0000fad4  700c0200      andeq    r0, r2, r0, ror ip                          
  0000fad8  080c0200      andeq    r0, r2, r8, lsl #24                         
  0000fadc  1c0c0200      andeq    r0, r2, ip, lsl ip                          
  0000fae0  440c0200      andeq    r0, r2, r4, asr #24                         
  0000fae4  ec0b0200      andeq    r0, r2, ip, ror #23                         
  0000fae8  f40b0200      strdeq   r0, r1, [r2], -r4                           
  0000faec  4c080200      andeq    r0, r2, ip, asr #16                         

; ─── HW_DM_CheckCurVer_Smooth @ 0xfaf0 ───
  0000faf0  0dc0a0e1      mov      ip, sp                                      
  0000faf4  3b00a0e3      mov      r0, #0x3b                                   
  0000faf8  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0000fafc  04b04ce2      sub      fp, ip, #4                                  
  0000fb00  28d04de2      sub      sp, sp, #0x28                               
  0000fb04  1510a0e3      mov      r1, #0x15                                   
  0000fb08  000141e3      movt     r0, #0x1100                                 
  0000fb0c  34204be2      sub      r2, fp, #0x34                               
  0000fb10  0040a0e3      mov      r4, #0                                      
  0000fb14  34400be5      str      r4, [fp, #-0x34]                            
  0000fb18  30400be5      str      r4, [fp, #-0x30]                            
  0000fb1c  2c400be5      str      r4, [fp, #-0x2c]                            
  0000fb20  28400be5      str      r4, [fp, #-0x28]                            
  0000fb24  24400be5      str      r4, [fp, #-0x24]                            
  0000fb28  20404be5      strb     r4, [fp, #-0x20]                            
  0000fb2c  06eaffeb      bl       #0xa34c                                     
  0000fb30  005050e2      subs     r5, r0, #0                                  
  0000fb34  2900001a      bne      #0xfbe0                                     
  0000fb38  34004be2      sub      r0, fp, #0x34                               
  0000fb3c  f3ecffeb      bl       #0xaf10                                     
  0000fb40  140050e3      cmp      r0, #0x14                                   
  0000fb44  0c00000a      beq      #0xfb7c                                     
  0000fb48  48019fe5      ldr      r0, [pc, #0x148]                            
  0000fb4c  0530a0e1      mov      r3, r5                                      
  0000fb50  00508de5      str      r5, [sp]                                    
  0000fb54  0120a0e3      mov      r2, #1                                      
  0000fb58  04508de5      str      r5, [sp, #4]                                
  0000fb5c  ef1500e3      movw     r1, #0x5ef                                  
  0000fb60  08508de5      str      r5, [sp, #8]                                
  0000fb64  00008fe0      add      r0, pc, r0                                  
  0000fb68  0250a0e1      mov      r5, r2                                      
  0000fb6c  bceaffeb      bl       #0xa664                                     
  0000fb70  0500a0e1      mov      r0, r5                                      
  0000fb74  1cd04be2      sub      sp, fp, #0x1c                               
  0000fb78  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000fb7c  18119fe5      ldr      r1, [pc, #0x118]                            
  0000fb80  28004be2      sub      r0, fp, #0x28                               
  0000fb84  0220a0e3      mov      r2, #2                                      
  0000fb88  01108fe0      add      r1, pc, r1                                  
  0000fb8c  b3eeffeb      bl       #0xb660                                     
  0000fb90  000050e3      cmp      r0, #0                                      
  0000fb94  1b0000da      ble      #0xfc08                                     
  0000fb98  00419fe5      ldr      r4, [pc, #0x100]                            
  0000fb9c  04408fe0      add      r4, pc, r4                                  
  0000fba0  0400a0e1      mov      r0, r4                                      
  0000fba4  d3ecffeb      bl       #0xaef8                                     
  0000fba8  010050e3      cmp      r0, #1                                      
  0000fbac  00c0a0e1      mov      ip, r0                                      
  0000fbb0  1f00000a      beq      #0xfc34                                     
  0000fbb4  e8709fe5      ldr      r7, [pc, #0xe8]                             
  0000fbb8  07708fe0      add      r7, pc, r7                                  
  0000fbbc  0700a0e1      mov      r0, r7                                      
  0000fbc0  ccecffeb      bl       #0xaef8                                     
  0000fbc4  010050e3      cmp      r0, #1                                      
  0000fbc8  0060a0e1      mov      r6, r0                                      
  0000fbcc  2300000a      beq      #0xfc60                                     
  0000fbd0  d0009fe5      ldr      r0, [pc, #0xd0]                             
  0000fbd4  00008fe0      add      r0, pc, r0                                  
  0000fbd8  63ecffeb      bl       #0xad6c                                     
  0000fbdc  e3ffffea      b        #0xfb70                                     
  0000fbe0  c4009fe5      ldr      r0, [pc, #0xc4]                             
  0000fbe4  e71500e3      movw     r1, #0x5e7                                  
  0000fbe8  00408de5      str      r4, [sp]                                    
  0000fbec  0520a0e1      mov      r2, r5                                      
  0000fbf0  04408de5      str      r4, [sp, #4]                                
  0000fbf4  0430a0e1      mov      r3, r4                                      
  0000fbf8  08408de5      str      r4, [sp, #8]                                
  0000fbfc  00008fe0      add      r0, pc, r0                                  
  0000fc00  97eaffeb      bl       #0xa664                                     
  0000fc04  d9ffffea      b        #0xfb70                                     
  0000fc08  a0009fe5      ldr      r0, [pc, #0xa0]                             
  0000fc0c  0530a0e1      mov      r3, r5                                      
  0000fc10  00508de5      str      r5, [sp]                                    
  0000fc14  0120a0e3      mov      r2, #1                                      
  0000fc18  04508de5      str      r5, [sp, #4]                                
  0000fc1c  f61500e3      movw     r1, #0x5f6                                  
  0000fc20  08508de5      str      r5, [sp, #8]                                
  0000fc24  00008fe0      add      r0, pc, r0                                  
  0000fc28  0250a0e1      mov      r5, r2                                      
  0000fc2c  8ceaffeb      bl       #0xa664                                     
  0000fc30  ceffffea      b        #0xfb70                                     
  0000fc34  0020a0e1      mov      r2, r0                                      
  0000fc38  74009fe5      ldr      r0, [pc, #0x74]                             
  0000fc3c  00508de5      str      r5, [sp]                                    
  0000fc40  0530a0e1      mov      r3, r5                                      
  0000fc44  04508de5      str      r5, [sp, #4]                                
  0000fc48  fc1500e3      movw     r1, #0x5fc                                  
  0000fc4c  08508de5      str      r5, [sp, #8]                                
  0000fc50  00008fe0      add      r0, pc, r0                                  
  0000fc54  0c50a0e1      mov      r5, ip                                      
  0000fc58  81eaffeb      bl       #0xa664                                     
  0000fc5c  c3ffffea      b        #0xfb70                                     
  0000fc60  0410a0e1      mov      r1, r4                                      
  0000fc64  0700a0e1      mov      r0, r7                                      
  0000fc68  33ecffeb      bl       #0xad3c                                     
  0000fc6c  44009fe5      ldr      r0, [pc, #0x44]                             
  0000fc70  00508de5      str      r5, [sp]                                    
  0000fc74  0530a0e1      mov      r3, r5                                      
  0000fc78  04508de5      str      r5, [sp, #4]                                
  0000fc7c  051600e3      movw     r1, #0x605                                  
  0000fc80  08508de5      str      r5, [sp, #8]                                
  0000fc84  00008fe0      add      r0, pc, r0                                  
  0000fc88  0620a0e1      mov      r2, r6                                      
  0000fc8c  0650a0e1      mov      r5, r6                                      
  0000fc90  73eaffeb      bl       #0xa664                                     
  0000fc94  b5ffffea      b        #0xfb70                                     
  0000fc98  d0050200      ldrdeq   r0, r1, [r2], -r0                           
  0000fc9c  340b0200      andeq    r0, r2, r4, lsr fp                          
  0000fca0  240b0200      andeq    r0, r2, r4, lsr #22                         
  0000fca4  280b0200      andeq    r0, r2, r8, lsr #22                         
  0000fca8  2c0b0200      andeq    r0, r2, ip, lsr #22                         
  0000fcac  38050200      andeq    r0, r2, r8, lsr r5                          
  0000fcb0  10050200      andeq    r0, r2, r0, lsl r5                          
  0000fcb4  e4040200      andeq    r0, r2, r4, ror #9                          
  0000fcb8  b0040200      strheq   r0, [r2], -r0                               

; ─── HW_DM_TyAddObject @ 0xfcbc ───
  0000fcbc  0dc0a0e1      mov      ip, sp                                      
  0000fcc0  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000fcc4  04b04ce2      sub      fp, ip, #4                                  
  0000fcc8  1cd04de2      sub      sp, sp, #0x1c                               
  0000fccc  0050a0e1      mov      r5, r0                                      
  0000fcd0  0160a0e1      mov      r6, r1                                      
  0000fcd4  1500a0e3      mov      r0, #0x15                                   
  0000fcd8  0010a0e3      mov      r1, #0                                      
  0000fcdc  0520a0e1      mov      r2, r5                                      
  0000fce0  24304be2      sub      r3, fp, #0x24                               
  0000fce4  02c0a0e3      mov      ip, #2                                      
  0000fce8  24c00be5      str      ip, [fp, #-0x24]                            
  0000fcec  00c0e0e3      mvn      ip, #0                                      
  0000fcf0  20c00be5      str      ip, [fp, #-0x20]                            
  0000fcf4  feeeffeb      bl       #0xb8f4                                     
  0000fcf8  004050e2      subs     r4, r0, #0                                  
  0000fcfc  1000001a      bne      #0xfd44                                     
  0000fd00  000056e3      cmp      r6, #0                                      
  0000fd04  1a00001a      bne      #0xfd74                                     
  0000fd08  24301be5      ldr      r3, [fp, #-0x24]                            
  0000fd0c  000053e3      cmp      r3, #0                                      
  0000fd10  1f00000a      beq      #0xfd94                                     
  0000fd14  9c009fe5      ldr      r0, [pc, #0x9c]                             
  0000fd18  0030a0e3      mov      r3, #0                                      
  0000fd1c  411600e3      movw     r1, #0x641                                  
  0000fd20  00308de5      str      r3, [sp]                                    
  0000fd24  00008fe0      add      r0, pc, r0                                  
  0000fd28  04308de5      str      r3, [sp, #4]                                
  0000fd2c  0420a0e1      mov      r2, r4                                      
  0000fd30  08308de5      str      r3, [sp, #8]                                
  0000fd34  4aeaffeb      bl       #0xa664                                     
  0000fd38  0400a0e1      mov      r0, r4                                      
  0000fd3c  18d04be2      sub      sp, fp, #0x18                               
  0000fd40  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  0000fd44  0000a0e3      mov      r0, #0                                      
  0000fd48  00008de5      str      r0, [sp]                                    
  0000fd4c  04008de5      str      r0, [sp, #4]                                
  0000fd50  0030a0e1      mov      r3, r0                                      
  0000fd54  08008de5      str      r0, [sp, #8]                                
  0000fd58  0420a0e1      mov      r2, r4                                      
  0000fd5c  58009fe5      ldr      r0, [pc, #0x58]                             
  0000fd60  2b1600e3      movw     r1, #0x62b                                  
  0000fd64  0140a0e3      mov      r4, #1                                      
  0000fd68  00008fe0      add      r0, pc, r0                                  
  0000fd6c  3ceaffeb      bl       #0xa664                                     
  0000fd70  f0ffffea      b        #0xfd38                                     
  0000fd74  0410a0e1      mov      r1, r4                                      
  0000fd78  0430a0e1      mov      r3, r4                                      
  0000fd7c  00608de5      str      r6, [sp]                                    
  0000fd80  1500a0e3      mov      r0, #0x15                                   
  0000fd84  0520a0e1      mov      r2, r5                                      
  0000fd88  a5ecffeb      bl       #0xb024                                     
  0000fd8c  0040a0e1      mov      r4, r0                                      
  0000fd90  dfffffea      b        #0xfd14                                     
  0000fd94  0410a0e1      mov      r1, r4                                      
  0000fd98  20304be2      sub      r3, fp, #0x20                               
  0000fd9c  1500a0e3      mov      r0, #0x15                                   
  0000fda0  00308de5      str      r3, [sp]                                    
  0000fda4  0520a0e1      mov      r2, r5                                      
  0000fda8  0430a0e1      mov      r3, r4                                      
  0000fdac  cfecffeb      bl       #0xb0f0                                     
  0000fdb0  0040a0e1      mov      r4, r0                                      
  0000fdb4  d6ffffea      b        #0xfd14                                     
  0000fdb8  10040200      andeq    r0, r2, r0, lsl r4                          
  0000fdbc  cc030200      andeq    r0, r2, ip, asr #7                          

; ─── HW_DM_SSLIsNeedSmooth @ 0xfdc0 ───
  0000fdc0  88009fe5      ldr      r0, [pc, #0x88]                             
  0000fdc4  0dc0a0e1      mov      ip, sp                                      
  0000fdc8  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000fdcc  04b04ce2      sub      fp, ip, #4                                  
  0000fdd0  1cd04de2      sub      sp, sp, #0x1c                               
  0000fdd4  00008fe0      add      r0, pc, r0                                  
  0000fdd8  0230a0e3      mov      r3, #2                                      
  0000fddc  18300be5      str      r3, [fp, #-0x18]                            
  0000fde0  e4ebffeb      bl       #0xad78                                     
  0000fde4  000050e3      cmp      r0, #0                                      
  0000fde8  0100001a      bne      #0xfdf4                                     
  0000fdec  10d04be2      sub      sp, fp, #0x10                               
  0000fdf0  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000fdf4  1500a0e3      mov      r0, #0x15                                   
  0000fdf8  0010a0e3      mov      r1, #0                                      
  0000fdfc  612ca0e3      mov      r2, #0x6100                                 
  0000fe00  18304be2      sub      r3, fp, #0x18                               
  0000fe04  382642e3      movt     r2, #0x2638                                 
  0000fe08  b9eeffeb      bl       #0xb8f4                                     
  0000fe0c  002050e2      subs     r2, r0, #0                                  
  0000fe10  0300001a      bne      #0xfe24                                     
  0000fe14  18001be5      ldr      r0, [fp, #-0x18]                            
  0000fe18  010070e2      rsbs     r0, r0, #1                                  
  0000fe1c  0000a033      movlo    r0, #0                                      
  0000fe20  f1ffffea      b        #0xfdec                                     
  0000fe24  28009fe5      ldr      r0, [pc, #0x28]                             
  0000fe28  0040a0e3      mov      r4, #0                                      
  0000fe2c  621600e3      movw     r1, #0x662                                  
  0000fe30  00408de5      str      r4, [sp]                                    
  0000fe34  00008fe0      add      r0, pc, r0                                  
  0000fe38  04408de5      str      r4, [sp, #4]                                
  0000fe3c  08408de5      str      r4, [sp, #8]                                
  0000fe40  0430a0e1      mov      r3, r4                                      
  0000fe44  06eaffeb      bl       #0xa664                                     
  0000fe48  0400a0e1      mov      r0, r4                                      
  0000fe4c  e6ffffea      b        #0xfdec                                     
  0000fe50  48090200      andeq    r0, r2, r8, asr #18                         
  0000fe54  00030200      andeq    r0, r2, r0, lsl #6                          

; ─── HW_DM_SSLNodeSmooth @ 0xfe58 ───
  0000fe58  00019fe5      ldr      r0, [pc, #0x100]                            
  0000fe5c  0dc0a0e1      mov      ip, sp                                      
  0000fe60  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000fe64  04b04ce2      sub      fp, ip, #4                                  
  0000fe68  18d04de2      sub      sp, sp, #0x18                               
  0000fe6c  00008fe0      add      r0, pc, r0                                  
  0000fe70  0040a0e3      mov      r4, #0                                      
  0000fe74  18400be5      str      r4, [fp, #-0x18]                            
  0000fe78  c0e9ffeb      bl       #0xa580                                     
  0000fe7c  d4e9ffeb      bl       #0xa5d4                                     
  0000fe80  005050e2      subs     r5, r0, #0                                  
  0000fe84  2800000a      beq      #0xff2c                                     
  0000fe88  610ca0e3      mov      r0, #0x6100                                 
  0000fe8c  0410a0e1      mov      r1, r4                                      
  0000fe90  380642e3      movt     r0, #0x2638                                 
  0000fe94  13edffeb      bl       #0xb2e8                                     
  0000fe98  005050e2      subs     r5, r0, #0                                  
  0000fe9c  1500001a      bne      #0xfef8                                     
  0000fea0  18404be2      sub      r4, fp, #0x18                               
  0000fea4  0120a0e3      mov      r2, #1                                      
  0000fea8  0430a0e3      mov      r3, #4                                      
  0000feac  30008de8      stm      sp, {r4, r5}                                
  0000feb0  610ca0e3      mov      r0, #0x6100                                 
  0000feb4  021106e3      movw     r1, #0x6102                                 
  0000feb8  380642e3      movt     r0, #0x2638                                 
  0000febc  381642e3      movt     r1, #0x2638                                 
  0000fec0  47eaffeb      bl       #0xa7e4                                     
  0000fec4  30008de8      stm      sp, {r4, r5}                                
  0000fec8  610ca0e3      mov      r0, #0x6100                                 
  0000fecc  031106e3      movw     r1, #0x6103                                 
  0000fed0  380642e3      movt     r0, #0x2638                                 
  0000fed4  381642e3      movt     r1, #0x2638                                 
  0000fed8  0120a0e3      mov      r2, #1                                      
  0000fedc  0430a0e3      mov      r3, #4                                      
  0000fee0  3feaffeb      bl       #0xa7e4                                     
  0000fee4  1500a0e3      mov      r0, #0x15                                   
  0000fee8  0510a0e1      mov      r1, r5                                      
  0000feec  06edffeb      bl       #0xb30c                                     
  0000fef0  14d04be2      sub      sp, fp, #0x14                               
  0000fef4  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000fef8  64009fe5      ldr      r0, [pc, #0x64]                             
  0000fefc  691ea0e3      mov      r1, #0x690                                  
  0000ff00  00408de5      str      r4, [sp]                                    
  0000ff04  0520a0e1      mov      r2, r5                                      
  0000ff08  04408de5      str      r4, [sp, #4]                                
  0000ff0c  0430a0e1      mov      r3, r4                                      
  0000ff10  08408de5      str      r4, [sp, #8]                                
  0000ff14  00008fe0      add      r0, pc, r0                                  
  0000ff18  d1e9ffeb      bl       #0xa664                                     
  0000ff1c  0410a0e1      mov      r1, r4                                      
  0000ff20  1500a0e3      mov      r0, #0x15                                   
  0000ff24  f8ecffeb      bl       #0xb30c                                     
  0000ff28  f0ffffea      b        #0xfef0                                     
  0000ff2c  34009fe5      ldr      r0, [pc, #0x34]                             
  0000ff30  00008fe0      add      r0, pc, r0                                  
  0000ff34  91e9ffeb      bl       #0xa580                                     
  0000ff38  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000ff3c  00508de5      str      r5, [sp]                                    
  0000ff40  871600e3      movw     r1, #0x687                                  
  0000ff44  04508de5      str      r5, [sp, #4]                                
  0000ff48  0120a0e3      mov      r2, #1                                      
  0000ff4c  08508de5      str      r5, [sp, #8]                                
  0000ff50  00008fe0      add      r0, pc, r0                                  
  0000ff54  0530a0e1      mov      r3, r5                                      
  0000ff58  c1e9ffeb      bl       #0xa664                                     
  0000ff5c  e3ffffea      b        #0xfef0                                     
  0000ff60  cc080200      andeq    r0, r2, ip, asr #17                         
  0000ff64  20020200      andeq    r0, r2, r0, lsr #4                          
  0000ff68  24080200      andeq    r0, r2, r4, lsr #16                         
  0000ff6c  e4010200      andeq    r0, r2, r4, ror #3                          

; ─── HW_DM_PDT_ModifyProductName @ 0xff70 ───
  0000ff70  0dc0a0e1      mov      ip, sp                                      
  0000ff74  0010a0e3      mov      r1, #0                                      
  0000ff78  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000ff7c  04b04ce2      sub      fp, ip, #4                                  
  0000ff80  cddf4de2      sub      sp, sp, #0x334                              
  0000ff84  4120a0e3      mov      r2, #0x41                                   
  0000ff88  cd0f4be2      sub      r0, fp, #0x334                              
  0000ff8c  0c50a0e3      mov      r5, #0xc                                    
  0000ff90  38530be5      str      r5, [fp, #-0x338]                           
  0000ff94  2ee9ffeb      bl       #0xa454                                     
  0000ff98  0010a0e3      mov      r1, #0                                      
  0000ff9c  4120a0e3      mov      r2, #0x41                                   
  0000ffa0  2f0e4be2      sub      r0, fp, #0x2f0                              
  0000ffa4  2ae9ffeb      bl       #0xa454                                     
  0000ffa8  0010a0e3      mov      r1, #0                                      
  0000ffac  012100e3      movw     r2, #0x101                                  
  0000ffb0  890f4be2      sub      r0, fp, #0x224                              
  0000ffb4  26e9ffeb      bl       #0xa454                                     
  0000ffb8  0010a0e3      mov      r1, #0                                      
  0000ffbc  4120a0e3      mov      r2, #0x41                                   
  0000ffc0  ab0f4be2      sub      r0, fp, #0x2ac                              
  0000ffc4  22e9ffeb      bl       #0xa454                                     
  0000ffc8  0010a0e3      mov      r1, #0                                      
  0000ffcc  4120a0e3      mov      r2, #0x41                                   
  0000ffd0  9a0f4be2      sub      r0, fp, #0x268                              
  0000ffd4  1ee9ffeb      bl       #0xa454                                     
  0000ffd8  0010a0e3      mov      r1, #0                                      
  0000ffdc  012100e3      movw     r2, #0x101                                  
  0000ffe0  120e4be2      sub      r0, fp, #0x120                              
  0000ffe4  1ae9ffeb      bl       #0xa454                                     
  0000ffe8  ce0f4be2      sub      r0, fp, #0x338                              
  0000ffec  1dedffeb      bl       #0xb468                                     
  0000fff0  004050e2      subs     r4, r0, #0                                  
  0000fff4  0500001a      bne      #0x10010                                    
  0000fff8  38331be5      ldr      r3, [fp, #-0x338]                           
  0000fffc  020053e3      cmp      r3, #2                                      
  00010000  0d00000a      beq      #0x1003c                                    
  00010004  0400a0e1      mov      r0, r4                                      
  00010008  18d04be2      sub      sp, fp, #0x18                               
  0001000c  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  00010010  f4019fe5      ldr      r0, [pc, #0x1f4]                            
  00010014  00c0a0e3      mov      ip, #0                                      
  00010018  b81600e3      movw     r1, #0x6b8                                  
  0001001c  00c08de5      str      ip, [sp]                                    
  00010020  00008fe0      add      r0, pc, r0                                  
  00010024  0420a0e1      mov      r2, r4                                      
  00010028  04c08de5      str      ip, [sp, #4]                                
  0001002c  38331be5      ldr      r3, [fp, #-0x338]                           
  00010030  08c08de5      str      ip, [sp, #8]                                
  00010034  8ae9ffeb      bl       #0xa664                                     
  00010038  f1ffffea      b        #0x10004                                    
  0001003c  cc019fe5      ldr      r0, [pc, #0x1cc]                            
  00010040  00008fe0      add      r0, pc, r0                                  
  00010044  4bebffeb      bl       #0xad78                                     
  00010048  010050e3      cmp      r0, #1                                      
  0001004c  ecffff1a      bne      #0x10004                                    
  00010050  4110a0e3      mov      r1, #0x41                                   
  00010054  cd2f4be2      sub      r2, fp, #0x334                              
  00010058  0b00a0e3      mov      r0, #0xb                                    
  0001005c  bae8ffeb      bl       #0xa34c                                     
  00010060  4110a0e3      mov      r1, #0x41                                   
  00010064  2f2e4be2      sub      r2, fp, #0x2f0                              
  00010068  0060a0e1      mov      r6, r0                                      
  0001006c  0d00a0e3      mov      r0, #0xd                                    
  00010070  b5e8ffeb      bl       #0xa34c                                     
  00010074  011100e3      movw     r1, #0x101                                  
  00010078  892f4be2      sub      r2, fp, #0x224                              
  0001007c  066080e1      orr      r6, r0, r6                                  
  00010080  0500a0e1      mov      r0, r5                                      
  00010084  b0e8ffeb      bl       #0xa34c                                     
  00010088  006096e1      orrs     r6, r6, r0                                  
  0001008c  3600001a      bne      #0x1016c                                    
  00010090  7c119fe5      ldr      r1, [pc, #0x17c]                            
  00010094  cd0f4be2      sub      r0, fp, #0x334                              
  00010098  01108fe0      add      r1, pc, r1                                  
  0001009c  4eeaffeb      bl       #0xa9dc                                     
  000100a0  000050e3      cmp      r0, #0                                      
  000100a4  0500000a      beq      #0x100c0                                    
  000100a8  68119fe5      ldr      r1, [pc, #0x168]                            
  000100ac  cd0f4be2      sub      r0, fp, #0x334                              
  000100b0  01108fe0      add      r1, pc, r1                                  
  000100b4  48eaffeb      bl       #0xa9dc                                     
  000100b8  000050e3      cmp      r0, #0                                      
  000100bc  3f00001a      bne      #0x101c0                                    
  000100c0  54419fe5      ldr      r4, [pc, #0x154]                            
  000100c4  4110a0e3      mov      r1, #0x41                                   
  000100c8  4020a0e3      mov      r2, #0x40                                   
  000100cc  cd0f4be2      sub      r0, fp, #0x334                              
  000100d0  04408fe0      add      r4, pc, r4                                  
  000100d4  00008de5      str      r0, [sp]                                    
  000100d8  ab0f4be2      sub      r0, fp, #0x2ac                              
  000100dc  0430a0e1      mov      r3, r4                                      
  000100e0  43eaffeb      bl       #0xa9f4                                     
  000100e4  0430a0e1      mov      r3, r4                                      
  000100e8  4110a0e3      mov      r1, #0x41                                   
  000100ec  4020a0e3      mov      r2, #0x40                                   
  000100f0  2f0e4be2      sub      r0, fp, #0x2f0                              
  000100f4  00008de5      str      r0, [sp]                                    
  000100f8  9a0f4be2      sub      r0, fp, #0x268                              
  000100fc  3ceaffeb      bl       #0xa9f4                                     
  00010100  0430a0e1      mov      r3, r4                                      
  00010104  011100e3      movw     r1, #0x101                                  
  00010108  012ca0e3      mov      r2, #0x100                                  
  0001010c  890f4be2      sub      r0, fp, #0x224                              
  00010110  00008de5      str      r0, [sp]                                    
  00010114  120e4be2      sub      r0, fp, #0x120                              
  00010118  35eaffeb      bl       #0xa9f4                                     
  0001011c  4110a0e3      mov      r1, #0x41                                   
  00010120  ab2f4be2      sub      r2, fp, #0x2ac                              
  00010124  0b00a0e3      mov      r0, #0xb                                    
  00010128  0feeffeb      bl       #0xb96c                                     
  0001012c  4110a0e3      mov      r1, #0x41                                   
  00010130  9a2f4be2      sub      r2, fp, #0x268                              
  00010134  0040a0e1      mov      r4, r0                                      
  00010138  0d00a0e3      mov      r0, #0xd                                    
  0001013c  0aeeffeb      bl       #0xb96c                                     
  00010140  011100e3      movw     r1, #0x101                                  
  00010144  122e4be2      sub      r2, fp, #0x120                              
  00010148  044080e1      orr      r4, r0, r4                                  
  0001014c  0c00a0e3      mov      r0, #0xc                                    
  00010150  05eeffeb      bl       #0xb96c                                     
  00010154  004094e1      orrs     r4, r4, r0                                  
  00010158  0e00001a      bne      #0x10198                                    
  0001015c  bc009fe5      ldr      r0, [pc, #0xbc]                             
  00010160  00008fe0      add      r0, pc, r0                                  
  00010164  2fe9ffeb      bl       #0xa628                                     
  00010168  a5ffffea      b        #0x10004                                    
  0001016c  b0009fe5      ldr      r0, [pc, #0xb0]                             
  00010170  0430a0e1      mov      r3, r4                                      
  00010174  00408de5      str      r4, [sp]                                    
  00010178  ce1600e3      movw     r1, #0x6ce                                  
  0001017c  04408de5      str      r4, [sp, #4]                                
  00010180  0620a0e1      mov      r2, r6                                      
  00010184  08408de5      str      r4, [sp, #8]                                
  00010188  00008fe0      add      r0, pc, r0                                  
  0001018c  0640a0e1      mov      r4, r6                                      
  00010190  33e9ffeb      bl       #0xa664                                     
  00010194  9affffea      b        #0x10004                                    
  00010198  88009fe5      ldr      r0, [pc, #0x88]                             
  0001019c  0030a0e3      mov      r3, #0                                      
  000101a0  ea1600e3      movw     r1, #0x6ea                                  
  000101a4  00308de5      str      r3, [sp]                                    
  000101a8  00008fe0      add      r0, pc, r0                                  
  000101ac  04308de5      str      r3, [sp, #4]                                
  000101b0  0420a0e1      mov      r2, r4                                      
  000101b4  08308de5      str      r3, [sp, #8]                                
  000101b8  29e9ffeb      bl       #0xa664                                     
  000101bc  90ffffea      b        #0x10004                                    
  000101c0  64109fe5      ldr      r1, [pc, #0x64]                             
  000101c4  cd0f4be2      sub      r0, fp, #0x334                              
  000101c8  01108fe0      add      r1, pc, r1                                  
  000101cc  02eaffeb      bl       #0xa9dc                                     
  000101d0  000050e3      cmp      r0, #0                                      
  000101d4  b9ffff0a      beq      #0x100c0                                    
  000101d8  50109fe5      ldr      r1, [pc, #0x50]                             
  000101dc  cd0f4be2      sub      r0, fp, #0x334                              
  000101e0  01108fe0      add      r1, pc, r1                                  
  000101e4  fce9ffeb      bl       #0xa9dc                                     
  000101e8  000050e3      cmp      r0, #0                                      
  000101ec  b3ffff0a      beq      #0x100c0                                    
  000101f0  3c109fe5      ldr      r1, [pc, #0x3c]                             
  000101f4  cd0f4be2      sub      r0, fp, #0x334                              
  000101f8  01108fe0      add      r1, pc, r1                                  
  000101fc  f6e9ffeb      bl       #0xa9dc                                     
  00010200  000050e3      cmp      r0, #0                                      
  00010204  adffff0a      beq      #0x100c0                                    
  00010208  7dffffea      b        #0x10004                                    
  0001020c  14010200      andeq    r0, r2, r4, lsl r1                          
  00010210  3c070200      andeq    r0, r2, ip, lsr r7                          
  00010214  00070200      andeq    r0, r2, r0, lsl #14                         
  00010218  f8060200      strdeq   r0, r1, [r2], -r8                           
  0001021c  d0060200      ldrdeq   r0, r1, [r2], -r0                           
  00010220  74060200      andeq    r0, r2, r4, ror r6                          
  00010224  acff0100      andeq    pc, r1, ip, lsr #31                         
  00010228  8cff0100      andeq    pc, r1, ip, lsl #31                         
  0001022c  e8050200      andeq    r0, r2, r8, ror #11                         
  00010230  dc050200      ldrdeq   r0, r1, [r2], -ip                           
  00010234  d0050200      ldrdeq   r0, r1, [r2], -r0                           

; ─── HW_DM_GET_SERIALNNUMBER_INFO_Func @ 0x10238 ───
  00010238  0dc0a0e1      mov      ip, sp                                      
  0001023c  4120a0e3      mov      r2, #0x41                                   
  00010240  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  00010244  04b04ce2      sub      fp, ip, #4                                  
  00010248  98d04de2      sub      sp, sp, #0x98                               
  0001024c  0060a0e1      mov      r6, r0                                      
  00010250  40519fe5      ldr      r5, [pc, #0x140]                            
  00010254  0170a0e1      mov      r7, r1                                      
  00010258  a4004be2      sub      r0, fp, #0xa4                               
  0001025c  0010a0e3      mov      r1, #0                                      
  00010260  05508fe0      add      r5, pc, r5                                  
  00010264  7ae8ffeb      bl       #0xa454                                     
  00010268  0010a0e3      mov      r1, #0                                      
  0001026c  4120a0e3      mov      r2, #0x41                                   
  00010270  60004be2      sub      r0, fp, #0x60                               
  00010274  76e8ffeb      bl       #0xa454                                     
  00010278  1c319fe5      ldr      r3, [pc, #0x11c]                            
  0001027c  1600a0e3      mov      r0, #0x16                                   
  00010280  0510a0e1      mov      r1, r5                                      
  00010284  fa2600e3      movw     r2, #0x6fa                                  
  00010288  03308fe0      add      r3, pc, r3                                  
  0001028c  00608de5      str      r6, [sp]                                    
  00010290  80e9ffeb      bl       #0xa898                                     
  00010294  3500a0e3      mov      r0, #0x35                                   
  00010298  4110a0e3      mov      r1, #0x41                                   
  0001029c  000141e3      movt     r0, #0x1100                                 
  000102a0  60204be2      sub      r2, fp, #0x60                               
  000102a4  28e8ffeb      bl       #0xa34c                                     
  000102a8  004050e2      subs     r4, r0, #0                                  
  000102ac  2700001a      bne      #0x10350                                    
  000102b0  7660ffe6      uxth     r6, r6                                      
  000102b4  0f0056e3      cmp      r6, #0xf                                    
  000102b8  0f00000a      beq      #0x102fc                                    
  000102bc  60204be2      sub      r2, fp, #0x60                               
  000102c0  4110a0e3      mov      r1, #0x41                                   
  000102c4  4030a0e3      mov      r3, #0x40                                   
  000102c8  830f87e2      add      r0, r7, #0x20c                              
  000102cc  85e7ffeb      bl       #0xa0e8                                     
  000102d0  00408de5      str      r4, [sp]                                    
  000102d4  04408de5      str      r4, [sp, #4]                                
  000102d8  0500a0e1      mov      r0, r5                                      
  000102dc  08408de5      str      r4, [sp, #8]                                
  000102e0  071700e3      movw     r1, #0x707                                  
  000102e4  0120a0e3      mov      r2, #1                                      
  000102e8  0430a0e1      mov      r3, r4                                      
  000102ec  dce8ffeb      bl       #0xa664                                     
  000102f0  0400a0e1      mov      r0, r4                                      
  000102f4  1cd04be2      sub      sp, fp, #0x1c                               
  000102f8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  000102fc  60004be2      sub      r0, fp, #0x60                               
  00010300  a4104be2      sub      r1, fp, #0xa4                               
  00010304  b7e9ffeb      bl       #0xa9e8                                     
  00010308  004050e2      subs     r4, r0, #0                                  
  0001030c  1800001a      bne      #0x10374                                    
  00010310  88309fe5      ldr      r3, [pc, #0x88]                             
  00010314  0510a0e1      mov      r1, r5                                      
  00010318  60c04be2      sub      ip, fp, #0x60                               
  0001031c  1600a0e3      mov      r0, #0x16                                   
  00010320  00c08de5      str      ip, [sp]                                    
  00010324  142700e3      movw     r2, #0x714                                  
  00010328  a4c04be2      sub      ip, fp, #0xa4                               
  0001032c  03308fe0      add      r3, pc, r3                                  
  00010330  04c08de5      str      ip, [sp, #4]                                
  00010334  57e9ffeb      bl       #0xa898                                     
  00010338  830f87e2      add      r0, r7, #0x20c                              
  0001033c  4110a0e3      mov      r1, #0x41                                   
  00010340  a4204be2      sub      r2, fp, #0xa4                               
  00010344  4030a0e3      mov      r3, #0x40                                   
  00010348  66e7ffeb      bl       #0xa0e8                                     
  0001034c  e7ffffea      b        #0x102f0                                    
  00010350  0030a0e3      mov      r3, #0                                      
  00010354  0500a0e1      mov      r0, r5                                      
  00010358  00308de5      str      r3, [sp]                                    
  0001035c  071ca0e3      mov      r1, #0x700                                  
  00010360  04308de5      str      r3, [sp, #4]                                
  00010364  0420a0e1      mov      r2, r4                                      
  00010368  08308de5      str      r3, [sp, #8]                                
  0001036c  bce8ffeb      bl       #0xa664                                     
  00010370  deffffea      b        #0x102f0                                    
  00010374  0030a0e3      mov      r3, #0                                      
  00010378  0500a0e1      mov      r0, r5                                      
  0001037c  00308de5      str      r3, [sp]                                    
  00010380  711ea0e3      mov      r1, #0x710                                  
  00010384  04308de5      str      r3, [sp, #4]                                
  00010388  0420a0e1      mov      r2, r4                                      
  0001038c  08308de5      str      r3, [sp, #8]                                
  00010390  b3e8ffeb      bl       #0xa664                                     
  00010394  d5ffffea      b        #0x102f0                                    