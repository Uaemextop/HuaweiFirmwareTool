### HW_DM_RPC_GetEfuseInfo @ 0x2ea14
  0002ea14  0dc0a0e1      mov      ip, sp                                      
  0002ea18  0000a0e3      mov      r0, #0                                      
  0002ea1c  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ea20  04b04ce2      sub      fp, ip, #4                                  
  0002ea24  0340a0e1      mov      r4, r3                                      
  0002ea28  000051e3      cmp      r1, #0                                      
  0002ea2c  00005413      cmpne    r4, #0                                      
  0002ea30  e0d04de2      sub      sp, sp, #0xe0                               
  0002ea34  0130a0e1      mov      r3, r1                                      
  0002ea38  0050a013      movne    r5, #0                                      
  0002ea3c  0150a003      moveq    r5, #1                                      
  0002ea40  ec000be5      str      r0, [fp, #-0xec]                            
  0002ea44  e8000be5      str      r0, [fp, #-0xe8]                            
  0002ea48  e4000be5      str      r0, [fp, #-0xe4]                            
  0002ea4c  e0000be5      str      r0, [fp, #-0xe0]                            
  0002ea50  dc000be5      str      r0, [fp, #-0xdc]                            
  0002ea54  d8000be5      str      r0, [fp, #-0xd8]                            
  0002ea58  d4000be5      str      r0, [fp, #-0xd4]                            
  0002ea5c  d0000be5      str      r0, [fp, #-0xd0]                            
  0002ea60  cc000be5      str      r0, [fp, #-0xcc]                            
  0002ea64  c8000be5      str      r0, [fp, #-0xc8]                            
  0002ea68  c4000be5      str      r0, [fp, #-0xc4]                            
  0002ea6c  c0000be5      str      r0, [fp, #-0xc0]                            
  0002ea70  0d00001a      bne      #0x2eaac                                    
  0002ea74  04008de5      str      r0, [sp, #4]                                
  0002ea78  911fa0e3      mov      r1, #0x244                                  
  0002ea7c  08008de5      str      r0, [sp, #8]                                
  0002ea80  032405e3      movw     r2, #0x5403                                 
  0002ea84  6c019fe5      ldr      r0, [pc, #0x16c]                            
  0002ea88  20274fe3      movt     r2, #0xf720                                 
  0002ea8c  00408de5      str      r4, [sp]                                    
  0002ea90  035405e3      movw     r5, #0x5403                                 
  0002ea94  00008fe0      add      r0, pc, r0                                  
  0002ea98  20574fe3      movt     r5, #0xf720                                 
  0002ea9c  f06effeb      bl       #0xa664                                     
  0002eaa0  0500a0e1      mov      r0, r5                                      
  0002eaa4  1cd04be2      sub      sp, fp, #0x1c                               
  0002eaa8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002eaac  a010a0e3      mov      r1, #0xa0                                   
  0002eab0  0520a0e1      mov      r2, r5                                      
  0002eab4  0130a0e1      mov      r3, r1                                      
  0002eab8  bc004be2      sub      r0, fp, #0xbc                               
  0002eabc  096fffeb      bl       #0xa6e8                                     
  0002eac0  bc004be2      sub      r0, fp, #0xbc                               
  0002eac4  ba70ffeb      bl       #0xadb4                                     
  0002eac8  006050e2      subs     r6, r0, #0                                  
  0002eacc  3100001a      bne      #0x2eb98                                    
  0002ead0  24719fe5      ldr      r7, [pc, #0x124]                            
  0002ead4  1500a0e3      mov      r0, #0x15                                   
  0002ead8  20319fe5      ldr      r3, [pc, #0x120]                            
  0002eadc  4f2200e3      movw     r2, #0x24f                                  
  0002eae0  07708fe0      add      r7, pc, r7                                  
  0002eae4  bc104be2      sub      r1, fp, #0xbc                               
  0002eae8  03308fe0      add      r3, pc, r3                                  
  0002eaec  00108de5      str      r1, [sp]                                    
  0002eaf0  0710a0e1      mov      r1, r7                                      
  0002eaf4  676fffeb      bl       #0xa898                                     
  0002eaf8  ec004be2      sub      r0, fp, #0xec                               
  0002eafc  3971ffeb      bl       #0xafe8                                     
  0002eb00  005050e2      subs     r5, r0, #0                                  
  0002eb04  1900001a      bne      #0x2eb70                                    
  0002eb08  f4609fe5      ldr      r6, [pc, #0xf4]                             
  0002eb0c  5430a0e3      mov      r3, #0x54                                   
  0002eb10  e8004be2      sub      r0, fp, #0xe8                               
  0002eb14  1c10a0e3      mov      r1, #0x1c                                   
  0002eb18  0420a0e1      mov      r2, r4                                      
  0002eb1c  06608fe0      add      r6, pc, r6                                  
  0002eb20  a472ffeb      bl       #0xb5b8                                     
  0002eb24  c8001be5      ldr      r0, [fp, #-0xc8]                            
  0002eb28  541084e2      add      r1, r4, #0x54                               
  0002eb2c  0d20a0e3      mov      r2, #0xd                                    
  0002eb30  c370ffeb      bl       #0xae44                                     
  0002eb34  611084e2      add      r1, r4, #0x61                               
  0002eb38  0b20a0e3      mov      r2, #0xb                                    
  0002eb3c  c4001be5      ldr      r0, [fp, #-0xc4]                            
  0002eb40  bf70ffeb      bl       #0xae44                                     
  0002eb44  0600a0e1      mov      r0, r6                                      
  0002eb48  f070ffeb      bl       #0xaf10                                     
  0002eb4c  0610a0e1      mov      r1, r6                                      
  0002eb50  0020a0e1      mov      r2, r0                                      
  0002eb54  bc004be2      sub      r0, fp, #0xbc                               
  0002eb58  3c72ffeb      bl       #0xb450                                     
  0002eb5c  000050e3      cmp      r0, #0                                      
  0002eb60  1700001a      bne      #0x2ebc4                                    
  0002eb64  c0301be5      ldr      r3, [fp, #-0xc0]                            
  0002eb68  6c3084e5      str      r3, [r4, #0x6c]                             
  0002eb6c  cbffffea      b        #0x2eaa0                                    
  0002eb70  0520a0e1      mov      r2, r5                                      
  0002eb74  00608de5      str      r6, [sp]                                    
  0002eb78  04608de5      str      r6, [sp, #4]                                
  0002eb7c  0700a0e1      mov      r0, r7                                      
  0002eb80  08608de5      str      r6, [sp, #8]                                
  0002eb84  951fa0e3      mov      r1, #0x254                                  
  0002eb88  0630a0e1      mov      r3, r6                                      
  0002eb8c  0150a0e3      mov      r5, #1                                      
  0002eb90  b36effeb      bl       #0xa664                                     
  0002eb94  c1ffffea      b        #0x2eaa0                                    
  0002eb98  68009fe5      ldr      r0, [pc, #0x68]                             
  0002eb9c  0530a0e1      mov      r3, r5                                      
  0002eba0  00508de5      str      r5, [sp]                                    
  0002eba4  931fa0e3      mov      r1, #0x24c                                  
  0002eba8  04508de5      str      r5, [sp, #4]                                
  0002ebac  0620a0e1      mov      r2, r6                                      
  0002ebb0  08508de5      str      r5, [sp, #8]                                
  0002ebb4  00008fe0      add      r0, pc, r0                                  
  0002ebb8  0150a0e3      mov      r5, #1                                      
  0002ebbc  a86effeb      bl       #0xa664                                     
  0002ebc0  b6ffffea      b        #0x2eaa0                                    
  0002ebc4  40609fe5      ldr      r6, [pc, #0x40]                             
  0002ebc8  06608fe0      add      r6, pc, r6                                  
  0002ebcc  0600a0e1      mov      r0, r6                                      
  0002ebd0  ce70ffeb      bl       #0xaf10                                     
  0002ebd4  0610a0e1      mov      r1, r6                                      
  0002ebd8  0020a0e1      mov      r2, r0                                      
  0002ebdc  bc004be2      sub      r0, fp, #0xbc                               
  0002ebe0  1a72ffeb      bl       #0xb450                                     
  0002ebe4  000050e3      cmp      r0, #0                                      
  0002ebe8  6330a013      movne    r3, #0x63                                   
  0002ebec  6c308415      strne    r3, [r4, #0x6c]                             
  0002ebf0  aaffff1a      bne      #0x2eaa0                                    
  0002ebf4  daffffea      b        #0x2eb64                                    
  0002ebf8  905d0000      muleq    r0, r0, sp                                  
  0002ebfc  445d0000      andeq    r5, r0, r4, asr #26                         
  0002ec00  405e0000      andeq    r5, r0, r0, asr #28                         
  0002ec04  185e0000      andeq    r5, r0, r8, lsl lr                          
  0002ec08  705c0000      andeq    r5, r0, r0, ror ip                          
  0002ec0c  745d0000      andeq    r5, r0, r4, ror sp                          
  0002ec10  0dc0a0e1      mov      ip, sp                                      
  0002ec14  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ec18  04b04ce2      sub      fp, ip, #4                                  
  0002ec1c  862e4be2      sub      r2, fp, #0x860                              
  0002ec20  86de4de2      sub      sp, sp, #0x860                              
  0002ec24  0c2042e2      sub      r2, r2, #0xc                                
  0002ec28  0040a0e3      mov      r4, #0                                      
  0002ec2c  08c082e2      add      ip, r2, #8                                  
  0002ec30  08d04de2      sub      sp, sp, #8                                  
  0002ec34  0150a0e1      mov      r5, r1                                      
  0002ec38  860e4be2      sub      r0, fp, #0x860                              
  0002ec3c  0410a0e1      mov      r1, r4                                      
  0002ec40  8020a0e3      mov      r2, #0x80                                   
  0002ec44  0360a0e1      mov      r6, r3                                      
  0002ec48  70480be5      str      r4, [fp, #-0x870]                           
  0002ec4c  6c480be5      str      r4, [fp, #-0x86c]                           
  0002ec50  68480be5      str      r4, [fp, #-0x868]                           
  0002ec54  00408ce5      str      r4, [ip]                                    
  0002ec58  fd6dffeb      bl       #0xa454                                     
  0002ec5c  040055e1      cmp      r5, r4                                      
  0002ec60  04005611      cmpne    r6, r4                                      
  0002ec64  0070a013      movne    r7, #0                                      
  0002ec68  0170a003      moveq    r7, #1                                      
  0002ec6c  1200000a      beq      #0x2ecbc                                    
  0002ec70  9030d5e5      ldrb     r3, [r5, #0x90]                             
  0002ec74  034003e2      and      r4, r3, #3                                  
  0002ec78  030054e3      cmp      r4, #3                                      
  0002ec7c  1b00000a      beq      #0x2ecf0                                    
  0002ec80  84019fe5      ldr      r0, [pc, #0x184]                            
  0002ec84  d320e0e7      ubfx     r2, r3, #1, #1                              
  0002ec88  8e1200e3      movw     r1, #0x28e                                  
  0002ec8c  84008de8      stm      sp, {r2, r7}                                
  0002ec90  08708de5      str      r7, [sp, #8]                                
  0002ec94  022405e3      movw     r2, #0x5402                                 
  0002ec98  00008fe0      add      r0, pc, r0                                  
  0002ec9c  20274fe3      movt     r2, #0xf720                                 
  0002eca0  013003e2      and      r3, r3, #1                                  
  0002eca4  024405e3      movw     r4, #0x5402                                 
  0002eca8  6d6effeb      bl       #0xa664                                     
  0002ecac  20474fe3      movt     r4, #0xf720                                 
  0002ecb0  0400a0e1      mov      r0, r4                                      
  0002ecb4  1cd04be2      sub      sp, fp, #0x1c                               
  0002ecb8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002ecbc  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0002ecc0  871200e3      movw     r1, #0x287                                  
  0002ecc4  04408de5      str      r4, [sp, #4]                                
  0002ecc8  032405e3      movw     r2, #0x5403                                 
  0002eccc  08408de5      str      r4, [sp, #8]                                
  0002ecd0  20274fe3      movt     r2, #0xf720                                 
  0002ecd4  00608de5      str      r6, [sp]                                    
  0002ecd8  00008fe0      add      r0, pc, r0                                  
  0002ecdc  0530a0e1      mov      r3, r5                                      
  0002ece0  034405e3      movw     r4, #0x5403                                 
  0002ece4  5e6effeb      bl       #0xa664                                     
  0002ece8  20474fe3      movt     r4, #0xf720                                 
  0002ecec  efffffea      b        #0x2ecb0                                    
  0002ecf0  1010a0e3      mov      r1, #0x10                                   
  0002ecf4  0520a0e1      mov      r2, r5                                      
  0002ecf8  0130a0e1      mov      r3, r1                                      
  0002ecfc  870e4be2      sub      r0, fp, #0x870                              
  0002ed00  9e6fffeb      bl       #0xab80                                     
  0002ed04  870e4be2      sub      r0, fp, #0x870                              
  0002ed08  b472ffeb      bl       #0xb7e0                                     
  0002ed0c  003050e2      subs     r3, r0, #0                                  
  0002ed10  0b00001a      bne      #0x2ed44                                    
  0002ed14  f8009fe5      ldr      r0, [pc, #0xf8]                             
  0002ed18  a61fa0e3      mov      r1, #0x298                                  
  0002ed1c  00308de5      str      r3, [sp]                                    
  0002ed20  022405e3      movw     r2, #0x5402                                 
  0002ed24  04308de5      str      r3, [sp, #4]                                
  0002ed28  20274fe3      movt     r2, #0xf720                                 
  0002ed2c  08308de5      str      r3, [sp, #8]                                
  0002ed30  00008fe0      add      r0, pc, r0                                  
  0002ed34  024405e3      movw     r4, #0x5402                                 
  0002ed38  496effeb      bl       #0xa664                                     
  0002ed3c  20474fe3      movt     r4, #0xf720                                 
  0002ed40  daffffea      b        #0x2ecb0                                    
  0002ed44  8010a0e3      mov      r1, #0x80                                   
  0002ed48  102085e2      add      r2, r5, #0x10                               
  0002ed4c  0130a0e1      mov      r3, r1                                      
  0002ed50  860e4be2      sub      r0, fp, #0x860                              
  0002ed54  896fffeb      bl       #0xab80                                     
  0002ed58  c41700e3      movw     r1, #0x7c4                                  
  0002ed5c  0130a0e1      mov      r3, r1                                      
  0002ed60  0720a0e1      mov      r2, r7                                      
  0002ed64  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002ed68  5e6effeb      bl       #0xa6e8                                     
  0002ed6c  7d3e4be2      sub      r3, fp, #0x7d0                              
  0002ed70  0c3043e2      sub      r3, r3, #0xc                                
  0002ed74  870e4be2      sub      r0, fp, #0x870                              
  0002ed78  241083e2      add      r1, r3, #0x24                               
  0002ed7c  4372ffeb      bl       #0xb690                                     
  0002ed80  90209fe5      ldr      r2, [pc, #0x90]                             
  0002ed84  b8c71be5      ldr      ip, [fp, #-0x7b8]                           
  0002ed88  2010a0e3      mov      r1, #0x20                                   
  0002ed8c  02208fe0      add      r2, pc, r2                                  
  0002ed90  0530a0e3      mov      r3, #5                                      
  0002ed94  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002ed98  3ccfbfe6      rev      ip, ip                                      
  0002ed9c  a4404be5      strb     r4, [fp, #-0xa4]                            
  0002eda0  b8c70be5      str      ip, [fp, #-0x7b8]                           
  0002eda4  1dc0a0e3      mov      ip, #0x1d                                   
  0002eda8  a3c04be5      strb     ip, [fp, #-0xa3]                            
  0002edac  0bc0a0e3      mov      ip, #0xb                                    
  0002edb0  c0c70be5      str      ip, [fp, #-0x7c0]                           
  0002edb4  cb6cffeb      bl       #0xa0e8                                     
  0002edb8  7dce4be2      sub      ip, fp, #0x7d0                              
  0002edbc  011ca0e3      mov      r1, #0x100                                  
  0002edc0  0cc04ce2      sub      ip, ip, #0xc                                
  0002edc4  862e4be2      sub      r2, fp, #0x860                              
  0002edc8  0130a0e1      mov      r3, r1                                      
  0002edcc  8a0f8ce2      add      r0, ip, #0x228                              
  0002edd0  c46cffeb      bl       #0xa0e8                                     
  0002edd4  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002edd8  2a71ffeb      bl       #0xb288                                     
  0002eddc  004050e2      subs     r4, r0, #0                                  
  0002ede0  b2ffff0a      beq      #0x2ecb0                                    
  0002ede4  30009fe5      ldr      r0, [pc, #0x30]                             
  0002ede8  ab1fa0e3      mov      r1, #0x2ac                                  
  0002edec  00708de5      str      r7, [sp]                                    
  0002edf0  0420a0e1      mov      r2, r4                                      
  0002edf4  04708de5      str      r7, [sp, #4]                                
  0002edf8  0730a0e1      mov      r3, r7                                      
  0002edfc  08708de5      str      r7, [sp, #8]                                
  0002ee00  00008fe0      add      r0, pc, r0                                  
  0002ee04  166effeb      bl       #0xa664                                     
  0002ee08  a8ffffea      b        #0x2ecb0                                    
  0002ee0c  8c5b0000      andeq    r5, r0, ip, lsl #23                         
  0002ee10  4c5b0000      andeq    r5, r0, ip, asr #22                         
  0002ee14  f45a0000      strdeq   r5, r6, [r0], -r4                           
  0002ee18  48110000      andeq    r1, r0, r8, asr #2                          
  0002ee1c  245a0000      andeq    r5, r0, r4, lsr #20                         
  0002ee20  90019fe5      ldr      r0, [pc, #0x190]                            
  0002ee24  0dc0a0e1      mov      ip, sp                                      
  0002ee28  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ee2c  04b04ce2      sub      fp, ip, #4                                  
  0002ee30  0040a0e3      mov      r4, #0                                      
  0002ee34  28d04de2      sub      sp, sp, #0x28                               
  0002ee38  00008fe0      add      r0, pc, r0                                  
  0002ee3c  0410a0e1      mov      r1, r4                                      
  0002ee40  2c204be2      sub      r2, fp, #0x2c                               
  0002ee44  30304be2      sub      r3, fp, #0x30                               
  0002ee48  30400be5      str      r4, [fp, #-0x30]                            
  0002ee4c  2c400be5      str      r4, [fp, #-0x2c]                            
  0002ee50  28400be5      str      r4, [fp, #-0x28]                            
  0002ee54  24400be5      str      r4, [fp, #-0x24]                            
  0002ee58  20400be5      str      r4, [fp, #-0x20]                            
  0002ee5c  ef6cffeb      bl       #0xa220                                     
  0002ee60  005050e2      subs     r5, r0, #0                                  
  0002ee64  3100001a      bne      #0x2ef30                                    
  0002ee68  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0002ee6c  2c104be2      sub      r1, fp, #0x2c                               
  0002ee70  30201be5      ldr      r2, [fp, #-0x30]                            
  0002ee74  00008fe0      add      r0, pc, r0                                  
  0002ee78  c06dffeb      bl       #0xa580                                     
  0002ee7c  0107a0e3      mov      r0, #0x40000                                
  0002ee80  3a70ffeb      bl       #0xaf70                                     
  0002ee84  004050e2      subs     r4, r0, #0                                  
  0002ee88  3500000a      beq      #0x2ef64                                    
  0002ee8c  0218a0e3      mov      r1, #0x20000                                
  0002ee90  016084e0      add      r6, r4, r1                                  
  0002ee94  0130a0e1      mov      r3, r1                                      
  0002ee98  ff20a0e3      mov      r2, #0xff                                   
  0002ee9c  116effeb      bl       #0xa6e8                                     
  0002eea0  2c004be2      sub      r0, fp, #0x2c                               
  0002eea4  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eea8  0620a0e1      mov      r2, r6                                      
  0002eeac  0238a0e3      mov      r3, #0x20000                                
  0002eeb0  936effeb      bl       #0xa904                                     
  0002eeb4  007050e2      subs     r7, r0, #0                                  
  0002eeb8  0f00001a      bne      #0x2eefc                                    
  0002eebc  0400a0e1      mov      r0, r4                                      
  0002eec0  0610a0e1      mov      r1, r6                                      
  0002eec4  0228a0e3      mov      r2, #0x20000                                
  0002eec8  416fffeb      bl       #0xabd4                                     
  0002eecc  000050e3      cmp      r0, #0                                      
  0002eed0  0600000a      beq      #0x2eef0                                    
  0002eed4  0420a0e1      mov      r2, r4                                      
  0002eed8  2c004be2      sub      r0, fp, #0x2c                               
  0002eedc  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eee0  0238a0e3      mov      r3, #0x20000                                
  0002eee4  1c72ffeb      bl       #0xb75c                                     
  0002eee8  002050e2      subs     r2, r0, #0                                  
  0002eeec  2600001a      bne      #0x2ef8c                                    
  0002eef0  0400a0e1      mov      r0, r4                                      
  0002eef4  646effeb      bl       #0xa88c                                     
  0002eef8  0a0000ea      b        #0x2ef28                                    
  0002eefc  bc009fe5      ldr      r0, [pc, #0xbc]                             
  0002ef00  ba1fa0e3      mov      r1, #0x2e8                                  
  0002ef04  00508de5      str      r5, [sp]                                    
  0002ef08  0720a0e1      mov      r2, r7                                      
  0002ef0c  00008fe0      add      r0, pc, r0                                  
  0002ef10  04508de5      str      r5, [sp, #4]                                
  0002ef14  08508de5      str      r5, [sp, #8]                                
  0002ef18  30301be5      ldr      r3, [fp, #-0x30]                            
  0002ef1c  d06dffeb      bl       #0xa664                                     
  0002ef20  0400a0e1      mov      r0, r4                                      
  0002ef24  586effeb      bl       #0xa88c                                     
  0002ef28  1cd04be2      sub      sp, fp, #0x1c                               
  0002ef2c  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002ef30  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0002ef34  00008fe0      add      r0, pc, r0                                  
  0002ef38  906dffeb      bl       #0xa580                                     
  0002ef3c  84009fe5      ldr      r0, [pc, #0x84]                             
  0002ef40  00408de5      str      r4, [sp]                                    
  0002ef44  b51fa0e3      mov      r1, #0x2d4                                  
  0002ef48  04408de5      str      r4, [sp, #4]                                
  0002ef4c  0520a0e1      mov      r2, r5                                      
  0002ef50  08408de5      str      r4, [sp, #8]                                
  0002ef54  00008fe0      add      r0, pc, r0                                  
  0002ef58  0430a0e1      mov      r3, r4                                      
  0002ef5c  c06dffeb      bl       #0xa664                                     
  0002ef60  f0ffffea      b        #0x2ef28                                    
  0002ef64  60009fe5      ldr      r0, [pc, #0x60]                             
  0002ef68  b71fa0e3      mov      r1, #0x2dc                                  
  0002ef6c  00408de5      str      r4, [sp]                                    
  0002ef70  0120a0e3      mov      r2, #1                                      
  0002ef74  04408de5      str      r4, [sp, #4]                                
  0002ef78  0430a0e1      mov      r3, r4                                      
  0002ef7c  08408de5      str      r4, [sp, #8]                                
  0002ef80  00008fe0      add      r0, pc, r0                                  
  0002ef84  b66dffeb      bl       #0xa664                                     
  0002ef88  e6ffffea      b        #0x2ef28                                    
  0002ef8c  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002ef90  f31200e3      movw     r1, #0x2f3                                  
  0002ef94  00708de5      str      r7, [sp]                                    
  0002ef98  04708de5      str      r7, [sp, #4]                                
  0002ef9c  00008fe0      add      r0, pc, r0                                  
  0002efa0  08708de5      str      r7, [sp, #8]                                
  0002efa4  30301be5      ldr      r3, [fp, #-0x30]                            
  0002efa8  ad6dffeb      bl       #0xa664                                     
  0002efac  0400a0e1      mov      r0, r4                                      
  0002efb0  356effeb      bl       #0xa88c                                     
  0002efb4  dbffffea      b        #0x2ef28                                    
  0002efb8  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efbc  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efc0  18590000      andeq    r5, r0, r8, lsl sb                          
  0002efc4  185a0000      andeq    r5, r0, r8, lsl sl                          
  0002efc8  d0580000      ldrdeq   r5, r6, [r0], -r0                           
  0002efcc  a4580000      andeq    r5, r0, r4, lsr #17                         
  0002efd0  88580000      andeq    r5, r0, r8, lsl #17                         
  0002efd4  0dc0a0e1      mov      ip, sp                                      
  0002efd8  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0002efdc  04b04ce2      sub      fp, ip, #4                                  
  0002efe0  005051e2      subs     r5, r1, #0                                  
  0002efe4  18d04de2      sub      sp, sp, #0x18                               
  0002efe8  0040a0e3      mov      r4, #0                                      
  0002efec  0060a0e1      mov      r6, r0                                      
  0002eff0  0270a0e1      mov      r7, r2                                      
  0002eff4  2c400be5      str      r4, [fp, #-0x2c]                            
  0002eff8  28400be5      str      r4, [fp, #-0x28]                            
  0002effc  4000000a      beq      #0x2f104                                    
  0002f000  1500a0e3      mov      r0, #0x15                                   
  0002f004  0410a0e1      mov      r1, r4                                      
  0002f008  0620a0e1      mov      r2, r6                                      
  0002f00c  2c304be2      sub      r3, fp, #0x2c                               
  0002f010  8a6dffeb      bl       #0xa640                                     
  0002f014  008050e2      subs     r8, r0, #0                                  
  0002f018  2e00001a      bne      #0x2f0d8                                    
  0002f01c  2c201be5      ldr      r2, [fp, #-0x2c]                            
  0002f020  070052e1      cmp      r2, r7                                      
  0002f024  2000008a      bhi      #0x2f0ac                                    
  0002f028  000052e3      cmp      r2, #0                                      
  0002f02c  002085e5      str      r2, [r5]                                    
  0002f030  1a00000a      beq      #0x2f0a0                                    
  0002f034  28704be2      sub      r7, fp, #0x28                               
  0002f038  0040a0e3      mov      r4, #0                                      
  0002f03c  040000ea      b        #0x2f054                                    
  0002f040  2c101be5      ldr      r1, [fp, #-0x2c]                            
  0002f044  040051e1      cmp      r1, r4                                      
  0002f048  28101be5      ldr      r1, [fp, #-0x28]                            
  0002f04c  0410a5e5      str      r1, [r5, #4]!                               
  0002f050  1200009a      bls      #0x2f0a0                                    
  0002f054  0430a0e1      mov      r3, r4                                      
  0002f058  00708de5      str      r7, [sp]                                    
  0002f05c  1500a0e3      mov      r0, #0x15                                   
  0002f060  0010a0e3      mov      r1, #0                                      
  0002f064  0620a0e1      mov      r2, r6                                      
  0002f068  014084e2      add      r4, r4, #1                                  
  0002f06c  3d6dffeb      bl       #0xa568                                     
  0002f070  00a050e2      subs     sl, r0, #0                                  
  0002f074  f1ffff0a      beq      #0x2f040                                    
  0002f078  b0009fe5      ldr      r0, [pc, #0xb0]                             
  0002f07c  0030a0e3      mov      r3, #0                                      
  0002f080  6910a0e3      mov      r1, #0x69                                   
  0002f084  00308de5      str      r3, [sp]                                    
  0002f088  00008fe0      add      r0, pc, r0                                  
  0002f08c  04308de5      str      r3, [sp, #4]                                
  0002f090  0a20a0e1      mov      r2, sl                                      
  0002f094  08308de5      str      r3, [sp, #8]                                
  0002f098  716dffeb      bl       #0xa664                                     
  0002f09c  0a80a0e1      mov      r8, sl                                      
  0002f0a0  0800a0e1      mov      r0, r8                                      
  0002f0a4  24d04be2      sub      sp, fp, #0x24                               
  0002f0a8  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0002f0ac  80009fe5      ldr      r0, [pc, #0x80]                             
  0002f0b0  5a10a0e3      mov      r1, #0x5a                                   
  0002f0b4  00808de5      str      r8, [sp]                                    
  0002f0b8  0630a0e1      mov      r3, r6                                      
  0002f0bc  04808de5      str      r8, [sp, #4]                                
  0002f0c0  00008fe0      add      r0, pc, r0                                  
  0002f0c4  08808de5      str      r8, [sp, #8]                                
  0002f0c8  656dffeb      bl       #0xa664                                     
  0002f0cc  0720a0e1      mov      r2, r7                                      
  0002f0d0  2c700be5      str      r7, [fp, #-0x2c]                            
  0002f0d4  d3ffffea      b        #0x2f028                                    
  0002f0d8  2c001be5      ldr      r0, [fp, #-0x2c]                            
  0002f0dc  5410a0e3      mov      r1, #0x54                                   
  0002f0e0  04408de5      str      r4, [sp, #4]                                
  0002f0e4  0820a0e1      mov      r2, r8                                      
  0002f0e8  08408de5      str      r4, [sp, #8]                                
  0002f0ec  0630a0e1      mov      r3, r6                                      
  0002f0f0  00008de5      str      r0, [sp]                                    
  0002f0f4  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002f0f8  00008fe0      add      r0, pc, r0                                  
  0002f0fc  586dffeb      bl       #0xa664                                     
  0002f100  e6ffffea      b        #0x2f0a0                                    
  0002f104  30009fe5      ldr      r0, [pc, #0x30]                             
  0002f108  0120a0e3      mov      r2, #1                                      
  0002f10c  00508de5      str      r5, [sp]                                    
  0002f110  4910a0e3      mov      r1, #0x49                                   
  0002f114  04508de5      str      r5, [sp, #4]                                
  0002f118  0530a0e1      mov      r3, r5                                      
  0002f11c  08508de5      str      r5, [sp, #8]                                
  0002f120  00008fe0      add      r0, pc, r0                                  
  0002f124  0280a0e1      mov      r8, r2                                      
  0002f128  4d6dffeb      bl       #0xa664                                     
  0002f12c  dbffffea      b        #0x2f0a0                                    
  0002f130  28590000      andeq    r5, r0, r8, lsr #18                         
  0002f134  f0580000      strdeq   r5, r6, [r0], -r0                           
  0002f138  b8580000      strheq   r5, [r0], -r8                               
  0002f13c  90580000      muleq    r0, r0, r8                                  
  0002f140  0dc0a0e1      mov      ip, sp                                      
  0002f144  0030a0e3      mov      r3, #0                                      
  0002f148  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0002f14c  04b04ce2      sub      fp, ip, #4                                  
  0002f150  008050e2      subs     r8, r0, #0                                  
  0002f154  24d04de2      sub      sp, sp, #0x24                               
  0002f158  0170a0e1      mov      r7, r1                                      
  0002f15c  38300be5      str      r3, [fp, #-0x38]                            
  0002f160  34300be5      str      r3, [fp, #-0x34]                            
  0002f164  30300be5      str      r3, [fp, #-0x30]                            
  0002f168  5b00000a      beq      #0x2f2dc                                    
  0002f16c  0310a0e1      mov      r1, r3                                      
  0002f170  1500a0e3      mov      r0, #0x15                                   
  0002f174  38304be2      sub      r3, fp, #0x38                               
  0002f178  252ca0e3      mov      r2, #0x2500                                 
  0002f17c  872e42e3      movt     r2, #0x2e87                                 
  0002f180  2e6dffeb      bl       #0xa640                                     
  0002f184  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f188  00a050e2      subs     sl, r0, #0                                  
  0002f18c  4600001a      bne      #0x2f2ac                                    
  0002f190  100053e3      cmp      r3, #0x10                                   
  0002f194  4400008a      bhi      #0x2f2ac                                    
  0002f198  000053e3      cmp      r3, #0                                      
  0002f19c  5304e7e7      ubfx     r0, r3, #8, #8                              
  0002f1a0  5318e7e7      ubfx     r1, r3, #0x10, #8                           
  0002f1a4  232ca0e1      lsr      r2, r3, #0x18                               
  0002f1a8  0030c8e5      strb     r3, [r8]                                    
  0002f1ac  0100c8e5      strb     r0, [r8, #1]                                
  0002f1b0  0210c8e5      strb     r1, [r8, #2]                                
  0002f1b4  0320c8e5      strb     r2, [r8, #3]                                
  0002f1b8  4400000a      beq      #0x2f2d0                                    
  0002f1bc  34604be2      sub      r6, fp, #0x34                               
  0002f1c0  0a40a0e1      mov      r4, sl                                      
  0002f1c4  220000ea      b        #0x2f254                                    
  0002f1c8  34c01be5      ldr      ip, [fp, #-0x34]                            
  0002f1cc  0c0057e1      cmp      r7, ip                                      
  0002f1d0  1b00000a      beq      #0x2f244                                    
  0002f1d4  1070ffeb      bl       #0xb21c                                     
  0002f1d8  251ca0e3      mov      r1, #0x2500                                 
  0002f1dc  0130a0e3      mov      r3, #1                                      
  0002f1e0  871e42e3      movt     r1, #0x2e87                                 
  0002f1e4  005050e2      subs     r5, r0, #0                                  
  0002f1e8  0520a0e1      mov      r2, r5                                      
  0002f1ec  4500001a      bne      #0x2f308                                    
  0002f1f0  60008de8      stm      sp, {r5, r6}                                
  0002f1f4  08508de5      str      r5, [sp, #8]                                
  0002f1f8  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f1fc  7c6cffeb      bl       #0xa3f4                                     
  0002f200  843384e0      add      r3, r4, r4, lsl #7                          
  0002f204  252ca0e3      mov      r2, #0x2500                                 
  0002f208  872e42e3      movt     r2, #0x2e87                                 
  0002f20c  833088e0      add      r3, r8, r3, lsl #1                          
  0002f210  043083e2      add      r3, r3, #4                                  

### HW_DM_RPC_SetEfuseLoad @ 0x2ec10
  0002ec10  0dc0a0e1      mov      ip, sp                                      
  0002ec14  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ec18  04b04ce2      sub      fp, ip, #4                                  
  0002ec1c  862e4be2      sub      r2, fp, #0x860                              
  0002ec20  86de4de2      sub      sp, sp, #0x860                              
  0002ec24  0c2042e2      sub      r2, r2, #0xc                                
  0002ec28  0040a0e3      mov      r4, #0                                      
  0002ec2c  08c082e2      add      ip, r2, #8                                  
  0002ec30  08d04de2      sub      sp, sp, #8                                  
  0002ec34  0150a0e1      mov      r5, r1                                      
  0002ec38  860e4be2      sub      r0, fp, #0x860                              
  0002ec3c  0410a0e1      mov      r1, r4                                      
  0002ec40  8020a0e3      mov      r2, #0x80                                   
  0002ec44  0360a0e1      mov      r6, r3                                      
  0002ec48  70480be5      str      r4, [fp, #-0x870]                           
  0002ec4c  6c480be5      str      r4, [fp, #-0x86c]                           
  0002ec50  68480be5      str      r4, [fp, #-0x868]                           
  0002ec54  00408ce5      str      r4, [ip]                                    
  0002ec58  fd6dffeb      bl       #0xa454                                     
  0002ec5c  040055e1      cmp      r5, r4                                      
  0002ec60  04005611      cmpne    r6, r4                                      
  0002ec64  0070a013      movne    r7, #0                                      
  0002ec68  0170a003      moveq    r7, #1                                      
  0002ec6c  1200000a      beq      #0x2ecbc                                    
  0002ec70  9030d5e5      ldrb     r3, [r5, #0x90]                             
  0002ec74  034003e2      and      r4, r3, #3                                  
  0002ec78  030054e3      cmp      r4, #3                                      
  0002ec7c  1b00000a      beq      #0x2ecf0                                    
  0002ec80  84019fe5      ldr      r0, [pc, #0x184]                            
  0002ec84  d320e0e7      ubfx     r2, r3, #1, #1                              
  0002ec88  8e1200e3      movw     r1, #0x28e                                  
  0002ec8c  84008de8      stm      sp, {r2, r7}                                
  0002ec90  08708de5      str      r7, [sp, #8]                                
  0002ec94  022405e3      movw     r2, #0x5402                                 
  0002ec98  00008fe0      add      r0, pc, r0                                  
  0002ec9c  20274fe3      movt     r2, #0xf720                                 
  0002eca0  013003e2      and      r3, r3, #1                                  
  0002eca4  024405e3      movw     r4, #0x5402                                 
  0002eca8  6d6effeb      bl       #0xa664                                     
  0002ecac  20474fe3      movt     r4, #0xf720                                 
  0002ecb0  0400a0e1      mov      r0, r4                                      
  0002ecb4  1cd04be2      sub      sp, fp, #0x1c                               
  0002ecb8  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002ecbc  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0002ecc0  871200e3      movw     r1, #0x287                                  
  0002ecc4  04408de5      str      r4, [sp, #4]                                
  0002ecc8  032405e3      movw     r2, #0x5403                                 
  0002eccc  08408de5      str      r4, [sp, #8]                                
  0002ecd0  20274fe3      movt     r2, #0xf720                                 
  0002ecd4  00608de5      str      r6, [sp]                                    
  0002ecd8  00008fe0      add      r0, pc, r0                                  
  0002ecdc  0530a0e1      mov      r3, r5                                      
  0002ece0  034405e3      movw     r4, #0x5403                                 
  0002ece4  5e6effeb      bl       #0xa664                                     
  0002ece8  20474fe3      movt     r4, #0xf720                                 
  0002ecec  efffffea      b        #0x2ecb0                                    
  0002ecf0  1010a0e3      mov      r1, #0x10                                   
  0002ecf4  0520a0e1      mov      r2, r5                                      
  0002ecf8  0130a0e1      mov      r3, r1                                      
  0002ecfc  870e4be2      sub      r0, fp, #0x870                              
  0002ed00  9e6fffeb      bl       #0xab80                                     
  0002ed04  870e4be2      sub      r0, fp, #0x870                              
  0002ed08  b472ffeb      bl       #0xb7e0                                     
  0002ed0c  003050e2      subs     r3, r0, #0                                  
  0002ed10  0b00001a      bne      #0x2ed44                                    
  0002ed14  f8009fe5      ldr      r0, [pc, #0xf8]                             
  0002ed18  a61fa0e3      mov      r1, #0x298                                  
  0002ed1c  00308de5      str      r3, [sp]                                    
  0002ed20  022405e3      movw     r2, #0x5402                                 
  0002ed24  04308de5      str      r3, [sp, #4]                                
  0002ed28  20274fe3      movt     r2, #0xf720                                 
  0002ed2c  08308de5      str      r3, [sp, #8]                                
  0002ed30  00008fe0      add      r0, pc, r0                                  
  0002ed34  024405e3      movw     r4, #0x5402                                 
  0002ed38  496effeb      bl       #0xa664                                     
  0002ed3c  20474fe3      movt     r4, #0xf720                                 
  0002ed40  daffffea      b        #0x2ecb0                                    
  0002ed44  8010a0e3      mov      r1, #0x80                                   
  0002ed48  102085e2      add      r2, r5, #0x10                               
  0002ed4c  0130a0e1      mov      r3, r1                                      
  0002ed50  860e4be2      sub      r0, fp, #0x860                              
  0002ed54  896fffeb      bl       #0xab80                                     
  0002ed58  c41700e3      movw     r1, #0x7c4                                  
  0002ed5c  0130a0e1      mov      r3, r1                                      
  0002ed60  0720a0e1      mov      r2, r7                                      
  0002ed64  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002ed68  5e6effeb      bl       #0xa6e8                                     
  0002ed6c  7d3e4be2      sub      r3, fp, #0x7d0                              
  0002ed70  0c3043e2      sub      r3, r3, #0xc                                
  0002ed74  870e4be2      sub      r0, fp, #0x870                              
  0002ed78  241083e2      add      r1, r3, #0x24                               
  0002ed7c  4372ffeb      bl       #0xb690                                     
  0002ed80  90209fe5      ldr      r2, [pc, #0x90]                             
  0002ed84  b8c71be5      ldr      ip, [fp, #-0x7b8]                           
  0002ed88  2010a0e3      mov      r1, #0x20                                   
  0002ed8c  02208fe0      add      r2, pc, r2                                  
  0002ed90  0530a0e3      mov      r3, #5                                      
  0002ed94  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002ed98  3ccfbfe6      rev      ip, ip                                      
  0002ed9c  a4404be5      strb     r4, [fp, #-0xa4]                            
  0002eda0  b8c70be5      str      ip, [fp, #-0x7b8]                           
  0002eda4  1dc0a0e3      mov      ip, #0x1d                                   
  0002eda8  a3c04be5      strb     ip, [fp, #-0xa3]                            
  0002edac  0bc0a0e3      mov      ip, #0xb                                    
  0002edb0  c0c70be5      str      ip, [fp, #-0x7c0]                           
  0002edb4  cb6cffeb      bl       #0xa0e8                                     
  0002edb8  7dce4be2      sub      ip, fp, #0x7d0                              
  0002edbc  011ca0e3      mov      r1, #0x100                                  
  0002edc0  0cc04ce2      sub      ip, ip, #0xc                                
  0002edc4  862e4be2      sub      r2, fp, #0x860                              
  0002edc8  0130a0e1      mov      r3, r1                                      
  0002edcc  8a0f8ce2      add      r0, ip, #0x228                              
  0002edd0  c46cffeb      bl       #0xa0e8                                     
  0002edd4  7e0e4be2      sub      r0, fp, #0x7e0                              
  0002edd8  2a71ffeb      bl       #0xb288                                     
  0002eddc  004050e2      subs     r4, r0, #0                                  
  0002ede0  b2ffff0a      beq      #0x2ecb0                                    
  0002ede4  30009fe5      ldr      r0, [pc, #0x30]                             
  0002ede8  ab1fa0e3      mov      r1, #0x2ac                                  
  0002edec  00708de5      str      r7, [sp]                                    
  0002edf0  0420a0e1      mov      r2, r4                                      
  0002edf4  04708de5      str      r7, [sp, #4]                                
  0002edf8  0730a0e1      mov      r3, r7                                      
  0002edfc  08708de5      str      r7, [sp, #8]                                
  0002ee00  00008fe0      add      r0, pc, r0                                  
  0002ee04  166effeb      bl       #0xa664                                     
  0002ee08  a8ffffea      b        #0x2ecb0                                    
  0002ee0c  8c5b0000      andeq    r5, r0, ip, lsl #23                         
  0002ee10  4c5b0000      andeq    r5, r0, ip, asr #22                         
  0002ee14  f45a0000      strdeq   r5, r6, [r0], -r4                           
  0002ee18  48110000      andeq    r1, r0, r8, asr #2                          
  0002ee1c  245a0000      andeq    r5, r0, r4, lsr #20                         
  0002ee20  90019fe5      ldr      r0, [pc, #0x190]                            
  0002ee24  0dc0a0e1      mov      ip, sp                                      
  0002ee28  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ee2c  04b04ce2      sub      fp, ip, #4                                  
  0002ee30  0040a0e3      mov      r4, #0                                      
  0002ee34  28d04de2      sub      sp, sp, #0x28                               
  0002ee38  00008fe0      add      r0, pc, r0                                  
  0002ee3c  0410a0e1      mov      r1, r4                                      
  0002ee40  2c204be2      sub      r2, fp, #0x2c                               
  0002ee44  30304be2      sub      r3, fp, #0x30                               
  0002ee48  30400be5      str      r4, [fp, #-0x30]                            
  0002ee4c  2c400be5      str      r4, [fp, #-0x2c]                            
  0002ee50  28400be5      str      r4, [fp, #-0x28]                            
  0002ee54  24400be5      str      r4, [fp, #-0x24]                            
  0002ee58  20400be5      str      r4, [fp, #-0x20]                            
  0002ee5c  ef6cffeb      bl       #0xa220                                     
  0002ee60  005050e2      subs     r5, r0, #0                                  
  0002ee64  3100001a      bne      #0x2ef30                                    
  0002ee68  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0002ee6c  2c104be2      sub      r1, fp, #0x2c                               
  0002ee70  30201be5      ldr      r2, [fp, #-0x30]                            
  0002ee74  00008fe0      add      r0, pc, r0                                  
  0002ee78  c06dffeb      bl       #0xa580                                     
  0002ee7c  0107a0e3      mov      r0, #0x40000                                
  0002ee80  3a70ffeb      bl       #0xaf70                                     
  0002ee84  004050e2      subs     r4, r0, #0                                  
  0002ee88  3500000a      beq      #0x2ef64                                    
  0002ee8c  0218a0e3      mov      r1, #0x20000                                
  0002ee90  016084e0      add      r6, r4, r1                                  
  0002ee94  0130a0e1      mov      r3, r1                                      
  0002ee98  ff20a0e3      mov      r2, #0xff                                   
  0002ee9c  116effeb      bl       #0xa6e8                                     
  0002eea0  2c004be2      sub      r0, fp, #0x2c                               
  0002eea4  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eea8  0620a0e1      mov      r2, r6                                      
  0002eeac  0238a0e3      mov      r3, #0x20000                                
  0002eeb0  936effeb      bl       #0xa904                                     
  0002eeb4  007050e2      subs     r7, r0, #0                                  
  0002eeb8  0f00001a      bne      #0x2eefc                                    
  0002eebc  0400a0e1      mov      r0, r4                                      
  0002eec0  0610a0e1      mov      r1, r6                                      
  0002eec4  0228a0e3      mov      r2, #0x20000                                
  0002eec8  416fffeb      bl       #0xabd4                                     
  0002eecc  000050e3      cmp      r0, #0                                      
  0002eed0  0600000a      beq      #0x2eef0                                    
  0002eed4  0420a0e1      mov      r2, r4                                      
  0002eed8  2c004be2      sub      r0, fp, #0x2c                               
  0002eedc  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eee0  0238a0e3      mov      r3, #0x20000                                
  0002eee4  1c72ffeb      bl       #0xb75c                                     
  0002eee8  002050e2      subs     r2, r0, #0                                  
  0002eeec  2600001a      bne      #0x2ef8c                                    
  0002eef0  0400a0e1      mov      r0, r4                                      
  0002eef4  646effeb      bl       #0xa88c                                     
  0002eef8  0a0000ea      b        #0x2ef28                                    
  0002eefc  bc009fe5      ldr      r0, [pc, #0xbc]                             
  0002ef00  ba1fa0e3      mov      r1, #0x2e8                                  
  0002ef04  00508de5      str      r5, [sp]                                    
  0002ef08  0720a0e1      mov      r2, r7                                      
  0002ef0c  00008fe0      add      r0, pc, r0                                  
  0002ef10  04508de5      str      r5, [sp, #4]                                
  0002ef14  08508de5      str      r5, [sp, #8]                                
  0002ef18  30301be5      ldr      r3, [fp, #-0x30]                            
  0002ef1c  d06dffeb      bl       #0xa664                                     
  0002ef20  0400a0e1      mov      r0, r4                                      
  0002ef24  586effeb      bl       #0xa88c                                     
  0002ef28  1cd04be2      sub      sp, fp, #0x1c                               
  0002ef2c  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002ef30  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0002ef34  00008fe0      add      r0, pc, r0                                  
  0002ef38  906dffeb      bl       #0xa580                                     
  0002ef3c  84009fe5      ldr      r0, [pc, #0x84]                             
  0002ef40  00408de5      str      r4, [sp]                                    
  0002ef44  b51fa0e3      mov      r1, #0x2d4                                  
  0002ef48  04408de5      str      r4, [sp, #4]                                
  0002ef4c  0520a0e1      mov      r2, r5                                      
  0002ef50  08408de5      str      r4, [sp, #8]                                
  0002ef54  00008fe0      add      r0, pc, r0                                  
  0002ef58  0430a0e1      mov      r3, r4                                      
  0002ef5c  c06dffeb      bl       #0xa664                                     
  0002ef60  f0ffffea      b        #0x2ef28                                    
  0002ef64  60009fe5      ldr      r0, [pc, #0x60]                             
  0002ef68  b71fa0e3      mov      r1, #0x2dc                                  
  0002ef6c  00408de5      str      r4, [sp]                                    
  0002ef70  0120a0e3      mov      r2, #1                                      
  0002ef74  04408de5      str      r4, [sp, #4]                                
  0002ef78  0430a0e1      mov      r3, r4                                      
  0002ef7c  08408de5      str      r4, [sp, #8]                                
  0002ef80  00008fe0      add      r0, pc, r0                                  
  0002ef84  b66dffeb      bl       #0xa664                                     
  0002ef88  e6ffffea      b        #0x2ef28                                    
  0002ef8c  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002ef90  f31200e3      movw     r1, #0x2f3                                  
  0002ef94  00708de5      str      r7, [sp]                                    
  0002ef98  04708de5      str      r7, [sp, #4]                                
  0002ef9c  00008fe0      add      r0, pc, r0                                  
  0002efa0  08708de5      str      r7, [sp, #8]                                
  0002efa4  30301be5      ldr      r3, [fp, #-0x30]                            
  0002efa8  ad6dffeb      bl       #0xa664                                     
  0002efac  0400a0e1      mov      r0, r4                                      
  0002efb0  356effeb      bl       #0xa88c                                     
  0002efb4  dbffffea      b        #0x2ef28                                    
  0002efb8  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efbc  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efc0  18590000      andeq    r5, r0, r8, lsl sb                          
  0002efc4  185a0000      andeq    r5, r0, r8, lsl sl                          
  0002efc8  d0580000      ldrdeq   r5, r6, [r0], -r0                           
  0002efcc  a4580000      andeq    r5, r0, r4, lsr #17                         
  0002efd0  88580000      andeq    r5, r0, r8, lsl #17                         
  0002efd4  0dc0a0e1      mov      ip, sp                                      
  0002efd8  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0002efdc  04b04ce2      sub      fp, ip, #4                                  
  0002efe0  005051e2      subs     r5, r1, #0                                  
  0002efe4  18d04de2      sub      sp, sp, #0x18                               
  0002efe8  0040a0e3      mov      r4, #0                                      
  0002efec  0060a0e1      mov      r6, r0                                      
  0002eff0  0270a0e1      mov      r7, r2                                      
  0002eff4  2c400be5      str      r4, [fp, #-0x2c]                            
  0002eff8  28400be5      str      r4, [fp, #-0x28]                            
  0002effc  4000000a      beq      #0x2f104                                    
  0002f000  1500a0e3      mov      r0, #0x15                                   
  0002f004  0410a0e1      mov      r1, r4                                      
  0002f008  0620a0e1      mov      r2, r6                                      
  0002f00c  2c304be2      sub      r3, fp, #0x2c                               
  0002f010  8a6dffeb      bl       #0xa640                                     
  0002f014  008050e2      subs     r8, r0, #0                                  
  0002f018  2e00001a      bne      #0x2f0d8                                    
  0002f01c  2c201be5      ldr      r2, [fp, #-0x2c]                            
  0002f020  070052e1      cmp      r2, r7                                      
  0002f024  2000008a      bhi      #0x2f0ac                                    
  0002f028  000052e3      cmp      r2, #0                                      
  0002f02c  002085e5      str      r2, [r5]                                    
  0002f030  1a00000a      beq      #0x2f0a0                                    
  0002f034  28704be2      sub      r7, fp, #0x28                               
  0002f038  0040a0e3      mov      r4, #0                                      
  0002f03c  040000ea      b        #0x2f054                                    
  0002f040  2c101be5      ldr      r1, [fp, #-0x2c]                            
  0002f044  040051e1      cmp      r1, r4                                      
  0002f048  28101be5      ldr      r1, [fp, #-0x28]                            
  0002f04c  0410a5e5      str      r1, [r5, #4]!                               
  0002f050  1200009a      bls      #0x2f0a0                                    
  0002f054  0430a0e1      mov      r3, r4                                      
  0002f058  00708de5      str      r7, [sp]                                    
  0002f05c  1500a0e3      mov      r0, #0x15                                   
  0002f060  0010a0e3      mov      r1, #0                                      
  0002f064  0620a0e1      mov      r2, r6                                      
  0002f068  014084e2      add      r4, r4, #1                                  
  0002f06c  3d6dffeb      bl       #0xa568                                     
  0002f070  00a050e2      subs     sl, r0, #0                                  
  0002f074  f1ffff0a      beq      #0x2f040                                    
  0002f078  b0009fe5      ldr      r0, [pc, #0xb0]                             
  0002f07c  0030a0e3      mov      r3, #0                                      
  0002f080  6910a0e3      mov      r1, #0x69                                   
  0002f084  00308de5      str      r3, [sp]                                    
  0002f088  00008fe0      add      r0, pc, r0                                  
  0002f08c  04308de5      str      r3, [sp, #4]                                
  0002f090  0a20a0e1      mov      r2, sl                                      
  0002f094  08308de5      str      r3, [sp, #8]                                
  0002f098  716dffeb      bl       #0xa664                                     
  0002f09c  0a80a0e1      mov      r8, sl                                      
  0002f0a0  0800a0e1      mov      r0, r8                                      
  0002f0a4  24d04be2      sub      sp, fp, #0x24                               
  0002f0a8  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0002f0ac  80009fe5      ldr      r0, [pc, #0x80]                             
  0002f0b0  5a10a0e3      mov      r1, #0x5a                                   
  0002f0b4  00808de5      str      r8, [sp]                                    
  0002f0b8  0630a0e1      mov      r3, r6                                      
  0002f0bc  04808de5      str      r8, [sp, #4]                                
  0002f0c0  00008fe0      add      r0, pc, r0                                  
  0002f0c4  08808de5      str      r8, [sp, #8]                                
  0002f0c8  656dffeb      bl       #0xa664                                     
  0002f0cc  0720a0e1      mov      r2, r7                                      
  0002f0d0  2c700be5      str      r7, [fp, #-0x2c]                            
  0002f0d4  d3ffffea      b        #0x2f028                                    
  0002f0d8  2c001be5      ldr      r0, [fp, #-0x2c]                            
  0002f0dc  5410a0e3      mov      r1, #0x54                                   
  0002f0e0  04408de5      str      r4, [sp, #4]                                
  0002f0e4  0820a0e1      mov      r2, r8                                      
  0002f0e8  08408de5      str      r4, [sp, #8]                                
  0002f0ec  0630a0e1      mov      r3, r6                                      
  0002f0f0  00008de5      str      r0, [sp]                                    
  0002f0f4  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002f0f8  00008fe0      add      r0, pc, r0                                  
  0002f0fc  586dffeb      bl       #0xa664                                     
  0002f100  e6ffffea      b        #0x2f0a0                                    
  0002f104  30009fe5      ldr      r0, [pc, #0x30]                             
  0002f108  0120a0e3      mov      r2, #1                                      
  0002f10c  00508de5      str      r5, [sp]                                    
  0002f110  4910a0e3      mov      r1, #0x49                                   
  0002f114  04508de5      str      r5, [sp, #4]                                
  0002f118  0530a0e1      mov      r3, r5                                      
  0002f11c  08508de5      str      r5, [sp, #8]                                
  0002f120  00008fe0      add      r0, pc, r0                                  
  0002f124  0280a0e1      mov      r8, r2                                      
  0002f128  4d6dffeb      bl       #0xa664                                     
  0002f12c  dbffffea      b        #0x2f0a0                                    
  0002f130  28590000      andeq    r5, r0, r8, lsr #18                         
  0002f134  f0580000      strdeq   r5, r6, [r0], -r0                           
  0002f138  b8580000      strheq   r5, [r0], -r8                               
  0002f13c  90580000      muleq    r0, r0, r8                                  
  0002f140  0dc0a0e1      mov      ip, sp                                      
  0002f144  0030a0e3      mov      r3, #0                                      
  0002f148  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0002f14c  04b04ce2      sub      fp, ip, #4                                  
  0002f150  008050e2      subs     r8, r0, #0                                  
  0002f154  24d04de2      sub      sp, sp, #0x24                               
  0002f158  0170a0e1      mov      r7, r1                                      
  0002f15c  38300be5      str      r3, [fp, #-0x38]                            
  0002f160  34300be5      str      r3, [fp, #-0x34]                            
  0002f164  30300be5      str      r3, [fp, #-0x30]                            
  0002f168  5b00000a      beq      #0x2f2dc                                    
  0002f16c  0310a0e1      mov      r1, r3                                      
  0002f170  1500a0e3      mov      r0, #0x15                                   
  0002f174  38304be2      sub      r3, fp, #0x38                               
  0002f178  252ca0e3      mov      r2, #0x2500                                 
  0002f17c  872e42e3      movt     r2, #0x2e87                                 
  0002f180  2e6dffeb      bl       #0xa640                                     
  0002f184  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f188  00a050e2      subs     sl, r0, #0                                  
  0002f18c  4600001a      bne      #0x2f2ac                                    
  0002f190  100053e3      cmp      r3, #0x10                                   
  0002f194  4400008a      bhi      #0x2f2ac                                    
  0002f198  000053e3      cmp      r3, #0                                      
  0002f19c  5304e7e7      ubfx     r0, r3, #8, #8                              
  0002f1a0  5318e7e7      ubfx     r1, r3, #0x10, #8                           
  0002f1a4  232ca0e1      lsr      r2, r3, #0x18                               
  0002f1a8  0030c8e5      strb     r3, [r8]                                    
  0002f1ac  0100c8e5      strb     r0, [r8, #1]                                
  0002f1b0  0210c8e5      strb     r1, [r8, #2]                                
  0002f1b4  0320c8e5      strb     r2, [r8, #3]                                
  0002f1b8  4400000a      beq      #0x2f2d0                                    
  0002f1bc  34604be2      sub      r6, fp, #0x34                               
  0002f1c0  0a40a0e1      mov      r4, sl                                      
  0002f1c4  220000ea      b        #0x2f254                                    
  0002f1c8  34c01be5      ldr      ip, [fp, #-0x34]                            
  0002f1cc  0c0057e1      cmp      r7, ip                                      
  0002f1d0  1b00000a      beq      #0x2f244                                    
  0002f1d4  1070ffeb      bl       #0xb21c                                     
  0002f1d8  251ca0e3      mov      r1, #0x2500                                 
  0002f1dc  0130a0e3      mov      r3, #1                                      
  0002f1e0  871e42e3      movt     r1, #0x2e87                                 
  0002f1e4  005050e2      subs     r5, r0, #0                                  
  0002f1e8  0520a0e1      mov      r2, r5                                      
  0002f1ec  4500001a      bne      #0x2f308                                    
  0002f1f0  60008de8      stm      sp, {r5, r6}                                
  0002f1f4  08508de5      str      r5, [sp, #8]                                
  0002f1f8  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f1fc  7c6cffeb      bl       #0xa3f4                                     
  0002f200  843384e0      add      r3, r4, r4, lsl #7                          
  0002f204  252ca0e3      mov      r2, #0x2500                                 
  0002f208  872e42e3      movt     r2, #0x2e87                                 
  0002f20c  833088e0      add      r3, r8, r3, lsl #1                          
  0002f210  043083e2      add      r3, r3, #4                                  
  0002f214  009050e2      subs     sb, r0, #0                                  
  0002f218  1500a0e3      mov      r0, #0x15                                   
  0002f21c  4300001a      bne      #0x2f330                                    
  0002f220  021100e3      movw     r1, #0x102                                  
  0002f224  00108de5      str      r1, [sp]                                    
  0002f228  30101be5      ldr      r1, [fp, #-0x30]                            
  0002f22c  356effeb      bl       #0xab08                                     
  0002f230  0050a0e1      mov      r5, r0                                      
  0002f234  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f238  556fffeb      bl       #0xaf94                                     
  0002f23c  000055e3      cmp      r5, #0                                      
  0002f240  4700001a      bne      #0x2f364                                    
  0002f244  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f248  014084e2      add      r4, r4, #1                                  
  0002f24c  040053e1      cmp      r3, r4                                      
  0002f250  1e00009a      bls      #0x2f2d0                                    
  0002f254  0430a0e1      mov      r3, r4                                      
  0002f258  0010a0e3      mov      r1, #0                                      
  0002f25c  00608de5      str      r6, [sp]                                    
  0002f260  1500a0e3      mov      r0, #0x15                                   
  0002f264  252ca0e3      mov      r2, #0x2500                                 
  0002f268  872e42e3      movt     r2, #0x2e87                                 
  0002f26c  bd6cffeb      bl       #0xa568                                     
  0002f270  009050e2      subs     sb, r0, #0                                  
  0002f274  30004be2      sub      r0, fp, #0x30                               
  0002f278  d2ffff0a      beq      #0x2f1c8                                    
  0002f27c  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0002f280  00c0a0e3      mov      ip, #0                                      
  0002f284  a510a0e3      mov      r1, #0xa5                                   
  0002f288  00c08de5      str      ip, [sp]                                    
  0002f28c  00008fe0      add      r0, pc, r0                                  
  0002f290  0920a0e1      mov      r2, sb                                      
  0002f294  04c08de5      str      ip, [sp, #4]                                
  0002f298  09a0a0e1      mov      sl, sb                                      
  0002f29c  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f2a0  08c08de5      str      ip, [sp, #8]                                
  0002f2a4  ee6cffeb      bl       #0xa664                                     
  0002f2a8  080000ea      b        #0x2f2d0                                    
  0002f2ac  e0009fe5      ldr      r0, [pc, #0xe0]                             
  0002f2b0  00c0a0e3      mov      ip, #0                                      
  0002f2b4  9710a0e3      mov      r1, #0x97                                   
  0002f2b8  00c08de5      str      ip, [sp]                                    
  0002f2bc  00008fe0      add      r0, pc, r0                                  
  0002f2c0  04c08de5      str      ip, [sp, #4]                                
  0002f2c4  0a20a0e1      mov      r2, sl                                      
  0002f2c8  08c08de5      str      ip, [sp, #8]                                
  0002f2cc  e46cffeb      bl       #0xa664                                     
  0002f2d0  0a00a0e1      mov      r0, sl                                      
  0002f2d4  28d04be2      sub      sp, fp, #0x28                               
  0002f2d8  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  0002f2dc  b4009fe5      ldr      r0, [pc, #0xb4]                             
  0002f2e0  0120a0e3      mov      r2, #1                                      
  0002f2e4  00808de5      str      r8, [sp]                                    
  0002f2e8  8d10a0e3      mov      r1, #0x8d                                   
  0002f2ec  04808de5      str      r8, [sp, #4]                                
  0002f2f0  0830a0e1      mov      r3, r8                                      
  0002f2f4  08808de5      str      r8, [sp, #8]                                
  0002f2f8  00008fe0      add      r0, pc, r0                                  
  0002f2fc  02a0a0e1      mov      sl, r2                                      
  0002f300  d76cffeb      bl       #0xa664                                     
  0002f304  f1ffffea      b        #0x2f2d0                                    
  0002f308  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0002f30c  b310a0e3      mov      r1, #0xb3                                   
  0002f310  00908de5      str      sb, [sp]                                    
  0002f314  0930a0e1      mov      r3, sb                                      
  0002f318  04908de5      str      sb, [sp, #4]                                
  0002f31c  00008fe0      add      r0, pc, r0                                  
  0002f320  08908de5      str      sb, [sp, #8]                                
  0002f324  05a0a0e1      mov      sl, r5                                      
  0002f328  cd6cffeb      bl       #0xa664                                     
  0002f32c  e7ffffea      b        #0x2f2d0                                    
  0002f330  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f334  09a0a0e1      mov      sl, sb                                      
  0002f338  156fffeb      bl       #0xaf94                                     
  0002f33c  5c009fe5      ldr      r0, [pc, #0x5c]                             
  0002f340  00508de5      str      r5, [sp]                                    
  0002f344  bf10a0e3      mov      r1, #0xbf                                   
  0002f348  04508de5      str      r5, [sp, #4]                                
  0002f34c  0920a0e1      mov      r2, sb                                      
  0002f350  08508de5      str      r5, [sp, #8]                                
  0002f354  00008fe0      add      r0, pc, r0                                  
  0002f358  34301be5      ldr      r3, [fp, #-0x34]                            
  0002f35c  c06cffeb      bl       #0xa664                                     
  0002f360  daffffea      b        #0x2f2d0                                    
  0002f364  38009fe5      ldr      r0, [pc, #0x38]                             
  0002f368  ca10a0e3      mov      r1, #0xca                                   
  0002f36c  00908de5      str      sb, [sp]                                    
  0002f370  0520a0e1      mov      r2, r5                                      
  0002f374  04908de5      str      sb, [sp, #4]                                
  0002f378  00008fe0      add      r0, pc, r0                                  
  0002f37c  08908de5      str      sb, [sp, #8]                                
  0002f380  05a0a0e1      mov      sl, r5                                      
  0002f384  34301be5      ldr      r3, [fp, #-0x34]                            
  0002f388  b56cffeb      bl       #0xa664                                     
  0002f38c  cfffffea      b        #0x2f2d0                                    
  0002f390  24570000      andeq    r5, r0, r4, lsr #14                         
  0002f394  f4560000      strdeq   r5, r6, [r0], -r4                           
  0002f398  b8560000      strheq   r5, [r0], -r8                               
  0002f39c  94560000      muleq    r0, r4, r6                                  
  0002f3a0  5c560000      andeq    r5, r0, ip, asr r6                          
  0002f3a4  38560000      andeq    r5, r0, r8, lsr r6                          
  0002f3a8  0dc0a0e1      mov      ip, sp                                      
  0002f3ac  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002f3b0  04b04ce2      sub      fp, ip, #4                                  
  0002f3b4  0350a0e1      mov      r5, r3                                      
  0002f3b8  000051e3      cmp      r1, #0                                      
  0002f3bc  00005513      cmpne    r5, #0                                      
  0002f3c0  18d04de2      sub      sp, sp, #0x18                               
  0002f3c4  00c0a0e3      mov      ip, #0                                      
  0002f3c8  0130a0e1      mov      r3, r1                                      
  0002f3cc  0060a013      movne    r6, #0                                      
  0002f3d0  0160a003      moveq    r6, #1                                      
  0002f3d4  24c00be5      str      ip, [fp, #-0x24]                            
  0002f3d8  20c00be5      str      ip, [fp, #-0x20]                            
  0002f3dc  2c00000a      beq      #0x2f494                                    
  0002f3e0  003091e5      ldr      r3, [r1]                                    
  0002f3e4  20004be2      sub      r0, fp, #0x20                               
  0002f3e8  24300be5      str      r3, [fp, #-0x24]                            
  0002f3ec  8a6fffeb      bl       #0xb21c                                     
  0002f3f0  004050e2      subs     r4, r0, #0                                  
  0002f3f4  0f00000a      beq      #0x2f438                                    
  0002f3f8  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0002f3fc  fc10a0e3      mov      r1, #0xfc                                   
  0002f400  00608de5      str      r6, [sp]                                    
  0002f404  0420a0e1      mov      r2, r4                                      
  0002f408  04608de5      str      r6, [sp, #4]                                
  0002f40c  00008fe0      add      r0, pc, r0                                  

### HW_DM_ClearEfuseFlash @ 0x2ee20
  0002ee20  90019fe5      ldr      r0, [pc, #0x190]                            
  0002ee24  0dc0a0e1      mov      ip, sp                                      
  0002ee28  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002ee2c  04b04ce2      sub      fp, ip, #4                                  
  0002ee30  0040a0e3      mov      r4, #0                                      
  0002ee34  28d04de2      sub      sp, sp, #0x28                               
  0002ee38  00008fe0      add      r0, pc, r0                                  
  0002ee3c  0410a0e1      mov      r1, r4                                      
  0002ee40  2c204be2      sub      r2, fp, #0x2c                               
  0002ee44  30304be2      sub      r3, fp, #0x30                               
  0002ee48  30400be5      str      r4, [fp, #-0x30]                            
  0002ee4c  2c400be5      str      r4, [fp, #-0x2c]                            
  0002ee50  28400be5      str      r4, [fp, #-0x28]                            
  0002ee54  24400be5      str      r4, [fp, #-0x24]                            
  0002ee58  20400be5      str      r4, [fp, #-0x20]                            
  0002ee5c  ef6cffeb      bl       #0xa220                                     
  0002ee60  005050e2      subs     r5, r0, #0                                  
  0002ee64  3100001a      bne      #0x2ef30                                    
  0002ee68  4c019fe5      ldr      r0, [pc, #0x14c]                            
  0002ee6c  2c104be2      sub      r1, fp, #0x2c                               
  0002ee70  30201be5      ldr      r2, [fp, #-0x30]                            
  0002ee74  00008fe0      add      r0, pc, r0                                  
  0002ee78  c06dffeb      bl       #0xa580                                     
  0002ee7c  0107a0e3      mov      r0, #0x40000                                
  0002ee80  3a70ffeb      bl       #0xaf70                                     
  0002ee84  004050e2      subs     r4, r0, #0                                  
  0002ee88  3500000a      beq      #0x2ef64                                    
  0002ee8c  0218a0e3      mov      r1, #0x20000                                
  0002ee90  016084e0      add      r6, r4, r1                                  
  0002ee94  0130a0e1      mov      r3, r1                                      
  0002ee98  ff20a0e3      mov      r2, #0xff                                   
  0002ee9c  116effeb      bl       #0xa6e8                                     
  0002eea0  2c004be2      sub      r0, fp, #0x2c                               
  0002eea4  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eea8  0620a0e1      mov      r2, r6                                      
  0002eeac  0238a0e3      mov      r3, #0x20000                                
  0002eeb0  936effeb      bl       #0xa904                                     
  0002eeb4  007050e2      subs     r7, r0, #0                                  
  0002eeb8  0f00001a      bne      #0x2eefc                                    
  0002eebc  0400a0e1      mov      r0, r4                                      
  0002eec0  0610a0e1      mov      r1, r6                                      
  0002eec4  0228a0e3      mov      r2, #0x20000                                
  0002eec8  416fffeb      bl       #0xabd4                                     
  0002eecc  000050e3      cmp      r0, #0                                      
  0002eed0  0600000a      beq      #0x2eef0                                    
  0002eed4  0420a0e1      mov      r2, r4                                      
  0002eed8  2c004be2      sub      r0, fp, #0x2c                               
  0002eedc  30101be5      ldr      r1, [fp, #-0x30]                            
  0002eee0  0238a0e3      mov      r3, #0x20000                                
  0002eee4  1c72ffeb      bl       #0xb75c                                     
  0002eee8  002050e2      subs     r2, r0, #0                                  
  0002eeec  2600001a      bne      #0x2ef8c                                    
  0002eef0  0400a0e1      mov      r0, r4                                      
  0002eef4  646effeb      bl       #0xa88c                                     
  0002eef8  0a0000ea      b        #0x2ef28                                    
  0002eefc  bc009fe5      ldr      r0, [pc, #0xbc]                             
  0002ef00  ba1fa0e3      mov      r1, #0x2e8                                  
  0002ef04  00508de5      str      r5, [sp]                                    
  0002ef08  0720a0e1      mov      r2, r7                                      
  0002ef0c  00008fe0      add      r0, pc, r0                                  
  0002ef10  04508de5      str      r5, [sp, #4]                                
  0002ef14  08508de5      str      r5, [sp, #8]                                
  0002ef18  30301be5      ldr      r3, [fp, #-0x30]                            
  0002ef1c  d06dffeb      bl       #0xa664                                     
  0002ef20  0400a0e1      mov      r0, r4                                      
  0002ef24  586effeb      bl       #0xa88c                                     
  0002ef28  1cd04be2      sub      sp, fp, #0x1c                               
  0002ef2c  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002ef30  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0002ef34  00008fe0      add      r0, pc, r0                                  
  0002ef38  906dffeb      bl       #0xa580                                     
  0002ef3c  84009fe5      ldr      r0, [pc, #0x84]                             
  0002ef40  00408de5      str      r4, [sp]                                    
  0002ef44  b51fa0e3      mov      r1, #0x2d4                                  
  0002ef48  04408de5      str      r4, [sp, #4]                                
  0002ef4c  0520a0e1      mov      r2, r5                                      
  0002ef50  08408de5      str      r4, [sp, #8]                                
  0002ef54  00008fe0      add      r0, pc, r0                                  
  0002ef58  0430a0e1      mov      r3, r4                                      
  0002ef5c  c06dffeb      bl       #0xa664                                     
  0002ef60  f0ffffea      b        #0x2ef28                                    
  0002ef64  60009fe5      ldr      r0, [pc, #0x60]                             
  0002ef68  b71fa0e3      mov      r1, #0x2dc                                  
  0002ef6c  00408de5      str      r4, [sp]                                    
  0002ef70  0120a0e3      mov      r2, #1                                      
  0002ef74  04408de5      str      r4, [sp, #4]                                
  0002ef78  0430a0e1      mov      r3, r4                                      
  0002ef7c  08408de5      str      r4, [sp, #8]                                
  0002ef80  00008fe0      add      r0, pc, r0                                  
  0002ef84  b66dffeb      bl       #0xa664                                     
  0002ef88  e6ffffea      b        #0x2ef28                                    
  0002ef8c  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002ef90  f31200e3      movw     r1, #0x2f3                                  
  0002ef94  00708de5      str      r7, [sp]                                    
  0002ef98  04708de5      str      r7, [sp, #4]                                
  0002ef9c  00008fe0      add      r0, pc, r0                                  
  0002efa0  08708de5      str      r7, [sp, #8]                                
  0002efa4  30301be5      ldr      r3, [fp, #-0x30]                            
  0002efa8  ad6dffeb      bl       #0xa664                                     
  0002efac  0400a0e1      mov      r0, r4                                      
  0002efb0  356effeb      bl       #0xa88c                                     
  0002efb4  dbffffea      b        #0x2ef28                                    
  0002efb8  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efbc  0c5b0000      andeq    r5, r0, ip, lsl #22                         
  0002efc0  18590000      andeq    r5, r0, r8, lsl sb                          
  0002efc4  185a0000      andeq    r5, r0, r8, lsl sl                          
  0002efc8  d0580000      ldrdeq   r5, r6, [r0], -r0                           
  0002efcc  a4580000      andeq    r5, r0, r4, lsr #17                         
  0002efd0  88580000      andeq    r5, r0, r8, lsl #17                         
  0002efd4  0dc0a0e1      mov      ip, sp                                      
  0002efd8  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  0002efdc  04b04ce2      sub      fp, ip, #4                                  
  0002efe0  005051e2      subs     r5, r1, #0                                  
  0002efe4  18d04de2      sub      sp, sp, #0x18                               
  0002efe8  0040a0e3      mov      r4, #0                                      
  0002efec  0060a0e1      mov      r6, r0                                      
  0002eff0  0270a0e1      mov      r7, r2                                      
  0002eff4  2c400be5      str      r4, [fp, #-0x2c]                            
  0002eff8  28400be5      str      r4, [fp, #-0x28]                            
  0002effc  4000000a      beq      #0x2f104                                    
  0002f000  1500a0e3      mov      r0, #0x15                                   
  0002f004  0410a0e1      mov      r1, r4                                      
  0002f008  0620a0e1      mov      r2, r6                                      
  0002f00c  2c304be2      sub      r3, fp, #0x2c                               
  0002f010  8a6dffeb      bl       #0xa640                                     
  0002f014  008050e2      subs     r8, r0, #0                                  
  0002f018  2e00001a      bne      #0x2f0d8                                    
  0002f01c  2c201be5      ldr      r2, [fp, #-0x2c]                            
  0002f020  070052e1      cmp      r2, r7                                      
  0002f024  2000008a      bhi      #0x2f0ac                                    
  0002f028  000052e3      cmp      r2, #0                                      
  0002f02c  002085e5      str      r2, [r5]                                    
  0002f030  1a00000a      beq      #0x2f0a0                                    
  0002f034  28704be2      sub      r7, fp, #0x28                               
  0002f038  0040a0e3      mov      r4, #0                                      
  0002f03c  040000ea      b        #0x2f054                                    
  0002f040  2c101be5      ldr      r1, [fp, #-0x2c]                            
  0002f044  040051e1      cmp      r1, r4                                      
  0002f048  28101be5      ldr      r1, [fp, #-0x28]                            
  0002f04c  0410a5e5      str      r1, [r5, #4]!                               
  0002f050  1200009a      bls      #0x2f0a0                                    
  0002f054  0430a0e1      mov      r3, r4                                      
  0002f058  00708de5      str      r7, [sp]                                    
  0002f05c  1500a0e3      mov      r0, #0x15                                   
  0002f060  0010a0e3      mov      r1, #0                                      
  0002f064  0620a0e1      mov      r2, r6                                      
  0002f068  014084e2      add      r4, r4, #1                                  
  0002f06c  3d6dffeb      bl       #0xa568                                     
  0002f070  00a050e2      subs     sl, r0, #0                                  
  0002f074  f1ffff0a      beq      #0x2f040                                    
  0002f078  b0009fe5      ldr      r0, [pc, #0xb0]                             
  0002f07c  0030a0e3      mov      r3, #0                                      
  0002f080  6910a0e3      mov      r1, #0x69                                   
  0002f084  00308de5      str      r3, [sp]                                    
  0002f088  00008fe0      add      r0, pc, r0                                  
  0002f08c  04308de5      str      r3, [sp, #4]                                
  0002f090  0a20a0e1      mov      r2, sl                                      
  0002f094  08308de5      str      r3, [sp, #8]                                
  0002f098  716dffeb      bl       #0xa664                                     
  0002f09c  0a80a0e1      mov      r8, sl                                      
  0002f0a0  0800a0e1      mov      r0, r8                                      
  0002f0a4  24d04be2      sub      sp, fp, #0x24                               
  0002f0a8  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  0002f0ac  80009fe5      ldr      r0, [pc, #0x80]                             
  0002f0b0  5a10a0e3      mov      r1, #0x5a                                   
  0002f0b4  00808de5      str      r8, [sp]                                    
  0002f0b8  0630a0e1      mov      r3, r6                                      
  0002f0bc  04808de5      str      r8, [sp, #4]                                
  0002f0c0  00008fe0      add      r0, pc, r0                                  
  0002f0c4  08808de5      str      r8, [sp, #8]                                
  0002f0c8  656dffeb      bl       #0xa664                                     
  0002f0cc  0720a0e1      mov      r2, r7                                      
  0002f0d0  2c700be5      str      r7, [fp, #-0x2c]                            
  0002f0d4  d3ffffea      b        #0x2f028                                    
  0002f0d8  2c001be5      ldr      r0, [fp, #-0x2c]                            
  0002f0dc  5410a0e3      mov      r1, #0x54                                   
  0002f0e0  04408de5      str      r4, [sp, #4]                                
  0002f0e4  0820a0e1      mov      r2, r8                                      
  0002f0e8  08408de5      str      r4, [sp, #8]                                
  0002f0ec  0630a0e1      mov      r3, r6                                      
  0002f0f0  00008de5      str      r0, [sp]                                    
  0002f0f4  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0002f0f8  00008fe0      add      r0, pc, r0                                  
  0002f0fc  586dffeb      bl       #0xa664                                     
  0002f100  e6ffffea      b        #0x2f0a0                                    
  0002f104  30009fe5      ldr      r0, [pc, #0x30]                             
  0002f108  0120a0e3      mov      r2, #1                                      
  0002f10c  00508de5      str      r5, [sp]                                    
  0002f110  4910a0e3      mov      r1, #0x49                                   
  0002f114  04508de5      str      r5, [sp, #4]                                
  0002f118  0530a0e1      mov      r3, r5                                      
  0002f11c  08508de5      str      r5, [sp, #8]                                
  0002f120  00008fe0      add      r0, pc, r0                                  
  0002f124  0280a0e1      mov      r8, r2                                      
  0002f128  4d6dffeb      bl       #0xa664                                     
  0002f12c  dbffffea      b        #0x2f0a0                                    
  0002f130  28590000      andeq    r5, r0, r8, lsr #18                         
  0002f134  f0580000      strdeq   r5, r6, [r0], -r0                           
  0002f138  b8580000      strheq   r5, [r0], -r8                               
  0002f13c  90580000      muleq    r0, r0, r8                                  
  0002f140  0dc0a0e1      mov      ip, sp                                      
  0002f144  0030a0e3      mov      r3, #0                                      
  0002f148  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0002f14c  04b04ce2      sub      fp, ip, #4                                  
  0002f150  008050e2      subs     r8, r0, #0                                  
  0002f154  24d04de2      sub      sp, sp, #0x24                               
  0002f158  0170a0e1      mov      r7, r1                                      
  0002f15c  38300be5      str      r3, [fp, #-0x38]                            
  0002f160  34300be5      str      r3, [fp, #-0x34]                            
  0002f164  30300be5      str      r3, [fp, #-0x30]                            
  0002f168  5b00000a      beq      #0x2f2dc                                    
  0002f16c  0310a0e1      mov      r1, r3                                      
  0002f170  1500a0e3      mov      r0, #0x15                                   
  0002f174  38304be2      sub      r3, fp, #0x38                               
  0002f178  252ca0e3      mov      r2, #0x2500                                 
  0002f17c  872e42e3      movt     r2, #0x2e87                                 
  0002f180  2e6dffeb      bl       #0xa640                                     
  0002f184  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f188  00a050e2      subs     sl, r0, #0                                  
  0002f18c  4600001a      bne      #0x2f2ac                                    
  0002f190  100053e3      cmp      r3, #0x10                                   
  0002f194  4400008a      bhi      #0x2f2ac                                    
  0002f198  000053e3      cmp      r3, #0                                      
  0002f19c  5304e7e7      ubfx     r0, r3, #8, #8                              
  0002f1a0  5318e7e7      ubfx     r1, r3, #0x10, #8                           
  0002f1a4  232ca0e1      lsr      r2, r3, #0x18                               
  0002f1a8  0030c8e5      strb     r3, [r8]                                    
  0002f1ac  0100c8e5      strb     r0, [r8, #1]                                
  0002f1b0  0210c8e5      strb     r1, [r8, #2]                                
  0002f1b4  0320c8e5      strb     r2, [r8, #3]                                
  0002f1b8  4400000a      beq      #0x2f2d0                                    
  0002f1bc  34604be2      sub      r6, fp, #0x34                               
  0002f1c0  0a40a0e1      mov      r4, sl                                      
  0002f1c4  220000ea      b        #0x2f254                                    
  0002f1c8  34c01be5      ldr      ip, [fp, #-0x34]                            
  0002f1cc  0c0057e1      cmp      r7, ip                                      
  0002f1d0  1b00000a      beq      #0x2f244                                    
  0002f1d4  1070ffeb      bl       #0xb21c                                     
  0002f1d8  251ca0e3      mov      r1, #0x2500                                 
  0002f1dc  0130a0e3      mov      r3, #1                                      
  0002f1e0  871e42e3      movt     r1, #0x2e87                                 
  0002f1e4  005050e2      subs     r5, r0, #0                                  
  0002f1e8  0520a0e1      mov      r2, r5                                      
  0002f1ec  4500001a      bne      #0x2f308                                    
  0002f1f0  60008de8      stm      sp, {r5, r6}                                
  0002f1f4  08508de5      str      r5, [sp, #8]                                
  0002f1f8  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f1fc  7c6cffeb      bl       #0xa3f4                                     
  0002f200  843384e0      add      r3, r4, r4, lsl #7                          
  0002f204  252ca0e3      mov      r2, #0x2500                                 
  0002f208  872e42e3      movt     r2, #0x2e87                                 
  0002f20c  833088e0      add      r3, r8, r3, lsl #1                          
  0002f210  043083e2      add      r3, r3, #4                                  
  0002f214  009050e2      subs     sb, r0, #0                                  
  0002f218  1500a0e3      mov      r0, #0x15                                   
  0002f21c  4300001a      bne      #0x2f330                                    
  0002f220  021100e3      movw     r1, #0x102                                  
  0002f224  00108de5      str      r1, [sp]                                    
  0002f228  30101be5      ldr      r1, [fp, #-0x30]                            
  0002f22c  356effeb      bl       #0xab08                                     
  0002f230  0050a0e1      mov      r5, r0                                      
  0002f234  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f238  556fffeb      bl       #0xaf94                                     
  0002f23c  000055e3      cmp      r5, #0                                      
  0002f240  4700001a      bne      #0x2f364                                    
  0002f244  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f248  014084e2      add      r4, r4, #1                                  
  0002f24c  040053e1      cmp      r3, r4                                      
  0002f250  1e00009a      bls      #0x2f2d0                                    
  0002f254  0430a0e1      mov      r3, r4                                      
  0002f258  0010a0e3      mov      r1, #0                                      
  0002f25c  00608de5      str      r6, [sp]                                    
  0002f260  1500a0e3      mov      r0, #0x15                                   
  0002f264  252ca0e3      mov      r2, #0x2500                                 
  0002f268  872e42e3      movt     r2, #0x2e87                                 
  0002f26c  bd6cffeb      bl       #0xa568                                     
  0002f270  009050e2      subs     sb, r0, #0                                  
  0002f274  30004be2      sub      r0, fp, #0x30                               
  0002f278  d2ffff0a      beq      #0x2f1c8                                    
  0002f27c  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0002f280  00c0a0e3      mov      ip, #0                                      
  0002f284  a510a0e3      mov      r1, #0xa5                                   
  0002f288  00c08de5      str      ip, [sp]                                    
  0002f28c  00008fe0      add      r0, pc, r0                                  
  0002f290  0920a0e1      mov      r2, sb                                      
  0002f294  04c08de5      str      ip, [sp, #4]                                
  0002f298  09a0a0e1      mov      sl, sb                                      
  0002f29c  38301be5      ldr      r3, [fp, #-0x38]                            
  0002f2a0  08c08de5      str      ip, [sp, #8]                                
  0002f2a4  ee6cffeb      bl       #0xa664                                     
  0002f2a8  080000ea      b        #0x2f2d0                                    
  0002f2ac  e0009fe5      ldr      r0, [pc, #0xe0]                             
  0002f2b0  00c0a0e3      mov      ip, #0                                      
  0002f2b4  9710a0e3      mov      r1, #0x97                                   
  0002f2b8  00c08de5      str      ip, [sp]                                    
  0002f2bc  00008fe0      add      r0, pc, r0                                  
  0002f2c0  04c08de5      str      ip, [sp, #4]                                
  0002f2c4  0a20a0e1      mov      r2, sl                                      
  0002f2c8  08c08de5      str      ip, [sp, #8]                                
  0002f2cc  e46cffeb      bl       #0xa664                                     
  0002f2d0  0a00a0e1      mov      r0, sl                                      
  0002f2d4  28d04be2      sub      sp, fp, #0x28                               
  0002f2d8  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  0002f2dc  b4009fe5      ldr      r0, [pc, #0xb4]                             
  0002f2e0  0120a0e3      mov      r2, #1                                      
  0002f2e4  00808de5      str      r8, [sp]                                    
  0002f2e8  8d10a0e3      mov      r1, #0x8d                                   
  0002f2ec  04808de5      str      r8, [sp, #4]                                
  0002f2f0  0830a0e1      mov      r3, r8                                      
  0002f2f4  08808de5      str      r8, [sp, #8]                                
  0002f2f8  00008fe0      add      r0, pc, r0                                  
  0002f2fc  02a0a0e1      mov      sl, r2                                      
  0002f300  d76cffeb      bl       #0xa664                                     
  0002f304  f1ffffea      b        #0x2f2d0                                    
  0002f308  8c009fe5      ldr      r0, [pc, #0x8c]                             
  0002f30c  b310a0e3      mov      r1, #0xb3                                   
  0002f310  00908de5      str      sb, [sp]                                    
  0002f314  0930a0e1      mov      r3, sb                                      
  0002f318  04908de5      str      sb, [sp, #4]                                
  0002f31c  00008fe0      add      r0, pc, r0                                  
  0002f320  08908de5      str      sb, [sp, #8]                                
  0002f324  05a0a0e1      mov      sl, r5                                      
  0002f328  cd6cffeb      bl       #0xa664                                     
  0002f32c  e7ffffea      b        #0x2f2d0                                    
  0002f330  30001be5      ldr      r0, [fp, #-0x30]                            
  0002f334  09a0a0e1      mov      sl, sb                                      
  0002f338  156fffeb      bl       #0xaf94                                     
  0002f33c  5c009fe5      ldr      r0, [pc, #0x5c]                             
  0002f340  00508de5      str      r5, [sp]                                    
  0002f344  bf10a0e3      mov      r1, #0xbf                                   
  0002f348  04508de5      str      r5, [sp, #4]                                
  0002f34c  0920a0e1      mov      r2, sb                                      
  0002f350  08508de5      str      r5, [sp, #8]                                
  0002f354  00008fe0      add      r0, pc, r0                                  
  0002f358  34301be5      ldr      r3, [fp, #-0x34]                            
  0002f35c  c06cffeb      bl       #0xa664                                     
  0002f360  daffffea      b        #0x2f2d0                                    
  0002f364  38009fe5      ldr      r0, [pc, #0x38]                             
  0002f368  ca10a0e3      mov      r1, #0xca                                   
  0002f36c  00908de5      str      sb, [sp]                                    
  0002f370  0520a0e1      mov      r2, r5                                      
  0002f374  04908de5      str      sb, [sp, #4]                                
  0002f378  00008fe0      add      r0, pc, r0                                  
  0002f37c  08908de5      str      sb, [sp, #8]                                
  0002f380  05a0a0e1      mov      sl, r5                                      
  0002f384  34301be5      ldr      r3, [fp, #-0x34]                            
  0002f388  b56cffeb      bl       #0xa664                                     
  0002f38c  cfffffea      b        #0x2f2d0                                    
  0002f390  24570000      andeq    r5, r0, r4, lsr #14                         
  0002f394  f4560000      strdeq   r5, r6, [r0], -r4                           
  0002f398  b8560000      strheq   r5, [r0], -r8                               
  0002f39c  94560000      muleq    r0, r4, r6                                  
  0002f3a0  5c560000      andeq    r5, r0, ip, asr r6                          
  0002f3a4  38560000      andeq    r5, r0, r8, lsr r6                          
  0002f3a8  0dc0a0e1      mov      ip, sp                                      
  0002f3ac  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002f3b0  04b04ce2      sub      fp, ip, #4                                  
  0002f3b4  0350a0e1      mov      r5, r3                                      
  0002f3b8  000051e3      cmp      r1, #0                                      
  0002f3bc  00005513      cmpne    r5, #0                                      
  0002f3c0  18d04de2      sub      sp, sp, #0x18                               
  0002f3c4  00c0a0e3      mov      ip, #0                                      
  0002f3c8  0130a0e1      mov      r3, r1                                      
  0002f3cc  0060a013      movne    r6, #0                                      
  0002f3d0  0160a003      moveq    r6, #1                                      
  0002f3d4  24c00be5      str      ip, [fp, #-0x24]                            
  0002f3d8  20c00be5      str      ip, [fp, #-0x20]                            
  0002f3dc  2c00000a      beq      #0x2f494                                    
  0002f3e0  003091e5      ldr      r3, [r1]                                    
  0002f3e4  20004be2      sub      r0, fp, #0x20                               
  0002f3e8  24300be5      str      r3, [fp, #-0x24]                            
  0002f3ec  8a6fffeb      bl       #0xb21c                                     
  0002f3f0  004050e2      subs     r4, r0, #0                                  
  0002f3f4  0f00000a      beq      #0x2f438                                    
  0002f3f8  0c019fe5      ldr      r0, [pc, #0x10c]                            
  0002f3fc  fc10a0e3      mov      r1, #0xfc                                   
  0002f400  00608de5      str      r6, [sp]                                    
  0002f404  0420a0e1      mov      r2, r4                                      
  0002f408  04608de5      str      r6, [sp, #4]                                
  0002f40c  00008fe0      add      r0, pc, r0                                  
  0002f410  08608de5      str      r6, [sp, #8]                                
  0002f414  24301be5      ldr      r3, [fp, #-0x24]                            
  0002f418  916cffeb      bl       #0xa664                                     
  0002f41c  20001be5      ldr      r0, [fp, #-0x20]                            
  0002f420  000050e3      cmp      r0, #0                                      
  0002f424  0000000a      beq      #0x2f42c                                    
  0002f428  d96effeb      bl       #0xaf94                                     
  0002f42c  0400a0e1      mov      r0, r4                                      
  0002f430  1cd04be2      sub      sp, fp, #0x1c                               
  0002f434  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002f438  00408de5      str      r4, [sp]                                    
  0002f43c  24304be2      sub      r3, fp, #0x24                               
  0002f440  08408de5      str      r4, [sp, #8]                                
  0002f444  0420a0e1      mov      r2, r4                                      
  0002f448  04308de5      str      r3, [sp, #4]                                
  0002f44c  251ca0e3      mov      r1, #0x2500                                 
  0002f450  20001be5      ldr      r0, [fp, #-0x20]                            
  0002f454  871e42e3      movt     r1, #0x2e87                                 
  0002f458  0130a0e3      mov      r3, #1                                      
  0002f45c  0470a0e1      mov      r7, r4                                      
  0002f460  e36bffeb      bl       #0xa3f4                                     
  0002f464  004050e2      subs     r4, r0, #0                                  
  0002f468  1300000a      beq      #0x2f4bc                                    
  0002f46c  9c009fe5      ldr      r0, [pc, #0x9c]                             
  0002f470  051100e3      movw     r1, #0x105                                  
  0002f474  00608de5      str      r6, [sp]                                    
  0002f478  0420a0e1      mov      r2, r4                                      
  0002f47c  04608de5      str      r6, [sp, #4]                                
  0002f480  00008fe0      add      r0, pc, r0                                  
  0002f484  08608de5      str      r6, [sp, #8]                                
  0002f488  24301be5      ldr      r3, [fp, #-0x24]                            
  0002f48c  746cffeb      bl       #0xa664                                     
  0002f490  e1ffffea      b        #0x2f41c                                    
  0002f494  78009fe5      ldr      r0, [pc, #0x78]                             
  0002f498  0120a0e3      mov      r2, #1                                      
  0002f49c  00508de5      str      r5, [sp]                                    
  0002f4a0  ee10a0e3      mov      r1, #0xee                                   
  0002f4a4  04c08de5      str      ip, [sp, #4]                                
  0002f4a8  00008fe0      add      r0, pc, r0                                  
  0002f4ac  08c08de5      str      ip, [sp, #8]                                
  0002f4b0  0240a0e1      mov      r4, r2                                      
  0002f4b4  6a6cffeb      bl       #0xa664                                     
  0002f4b8  dbffffea      b        #0x2f42c                                    
  0002f4bc  023100e3      movw     r3, #0x102                                  
  0002f4c0  1500a0e3      mov      r0, #0x15                                   
  0002f4c4  00308de5      str      r3, [sp]                                    
  0002f4c8  252ca0e3      mov      r2, #0x2500                                 
  0002f4cc  0530a0e1      mov      r3, r5                                      
  0002f4d0  20101be5      ldr      r1, [fp, #-0x20]                            
  0002f4d4  872e42e3      movt     r2, #0x2e87                                 
  0002f4d8  8a6dffeb      bl       #0xab08                                     
  0002f4dc  004050e2      subs     r4, r0, #0                                  
  0002f4e0  cdffff0a      beq      #0x2f41c                                    
  0002f4e4  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0002f4e8  0f1100e3      movw     r1, #0x10f                                  
  0002f4ec  00708de5      str      r7, [sp]                                    
  0002f4f0  0420a0e1      mov      r2, r4                                      
  0002f4f4  04708de5      str      r7, [sp, #4]                                
  0002f4f8  00008fe0      add      r0, pc, r0                                  
  0002f4fc  08708de5      str      r7, [sp, #8]                                
  0002f500  24301be5      ldr      r3, [fp, #-0x24]                            
  0002f504  566cffeb      bl       #0xa664                                     
  0002f508  c3ffffea      b        #0x2f41c                                    
  0002f50c  a4550000      andeq    r5, r0, r4, lsr #11                         
  0002f510  30550000      andeq    r5, r0, r0, lsr r5                          
  0002f514  08550000      andeq    r5, r0, r8, lsl #10                         
  0002f518  b8540000      strheq   r5, [r0], -r8                               
  0002f51c  0dc0a0e1      mov      ip, sp                                      
  0002f520  000050e3      cmp      r0, #0                                      
  0002f524  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  0002f528  04b04ce2      sub      fp, ip, #4                                  
  0002f52c  2cc29fe5      ldr      ip, [pc, #0x22c]                            
  0002f530  28d04de2      sub      sp, sp, #0x28                               
  0002f534  0040a0e1      mov      r4, r0                                      
  0002f538  0cc08fe0      add      ip, pc, ip                                  
  0002f53c  0150a0e1      mov      r5, r1                                      
  0002f540  0260a0e1      mov      r6, r2                                      
  0002f544  00e0a0e3      mov      lr, #0                                      
  0002f548  0f009ce8      ldm      ip, {r0, r1, r2, r3}                        
  0002f54c  2cc04be2      sub      ip, fp, #0x2c                               
  0002f550  b0e34be1      strh     lr, [fp, #-0x30]                            
  0002f554  23e8a0e1      lsr      lr, r3, #0x10                               
  0002f558  0700ace8      stm      ip!, {r0, r1, r2}                           
  0002f55c  b230cce0      strh     r3, [ip], #2                                
  0002f560  00e0cce5      strb     lr, [ip]                                    
  0002f564  2800000a      beq      #0x2f60c                                    
  0002f568  f4119fe5      ldr      r1, [pc, #0x1f4]                            
  0002f56c  0400a0e1      mov      r0, r4                                      
  0002f570  01108fe0      add      r1, pc, r1                                  
  0002f574  a96fffeb      bl       #0xb420                                     
  0002f578  000050e3      cmp      r0, #0                                      
  0002f57c  0c00000a      beq      #0x2f5b4                                    
  0002f580  e0019fe5      ldr      r0, [pc, #0x1e0]                            
  0002f584  0040a0e3      mov      r4, #0                                      
  0002f588  3e1100e3      movw     r1, #0x13e                                  
  0002f58c  00408de5      str      r4, [sp]                                    
  0002f590  00008fe0      add      r0, pc, r0                                  
  0002f594  04408de5      str      r4, [sp, #4]                                
  0002f598  0120a0e3      mov      r2, #1                                      
  0002f59c  08408de5      str      r4, [sp, #8]                                
  0002f5a0  0430a0e1      mov      r3, r4                                      
  0002f5a4  2e6cffeb      bl       #0xa664                                     
  0002f5a8  0400a0e1      mov      r0, r4                                      
  0002f5ac  1cd04be2      sub      sp, fp, #0x1c                               
  0002f5b0  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0002f5b4  b0119fe5      ldr      r1, [pc, #0x1b0]                            
  0002f5b8  0400a0e1      mov      r0, r4                                      
  0002f5bc  01108fe0      add      r1, pc, r1                                  
  0002f5c0  966fffeb      bl       #0xb420                                     
  0002f5c4  000050e3      cmp      r0, #0                                      
  0002f5c8  ecffff1a      bne      #0x2f580                                    
  0002f5cc  0030d4e5      ldrb     r3, [r4]                                    
  0002f5d0  000053e3      cmp      r3, #0                                      
  0002f5d4  0470a011      movne    r7, r4                                      
  0002f5d8  0300001a      bne      #0x2f5ec                                    
  0002f5dc  150000ea      b        #0x2f638                                    
  0002f5e0  0130f7e5      ldrb     r3, [r7, #1]!                               
  0002f5e4  000053e3      cmp      r3, #0                                      
  0002f5e8  1200000a      beq      #0x2f638                                    
  0002f5ec  2c004be2      sub      r0, fp, #0x2c                               
  0002f5f0  30104be2      sub      r1, fp, #0x30                               
  0002f5f4  30304be5      strb     r3, [fp, #-0x30]                            
  0002f5f8  886fffeb      bl       #0xb420                                     
  0002f5fc  000050e3      cmp      r0, #0                                      
  0002f600  f6ffff0a      beq      #0x2f5e0                                    
  0002f604  0000a0e3      mov      r0, #0                                      
  0002f608  e7ffffea      b        #0x2f5ac                                    
  0002f60c  5c019fe5      ldr      r0, [pc, #0x15c]                            
  0002f610  371100e3      movw     r1, #0x137                                  
  0002f614  00408de5      str      r4, [sp]                                    
  0002f618  0120a0e3      mov      r2, #1                                      
  0002f61c  00008fe0      add      r0, pc, r0                                  
