### HW_DM_GetRootPubKeyInfo @ 0x23838
  00023838  0dc0a0e1      mov      ip, sp                                      
  0002383c  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  00023840  04b04ce2      sub      fp, ip, #4                                  
  00023844  68d04de2      sub      sp, sp, #0x68                               
  00023848  0050a0e1      mov      r5, r0                                      
  0002384c  0160a0e1      mov      r6, r1                                      
  00023850  0280a0e1      mov      r8, r2                                      
  00023854  0010a0e3      mov      r1, #0                                      
  00023858  74004be2      sub      r0, fp, #0x74                               
  0002385c  1020a0e3      mov      r2, #0x10                                   
  00023860  7c100be5      str      r1, [fp, #-0x7c]                            
  00023864  0370a0e1      mov      r7, r3                                      
  00023868  78100be5      str      r1, [fp, #-0x78]                            
  0002386c  e19cffeb      bl       #0xabf8                                     
  00023870  000055e3      cmp      r5, #0                                      
  00023874  00005613      cmpne    r6, #0                                      
  00023878  0010a013      movne    r1, #0                                      
  0002387c  0110a003      moveq    r1, #1                                      
  00023880  0100000a      beq      #0x2388c                                    
  00023884  000057e3      cmp      r7, #0                                      
  00023888  0300001a      bne      #0x2389c                                    
  0002388c  cc0c00e3      movw     r0, #0xccc                                  
  00023890  0110a0e3      mov      r1, #1                                      
  00023894  27f1ffeb      bl       #0x1fd38                                    
  00023898  1b0000ea      b        #0x2390c                                    
  0002389c  54a19fe5      ldr      sl, [pc, #0x154]                            
  000238a0  74204be2      sub      r2, fp, #0x74                               
  000238a4  7c304be2      sub      r3, fp, #0x7c                               
  000238a8  0aa08fe0      add      sl, pc, sl                                  
  000238ac  0a00a0e1      mov      r0, sl                                      
  000238b0  319cffeb      bl       #0xa97c                                     
  000238b4  004050e2      subs     r4, r0, #0                                  
  000238b8  d60c0013      movwne   r0, #0xcd6                                  
  000238bc  0600001a      bne      #0x238dc                                    
  000238c0  0410a0e1      mov      r1, r4                                      
  000238c4  0a00a0e1      mov      r0, sl                                      
  000238c8  78204be2      sub      r2, fp, #0x78                               
  000238cc  2ba1ffeb      bl       #0xbd80                                     
  000238d0  004050e2      subs     r4, r0, #0                                  
  000238d4  0300000a      beq      #0x238e8                                    
  000238d8  da0c00e3      movw     r0, #0xcda                                  
  000238dc  0410a0e1      mov      r1, r4                                      
  000238e0  14f1ffeb      bl       #0x1fd38                                    
  000238e4  400000ea      b        #0x239ec                                    
  000238e8  78201be5      ldr      r2, [fp, #-0x78]                            
  000238ec  010a52e3      cmp      r2, #0x1000                                 
  000238f0  0700002a      bhs      #0x23914                                    
  000238f4  013aa0e3      mov      r3, #0x1000                                 
  000238f8  00308de5      str      r3, [sp]                                    
  000238fc  7c301be5      ldr      r3, [fp, #-0x7c]                            
  00023900  de0c00e3      movw     r0, #0xcde                                  
  00023904  0110a0e3      mov      r1, #1                                      
  00023908  cef0ffeb      bl       #0x1fc48                                    
  0002390c  0140a0e3      mov      r4, #1                                      
  00023910  350000ea      b        #0x239ec                                    
  00023914  7ca01be5      ldr      sl, [fp, #-0x7c]                            
  00023918  4010a0e3      mov      r1, #0x40                                   
  0002391c  0130a0e1      mov      r3, r1                                      
  00023920  64004be2      sub      r0, fp, #0x64                               
  00023924  0a2082e0      add      r2, r2, sl                                  
  00023928  01aa42e2      sub      sl, r2, #0x1000                             
  0002392c  0420a0e1      mov      r2, r4                                      
  00023930  7c9dffeb      bl       #0xaf28                                     
  00023934  74004be2      sub      r0, fp, #0x74                               
  00023938  0a10a0e1      mov      r1, sl                                      
  0002393c  64204be2      sub      r2, fp, #0x64                               
  00023940  4030a0e3      mov      r3, #0x40                                   
  00023944  ef9dffeb      bl       #0xb108                                     
  00023948  00c050e2      subs     ip, r0, #0                                  
  0002394c  0600001a      bne      #0x2396c                                    
  00023950  64201be5      ldr      r2, [fp, #-0x64]                            
  00023954  a0309fe5      ldr      r3, [pc, #0xa0]                             
  00023958  030052e1      cmp      r2, r3                                      
  0002395c  0200001a      bne      #0x2396c                                    
  00023960  54301be5      ldr      r3, [fp, #-0x54]                            
  00023964  080053e1      cmp      r3, r8                                      
  00023968  0a00009a      bls      #0x23998                                    
  0002396c  54301be5      ldr      r3, [fp, #-0x54]                            
  00023970  ee1c00e3      movw     r1, #0xcee                                  
  00023974  84009fe5      ldr      r0, [pc, #0x84]                             
  00023978  0120a0e3      mov      r2, #1                                      
  0002397c  08018de8      stm      sp, {r3, r8}                                
  00023980  00008fe0      add      r0, pc, r0                                  
  00023984  64301be5      ldr      r3, [fp, #-0x64]                            
  00023988  08308de5      str      r3, [sp, #8]                                
  0002398c  0c30a0e1      mov      r3, ip                                      
  00023990  379dffeb      bl       #0xae74                                     
  00023994  dcffffea      b        #0x2390c                                    
  00023998  58101be5      ldr      r1, [fp, #-0x58]                            
  0002399c  74004be2      sub      r0, fp, #0x74                               
  000239a0  0620a0e1      mov      r2, r6                                      
  000239a4  01108ae0      add      r1, sl, r1                                  
  000239a8  d69dffeb      bl       #0xb108                                     
  000239ac  004050e2      subs     r4, r0, #0                                  
  000239b0  0600000a      beq      #0x239d0                                    
  000239b4  58301be5      ldr      r3, [fp, #-0x58]                            
  000239b8  f70c00e3      movw     r0, #0xcf7                                  
  000239bc  0110a0e3      mov      r1, #1                                      
  000239c0  0420a0e1      mov      r2, r4                                      
  000239c4  00308de5      str      r3, [sp]                                    
  000239c8  54301be5      ldr      r3, [fp, #-0x54]                            
  000239cc  cdffffea      b        #0x23908                                    
  000239d0  54301be5      ldr      r3, [fp, #-0x54]                            
  000239d4  4010a0e3      mov      r1, #0x40                                   
  000239d8  0500a0e1      mov      r0, r5                                      
  000239dc  64204be2      sub      r2, fp, #0x64                               
  000239e0  003087e5      str      r3, [r7]                                    
  000239e4  0130a0e1      mov      r3, r1                                      
  000239e8  269effeb      bl       #0xb288                                     
  000239ec  0400a0e1      mov      r0, r4                                      
  000239f0  24d04be2      sub      sp, fp, #0x24                               
  000239f4  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  000239f8  e51d0100      andeq    r1, r1, r5, ror #27                         
  000239fc  09111720      andshs   r1, r7, sb, lsl #2                          
  00023a00  98160100      muleq    r1, r8, r6                                  
  00023a04  0dc0a0e1      mov      ip, sp                                      
  00023a08  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  00023a0c  006050e2      subs     r6, r0, #0                                  
  00023a10  04b04ce2      sub      fp, ip, #4                                  
  00023a14  4cd04de2      sub      sp, sp, #0x4c                               
  00023a18  1a0d0003      movweq   r0, #0xd1a                                  
  00023a1c  0400000a      beq      #0x23a34                                    
  00023a20  010aa0e3      mov      r0, #0x1000                                 
  00023a24  409fffeb      bl       #0xb72c                                     
  00023a28  005050e2      subs     r5, r0, #0                                  
  00023a2c  0400001a      bne      #0x23a44                                    
  00023a30  1d0d00e3      movw     r0, #0xd1d                                  
  00023a34  0110a0e3      mov      r1, #1                                      
  00023a38  0140a0e3      mov      r4, #1                                      
  00023a3c  bdf0ffeb      bl       #0x1fd38                                    
  00023a40  250000ea      b        #0x23adc                                    
  00023a44  4010a0e3      mov      r1, #0x40                                   
  00023a48  0020a0e3      mov      r2, #0                                      
  00023a4c  0130a0e1      mov      r3, r1                                      
  00023a50  5c004be2      sub      r0, fp, #0x5c                               
  00023a54  339dffeb      bl       #0xaf28                                     
  00023a58  5c004be2      sub      r0, fp, #0x5c                               
  00023a5c  0510a0e1      mov      r1, r5                                      
  00023a60  012aa0e3      mov      r2, #0x1000                                 
  00023a64  60304be2      sub      r3, fp, #0x60                               
  00023a68  5ba0ffeb      bl       #0xbbdc                                     
  00023a6c  004050e2      subs     r4, r0, #0                                  
  00023a70  0500a0e1      mov      r0, r5                                      
  00023a74  0700000a      beq      #0x23a98                                    
  00023a78  011aa0e3      mov      r1, #0x1000                                 
  00023a7c  0020a0e3      mov      r2, #0                                      
  00023a80  0130a0e1      mov      r3, r1                                      
  00023a84  279dffeb      bl       #0xaf28                                     
  00023a88  0500a0e1      mov      r0, r5                                      
  00023a8c  739dffeb      bl       #0xb060                                     
  00023a90  250d00e3      movw     r0, #0xd25                                  
  00023a94  0e0000ea      b        #0x23ad4                                    
  00023a98  0430a0e1      mov      r3, r4                                      
  00023a9c  60101be5      ldr      r1, [fp, #-0x60]                            
  00023aa0  0620a0e1      mov      r2, r6                                      
  00023aa4  d79fffeb      bl       #0xba08                                     
  00023aa8  011aa0e3      mov      r1, #0x1000                                 
  00023aac  0020a0e3      mov      r2, #0                                      
  00023ab0  0130a0e1      mov      r3, r1                                      
  00023ab4  0040a0e1      mov      r4, r0                                      
  00023ab8  0500a0e1      mov      r0, r5                                      
  00023abc  199dffeb      bl       #0xaf28                                     
  00023ac0  0500a0e1      mov      r0, r5                                      
  00023ac4  659dffeb      bl       #0xb060                                     
  00023ac8  000054e3      cmp      r4, #0                                      
  00023acc  0200000a      beq      #0x23adc                                    
  00023ad0  2e0d00e3      movw     r0, #0xd2e                                  
  00023ad4  0410a0e1      mov      r1, r4                                      
  00023ad8  96f0ffeb      bl       #0x1fd38                                    
  00023adc  0400a0e1      mov      r0, r4                                      
  00023ae0  18d04be2      sub      sp, fp, #0x18                               
  00023ae4  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  00023ae8  010050e3      cmp      r0, #1                                      
  00023aec  0700000a      beq      #0x23b10                                    
  00023af0  0200003a      blo      #0x23b00                                    
  00023af4  020050e3      cmp      r0, #2                                      
  00023af8  0e00001a      bne      #0x23b38                                    
  00023afc  070000ea      b        #0x23b20                                    
  00023b00  080091e5      ldr      r0, [r1, #8]                                
  00023b04  000082e5      str      r0, [r2]                                    
  00023b08  0c2091e5      ldr      r2, [r1, #0xc]                              
  00023b0c  060000ea      b        #0x23b2c                                    
  00023b10  100091e5      ldr      r0, [r1, #0x10]                             
  00023b14  000082e5      str      r0, [r2]                                    
  00023b18  142091e5      ldr      r2, [r1, #0x14]                             
  00023b1c  020000ea      b        #0x23b2c                                    
  00023b20  180091e5      ldr      r0, [r1, #0x18]                             
  00023b24  000082e5      str      r0, [r2]                                    
  00023b28  1c2091e5      ldr      r2, [r1, #0x1c]                             
  00023b2c  002083e5      str      r2, [r3]                                    
  00023b30  0000a0e3      mov      r0, #0                                      
  00023b34  1eff2fe1      bx       lr                                          