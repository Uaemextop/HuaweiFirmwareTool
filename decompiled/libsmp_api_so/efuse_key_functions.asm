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

### HW_DM_GetRootPubKeyFile @ 0x23a04
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
