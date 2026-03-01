# libsmp_api full disassembly

; ─── HW_CFG_DBSortCompare @ 0xc260 ───
  0000c260  003090e5      ldr      r3, [r0]                                    
  0000c264  000091e5      ldr      r0, [r1]                                    
  0000c268  030060e0      rsb      r0, r0, r3                                  
  0000c26c  1eff2fe1      bx       lr                                          
  0000c270  0dc0a0e1      mov      ip, sp                                      
  0000c274  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000c278  0050a0e1      mov      r5, r0                                      
  0000c27c  10d04de2      sub      sp, sp, #0x10                               
  0000c280  34009fe5      ldr      r0, [pc, #0x34]                             
  0000c284  04b04ce2      sub      fp, ip, #4                                  
  0000c288  0140a0e1      mov      r4, r1                                      
  0000c28c  02e0a0e1      mov      lr, r2                                      
  0000c290  00c0a0e3      mov      ip, #0                                      
  0000c294  00308de5      str      r3, [sp]                                    
  0000c298  04c08de5      str      ip, [sp, #4]                                
  0000c29c  00008fe0      add      r0, pc, r0                                  
  0000c2a0  08c08de5      str      ip, [sp, #8]                                
  0000c2a4  0510a0e1      mov      r1, r5                                      
  0000c2a8  0420a0e1      mov      r2, r4                                      
  0000c2ac  0e30a0e1      mov      r3, lr                                      
  0000c2b0  effaffeb      bl       #0xae74                                     
  0000c2b4  14d04be2      sub      sp, fp, #0x14                               
  0000c2b8  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000c2bc  cf6d0200      andeq    r6, r2, pc, asr #27                         
  0000c2c0  0dc0a0e1      mov      ip, sp                                      
  0000c2c4  0230a0e1      mov      r3, r2                                      
  0000c2c8  10d82de9      push     {r4, fp, ip, lr, pc}                        
  0000c2cc  0040a0e1      mov      r4, r0                                      
  0000c2d0  14d04de2      sub      sp, sp, #0x14                               
  0000c2d4  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000c2d8  04b04ce2      sub      fp, ip, #4                                  
  0000c2dc  01e0a0e1      mov      lr, r1                                      
  0000c2e0  00c0a0e3      mov      ip, #0                                      
  0000c2e4  00008fe0      add      r0, pc, r0                                  
  0000c2e8  00c08de5      str      ip, [sp]                                    
  0000c2ec  04c08de5      str      ip, [sp, #4]                                
  0000c2f0  0410a0e1      mov      r1, r4                                      
  0000c2f4  08c08de5      str      ip, [sp, #8]                                
  0000c2f8  0e20a0e1      mov      r2, lr                                      
  0000c2fc  dcfaffeb      bl       #0xae74                                     
  0000c300  10d04be2      sub      sp, fp, #0x10                               
  0000c304  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  0000c308  876d0200      andeq    r6, r2, r7, lsl #27                         
  0000c30c  0dc0a0e1      mov      ip, sp                                      
  0000c310  0030a0e3      mov      r3, #0                                      
  0000c314  00d82de9      push     {fp, ip, lr, pc}                            
  0000c318  04b04ce2      sub      fp, ip, #4                                  
  0000c31c  10d04de2      sub      sp, sp, #0x10                               
  0000c320  00c0a0e1      mov      ip, r0                                      
  0000c324  20009fe5      ldr      r0, [pc, #0x20]                             
  0000c328  0120a0e1      mov      r2, r1                                      
  0000c32c  00308de5      str      r3, [sp]                                    
  0000c330  04308de5      str      r3, [sp, #4]                                
  0000c334  00008fe0      add      r0, pc, r0                                  
  0000c338  08308de5      str      r3, [sp, #8]                                
  0000c33c  0c10a0e1      mov      r1, ip                                      
  0000c340  cbfaffeb      bl       #0xae74                                     
  0000c344  0cd04be2      sub      sp, fp, #0xc                                
  0000c348  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000c34c  376d0200      andeq    r6, r2, r7, lsr sp                          

; ─── HW_CFG_UCBITSWAP @ 0xc350 ───
  0000c350  1eff2fe1      bx       lr                                          

; ─── HW_CFG_RecordNFFDBUpdateLog @ 0xc354 ───
  0000c354  0dc0a0e1      mov      ip, sp                                      
  0000c358  90109fe5      ldr      r1, [pc, #0x90]                             
  0000c35c  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000c360  04b04ce2      sub      fp, ip, #4                                  
  0000c364  e0d04de2      sub      sp, sp, #0xe0                               
  0000c368  dc404be2      sub      r4, fp, #0xdc                               
  0000c36c  0050a0e1      mov      r5, r0                                      
  0000c370  01108fe0      add      r1, pc, r1                                  
  0000c374  0e20a0e3      mov      r2, #0xe                                    
  0000c378  ec004be2      sub      r0, fp, #0xec                               
  0000c37c  1effffeb      bl       #0xbffc                                     
  0000c380  0010a0e3      mov      r1, #0                                      
  0000c384  c820a0e3      mov      r2, #0xc8                                   
  0000c388  0400a0e1      mov      r0, r4                                      
  0000c38c  19faffeb      bl       #0xabf8                                     
  0000c390  0500a0e1      mov      r0, r5                                      
  0000c394  c2fdffeb      bl       #0xbaa4                                     
  0000c398  54309fe5      ldr      r3, [pc, #0x54]                             
  0000c39c  c810a0e3      mov      r1, #0xc8                                   
  0000c3a0  c720a0e3      mov      r2, #0xc7                                   
  0000c3a4  03308fe0      add      r3, pc, r3                                  
  0000c3a8  00008de5      str      r0, [sp]                                    
  0000c3ac  0400a0e1      mov      r0, r4                                      
  0000c3b0  81fbffeb      bl       #0xb1bc                                     
  0000c3b4  0400a0e1      mov      r0, r4                                      
  0000c3b8  c9fcffeb      bl       #0xb6e4                                     
  0000c3bc  0210a0e3      mov      r1, #2                                      
  0000c3c0  00408de5      str      r4, [sp]                                    
  0000c3c4  ec204be2      sub      r2, fp, #0xec                               
  0000c3c8  0e30a0e3      mov      r3, #0xe                                    
  0000c3cc  04008de5      str      r0, [sp, #4]                                
  0000c3d0  0300a0e3      mov      r0, #3                                      
  0000c3d4  20f9ffeb      bl       #0xa85c                                     
  0000c3d8  001050e2      subs     r1, r0, #0                                  
  0000c3dc  0100000a      beq      #0xc3e8                                     
  0000c3e0  5d00a0e3      mov      r0, #0x5d                                   
  0000c3e4  c8ffffeb      bl       #0xc30c                                     
  0000c3e8  14d04be2      sub      sp, fp, #0x14                               
  0000c3ec  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  0000c3f0  776d0200      andeq    r6, r2, r7, ror sp                          
  0000c3f4  1f6d0200      andeq    r6, r2, pc, lsl sp                          

; ─── HW_CFG_SaveLog @ 0xc3f8 ───
  0000c3f8  0dc0a0e1      mov      ip, sp                                      
  0000c3fc  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0000c400  04b04ce2      sub      fp, ip, #4                                  
  0000c404  24d04de2      sub      sp, sp, #0x24                               
  0000c408  0360a0e1      mov      r6, r3                                      
  0000c40c  01c0a0e1      mov      ip, r1                                      
  0000c410  14309be5      ldr      r3, [fp, #0x14]                             
  0000c414  0240a0e1      mov      r4, r2                                      
  0000c418  04809be5      ldr      r8, [fp, #4]                                
  0000c41c  0070a0e1      mov      r7, r0                                      
  0000c420  08509be5      ldr      r5, [fp, #8]                                
  0000c424  0d00a0e3      mov      r0, #0xd                                    
  0000c428  0ca09be5      ldr      sl, [fp, #0xc]                              
  0000c42c  30300be5      str      r3, [fp, #-0x30]                            
  0000c430  00108de5      str      r1, [sp]                                    
  0000c434  80319fe5      ldr      r3, [pc, #0x180]                            
  0000c438  80119fe5      ldr      r1, [pc, #0x180]                            
  0000c43c  08208de5      str      r2, [sp, #8]                                
  0000c440  03308fe0      add      r3, pc, r3                                  
  0000c444  04a08de5      str      sl, [sp, #4]                                
  0000c448  01108fe0      add      r1, pc, r1                                  
  0000c44c  0c508de5      str      r5, [sp, #0xc]                              
  0000c450  8020a0e3      mov      r2, #0x80                                   
  0000c454  10808de5      str      r8, [sp, #0x10]                             
  0000c458  14608de5      str      r6, [sp, #0x14]                             
  0000c45c  34c00be5      str      ip, [fp, #-0x34]                            
  0000c460  10909be5      ldr      sb, [fp, #0x10]                             
  0000c464  00fbffeb      bl       #0xb06c                                     
  0000c468  013044e2      sub      r3, r4, #1                                  
  0000c46c  34c01be5      ldr      ip, [fp, #-0x34]                            
  0000c470  040054e3      cmp      r4, #4                                      
  0000c474  01005313      cmpne    r3, #1                                      
  0000c478  0100009a      bls      #0xc484                                     
  0000c47c  050054e3      cmp      r4, #5                                      
  0000c480  4b00001a      bne      #0xc5b4                                     
  0000c484  0230cce3      bic      r3, ip, #2                                  
  0000c488  180053e3      cmp      r3, #0x18                                   
  0000c48c  0700000a      beq      #0xc4b0                                     
  0000c490  22005ce3      cmp      ip, #0x22                                   
  0000c494  ca005c13      cmpne    ip, #0xca                                   
  0000c498  0400000a      beq      #0xc4b0                                     
  0000c49c  123100e3      movw     r3, #0x112                                  
  0000c4a0  03005ce1      cmp      ip, r3                                      
  0000c4a4  23005c13      cmpne    ip, #0x23                                   
  0000c4a8  7630ff16      uxthne   r3, r6                                      
  0000c4ac  0600001a      bne      #0xc4cc                                     
  0000c4b0  003097e5      ldr      r3, [r7]                                    
  0000c4b4  000053e3      cmp      r3, #0                                      
  0000c4b8  3d00000a      beq      #0xc5b4                                     
  0000c4bc  1a005ce3      cmp      ip, #0x1a                                   
  0000c4c0  3b00001a      bne      #0xc5b4                                     
  0000c4c4  0330a0e3      mov      r3, #3                                      
  0000c4c8  0360a0e1      mov      r6, r3                                      
  0000c4cc  192053e2      subs     r2, r3, #0x19                               
  0000c4d0  0120a013      movne    r2, #1                                      
  0000c4d4  fe0053e3      cmp      r3, #0xfe                                   
  0000c4d8  0020a083      movhi    r2, #0                                      
  0000c4dc  000052e3      cmp      r2, #0                                      
  0000c4e0  3300000a      beq      #0xc5b4                                     
  0000c4e4  010053e3      cmp      r3, #1                                      
  0000c4e8  0300000a      beq      #0xc4fc                                     
  0000c4ec  002097e5      ldr      r2, [r7]                                    
  0000c4f0  000052e3      cmp      r2, #0                                      
  0000c4f4  0900000a      beq      #0xc520                                     
  0000c4f8  0d0000ea      b        #0xc534                                     
  0000c4fc  c0109fe5      ldr      r1, [pc, #0xc0]                             
  0000c500  0800a0e1      mov      r0, r8                                      
  0000c504  34300be5      str      r3, [fp, #-0x34]                            
  0000c508  01108fe0      add      r1, pc, r1                                  
  0000c50c  27fbffeb      bl       #0xb1b0                                     
  0000c510  34301be5      ldr      r3, [fp, #-0x34]                            
  0000c514  000050e3      cmp      r0, #0                                      
  0000c518  f3ffff1a      bne      #0xc4ec                                     
  0000c51c  240000ea      b        #0xc5b4                                     
  0000c520  0d0056e3      cmp      r6, #0xd                                    
  0000c524  04005413      cmpne    r4, #4                                      
  0000c528  0100000a      beq      #0xc534                                     
  0000c52c  0300a0e1      mov      r0, r3                                      
  0000c530  e6f9ffeb      bl       #0xacd0                                     
  0000c534  8cc09fe5      ldr      ip, [pc, #0x8c]                             
  0000c538  050054e3      cmp      r4, #5                                      
  0000c53c  88309fe5      ldr      r3, [pc, #0x88]                             
  0000c540  0d00a0e3      mov      r0, #0xd                                    
  0000c544  0cc08fe0      add      ip, pc, ip                                  
  0000c548  0750a003      moveq    r5, #7                                      
  0000c54c  a220a0e3      mov      r2, #0xa2                                   
  0000c550  03308fe0      add      r3, pc, r3                                  
  0000c554  0c10a0e1      mov      r1, ip                                      
  0000c558  00508de5      str      r5, [sp]                                    
  0000c55c  34c00be5      str      ip, [fp, #-0x34]                            
  0000c560  c1faffeb      bl       #0xb06c                                     
  0000c564  30301be5      ldr      r3, [fp, #-0x30]                            
  0000c568  0820a0e1      mov      r2, r8                                      
  0000c56c  00a08de5      str      sl, [sp]                                    
  0000c570  0610a0e1      mov      r1, r6                                      
  0000c574  04908de5      str      sb, [sp, #4]                                
  0000c578  08308de5      str      r3, [sp, #8]                                
  0000c57c  0530a0e1      mov      r3, r5                                      
  0000c580  000097e5      ldr      r0, [r7]                                    
  0000c584  e0fcffeb      bl       #0xb90c                                     
  0000c588  34c01be5      ldr      ip, [fp, #-0x34]                            
  0000c58c  002050e2      subs     r2, r0, #0                                  
  0000c590  0700000a      beq      #0xc5b4                                     
  0000c594  50008be9      stmib    fp, {r4, r6}                                
  0000c598  0c00a0e1      mov      r0, ip                                      
  0000c59c  0c508be5      str      r5, [fp, #0xc]                              
  0000c5a0  a810a0e3      mov      r1, #0xa8                                   
  0000c5a4  003097e5      ldr      r3, [r7]                                    
  0000c5a8  28d04be2      sub      sp, fp, #0x28                               
  0000c5ac  f06f9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, lr}
  0000c5b0  2ffaffea      b        #0xae74                                     
  0000c5b4  28d04be2      sub      sp, fp, #0x28                               
  0000c5b8  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  0000c5bc  b56c0200      strheq   r6, [r2], -r5                               
  0000c5c0  236c0200      andeq    r6, r2, r3, lsr #24                         
  0000c5c4  256c0200      andeq    r6, r2, r5, lsr #24                         
  0000c5c8  276b0200      andeq    r6, r2, r7, lsr #22                         
  0000c5cc  ee6b0200      andeq    r6, r2, lr, ror #23                         

; ─── HW_CFG_ConfigSetType @ 0xc5d0 ───
  0000c5d0  000050e3      cmp      r0, #0                                      
  0000c5d4  0dc0a0e1      mov      ip, sp                                      
  0000c5d8  00d82de9      push     {fp, ip, lr, pc}                            
  0000c5dc  04b04ce2      sub      fp, ip, #4                                  
  0000c5e0  0400001a      bne      #0xc5f8                                     
  0000c5e4  cb00a0e3      mov      r0, #0xcb                                   
  0000c5e8  54109fe5      ldr      r1, [pc, #0x54]                             
  0000c5ec  46ffffeb      bl       #0xc30c                                     
  0000c5f0  4c009fe5      ldr      r0, [pc, #0x4c]                             
  0000c5f4  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000c5f8  011041e2      sub      r1, r1, #1                                  
  0000c5fc  0130d0e7      ldrb     r3, [r0, r1]                                
  0000c600  030052e3      cmp      r2, #3                                      
  0000c604  02f18f90      addls    pc, pc, r2, lsl #2                          
  0000c608  090000ea      b        #0xc634                                     
  0000c60c  020000ea      b        #0xc61c                                     
  0000c610  040000ea      b        #0xc628                                     
  0000c614  060000ea      b        #0xc634                                     
  0000c618  050000ea      b        #0xc634                                     
  0000c61c  0330c3e3      bic      r3, r3, #3                                  
  0000c620  013083e3      orr      r3, r3, #1                                  
  0000c624  030000ea      b        #0xc638                                     
  0000c628  0330c3e3      bic      r3, r3, #3                                  
  0000c62c  023083e3      orr      r3, r3, #2                                  
  0000c630  000000ea      b        #0xc638                                     
  0000c634  033083e3      orr      r3, r3, #3                                  
  0000c638  0130c0e7      strb     r3, [r0, r1]                                
  0000c63c  0000a0e3      mov      r0, #0                                      
  0000c640  00a89de8      ldm      sp, {fp, sp, pc}                            