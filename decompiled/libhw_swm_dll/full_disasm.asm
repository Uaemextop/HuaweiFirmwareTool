# libhw_swm_dll full disassembly
  0000d39c  0dc0a0e1      mov      ip, sp                                      
  0000d3a0  0030a0e3      mov      r3, #0                                      
  0000d3a4  00d82de9      push     {fp, ip, lr, pc}                            
  0000d3a8  04b04ce2      sub      fp, ip, #4                                  
  0000d3ac  10d04de2      sub      sp, sp, #0x10                               
  0000d3b0  00c0a0e1      mov      ip, r0                                      
  0000d3b4  20009fe5      ldr      r0, [pc, #0x20]                             
  0000d3b8  0120a0e1      mov      r2, r1                                      
  0000d3bc  00308de5      str      r3, [sp]                                    
  0000d3c0  04308de5      str      r3, [sp, #4]                                
  0000d3c4  00008fe0      add      r0, pc, r0                                  
  0000d3c8  08308de5      str      r3, [sp, #8]                                
  0000d3cc  0c10a0e1      mov      r1, ip                                      
  0000d3d0  5bffffeb      bl       #0xd144                                     
  0000d3d4  0cd04be2      sub      sp, fp, #0xc                                
  0000d3d8  00a89de8      ldm      sp, {fp, sp, pc}                            
  0000d3dc  74a30200      andeq    sl, r2, r4, ror r3                          

; ─── HW_SWM_BackupFaild @ 0xd3e0 ───
  0000d3e0  14309fe5      ldr      r3, [pc, #0x14]                             
  0000d3e4  14209fe5      ldr      r2, [pc, #0x14]                             
  0000d3e8  03308fe0      add      r3, pc, r3                                  
  0000d3ec  023093e7      ldr      r3, [r3, r2]                                
  0000d3f0  0120a0e3      mov      r2, #1                                      
  0000d3f4  002083e5      str      r2, [r3]                                    
  0000d3f8  1eff2fe1      bx       lr                                          
  0000d3fc  10dc0300      andeq    sp, r3, r0, lsl ip                          
  0000d400  d40b0000      ldrdeq   r0, r1, [r0], -r4                           

; ─── HW_SWM_BackupSuccess @ 0xd404 ───
  0000d404  14309fe5      ldr      r3, [pc, #0x14]                             
  0000d408  14209fe5      ldr      r2, [pc, #0x14]                             
  0000d40c  03308fe0      add      r3, pc, r3                                  
  0000d410  023093e7      ldr      r3, [r3, r2]                                
  0000d414  0020a0e3      mov      r2, #0                                      
  0000d418  002083e5      str      r2, [r3]                                    
  0000d41c  1eff2fe1      bx       lr                                          
  0000d420  ecdb0300      andeq    sp, r3, ip, ror #23                         
  0000d424  d40b0000      ldrdeq   r0, r1, [r0], -r4                           

; ─── HW_SWM_BackupGetProgress @ 0xd428 ───
  0000d428  0dc0a0e1      mov      ip, sp                                      
  0000d42c  50209fe5      ldr      r2, [pc, #0x50]                             
  0000d430  78d82de9      push     {r3, r4, r5, r6, fp, ip, lr, pc}            
  0000d434  04b04ce2      sub      fp, ip, #4                                  
  0000d438  48309fe5      ldr      r3, [pc, #0x48]                             
  0000d43c  03308fe0      add      r3, pc, r3                                  
  0000d440  026093e7      ldr      r6, [r3, r2]                                
  0000d444  0c0096e5      ldr      r0, [r6, #0xc]                              
  0000d448  97f9ffeb      bl       #0xbaac                                     
  0000d44c  0020a0e3      mov      r2, #0                                      
  0000d450  34309fe5      ldr      r3, [pc, #0x34]                             
  0000d454  0cfaffeb      bl       #0xbc8c                                     
  0000d458  0040a0e1      mov      r4, r0                                      
  0000d45c  080096e5      ldr      r0, [r6, #8]                                
  0000d460  0150a0e1      mov      r5, r1                                      
  0000d464  90f9ffeb      bl       #0xbaac                                     
  0000d468  0020a0e1      mov      r2, r0                                      
  0000d46c  0130a0e1      mov      r3, r1                                      
  0000d470  0400a0e1      mov      r0, r4                                      
  0000d474  0510a0e1      mov      r1, r5                                      
  0000d478  dff9ffeb      bl       #0xbbfc                                     
  0000d47c  10feffeb      bl       #0xccc4                                     
  0000d480  78a89de8      ldm      sp, {r3, r4, r5, r6, fp, sp, pc}            
  0000d484  d40b0000      ldrdeq   r0, r1, [r0], -r4                           
  0000d488  bcdb0300      strheq   sp, [r3], -ip                               
  0000d48c  00005940      subsmi   r0, sb, r0                                  

; ─── HW_SWM_RecSuccessAlarm @ 0xd490 ───
  0000d490  0dc0a0e1      mov      ip, sp                                      
  0000d494  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  0000d498  0050a0e1      mov      r5, r0                                      
  0000d49c  04b04ce2      sub      fp, ip, #4                                  
  0000d4a0  0100a0e1      mov      r0, r1                                      
  0000d4a4  8bfdffeb      bl       #0xcad8                                     
  0000d4a8  020055e3      cmp      r5, #2                                      
  0000d4ac  0040a0e1      mov      r4, r0                                      
  0000d4b0  0400001a      bne      #0xd4c8                                     
  0000d4b4  84009fe5      ldr      r0, [pc, #0x84]                             
  0000d4b8  5cfdffeb      bl       #0xca30                                     
  0000d4bc  0010a0e1      mov      r1, r0                                      
  0000d4c0  78009fe5      ldr      r0, [pc, #0x78]                             
  0000d4c4  1a0000ea      b        #0xd534                                     
  0000d4c8  030055e3      cmp      r5, #3                                      
  0000d4cc  0400001a      bne      #0xd4e4                                     
  0000d4d0  6c009fe5      ldr      r0, [pc, #0x6c]                             
  0000d4d4  55fdffeb      bl       #0xca30                                     
  0000d4d8  0010a0e1      mov      r1, r0                                      
  0000d4dc  60009fe5      ldr      r0, [pc, #0x60]                             
  0000d4e0  130000ea      b        #0xd534                                     
  0000d4e4  0d0055e3      cmp      r5, #0xd                                    
  0000d4e8  0400001a      bne      #0xd500                                     
  0000d4ec  54009fe5      ldr      r0, [pc, #0x54]                             
  0000d4f0  4efdffeb      bl       #0xca30                                     
  0000d4f4  0010a0e1      mov      r1, r0                                      
  0000d4f8  48009fe5      ldr      r0, [pc, #0x48]                             
  0000d4fc  0c0000ea      b        #0xd534                                     
  0000d500  140055e3      cmp      r5, #0x14                                   
  0000d504  0400001a      bne      #0xd51c                                     
  0000d508  3c009fe5      ldr      r0, [pc, #0x3c]                             
  0000d50c  47fdffeb      bl       #0xca30                                     
  0000d510  0010a0e1      mov      r1, r0                                      
  0000d514  30009fe5      ldr      r0, [pc, #0x30]                             
  0000d518  050000ea      b        #0xd534                                     
  0000d51c  1b0055e3      cmp      r5, #0x1b                                   
  0000d520  30a89d18      ldmne    sp, {r4, r5, fp, sp, pc}                    
  0000d524  24009fe5      ldr      r0, [pc, #0x24]                             
  0000d528  40fdffeb      bl       #0xca30                                     
  0000d52c  0010a0e1      mov      r1, r0                                      
  0000d530  18009fe5      ldr      r0, [pc, #0x18]                             
  0000d534  0420a0e1      mov      r2, r4                                      
  0000d538  30689de8      ldm      sp, {r4, r5, fp, sp, lr}                    
  0000d53c  7bf9ffea      b        #0xbb30                                     
  0000d540  02451002      andseq   r4, r0, #0x800000                           
  0000d544  04451002      andseq   r4, r0, #4, #10                             
  0000d548  36451002      andseq   r4, r0, #0xd800000                          
  0000d54c  3e451002      andseq   r4, r0, #0xf800000                          
  0000d550  84451002      andseq   r4, r0, #132, #10                           

; ─── HW_SWM_GetVideoLogInFile @ 0xd554 ───
  0000d554  0dc0a0e1      mov      ip, sp                                      
  0000d558  0010a0e3      mov      r1, #0                                      
  0000d55c  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  0000d560  04b04ce2      sub      fp, ip, #4                                  
  0000d564  474f4be2      sub      r4, fp, #0x11c                              
  0000d568  5bdf4de2      sub      sp, sp, #0x16c                              
  0000d56c  015ca0e3      mov      r5, #0x100                                  
  0000d570  0060a0e1      mov      r6, r0                                      
  0000d574  0520a0e1      mov      r2, r5                                      
  0000d578  0400a0e1      mov      r0, r4                                      
  0000d57c  83fcffeb      bl       #0xc790                                     
  0000d580  0600a0e1      mov      r0, r6                                      
  0000d584  93f9ffeb      bl       #0xbbd8                                     
  0000d588  ff0050e3      cmp      r0, #0xff                                   
  0000d58c  3300008a      bhi      #0xd660                                     
  0000d590  0600a0e1      mov      r0, r6                                      
  0000d594  8ff9ffeb      bl       #0xbbd8                                     
  0000d598  0510a0e1      mov      r1, r5                                      
  0000d59c  0620a0e1      mov      r2, r6                                      
  0000d5a0  0030a0e1      mov      r3, r0                                      
  0000d5a4  0400a0e1      mov      r0, r4                                      
  0000d5a8  33ffffeb      bl       #0xd27c                                     
  0000d5ac  5410a0e3      mov      r1, #0x54                                   
  0000d5b0  0130a0e1      mov      r3, r1                                      
  0000d5b4  0020a0e3      mov      r2, #0                                      
  0000d5b8  170e4be2      sub      r0, fp, #0x170                              
  0000d5bc  a3f9ffeb      bl       #0xbc50                                     
  0000d5c0  a0209fe5      ldr      r2, [pc, #0xa0]                             
  0000d5c4  2010a0e3      mov      r1, #0x20                                   
  0000d5c8  d530a0e3      mov      r3, #0xd5                                   
  0000d5cc  02208fe0      add      r2, pc, r2                                  
  0000d5d0  28310be5      str      r3, [fp, #-0x128]                           
  0000d5d4  520f4be2      sub      r0, fp, #0x148                              
  0000d5d8  1230a0e3      mov      r3, #0x12                                   
  0000d5dc  4c310be5      str      r3, [fp, #-0x14c]                           
  0000d5e0  1f30a0e3      mov      r3, #0x1f                                   
  0000d5e4  24ffffeb      bl       #0xd27c                                     
  0000d5e8  8dfeffeb      bl       #0xd024                                     
  0000d5ec  2010a0e3      mov      r1, #0x20                                   
  0000d5f0  1f30a0e3      mov      r3, #0x1f                                   
  0000d5f4  0020a0e1      mov      r2, r0                                      
  0000d5f8  5b0f4be2      sub      r0, fp, #0x16c                              
  0000d5fc  1effffeb      bl       #0xd27c                                     
  0000d600  00508de5      str      r5, [sp]                                    
  0000d604  5d3f4be2      sub      r3, fp, #0x174                              
  0000d608  0020a0e3      mov      r2, #0                                      
  0000d60c  04308de5      str      r3, [sp, #4]                                
  0000d610  170e4be2      sub      r0, fp, #0x170                              
  0000d614  0430a0e3      mov      r3, #4                                      
  0000d618  0c208de5      str      r2, [sp, #0xc]                              
  0000d61c  08308de5      str      r3, [sp, #8]                                
  0000d620  0430a0e1      mov      r3, r4                                      
  0000d624  40109fe5      ldr      r1, [pc, #0x40]                             
  0000d628  3bf8ffeb      bl       #0xb71c                                     
  0000d62c  005050e2      subs     r5, r0, #0                                  
  0000d630  0200000a      beq      #0xd640                                     
  0000d634  c400a0e3      mov      r0, #0xc4                                   
  0000d638  0510a0e1      mov      r1, r5                                      
  0000d63c  56ffffeb      bl       #0xd39c                                     
  0000d640  28009fe5      ldr      r0, [pc, #0x28]                             
  0000d644  c620a0e3      mov      r2, #0xc6                                   
  0000d648  24109fe5      ldr      r1, [pc, #0x24]                             
  0000d64c  0530a0e1      mov      r3, r5                                      
  0000d650  00408de5      str      r4, [sp]                                    
  0000d654  00008fe0      add      r0, pc, r0                                  
  0000d658  01108fe0      add      r1, pc, r1                                  
  0000d65c  88feffeb      bl       #0xd084                                     
  0000d660  18d04be2      sub      sp, fp, #0x18                               
  0000d664  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  0000d668  7ca10200      andeq    sl, r2, ip, ror r1                          