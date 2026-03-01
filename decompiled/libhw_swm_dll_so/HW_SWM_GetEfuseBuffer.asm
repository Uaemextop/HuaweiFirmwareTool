### HW_SWM_GetEfuseBuffer @ 0x3736c
  0003736c  0dc0a0e1      mov      ip, sp                                      
  00037370  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  00037374  0050a0e1      mov      r5, r0                                      
  00037378  84609fe5      ldr      r6, [pc, #0x84]                             
  0003737c  04b04ce2      sub      fp, ip, #4                                  
  00037380  0510a0e1      mov      r1, r5                                      
  00037384  06608fe0      add      r6, pc, r6                                  
  00037388  0600a0e1      mov      r0, r6                                      
  0003738c  d851ffeb      bl       #0xbaf4                                     
  00037390  007050e2      subs     r7, r0, #0                                  
  00037394  0400000a      beq      #0x373ac                                    
  00037398  260100e3      movw     r0, #0x126                                  
  0003739c  0110a0e3      mov      r1, #1                                      
  000373a0  0bffffeb      bl       #0x36fd4                                    
  000373a4  0040a0e3      mov      r4, #0                                      
  000373a8  130000ea      b        #0x373fc                                    
  000373ac  000095e5      ldr      r0, [r5]                                    
  000373b0  0456ffeb      bl       #0xcbc8                                     
  000373b4  004050e2      subs     r4, r0, #0                                  
  000373b8  0300001a      bne      #0x373cc                                    
  000373bc  290100e3      movw     r0, #0x129                                  
  000373c0  0110a0e3      mov      r1, #1                                      
  000373c4  02ffffeb      bl       #0x36fd4                                    
  000373c8  0b0000ea      b        #0x373fc                                    
  000373cc  0600a0e1      mov      r0, r6                                      
  000373d0  0410a0e1      mov      r1, r4                                      
  000373d4  002095e5      ldr      r2, [r5]                                    
  000373d8  ac55ffeb      bl       #0xca90                                     
  000373dc  010070e3      cmn      r0, #1                                      
  000373e0  0500001a      bne      #0x373fc                                    
  000373e4  4b0fa0e3      mov      r0, #0x12c                                  
  000373e8  0110a0e3      mov      r1, #1                                      
  000373ec  f8feffeb      bl       #0x36fd4                                    
  000373f0  0400a0e1      mov      r0, r4                                      
  000373f4  e350ffeb      bl       #0xb788                                     
  000373f8  0740a0e1      mov      r4, r7                                      
  000373fc  0400a0e1      mov      r0, r4                                      
  00037400  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  00037404  182d0000      andeq    r2, r0, r8, lsl sp                          
  00037408  0dc0a0e1      mov      ip, sp                                      
  0003740c  0030a0e3      mov      r3, #0                                      
  00037410  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  00037414  04b04ce2      sub      fp, ip, #4                                  
  00037418  14004be2      sub      r0, fp, #0x14                               
  0003741c  08d04de2      sub      sp, sp, #8                                  
  00037420  043020e5      str      r3, [r0, #-4]!                              
  00037424  8050ffeb      bl       #0xb62c                                     
  00037428  004050e2      subs     r4, r0, #0                                  
  0003742c  0300001a      bne      #0x37440                                    
  00037430  520fa0e3      mov      r0, #0x148                                  
  00037434  0110a0e3      mov      r1, #1                                      
  00037438  e5feffeb      bl       #0x36fd4                                    
  0003743c  080000ea      b        #0x37464                                    
  00037440  18101be5      ldr      r1, [fp, #-0x18]                            
  00037444  ca55ffeb      bl       #0xcb74                                     
  00037448  000050e3      cmp      r0, #0                                      
  0003744c  0600000a      beq      #0x3746c                                    
  00037450  530fa0e3      mov      r0, #0x14c                                  
  00037454  0110a0e3      mov      r1, #1                                      
  00037458  ddfeffeb      bl       #0x36fd4                                    
  0003745c  0400a0e1      mov      r0, r4                                      
  00037460  c850ffeb      bl       #0xb788                                     
  00037464  0100a0e3      mov      r0, #1                                      
  00037468  0e0000ea      b        #0x374a8                                    
  0003746c  0400a0e1      mov      r0, r4                                      
  00037470  18101be5      ldr      r1, [fp, #-0x18]                            
  00037474  1c52ffeb      bl       #0xbcec                                     
  00037478  000050e3      cmp      r0, #0                                      
  0003747c  150ea013      movne    r0, #0x150                                  
  00037480  f3ffff1a      bne      #0x37454                                    
  00037484  0400a0e1      mov      r0, r4                                      
  00037488  18101be5      ldr      r1, [fp, #-0x18]                            
  0003748c  d952ffeb      bl       #0xbff8                                     
  00037490  005050e2      subs     r5, r0, #0                                  
  00037494  55010013      movwne   r0, #0x155                                  
  00037498  edffff1a      bne      #0x37454                                    
  0003749c  0400a0e1      mov      r0, r4                                      
  000374a0  b850ffeb      bl       #0xb788                                     
  000374a4  0500a0e1      mov      r0, r5                                      
  000374a8  14d04be2      sub      sp, fp, #0x14                               
  000374ac  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  000374b0  78309fe5      ldr      r3, [pc, #0x78]                             
  000374b4  0dc0a0e1      mov      ip, sp                                      
  000374b8  74209fe5      ldr      r2, [pc, #0x74]                             
  000374bc  10d82de9      push     {r4, fp, ip, lr, pc}                        
  000374c0  04b04ce2      sub      fp, ip, #4                                  
  000374c4  14d04de2      sub      sp, sp, #0x14                               
  000374c8  03308fe0      add      r3, pc, r3                                  
  000374cc  022093e7      ldr      r2, [r3, r2]                                
  000374d0  743092e5      ldr      r3, [r2, #0x74]                             
  000374d4  0240a0e1      mov      r4, r2                                      
  000374d8  000053e3      cmp      r3, #0                                      
  000374dc  0b00001a      bne      #0x37510                                    
  000374e0  50009fe5      ldr      r0, [pc, #0x50]                             
  000374e4  0030a0e3      mov      r3, #0                                      
  000374e8  761100e3      movw     r1, #0x176                                  
  000374ec  00308de5      str      r3, [sp]                                    
  000374f0  04308de5      str      r3, [sp, #4]                                
  000374f4  00008fe0      add      r0, pc, r0                                  
  000374f8  08308de5      str      r3, [sp, #8]                                
  000374fc  0120a0e3      mov      r2, #1                                      
  00037500  743094e5      ldr      r3, [r4, #0x74]                             
  00037504  0e57ffeb      bl       #0xd144                                     
  00037508  0100a0e3      mov      r0, #1                                      
  0003750c  050000ea      b        #0x37528                                    
  00037510  24009fe5      ldr      r0, [pc, #0x24]                             
  00037514  00008fe0      add      r0, pc, r0                                  
  00037518  33ff2fe1      blx      r3                                          
  0003751c  000050e3      cmp      r0, #0                                      
  00037520  eeffff0a      beq      #0x374e0                                    
  00037524  0000a0e3      mov      r0, #0                                      
  00037528  10d04be2      sub      sp, fp, #0x10                               
  0003752c  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  00037530  303b0100      andeq    r3, r1, r0, lsr fp                          
  00037534  cc0b0000      andeq    r0, r0, ip, asr #23                         
  00037538  50810000      andeq    r8, r0, r0, asr r1                          
  0003753c  882b0000      andeq    r2, r0, r8, lsl #23                         
  00037540  0dc0a0e1      mov      ip, sp                                      
  00037544  0010a0e3      mov      r1, #0                                      
  00037548  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  0003754c  04b04ce2      sub      fp, ip, #4                                  
  00037550  8c409fe5      ldr      r4, [pc, #0x8c]                             
  00037554  04408fe0      add      r4, pc, r4                                  
  00037558  0400a0e1      mov      r0, r4                                      
  0003755c  ba4fffeb      bl       #0xb44c                                     
  00037560  000050e3      cmp      r0, #0                                      
  00037564  0100001a      bne      #0x37570                                    
  00037568  0400a0e1      mov      r0, r4                                      
  0003756c  4452ffeb      bl       #0xbe84                                     
  00037570  70409fe5      ldr      r4, [pc, #0x70]                             
  00037574  0010a0e3      mov      r1, #0                                      
  00037578  04408fe0      add      r4, pc, r4                                  
  0003757c  0400a0e1      mov      r0, r4                                      
  00037580  b14fffeb      bl       #0xb44c                                     
  00037584  000050e3      cmp      r0, #0                                      
  00037588  0100001a      bne      #0x37594                                    
  0003758c  0400a0e1      mov      r0, r4                                      
  00037590  3b52ffeb      bl       #0xbe84                                     
  00037594  50409fe5      ldr      r4, [pc, #0x50]                             
  00037598  0010a0e3      mov      r1, #0                                      
  0003759c  04408fe0      add      r4, pc, r4                                  
  000375a0  0400a0e1      mov      r0, r4                                      
  000375a4  a84fffeb      bl       #0xb44c                                     
  000375a8  000050e3      cmp      r0, #0                                      
  000375ac  0100001a      bne      #0x375b8                                    
  000375b0  0400a0e1      mov      r0, r4                                      
  000375b4  3252ffeb      bl       #0xbe84                                     
  000375b8  30409fe5      ldr      r4, [pc, #0x30]                             
  000375bc  0010a0e3      mov      r1, #0                                      
  000375c0  04408fe0      add      r4, pc, r4                                  
  000375c4  0400a0e1      mov      r0, r4                                      
  000375c8  9f4fffeb      bl       #0xb44c                                     
  000375cc  000050e3      cmp      r0, #0                                      
  000375d0  0100001a      bne      #0x375dc                                    
  000375d4  0400a0e1      mov      r0, r4                                      
  000375d8  2952ffeb      bl       #0xbe84                                     
  000375dc  0000a0e3      mov      r0, #0                                      
  000375e0  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    
  000375e4  482b0000      andeq    r2, r0, r8, asr #22                         
  000375e8  f0800000      strdeq   r8, sb, [r0], -r0                           
  000375ec  db800000      ldrdeq   r8, sb, [r0], -fp                           
  000375f0  c5800000      andeq    r8, r0, r5, asr #1                          
  000375f4  0dc0a0e1      mov      ip, sp                                      
  000375f8  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  000375fc  04b04ce2      sub      fp, ip, #4                                  
  00037600  9c53ffeb      bl       #0xc478                                     
  00037604  004050e2      subs     r4, r0, #0                                  
  00037608  bd010013      movwne   r0, #0x1bd                                  
  0003760c  0700001a      bne      #0x37630                                    
  00037610  5f50ffeb      bl       #0xb794                                     
  00037614  004050e2      subs     r4, r0, #0                                  
  00037618  c1010013      movwne   r0, #0x1c1                                  
  0003761c  0300001a      bne      #0x37630                                    
  00037620  3c54ffeb      bl       #0xc718                                     
  00037624  004050e2      subs     r4, r0, #0                                  
  00037628  0200000a      beq      #0x37638                                    
  0003762c  c50100e3      movw     r0, #0x1c5                                  
  00037630  0410a0e1      mov      r1, r4                                      
  00037634  66feffeb      bl       #0x36fd4                                    
  00037638  0400a0e1      mov      r0, r4                                      
  0003763c  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    
  00037640  63666774      strbtvc  r6, [r7], #-0x663                           
  00037644  6f6f6c20      rsbhs    r6, ip, pc, ror #30                         
  00037648  64656c20      rsbhs    r6, ip, r4, ror #10                         
  0003764c  25732049      stmdbmi  r0!, {r0, r2, r5, r8, sb, ip, sp, lr}       
  00037650  6e746572      rsbvc    r7, r5, #0x6e000000                         
  00037654  6e657447      ldrbmi   r6, [r4, -lr, ror #10]!                     
  00037658  61746577      strbvc   r7, [r5, -r1, ror #8]!                      
  0003765c  61794465      strbvs   r7, [r4, #-0x961]                           
  00037660  76696365      strbvs   r6, [r3, #-0x976]!                          
  00037664  2e585f48      ldmdami  pc, {r1, r2, r3, r5, fp, ip, lr} ^          
  00037668  575f4461      qdaddvs  r5, r7, r4                                  
  0003766c  74614d6f      svcvs    #0x4d6174                                   
  00037670  64656c2e      cdphs    p5, #6, c6, c12, c4, #3                     
  00037674  585f4857      smlsldpl r5, r8, r8, pc                              
  00037678  5f547261      cmnvs    r2, pc, asr r4                              
  0003767c  6e736665      strbvs   r7, [r6, #-0x36e]!                          
  00037680  72517565      ldrbvs   r5, [r5, #-0x172]!                          
  00037684  75650000      andeq    r6, r0, r5, ror r5                          
  00037688  00000000      andeq    r0, r0, r0                                  
  0003768c  00000000      andeq    r0, r0, r0                                  
  00037690  00000000      andeq    r0, r0, r0                                  
  00037694  00000000      andeq    r0, r0, r0                                  
  00037698  00000000      andeq    r0, r0, r0                                  
  0003769c  00000000      andeq    r0, r0, r0                                  
  000376a0  00000000      andeq    r0, r0, r0                                  
  000376a4  00000000      andeq    r0, r0, r0                                  
  000376a8  00000000      andeq    r0, r0, r0                                  
  000376ac  00000000      andeq    r0, r0, r0                                  
  000376b0  00000000      andeq    r0, r0, r0                                  
  000376b4  00000000      andeq    r0, r0, r0                                  
  000376b8  00000000      andeq    r0, r0, r0                                  
  000376bc  00000000      andeq    r0, r0, r0                                  
  000376c0  00000000      andeq    r0, r0, r0                                  
  000376c4  00000000      andeq    r0, r0, r0                                  
  000376c8  00000000      andeq    r0, r0, r0                                  
  000376cc  00000000      andeq    r0, r0, r0                                  
  000376d0  00000000      andeq    r0, r0, r0                                  
  000376d4  00000000      andeq    r0, r0, r0                                  
  000376d8  00000000      andeq    r0, r0, r0                                  
  000376dc  00000000      andeq    r0, r0, r0                                  
  000376e0  00000000      andeq    r0, r0, r0                                  
  000376e4  00000000      andeq    r0, r0, r0                                  
  000376e8  00000000      andeq    r0, r0, r0                                  
  000376ec  00000000      andeq    r0, r0, r0                                  
  000376f0  00000000      andeq    r0, r0, r0                                  
  000376f4  00000000      andeq    r0, r0, r0                                  
  000376f8  00000000      andeq    r0, r0, r0                                  
  000376fc  00000000      andeq    r0, r0, r0                                  
  00037700  00000000      andeq    r0, r0, r0                                  
  00037704  00000000      andeq    r0, r0, r0                                  
  00037708  00000000      andeq    r0, r0, r0                                  
  0003770c  00000000      andeq    r0, r0, r0                                  
  00037710  00000000      andeq    r0, r0, r0                                  
  00037714  00000000      andeq    r0, r0, r0                                  
  00037718  00000000      andeq    r0, r0, r0                                  
  0003771c  00000000      andeq    r0, r0, r0                                  
  00037720  00000000      andeq    r0, r0, r0                                  
  00037724  00000000      andeq    r0, r0, r0                                  
  00037728  00000000      andeq    r0, r0, r0                                  
  0003772c  00000000      andeq    r0, r0, r0                                  
  00037730  00000000      andeq    r0, r0, r0                                  
  00037734  00000000      andeq    r0, r0, r0                                  
  00037738  00000000      andeq    r0, r0, r0                                  
  0003773c  00000000      andeq    r0, r0, r0                                  
  00037740  68775f73      cmpvc    pc, #104, #14                               
  00037744  776d5f62      subsvs   r6, pc, #0x1dc0                             
  00037748  61636b75      strbvc   r6, [fp, #-0x361]!                          
  0003774c  702e6300      rsbeq    r2, r3, r0, ror lr                          
  00037750  62627370      rsbsvc   r6, r3, r2, ror #4                          
  00037754  003c5357      ldrbpl   r3, [r3, -r0, lsl #24]                      
  00037758  4d3e5b25      ldrbhs   r3, [fp, #-0xe4d]                           
  0003775c  735f2564      strtvs   r5, [r5], #-0xf73                           
  00037760  5d48575f      svcpl    #0x57485d                                   
  00037764  53574d5f      svcpl    #0x4d5753                                   
  00037768  47657456      ldrbtpl  r6, [r4], -r7, asr #10                      
  0003776c  6964656f      svcvs    #0x656469                                   
  00037770  44696167      strbvs   r6, [r1, -r4, asr #18]!                     
  00037774  46696c65      strbvs   r6, [ip, #-0x946]!                          
  00037778  20726574      strbtvc  r7, [r5], #-0x220                           
  0003777c  3a307825      ldrbhs   r3, [r8, #-0x3a]!                           
  00037780  782c2066      qsub16vs r2, r0, r8                                  
  00037784  696c656e      cdpvs    p12, #6, c6, c5, c9, #3                     
  00037788  616d653a      blo      #0x1992d14                                  
  0003778c  25730d0a      beq      #0x394428                                   
  00037790  0d0a002f      svchs    #0xa0d                                      
  00037794  7661722f      svchs    #0x726176                                   
  00037798  56696465      strbvs   r6, [r4, #-0x956]!                          