### HW_SWM_LoadEfuse @ 0x375f4
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