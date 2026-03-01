# athtestcmd full disassembly
  000092c4  00b0a0e3      mov      fp, #0                                      
  000092c8  00e0a0e3      mov      lr, #0                                      
  000092cc  04109de4      pop      {r1}                                        
  000092d0  0d20a0e1      mov      r2, sp                                      
  000092d4  04202de5      str      r2, [sp, #-4]!                              
  000092d8  04002de5      str      r0, [sp, #-4]!                              
  000092dc  10c09fe5      ldr      ip, [pc, #0x10]                             
  000092e0  04c02de5      str      ip, [sp, #-4]!                              
  000092e4  0c009fe5      ldr      r0, [pc, #0xc]                              
  000092e8  0c309fe5      ldr      r3, [pc, #0xc]                              
  000092ec  b2ffffea      b        #0x91bc                                     
  000092f0  75ffffeb      bl       #0x90cc                                       ; → abort
  000092f4  fc510100      strdeq   r5, r6, [r1], -ip                           
  000092f8  2cb00000      andeq    fp, r0, ip, lsr #32                         
  000092fc  d08f0000      ldrdeq   r8, sb, [r0], -r0                           
  00009300  08402de9      push     {r3, lr}                                    
  00009304  a40e02e3      movw     r0, #0x2ea4                                 
  00009308  24309fe5      ldr      r3, [pc, #0x24]                             
  0000930c  020040e3      movt     r0, #2                                      
  00009310  033060e0      rsb      r3, r0, r3                                  
  00009314  060053e3      cmp      r3, #6                                      
  00009318  0880bd98      popls    {r3, pc}                                    
  0000931c  003000e3      movw     r3, #0                                      
  00009320  003040e3      movt     r3, #0                                      
  00009324  000053e3      cmp      r3, #0                                      
  00009328  0880bd08      popeq    {r3, pc}                                    
  0000932c  33ff2fe1      blx      r3                                          
  00009330  0880bde8      pop      {r3, pc}                                    
  00009334  a72e0200      andeq    r2, r2, r7, lsr #29                         
  00009338  08402de9      push     {r3, lr}                                    
  0000933c  a40e02e3      movw     r0, #0x2ea4                                 
  00009340  a43e02e3      movw     r3, #0x2ea4                                 
  00009344  020040e3      movt     r0, #2                                      
  00009348  023040e3      movt     r3, #2                                      
  0000934c  033060e0      rsb      r3, r0, r3                                  
  00009350  4331a0e1      asr      r3, r3, #2                                  
  00009354  a33f83e0      add      r3, r3, r3, lsr #31                         
  00009358  c310b0e1      asrs     r1, r3, #1                                  
  0000935c  0880bd08      popeq    {r3, pc}                                    
  00009360  002000e3      movw     r2, #0                                      
  00009364  002040e3      movt     r2, #0                                      
  00009368  000052e3      cmp      r2, #0                                      
  0000936c  0880bd08      popeq    {r3, pc}                                    
  00009370  32ff2fe1      blx      r2                                          
  00009374  0880bde8      pop      {r3, pc}                                    
  00009378  10402de9      push     {r4, lr}                                    
  0000937c  b84e02e3      movw     r4, #0x2eb8                                 
  00009380  024040e3      movt     r4, #2                                      
  00009384  0030d4e5      ldrb     r3, [r4]                                    
  00009388  000053e3      cmp      r3, #0                                      
  0000938c  1080bd18      popne    {r4, pc}                                    
  00009390  daffffeb      bl       #0x9300                                     
  00009394  003000e3      movw     r3, #0                                      
  00009398  003040e3      movt     r3, #0                                      
  0000939c  000053e3      cmp      r3, #0                                      
  000093a0  0200000a      beq      #0x93b0                                     
  000093a4  0c010ae3      movw     r0, #0xa10c                                 
  000093a8  010040e3      movt     r0, #1                                      
  000093ac  5bffffeb      bl       #0x9120                                     
  000093b0  0130a0e3      mov      r3, #1                                      
  000093b4  0030c4e5      strb     r3, [r4]                                    
  000093b8  1080bde8      pop      {r4, pc}                                    
  000093bc  08402de9      push     {r3, lr}                                    
  000093c0  003000e3      movw     r3, #0                                      
  000093c4  003040e3      movt     r3, #0                                      
  000093c8  000053e3      cmp      r3, #0                                      
  000093cc  0400000a      beq      #0x93e4                                     
  000093d0  0c010ae3      movw     r0, #0xa10c                                 
  000093d4  bc1e02e3      movw     r1, #0x2ebc                                 
  000093d8  010040e3      movt     r0, #1                                      
  000093dc  021040e3      movt     r1, #2                                      
  000093e0  b1ffffeb      bl       #0x92ac                                     
  000093e4  180102e3      movw     r0, #0x2118                                 
  000093e8  020040e3      movt     r0, #2                                      
  000093ec  003090e5      ldr      r3, [r0]                                    
  000093f0  000053e3      cmp      r3, #0                                      
  000093f4  0400000a      beq      #0x940c                                     
  000093f8  003000e3      movw     r3, #0                                      
  000093fc  003040e3      movt     r3, #0                                      
  00009400  000053e3      cmp      r3, #0                                      
  00009404  0000000a      beq      #0x940c                                     
  00009408  33ff2fe1      blx      r3                                          
  0000940c  0840bde8      pop      {r3, lr}                                    
  00009410  c8ffffea      b        #0x9338                                     
  00009414  04b02de5      str      fp, [sp, #-4]!                              
  00009418  00b08de2      add      fp, sp, #0                                  
  0000941c  14d04de2      sub      sp, sp, #0x14                               
  00009420  10000be5      str      r0, [fp, #-0x10]                            
  00009424  0130a0e1      mov      r3, r1                                      
  00009428  11304be5      strb     r3, [fp, #-0x11]                            
  0000942c  0030a0e3      mov      r3, #0                                      
  00009430  05304be5      strb     r3, [fp, #-5]                               
  00009434  0030a0e3      mov      r3, #0                                      
  00009438  06304be5      strb     r3, [fp, #-6]                               
  0000943c  090000ea      b        #0x9468                                     
  00009440  10301be5      ldr      r3, [fp, #-0x10]                            
  00009444  012083e2      add      r2, r3, #1                                  
  00009448  10200be5      str      r2, [fp, #-0x10]                            
  0000944c  0020d3e5      ldrb     r2, [r3]                                    
  00009450  05305be5      ldrb     r3, [fp, #-5]                               
  00009454  033022e0      eor      r3, r2, r3                                  
  00009458  05304be5      strb     r3, [fp, #-5]                               
  0000945c  06305be5      ldrb     r3, [fp, #-6]                               
  00009460  013083e2      add      r3, r3, #1                                  
  00009464  06304be5      strb     r3, [fp, #-6]                               
  00009468  06205be5      ldrb     r2, [fp, #-6]                               
  0000946c  11305be5      ldrb     r3, [fp, #-0x11]                            
  00009470  030052e1      cmp      r2, r3                                      
  00009474  f1ffff3a      blo      #0x9440                                     
  00009478  05305be5      ldrb     r3, [fp, #-5]                               
  0000947c  0330e0e1      mvn      r3, r3                                      
  00009480  05304be5      strb     r3, [fp, #-5]                               
  00009484  05305be5      ldrb     r3, [fp, #-5]                               
  00009488  0300a0e1      mov      r0, r3                                      
  0000948c  00d08be2      add      sp, fp, #0                                  
  00009490  0008bde8      ldm      sp!, {fp}                                   
  00009494  1eff2fe1      bx       lr                                          
  00009498  00482de9      push     {fp, lr}                                    
  0000949c  04b08de2      add      fp, sp, #4                                  
  000094a0  b43e02e3      movw     r3, #0x2eb4                                 
  000094a4  023040e3      movt     r3, #2                                      
  000094a8  002093e5      ldr      r2, [r3]                                    
  000094ac  803803e3      movw     r3, #0x3880                                 
  000094b0  023040e3      movt     r3, #2                                      
  000094b4  003093e5      ldr      r3, [r3]                                    
  000094b8  0200a0e1      mov      r0, r2                                      
  000094bc  a81406e3      movw     r1, #0x64a8                                 
  000094c0  011040e3      movt     r1, #1                                      
  000094c4  0320a0e1      mov      r2, r3                                      
  000094c8  11ffffeb      bl       #0x9114                                       ; → fprintf
  000094cc  b43e02e3      movw     r3, #0x2eb4                                 
  000094d0  023040e3      movt     r3, #2                                      
  000094d4  003093e5      ldr      r3, [r3]                                    
  000094d8  0300a0e1      mov      r0, r3                                      
  000094dc  c81406e3      movw     r1, #0x64c8                                 
  000094e0  011040e3      movt     r1, #1                                      
  000094e4  0c2205e3      movw     r2, #0x520c                                 
  000094e8  012040e3      movt     r2, #1                                      
  000094ec  08ffffeb      bl       #0x9114                                       ; → fprintf
  000094f0  0000a0e3      mov      r0, #0                                      
  000094f4  361c00eb      bl       #0x105d4                                    
  000094f8  0000e0e3      mvn      r0, #0                                      
  000094fc  cc1406e3      movw     r1, #0x64cc                                 
  00009500  011040e3      movt     r1, #1                                      
  00009504  35ffffeb      bl       #0x91e0                                       ; → err
  00009508  04b02de5      str      fp, [sp, #-4]!                              
  0000950c  00b08de2      add      fp, sp, #0                                  
  00009510  14d04de2      sub      sp, sp, #0x14                               
  00009514  10000be5      str      r0, [fp, #-0x10]                            
  00009518  14100be5      str      r1, [fp, #-0x14]                            
  0000951c  0030a0e3      mov      r3, #0                                      
  00009520  08300be5      str      r3, [fp, #-8]                               
  00009524  14301be5      ldr      r3, [fp, #-0x14]                            
  00009528  7330efe6      uxtb     r3, r3                                      
  0000952c  14300be5      str      r3, [fp, #-0x14]                            
  00009530  10301be5      ldr      r3, [fp, #-0x10]                            
  00009534  0020a0e3      mov      r2, #0                                      
  00009538  002083e5      str      r2, [r3]                                    
  0000953c  0030a0e3      mov      r3, #0                                      
  00009540  08300be5      str      r3, [fp, #-8]                               
  00009544  0b0000ea      b        #0x9578                                     
  00009548  10301be5      ldr      r3, [fp, #-0x10]                            
  0000954c  002093e5      ldr      r2, [r3]                                    
  00009550  08301be5      ldr      r3, [fp, #-8]                               
  00009554  8331a0e1      lsl      r3, r3, #3                                  
  00009558  14101be5      ldr      r1, [fp, #-0x14]                            
  0000955c  1133a0e1      lsl      r3, r1, r3                                  
  00009560  032082e1      orr      r2, r2, r3                                  
  00009564  10301be5      ldr      r3, [fp, #-0x10]                            
  00009568  002083e5      str      r2, [r3]                                    
  0000956c  08301be5      ldr      r3, [fp, #-8]                               
  00009570  013083e2      add      r3, r3, #1                                  
  00009574  08300be5      str      r3, [fp, #-8]                               
  00009578  08301be5      ldr      r3, [fp, #-8]                               
  0000957c  030053e3      cmp      r3, #3                                      
  00009580  f0ffffda      ble      #0x9548                                     
  00009584  00d08be2      add      sp, fp, #0                                  
  00009588  0008bde8      ldm      sp!, {fp}                                   
  0000958c  1eff2fe1      bx       lr                                          
  00009590  00482de9      push     {fp, lr}                                    
  00009594  04b08de2      add      fp, sp, #4                                  
  00009598  10d04de2      sub      sp, sp, #0x10                               
  0000959c  08000be5      str      r0, [fp, #-8]                               
  000095a0  0c100be5      str      r1, [fp, #-0xc]                             
  000095a4  10200be5      str      r2, [fp, #-0x10]                            
  000095a8  14300be5      str      r3, [fp, #-0x14]                            
  000095ac  14301be5      ldr      r3, [fp, #-0x14]                            
  000095b0  0020a0e3      mov      r2, #0                                      
  000095b4  002083e5      str      r2, [r3]                                    
  000095b8  08301be5      ldr      r3, [fp, #-8]                               
  000095bc  960053e3      cmp      r3, #0x96                                   
  000095c0  0500000a      beq      #0x95dc                                     
  000095c4  08301be5      ldr      r3, [fp, #-8]                               
  000095c8  970053e3      cmp      r3, #0x97                                   
  000095cc  0200000a      beq      #0x95dc                                     
  000095d0  08301be5      ldr      r3, [fp, #-8]                               
  000095d4  980053e3      cmp      r3, #0x98                                   
  000095d8  0300001a      bne      #0x95ec                                     
  000095dc  14301be5      ldr      r3, [fp, #-0x14]                            
  000095e0  0020a0e3      mov      r2, #0                                      
  000095e4  002083e5      str      r2, [r3]                                    
  000095e8  050000ea      b        #0x9604                                     
  000095ec  08301be5      ldr      r3, [fp, #-8]                               
  000095f0  3b0053e3      cmp      r3, #0x3b                                   
  000095f4  0200009a      bls      #0x9604                                     
  000095f8  14301be5      ldr      r3, [fp, #-0x14]                            
  000095fc  0120a0e3      mov      r2, #1                                      
  00009600  002083e5      str      r2, [r3]                                    
  00009604  14301be5      ldr      r3, [fp, #-0x14]                            
  00009608  003093e5      ldr      r3, [r3]                                    
  0000960c  dc0406e3      movw     r0, #0x64dc                                 
  00009610  010040e3      movt     r0, #1                                      
  00009614  0310a0e1      mov      r1, r3                                      
  00009618  7efeffeb      bl       #0x9018                                       ; → printf
  0000961c  08301be5      ldr      r3, [fp, #-8]                               
  00009620  ca0053e3      cmp      r3, #0xca                                   
  00009624  03f19f97      ldrls    pc, [pc, r3, lsl #2]                        
  00009628  570600ea      b        #0xaf8c                                     
  0000962c  58990000      andeq    sb, r0, r8, asr sb                          
  00009630  74990000      andeq    sb, r0, r4, ror sb                          
  00009634  ac990000      andeq    sb, r0, ip, lsr #19                         
  00009638  e4990000      andeq    sb, r0, r4, ror #19                         
  0000963c  1c9a0000      andeq    sb, r0, ip, lsl sl                          
  00009640  389a0000      andeq    sb, r0, r8, lsr sl                          
  00009644  549a0000      andeq    sb, r0, r4, asr sl                          
  00009648  709a0000      andeq    sb, r0, r0, ror sl                          
  0000964c  8c9a0000      andeq    sb, r0, ip, lsl #21                         
  00009650  a89a0000      andeq    sb, r0, r8, lsr #21                         
  00009654  c49a0000      andeq    sb, r0, r4, asr #21                         
  00009658  e09a0000      andeq    sb, r0, r0, ror #21                         
  0000965c  fc9a0000      strdeq   sb, sl, [r0], -ip                           
  00009660  189b0000      andeq    sb, r0, r8, lsl fp                          
  00009664  349b0000      andeq    sb, r0, r4, lsr fp                          
  00009668  509b0000      andeq    sb, r0, r0, asr fp                          
  0000966c  6c9b0000      andeq    sb, r0, ip, ror #22                         
  00009670  889b0000      andeq    sb, r0, r8, lsl #23                         
  00009674  a49b0000      andeq    sb, r0, r4, lsr #23                         
  00009678  c09b0000      andeq    sb, r0, r0, asr #23                         
  0000967c  dc9b0000      ldrdeq   sb, sl, [r0], -ip                           
  00009680  f89b0000      strdeq   sb, sl, [r0], -r8                           
  00009684  149c0000      andeq    sb, r0, r4, lsl ip                          
  00009688  309c0000      andeq    sb, r0, r0, lsr ip                          
  0000968c  4c9c0000      andeq    sb, r0, ip, asr #24                         
  00009690  689c0000      andeq    sb, r0, r8, ror #24                         
  00009694  849c0000      andeq    sb, r0, r4, lsl #25                         
  00009698  a09c0000      andeq    sb, r0, r0, lsr #25                         
  0000969c  bc9c0000      strheq   sb, [r0], -ip                               
  000096a0  d89c0000      ldrdeq   sb, sl, [r0], -r8                           
  000096a4  f49c0000      strdeq   sb, sl, [r0], -r4                           
  000096a8  109d0000      andeq    sb, r0, r0, lsl sp                          
  000096ac  2c9d0000      andeq    sb, r0, ip, lsr #26                         
  000096b0  489d0000      andeq    sb, r0, r8, asr #26                         
  000096b4  649d0000      andeq    sb, r0, r4, ror #26                         
  000096b8  809d0000      andeq    sb, r0, r0, lsl #27                         
  000096bc  9c9d0000      muleq    r0, ip, sp                                  
  000096c0  b89d0000      strheq   sb, [r0], -r8                               
  000096c4  d49d0000      ldrdeq   sb, sl, [r0], -r4                           
  000096c8  f09d0000      strdeq   sb, sl, [r0], -r0                           
  000096cc  0c9e0000      andeq    sb, r0, ip, lsl #28                         
  000096d0  289e0000      andeq    sb, r0, r8, lsr #28                         
  000096d4  449e0000      andeq    sb, r0, r4, asr #28                         
  000096d8  609e0000      andeq    sb, r0, r0, ror #28                         
  000096dc  7c9e0000      andeq    sb, r0, ip, ror lr                          
  000096e0  989e0000      muleq    r0, r8, lr                                  
  000096e4  b49e0000      strheq   sb, [r0], -r4                               
  000096e8  d09e0000      ldrdeq   sb, sl, [r0], -r0                           
  000096ec  ec9e0000      andeq    sb, r0, ip, ror #29                         
  000096f0  089f0000      andeq    sb, r0, r8, lsl #30                         
  000096f4  249f0000      andeq    sb, r0, r4, lsr #30                         
  000096f8  409f0000      andeq    sb, r0, r0, asr #30                         
  000096fc  5c9f0000      andeq    sb, r0, ip, asr pc                          
  00009700  789f0000      andeq    sb, r0, r8, ror pc                          
  00009704  949f0000      muleq    r0, r4, pc                                  
  00009708  b09f0000      strheq   sb, [r0], -r0                               
  0000970c  cc9f0000      andeq    sb, r0, ip, asr #31                         
  00009710  e89f0000      andeq    sb, r0, r8, ror #31                         
  00009714  04a00000      andeq    sl, r0, r4                                  
  00009718  20a00000      andeq    sl, r0, r0, lsr #32                         
  0000971c  3ca00000      andeq    sl, r0, ip, lsr r0                          
  00009720  58a00000      andeq    sl, r0, r8, asr r0                          
  00009724  74a00000      andeq    sl, r0, r4, ror r0                          
  00009728  90a00000      muleq    r0, r0, r0                                  
  0000972c  aca00000      andeq    sl, r0, ip, lsr #1                          
  00009730  c8a00000      andeq    sl, r0, r8, asr #1                          
  00009734  e4a00000      andeq    sl, r0, r4, ror #1                          
  00009738  00a10000      andeq    sl, r0, r0, lsl #2                          
  0000973c  1ca10000      andeq    sl, r0, ip, lsl r1                          
  00009740  38a10000      andeq    sl, r0, r8, lsr r1                          
  00009744  54a10000      andeq    sl, r0, r4, asr r1                          
  00009748  70a10000      andeq    sl, r0, r0, ror r1                          
  0000974c  8ca10000      andeq    sl, r0, ip, lsl #3                          
  00009750  a8a10000      andeq    sl, r0, r8, lsr #3                          
  00009754  c4a10000      andeq    sl, r0, r4, asr #3                          
  00009758  e0a10000      andeq    sl, r0, r0, ror #3                          
  0000975c  fca10000      strdeq   sl, fp, [r0], -ip                           
  00009760  18a20000      andeq    sl, r0, r8, lsl r2                          
  00009764  34a20000      andeq    sl, r0, r4, lsr r2                          
  00009768  50a20000      andeq    sl, r0, r0, asr r2                          
  0000976c  6ca20000      andeq    sl, r0, ip, ror #4                          
  00009770  88a20000      andeq    sl, r0, r8, lsl #5                          
  00009774  a4a20000      andeq    sl, r0, r4, lsr #5                          
  00009778  c0a20000      andeq    sl, r0, r0, asr #5                          
  0000977c  dca20000      ldrdeq   sl, fp, [r0], -ip                           
  00009780  f8a20000      strdeq   sl, fp, [r0], -r8                           
  00009784  14a30000      andeq    sl, r0, r4, lsl r3                          
  00009788  30a30000      andeq    sl, r0, r0, lsr r3                          
  0000978c  4ca30000      andeq    sl, r0, ip, asr #6                          
  00009790  68a30000      andeq    sl, r0, r8, ror #6                          
  00009794  84a30000      andeq    sl, r0, r4, lsl #7                          
  00009798  a0a30000      andeq    sl, r0, r0, lsr #7                          
  0000979c  bca30000      strheq   sl, [r0], -ip                               
  000097a0  d8a30000      ldrdeq   sl, fp, [r0], -r8                           
  000097a4  f4a30000      strdeq   sl, fp, [r0], -r4                           
  000097a8  10a40000      andeq    sl, r0, r0, lsl r4                          
  000097ac  2ca40000      andeq    sl, r0, ip, lsr #8                          
  000097b0  48a40000      andeq    sl, r0, r8, asr #8                          
  000097b4  64a40000      andeq    sl, r0, r4, ror #8                          
  000097b8  80a40000      andeq    sl, r0, r0, lsl #9                          
  000097bc  9ca40000      muleq    r0, ip, r4                                  
  000097c0  b8a40000      strheq   sl, [r0], -r8                               
  000097c4  d4a40000      ldrdeq   sl, fp, [r0], -r4                           
  000097c8  f0a40000      strdeq   sl, fp, [r0], -r0                           
  000097cc  0ca50000      andeq    sl, r0, ip, lsl #10                         
  000097d0  28a50000      andeq    sl, r0, r8, lsr #10                         
  000097d4  44a50000      andeq    sl, r0, r4, asr #10                         
  000097d8  60a50000      andeq    sl, r0, r0, ror #10                         
  000097dc  7ca50000      andeq    sl, r0, ip, ror r5                          
  000097e0  98a50000      muleq    r0, r8, r5                                  
  000097e4  b4a50000      strheq   sl, [r0], -r4                               
  000097e8  d0a50000      ldrdeq   sl, fp, [r0], -r0                           
  000097ec  eca50000      andeq    sl, r0, ip, ror #11                         
  000097f0  08a60000      andeq    sl, r0, r8, lsl #12                         
  000097f4  24a60000      andeq    sl, r0, r4, lsr #12                         
  000097f8  40a60000      andeq    sl, r0, r0, asr #12                         
  000097fc  5ca60000      andeq    sl, r0, ip, asr r6                          
  00009800  78a60000      andeq    sl, r0, r8, ror r6                          
  00009804  94a60000      muleq    r0, r4, r6                                  
  00009808  b0a60000      strheq   sl, [r0], -r0                               
  0000980c  cca60000      andeq    sl, r0, ip, asr #13                         
  00009810  e8a60000      andeq    sl, r0, r8, ror #13                         
  00009814  04a70000      andeq    sl, r0, r4, lsl #14                         
  00009818  20a70000      andeq    sl, r0, r0, lsr #14                         
  0000981c  3ca70000      andeq    sl, r0, ip, lsr r7                          
  00009820  58a70000      andeq    sl, r0, r8, asr r7                          
  00009824  74a70000      andeq    sl, r0, r4, ror r7                          
  00009828  90a70000      muleq    r0, r0, r7                                  
  0000982c  aca70000      andeq    sl, r0, ip, lsr #15                         
  00009830  c8a70000      andeq    sl, r0, r8, asr #15                         
  00009834  e4a70000      andeq    sl, r0, r4, ror #15                         
  00009838  00a80000      andeq    sl, r0, r0, lsl #16                         
  0000983c  1ca80000      andeq    sl, r0, ip, lsl r8                          
  00009840  38a80000      andeq    sl, r0, r8, lsr r8                          
  00009844  54a80000      andeq    sl, r0, r4, asr r8                          
  00009848  70a80000      andeq    sl, r0, r0, ror r8                          
  0000984c  8ca80000      andeq    sl, r0, ip, lsl #17                         
  00009850  a8a80000      andeq    sl, r0, r8, lsr #17                         
  00009854  c4a80000      andeq    sl, r0, r4, asr #17                         
  00009858  e0a80000      andeq    sl, r0, r0, ror #17                         
  0000985c  fca80000      strdeq   sl, fp, [r0], -ip                           
  00009860  18a90000      andeq    sl, r0, r8, lsl sb                          
  00009864  34a90000      andeq    sl, r0, r4, lsr sb                          
  00009868  50a90000      andeq    sl, r0, r0, asr sb                          
  0000986c  6ca90000      andeq    sl, r0, ip, ror #18                         
  00009870  88a90000      andeq    sl, r0, r8, lsl #19                         
  00009874  a4a90000      andeq    sl, r0, r4, lsr #19                         
  00009878  c0a90000      andeq    sl, r0, r0, asr #19                         
  0000987c  dca90000      ldrdeq   sl, fp, [r0], -ip                           
  00009880  f8a90000      strdeq   sl, fp, [r0], -r8                           
  00009884  90990000      muleq    r0, r0, sb                                  
  00009888  c8990000      andeq    sb, r0, r8, asr #19                         
  0000988c  009a0000      andeq    sb, r0, r0, lsl #20                         
  00009890  14aa0000      andeq    sl, r0, r4, lsl sl                          
  00009894  30aa0000      andeq    sl, r0, r0, lsr sl                          
  00009898  4caa0000      andeq    sl, r0, ip, asr #20                         
  0000989c  68aa0000      andeq    sl, r0, r8, ror #20                         
  000098a0  84aa0000      andeq    sl, r0, r4, lsl #21                         
  000098a4  a0aa0000      andeq    sl, r0, r0, lsr #21                         
  000098a8  bcaa0000      strheq   sl, [r0], -ip                               
  000098ac  d8aa0000      ldrdeq   sl, fp, [r0], -r8                           
  000098b0  f4aa0000      strdeq   sl, fp, [r0], -r4                           
  000098b4  10ab0000      andeq    sl, r0, r0, lsl fp                          
  000098b8  2cab0000      andeq    sl, r0, ip, lsr #22                         
  000098bc  48ab0000      andeq    sl, r0, r8, asr #22                         
  000098c0  64ab0000      andeq    sl, r0, r4, ror #22                         
  000098c4  80ab0000      andeq    sl, r0, r0, lsl #23                         
  000098c8  9cab0000      muleq    r0, ip, fp                                  
  000098cc  b8ab0000      strheq   sl, [r0], -r8                               
  000098d0  d4ab0000      ldrdeq   sl, fp, [r0], -r4                           
  000098d4  f0ab0000      strdeq   sl, fp, [r0], -r0                           
  000098d8  0cac0000      andeq    sl, r0, ip, lsl #24                         
  000098dc  28ac0000      andeq    sl, r0, r8, lsr #24                         
  000098e0  44ac0000      andeq    sl, r0, r4, asr #24                         
  000098e4  60ac0000      andeq    sl, r0, r0, ror #24                         
  000098e8  7cac0000      andeq    sl, r0, ip, ror ip                          
  000098ec  98ac0000      muleq    r0, r8, ip                                  
  000098f0  b4ac0000      strheq   sl, [r0], -r4                               
  000098f4  d0ac0000      ldrdeq   sl, fp, [r0], -r0                           
  000098f8  ecac0000      andeq    sl, r0, ip, ror #25                         
  000098fc  08ad0000      andeq    sl, r0, r8, lsl #26                         
  00009900  24ad0000      andeq    sl, r0, r4, lsr #26                         
  00009904  40ad0000      andeq    sl, r0, r0, asr #26                         
  00009908  5cad0000      andeq    sl, r0, ip, asr sp                          
  0000990c  78ad0000      andeq    sl, r0, r8, ror sp                          
  00009910  94ad0000      muleq    r0, r4, sp                                  
  00009914  b0ad0000      strheq   sl, [r0], -r0                               
  00009918  ccad0000      andeq    sl, r0, ip, asr #27                         
  0000991c  e8ad0000      andeq    sl, r0, r8, ror #27                         
  00009920  04ae0000      andeq    sl, r0, r4, lsl #28                         
  00009924  20ae0000      andeq    sl, r0, r0, lsr #28                         
  00009928  3cae0000      andeq    sl, r0, ip, lsr lr                          
  0000992c  58ae0000      andeq    sl, r0, r8, asr lr                          
  00009930  74ae0000      andeq    sl, r0, r4, ror lr                          
  00009934  90ae0000      muleq    r0, r0, lr                                  
  00009938  acae0000      andeq    sl, r0, ip, lsr #29                         
  0000993c  c8ae0000      andeq    sl, r0, r8, asr #29                         
  00009940  e4ae0000      andeq    sl, r0, r4, ror #29                         
  00009944  00af0000      andeq    sl, r0, r0, lsl #30                         
  00009948  1caf0000      andeq    sl, r0, ip, lsl pc                          
  0000994c  38af0000      andeq    sl, r0, r8, lsr pc                          
  00009950  54af0000      andeq    sl, r0, r4, asr pc                          
  00009954  70af0000      andeq    sl, r0, r0, ror pc                          
  00009958  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000995c  0020a0e3      mov      r2, #0                                      
  00009960  002083e5      str      r2, [r3]                                    
  00009964  10301be5      ldr      r3, [fp, #-0x10]                            
  00009968  0120a0e3      mov      r2, #1                                      
  0000996c  002083e5      str      r2, [r3]                                    
  00009970  850500ea      b        #0xaf8c                                     
  00009974  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009978  0020a0e3      mov      r2, #0                                      
  0000997c  002083e5      str      r2, [r3]                                    
  00009980  10301be5      ldr      r3, [fp, #-0x10]                            
  00009984  0220a0e3      mov      r2, #2                                      
  00009988  002083e5      str      r2, [r3]                                    
  0000998c  7e0500ea      b        #0xaf8c                                     
  00009990  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009994  0020a0e3      mov      r2, #0                                      
  00009998  002083e5      str      r2, [r3]                                    
  0000999c  10301be5      ldr      r3, [fp, #-0x10]                            
  000099a0  0420a0e3      mov      r2, #4                                      
  000099a4  002083e5      str      r2, [r3]                                    
  000099a8  770500ea      b        #0xaf8c                                     
  000099ac  0c301be5      ldr      r3, [fp, #-0xc]                             
  000099b0  0020a0e3      mov      r2, #0                                      
  000099b4  002083e5      str      r2, [r3]                                    
  000099b8  10301be5      ldr      r3, [fp, #-0x10]                            
  000099bc  0820a0e3      mov      r2, #8                                      
  000099c0  002083e5      str      r2, [r3]                                    
  000099c4  700500ea      b        #0xaf8c                                     
  000099c8  0c301be5      ldr      r3, [fp, #-0xc]                             
  000099cc  0020a0e3      mov      r2, #0                                      
  000099d0  002083e5      str      r2, [r3]                                    
  000099d4  10301be5      ldr      r3, [fp, #-0x10]                            
  000099d8  1020a0e3      mov      r2, #0x10                                   
  000099dc  002083e5      str      r2, [r3]                                    
  000099e0  690500ea      b        #0xaf8c                                     
  000099e4  0c301be5      ldr      r3, [fp, #-0xc]                             
  000099e8  0020a0e3      mov      r2, #0                                      
  000099ec  002083e5      str      r2, [r3]                                    
  000099f0  10301be5      ldr      r3, [fp, #-0x10]                            
  000099f4  2020a0e3      mov      r2, #0x20                                   
  000099f8  002083e5      str      r2, [r3]                                    
  000099fc  620500ea      b        #0xaf8c                                     
  00009a00  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a04  0020a0e3      mov      r2, #0                                      
  00009a08  002083e5      str      r2, [r3]                                    
  00009a0c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a10  4020a0e3      mov      r2, #0x40                                   
  00009a14  002083e5      str      r2, [r3]                                    
  00009a18  5b0500ea      b        #0xaf8c                                     
  00009a1c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a20  0020a0e3      mov      r2, #0                                      
  00009a24  002083e5      str      r2, [r3]                                    
  00009a28  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a2c  012ca0e3      mov      r2, #0x100                                  
  00009a30  002083e5      str      r2, [r3]                                    
  00009a34  540500ea      b        #0xaf8c                                     
  00009a38  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a3c  0020a0e3      mov      r2, #0                                      
  00009a40  002083e5      str      r2, [r3]                                    
  00009a44  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a48  022ca0e3      mov      r2, #0x200                                  
  00009a4c  002083e5      str      r2, [r3]                                    
  00009a50  4d0500ea      b        #0xaf8c                                     
  00009a54  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a58  0020a0e3      mov      r2, #0                                      
  00009a5c  002083e5      str      r2, [r3]                                    
  00009a60  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a64  012ba0e3      mov      r2, #0x400                                  
  00009a68  002083e5      str      r2, [r3]                                    
  00009a6c  460500ea      b        #0xaf8c                                     
  00009a70  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a74  0020a0e3      mov      r2, #0                                      
  00009a78  002083e5      str      r2, [r3]                                    
  00009a7c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a80  022ba0e3      mov      r2, #0x800                                  
  00009a84  002083e5      str      r2, [r3]                                    
  00009a88  3f0500ea      b        #0xaf8c                                     
  00009a8c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009a90  0020a0e3      mov      r2, #0                                      
  00009a94  002083e5      str      r2, [r3]                                    
  00009a98  10301be5      ldr      r3, [fp, #-0x10]                            
  00009a9c  012aa0e3      mov      r2, #0x1000                                 
  00009aa0  002083e5      str      r2, [r3]                                    
  00009aa4  380500ea      b        #0xaf8c                                     
  00009aa8  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009aac  0020a0e3      mov      r2, #0                                      
  00009ab0  002083e5      str      r2, [r3]                                    
  00009ab4  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ab8  022aa0e3      mov      r2, #0x2000                                 
  00009abc  002083e5      str      r2, [r3]                                    
  00009ac0  310500ea      b        #0xaf8c                                     
  00009ac4  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ac8  0020a0e3      mov      r2, #0                                      
  00009acc  002083e5      str      r2, [r3]                                    
  00009ad0  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ad4  0129a0e3      mov      r2, #0x4000                                 
  00009ad8  002083e5      str      r2, [r3]                                    
  00009adc  2a0500ea      b        #0xaf8c                                     
  00009ae0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ae4  0020a0e3      mov      r2, #0                                      
  00009ae8  002083e5      str      r2, [r3]                                    
  00009aec  10301be5      ldr      r3, [fp, #-0x10]                            
  00009af0  0229a0e3      mov      r2, #0x8000                                 
  00009af4  002083e5      str      r2, [r3]                                    
  00009af8  230500ea      b        #0xaf8c                                     
  00009afc  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b00  0020a0e3      mov      r2, #0                                      
  00009b04  002083e5      str      r2, [r3]                                    
  00009b08  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b0c  0128a0e3      mov      r2, #0x10000                                
  00009b10  002083e5      str      r2, [r3]                                    
  00009b14  1c0500ea      b        #0xaf8c                                     
  00009b18  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b1c  0020a0e3      mov      r2, #0                                      
  00009b20  002083e5      str      r2, [r3]                                    
  00009b24  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b28  0228a0e3      mov      r2, #0x20000                                
  00009b2c  002083e5      str      r2, [r3]                                    
  00009b30  150500ea      b        #0xaf8c                                     
  00009b34  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b38  0020a0e3      mov      r2, #0                                      
  00009b3c  002083e5      str      r2, [r3]                                    
  00009b40  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b44  0127a0e3      mov      r2, #0x40000                                
  00009b48  002083e5      str      r2, [r3]                                    
  00009b4c  0e0500ea      b        #0xaf8c                                     
  00009b50  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b54  0020a0e3      mov      r2, #0                                      
  00009b58  002083e5      str      r2, [r3]                                    
  00009b5c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b60  0227a0e3      mov      r2, #0x80000                                
  00009b64  002083e5      str      r2, [r3]                                    
  00009b68  070500ea      b        #0xaf8c                                     
  00009b6c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b70  0020a0e3      mov      r2, #0                                      
  00009b74  002083e5      str      r2, [r3]                                    
  00009b78  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b7c  0126a0e3      mov      r2, #0x100000                               
  00009b80  002083e5      str      r2, [r3]                                    
  00009b84  000500ea      b        #0xaf8c                                     
  00009b88  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009b8c  0020a0e3      mov      r2, #0                                      
  00009b90  002083e5      str      r2, [r3]                                    
  00009b94  10301be5      ldr      r3, [fp, #-0x10]                            
  00009b98  0226a0e3      mov      r2, #0x200000                               
  00009b9c  002083e5      str      r2, [r3]                                    
  00009ba0  f90400ea      b        #0xaf8c                                     
  00009ba4  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ba8  0020a0e3      mov      r2, #0                                      
  00009bac  002083e5      str      r2, [r3]                                    
  00009bb0  10301be5      ldr      r3, [fp, #-0x10]                            
  00009bb4  0125a0e3      mov      r2, #0x400000                               
  00009bb8  002083e5      str      r2, [r3]                                    
  00009bbc  f20400ea      b        #0xaf8c                                     
  00009bc0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009bc4  0020a0e3      mov      r2, #0                                      
  00009bc8  002083e5      str      r2, [r3]                                    
  00009bcc  10301be5      ldr      r3, [fp, #-0x10]                            
  00009bd0  0225a0e3      mov      r2, #0x800000                               
  00009bd4  002083e5      str      r2, [r3]                                    
  00009bd8  eb0400ea      b        #0xaf8c                                     
  00009bdc  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009be0  0120a0e3      mov      r2, #1                                      
  00009be4  002083e5      str      r2, [r3]                                    
  00009be8  10301be5      ldr      r3, [fp, #-0x10]                            
  00009bec  0120a0e3      mov      r2, #1                                      
  00009bf0  002083e5      str      r2, [r3]                                    
  00009bf4  e40400ea      b        #0xaf8c                                     
  00009bf8  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009bfc  0120a0e3      mov      r2, #1                                      
  00009c00  002083e5      str      r2, [r3]                                    
  00009c04  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c08  0220a0e3      mov      r2, #2                                      
  00009c0c  002083e5      str      r2, [r3]                                    
  00009c10  dd0400ea      b        #0xaf8c                                     
  00009c14  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009c18  0120a0e3      mov      r2, #1                                      
  00009c1c  002083e5      str      r2, [r3]                                    
  00009c20  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c24  0420a0e3      mov      r2, #4                                      
  00009c28  002083e5      str      r2, [r3]                                    
  00009c2c  d60400ea      b        #0xaf8c                                     
  00009c30  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009c34  0120a0e3      mov      r2, #1                                      
  00009c38  002083e5      str      r2, [r3]                                    
  00009c3c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c40  0820a0e3      mov      r2, #8                                      
  00009c44  002083e5      str      r2, [r3]                                    
  00009c48  cf0400ea      b        #0xaf8c                                     
  00009c4c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009c50  0120a0e3      mov      r2, #1                                      
  00009c54  002083e5      str      r2, [r3]                                    
  00009c58  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c5c  1020a0e3      mov      r2, #0x10                                   
  00009c60  002083e5      str      r2, [r3]                                    
  00009c64  c80400ea      b        #0xaf8c                                     
  00009c68  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009c6c  0120a0e3      mov      r2, #1                                      
  00009c70  002083e5      str      r2, [r3]                                    
  00009c74  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c78  2020a0e3      mov      r2, #0x20                                   
  00009c7c  002083e5      str      r2, [r3]                                    
  00009c80  c10400ea      b        #0xaf8c                                     
  00009c84  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009c88  0120a0e3      mov      r2, #1                                      
  00009c8c  002083e5      str      r2, [r3]                                    
  00009c90  10301be5      ldr      r3, [fp, #-0x10]                            
  00009c94  4020a0e3      mov      r2, #0x40                                   
  00009c98  002083e5      str      r2, [r3]                                    
  00009c9c  ba0400ea      b        #0xaf8c                                     
  00009ca0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ca4  0120a0e3      mov      r2, #1                                      
  00009ca8  002083e5      str      r2, [r3]                                    
  00009cac  10301be5      ldr      r3, [fp, #-0x10]                            
  00009cb0  8020a0e3      mov      r2, #0x80                                   
  00009cb4  002083e5      str      r2, [r3]                                    
  00009cb8  b30400ea      b        #0xaf8c                                     
  00009cbc  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009cc0  0120a0e3      mov      r2, #1                                      
  00009cc4  002083e5      str      r2, [r3]                                    
  00009cc8  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ccc  0128a0e3      mov      r2, #0x10000                                
  00009cd0  002083e5      str      r2, [r3]                                    
  00009cd4  ac0400ea      b        #0xaf8c                                     
  00009cd8  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009cdc  0120a0e3      mov      r2, #1                                      
  00009ce0  002083e5      str      r2, [r3]                                    
  00009ce4  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ce8  0228a0e3      mov      r2, #0x20000                                
  00009cec  002083e5      str      r2, [r3]                                    
  00009cf0  a50400ea      b        #0xaf8c                                     
  00009cf4  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009cf8  0120a0e3      mov      r2, #1                                      
  00009cfc  002083e5      str      r2, [r3]                                    
  00009d00  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d04  0127a0e3      mov      r2, #0x40000                                
  00009d08  002083e5      str      r2, [r3]                                    
  00009d0c  9e0400ea      b        #0xaf8c                                     
  00009d10  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009d14  0120a0e3      mov      r2, #1                                      
  00009d18  002083e5      str      r2, [r3]                                    
  00009d1c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d20  0227a0e3      mov      r2, #0x80000                                
  00009d24  002083e5      str      r2, [r3]                                    
  00009d28  970400ea      b        #0xaf8c                                     
  00009d2c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009d30  0120a0e3      mov      r2, #1                                      
  00009d34  002083e5      str      r2, [r3]                                    
  00009d38  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d3c  0126a0e3      mov      r2, #0x100000                               
  00009d40  002083e5      str      r2, [r3]                                    
  00009d44  900400ea      b        #0xaf8c                                     
  00009d48  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009d4c  0120a0e3      mov      r2, #1                                      
  00009d50  002083e5      str      r2, [r3]                                    
  00009d54  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d58  0226a0e3      mov      r2, #0x200000                               
  00009d5c  002083e5      str      r2, [r3]                                    
  00009d60  890400ea      b        #0xaf8c                                     
  00009d64  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009d68  0120a0e3      mov      r2, #1                                      
  00009d6c  002083e5      str      r2, [r3]                                    
  00009d70  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d74  0125a0e3      mov      r2, #0x400000                               
  00009d78  002083e5      str      r2, [r3]                                    
  00009d7c  820400ea      b        #0xaf8c                                     
  00009d80  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009d84  0120a0e3      mov      r2, #1                                      
  00009d88  002083e5      str      r2, [r3]                                    
  00009d8c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009d90  0225a0e3      mov      r2, #0x800000                               
  00009d94  002083e5      str      r2, [r3]                                    
  00009d98  7b0400ea      b        #0xaf8c                                     
  00009d9c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009da0  0020a0e3      mov      r2, #0                                      
  00009da4  002083e5      str      r2, [r3]                                    
  00009da8  10301be5      ldr      r3, [fp, #-0x10]                            
  00009dac  0124a0e3      mov      r2, #0x1000000                              
  00009db0  002083e5      str      r2, [r3]                                    
  00009db4  740400ea      b        #0xaf8c                                     
  00009db8  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009dbc  0020a0e3      mov      r2, #0                                      
  00009dc0  002083e5      str      r2, [r3]                                    
  00009dc4  10301be5      ldr      r3, [fp, #-0x10]                            
  00009dc8  0224a0e3      mov      r2, #0x2000000                              
  00009dcc  002083e5      str      r2, [r3]                                    
  00009dd0  6d0400ea      b        #0xaf8c                                     
  00009dd4  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009dd8  0020a0e3      mov      r2, #0                                      
  00009ddc  002083e5      str      r2, [r3]                                    
  00009de0  10301be5      ldr      r3, [fp, #-0x10]                            
  00009de4  0123a0e3      mov      r2, #0x4000000                              
  00009de8  002083e5      str      r2, [r3]                                    
  00009dec  660400ea      b        #0xaf8c                                     
  00009df0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009df4  0020a0e3      mov      r2, #0                                      
  00009df8  002083e5      str      r2, [r3]                                    
  00009dfc  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e00  0223a0e3      mov      r2, #0x8000000                              
  00009e04  002083e5      str      r2, [r3]                                    
  00009e08  5f0400ea      b        #0xaf8c                                     
  00009e0c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e10  0020a0e3      mov      r2, #0                                      
  00009e14  002083e5      str      r2, [r3]                                    
  00009e18  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e1c  0122a0e3      mov      r2, #0x10000000                             
  00009e20  002083e5      str      r2, [r3]                                    
  00009e24  580400ea      b        #0xaf8c                                     
  00009e28  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e2c  0020a0e3      mov      r2, #0                                      
  00009e30  002083e5      str      r2, [r3]                                    
  00009e34  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e38  0222a0e3      mov      r2, #0x20000000                             
  00009e3c  002083e5      str      r2, [r3]                                    
  00009e40  510400ea      b        #0xaf8c                                     
  00009e44  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e48  0020a0e3      mov      r2, #0                                      
  00009e4c  002083e5      str      r2, [r3]                                    
  00009e50  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e54  0121a0e3      mov      r2, #0x40000000                             
  00009e58  002083e5      str      r2, [r3]                                    
  00009e5c  4a0400ea      b        #0xaf8c                                     
  00009e60  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e64  0020a0e3      mov      r2, #0                                      
  00009e68  002083e5      str      r2, [r3]                                    
  00009e6c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e70  0221a0e3      mov      r2, #0x80000000                             
  00009e74  002083e5      str      r2, [r3]                                    
  00009e78  430400ea      b        #0xaf8c                                     
  00009e7c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e80  0120a0e3      mov      r2, #1                                      
  00009e84  002083e5      str      r2, [r3]                                    
  00009e88  10301be5      ldr      r3, [fp, #-0x10]                            
  00009e8c  012ca0e3      mov      r2, #0x100                                  
  00009e90  002083e5      str      r2, [r3]                                    
  00009e94  3c0400ea      b        #0xaf8c                                     
  00009e98  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009e9c  0120a0e3      mov      r2, #1                                      
  00009ea0  002083e5      str      r2, [r3]                                    
  00009ea4  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ea8  022ca0e3      mov      r2, #0x200                                  
  00009eac  002083e5      str      r2, [r3]                                    
  00009eb0  350400ea      b        #0xaf8c                                     
  00009eb4  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009eb8  0120a0e3      mov      r2, #1                                      
  00009ebc  002083e5      str      r2, [r3]                                    
  00009ec0  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ec4  012ba0e3      mov      r2, #0x400                                  
  00009ec8  002083e5      str      r2, [r3]                                    
  00009ecc  2e0400ea      b        #0xaf8c                                     
  00009ed0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ed4  0120a0e3      mov      r2, #1                                      
  00009ed8  002083e5      str      r2, [r3]                                    
  00009edc  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ee0  022ba0e3      mov      r2, #0x800                                  
  00009ee4  002083e5      str      r2, [r3]                                    
  00009ee8  270400ea      b        #0xaf8c                                     
  00009eec  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009ef0  0120a0e3      mov      r2, #1                                      
  00009ef4  002083e5      str      r2, [r3]                                    
  00009ef8  10301be5      ldr      r3, [fp, #-0x10]                            
  00009efc  012aa0e3      mov      r2, #0x1000                                 
  00009f00  002083e5      str      r2, [r3]                                    
  00009f04  200400ea      b        #0xaf8c                                     
  00009f08  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f0c  0120a0e3      mov      r2, #1                                      
  00009f10  002083e5      str      r2, [r3]                                    
  00009f14  10301be5      ldr      r3, [fp, #-0x10]                            
  00009f18  022aa0e3      mov      r2, #0x2000                                 
  00009f1c  002083e5      str      r2, [r3]                                    
  00009f20  190400ea      b        #0xaf8c                                     
  00009f24  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f28  0120a0e3      mov      r2, #1                                      
  00009f2c  002083e5      str      r2, [r3]                                    
  00009f30  10301be5      ldr      r3, [fp, #-0x10]                            
  00009f34  0129a0e3      mov      r2, #0x4000                                 
  00009f38  002083e5      str      r2, [r3]                                    
  00009f3c  120400ea      b        #0xaf8c                                     
  00009f40  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f44  0120a0e3      mov      r2, #1                                      
  00009f48  002083e5      str      r2, [r3]                                    
  00009f4c  10301be5      ldr      r3, [fp, #-0x10]                            
  00009f50  0229a0e3      mov      r2, #0x8000                                 
  00009f54  002083e5      str      r2, [r3]                                    
  00009f58  0b0400ea      b        #0xaf8c                                     
  00009f5c  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f60  0120a0e3      mov      r2, #1                                      
  00009f64  002083e5      str      r2, [r3]                                    
  00009f68  10301be5      ldr      r3, [fp, #-0x10]                            
  00009f6c  0124a0e3      mov      r2, #0x1000000                              
  00009f70  002083e5      str      r2, [r3]                                    
  00009f74  040400ea      b        #0xaf8c                                     
  00009f78  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f7c  0120a0e3      mov      r2, #1                                      
  00009f80  002083e5      str      r2, [r3]                                    
  00009f84  10301be5      ldr      r3, [fp, #-0x10]                            
  00009f88  0224a0e3      mov      r2, #0x2000000                              
  00009f8c  002083e5      str      r2, [r3]                                    
  00009f90  fd0300ea      b        #0xaf8c                                     
  00009f94  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009f98  0120a0e3      mov      r2, #1                                      
  00009f9c  002083e5      str      r2, [r3]                                    
  00009fa0  10301be5      ldr      r3, [fp, #-0x10]                            
  00009fa4  0123a0e3      mov      r2, #0x4000000                              
  00009fa8  002083e5      str      r2, [r3]                                    
  00009fac  f60300ea      b        #0xaf8c                                     
  00009fb0  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009fb4  0120a0e3      mov      r2, #1                                      
  00009fb8  002083e5      str      r2, [r3]                                    
  00009fbc  10301be5      ldr      r3, [fp, #-0x10]                            
  00009fc0  0223a0e3      mov      r2, #0x8000000                              
  00009fc4  002083e5      str      r2, [r3]                                    
  00009fc8  ef0300ea      b        #0xaf8c                                     
  00009fcc  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009fd0  0120a0e3      mov      r2, #1                                      
  00009fd4  002083e5      str      r2, [r3]                                    
  00009fd8  10301be5      ldr      r3, [fp, #-0x10]                            
  00009fdc  0122a0e3      mov      r2, #0x10000000                             
  00009fe0  002083e5      str      r2, [r3]                                    
  00009fe4  e80300ea      b        #0xaf8c                                     
  00009fe8  0c301be5      ldr      r3, [fp, #-0xc]                             
  00009fec  0120a0e3      mov      r2, #1                                      
  00009ff0  002083e5      str      r2, [r3]                                    
  00009ff4  10301be5      ldr      r3, [fp, #-0x10]                            
  00009ff8  0222a0e3      mov      r2, #0x20000000                             
  00009ffc  002083e5      str      r2, [r3]                                    
  0000a000  e10300ea      b        #0xaf8c                                     
  0000a004  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a008  0120a0e3      mov      r2, #1                                      
  0000a00c  002083e5      str      r2, [r3]                                    
  0000a010  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a014  0121a0e3      mov      r2, #0x40000000                             
  0000a018  002083e5      str      r2, [r3]                                    
  0000a01c  da0300ea      b        #0xaf8c                                     
  0000a020  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a024  0120a0e3      mov      r2, #1                                      
  0000a028  002083e5      str      r2, [r3]                                    
  0000a02c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a030  0221a0e3      mov      r2, #0x80000000                             
  0000a034  002083e5      str      r2, [r3]                                    
  0000a038  d30300ea      b        #0xaf8c                                     
  0000a03c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a040  0020a0e3      mov      r2, #0                                      
  0000a044  002083e5      str      r2, [r3]                                    
  0000a048  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a04c  0120a0e3      mov      r2, #1                                      
  0000a050  002083e5      str      r2, [r3]                                    
  0000a054  cc0300ea      b        #0xaf8c                                     
  0000a058  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a05c  0020a0e3      mov      r2, #0                                      
  0000a060  002083e5      str      r2, [r3]                                    
  0000a064  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a068  0220a0e3      mov      r2, #2                                      
  0000a06c  002083e5      str      r2, [r3]                                    
  0000a070  c50300ea      b        #0xaf8c                                     
  0000a074  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a078  0020a0e3      mov      r2, #0                                      
  0000a07c  002083e5      str      r2, [r3]                                    
  0000a080  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a084  0420a0e3      mov      r2, #4                                      
  0000a088  002083e5      str      r2, [r3]                                    
  0000a08c  be0300ea      b        #0xaf8c                                     
  0000a090  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a094  0020a0e3      mov      r2, #0                                      
  0000a098  002083e5      str      r2, [r3]                                    
  0000a09c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a0a0  0820a0e3      mov      r2, #8                                      
  0000a0a4  002083e5      str      r2, [r3]                                    
  0000a0a8  b70300ea      b        #0xaf8c                                     
  0000a0ac  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a0b0  0020a0e3      mov      r2, #0                                      
  0000a0b4  002083e5      str      r2, [r3]                                    
  0000a0b8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a0bc  1020a0e3      mov      r2, #0x10                                   
  0000a0c0  002083e5      str      r2, [r3]                                    
  0000a0c4  b00300ea      b        #0xaf8c                                     
  0000a0c8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a0cc  0020a0e3      mov      r2, #0                                      
  0000a0d0  002083e5      str      r2, [r3]                                    
  0000a0d4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a0d8  2020a0e3      mov      r2, #0x20                                   
  0000a0dc  002083e5      str      r2, [r3]                                    
  0000a0e0  a90300ea      b        #0xaf8c                                     
  0000a0e4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a0e8  0020a0e3      mov      r2, #0                                      
  0000a0ec  002083e5      str      r2, [r3]                                    
  0000a0f0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a0f4  4020a0e3      mov      r2, #0x40                                   
  0000a0f8  002083e5      str      r2, [r3]                                    
  0000a0fc  a20300ea      b        #0xaf8c                                     
  0000a100  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a104  0020a0e3      mov      r2, #0                                      
  0000a108  002083e5      str      r2, [r3]                                    
  0000a10c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a110  8020a0e3      mov      r2, #0x80                                   
  0000a114  002083e5      str      r2, [r3]                                    
  0000a118  9b0300ea      b        #0xaf8c                                     
  0000a11c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a120  0020a0e3      mov      r2, #0                                      
  0000a124  002083e5      str      r2, [r3]                                    
  0000a128  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a12c  012ca0e3      mov      r2, #0x100                                  
  0000a130  002083e5      str      r2, [r3]                                    
  0000a134  940300ea      b        #0xaf8c                                     
  0000a138  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a13c  0020a0e3      mov      r2, #0                                      
  0000a140  002083e5      str      r2, [r3]                                    
  0000a144  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a148  022ca0e3      mov      r2, #0x200                                  
  0000a14c  002083e5      str      r2, [r3]                                    
  0000a150  8d0300ea      b        #0xaf8c                                     
  0000a154  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a158  0120a0e3      mov      r2, #1                                      
  0000a15c  002083e5      str      r2, [r3]                                    
  0000a160  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a164  1020a0e3      mov      r2, #0x10                                   
  0000a168  002083e5      str      r2, [r3]                                    
  0000a16c  860300ea      b        #0xaf8c                                     
  0000a170  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a174  0120a0e3      mov      r2, #1                                      
  0000a178  002083e5      str      r2, [r3]                                    
  0000a17c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a180  2020a0e3      mov      r2, #0x20                                   
  0000a184  002083e5      str      r2, [r3]                                    
  0000a188  7f0300ea      b        #0xaf8c                                     
  0000a18c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a190  0120a0e3      mov      r2, #1                                      
  0000a194  002083e5      str      r2, [r3]                                    
  0000a198  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a19c  4020a0e3      mov      r2, #0x40                                   
  0000a1a0  002083e5      str      r2, [r3]                                    
  0000a1a4  780300ea      b        #0xaf8c                                     
  0000a1a8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a1ac  0120a0e3      mov      r2, #1                                      
  0000a1b0  002083e5      str      r2, [r3]                                    
  0000a1b4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a1b8  8020a0e3      mov      r2, #0x80                                   
  0000a1bc  002083e5      str      r2, [r3]                                    
  0000a1c0  710300ea      b        #0xaf8c                                     
  0000a1c4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a1c8  0120a0e3      mov      r2, #1                                      
  0000a1cc  002083e5      str      r2, [r3]                                    
  0000a1d0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a1d4  012ca0e3      mov      r2, #0x100                                  
  0000a1d8  002083e5      str      r2, [r3]                                    
  0000a1dc  6a0300ea      b        #0xaf8c                                     
  0000a1e0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a1e4  0120a0e3      mov      r2, #1                                      
  0000a1e8  002083e5      str      r2, [r3]                                    
  0000a1ec  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a1f0  022ca0e3      mov      r2, #0x200                                  
  0000a1f4  002083e5      str      r2, [r3]                                    
  0000a1f8  630300ea      b        #0xaf8c                                     
  0000a1fc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a200  0120a0e3      mov      r2, #1                                      
  0000a204  002083e5      str      r2, [r3]                                    
  0000a208  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a20c  012ba0e3      mov      r2, #0x400                                  
  0000a210  002083e5      str      r2, [r3]                                    
  0000a214  5c0300ea      b        #0xaf8c                                     
  0000a218  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a21c  0120a0e3      mov      r2, #1                                      
  0000a220  002083e5      str      r2, [r3]                                    
  0000a224  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a228  022ba0e3      mov      r2, #0x800                                  
  0000a22c  002083e5      str      r2, [r3]                                    
  0000a230  550300ea      b        #0xaf8c                                     
  0000a234  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a238  0120a0e3      mov      r2, #1                                      
  0000a23c  002083e5      str      r2, [r3]                                    
  0000a240  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a244  012aa0e3      mov      r2, #0x1000                                 
  0000a248  002083e5      str      r2, [r3]                                    
  0000a24c  4e0300ea      b        #0xaf8c                                     
  0000a250  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a254  0120a0e3      mov      r2, #1                                      
  0000a258  002083e5      str      r2, [r3]                                    
  0000a25c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a260  022aa0e3      mov      r2, #0x2000                                 
  0000a264  002083e5      str      r2, [r3]                                    
  0000a268  470300ea      b        #0xaf8c                                     
  0000a26c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a270  0220a0e3      mov      r2, #2                                      
  0000a274  002083e5      str      r2, [r3]                                    
  0000a278  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a27c  012ca0e3      mov      r2, #0x100                                  
  0000a280  002083e5      str      r2, [r3]                                    
  0000a284  400300ea      b        #0xaf8c                                     
  0000a288  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a28c  0220a0e3      mov      r2, #2                                      
  0000a290  002083e5      str      r2, [r3]                                    
  0000a294  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a298  022ca0e3      mov      r2, #0x200                                  
  0000a29c  002083e5      str      r2, [r3]                                    
  0000a2a0  390300ea      b        #0xaf8c                                     
  0000a2a4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a2a8  0220a0e3      mov      r2, #2                                      
  0000a2ac  002083e5      str      r2, [r3]                                    
  0000a2b0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a2b4  012ba0e3      mov      r2, #0x400                                  
  0000a2b8  002083e5      str      r2, [r3]                                    
  0000a2bc  320300ea      b        #0xaf8c                                     
  0000a2c0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a2c4  0220a0e3      mov      r2, #2                                      
  0000a2c8  002083e5      str      r2, [r3]                                    
  0000a2cc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a2d0  022ba0e3      mov      r2, #0x800                                  
  0000a2d4  002083e5      str      r2, [r3]                                    
  0000a2d8  2b0300ea      b        #0xaf8c                                     
  0000a2dc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a2e0  0220a0e3      mov      r2, #2                                      
  0000a2e4  002083e5      str      r2, [r3]                                    
  0000a2e8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a2ec  012aa0e3      mov      r2, #0x1000                                 
  0000a2f0  002083e5      str      r2, [r3]                                    
  0000a2f4  240300ea      b        #0xaf8c                                     
  0000a2f8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a2fc  0220a0e3      mov      r2, #2                                      
  0000a300  002083e5      str      r2, [r3]                                    
  0000a304  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a308  022aa0e3      mov      r2, #0x2000                                 
  0000a30c  002083e5      str      r2, [r3]                                    
  0000a310  1d0300ea      b        #0xaf8c                                     
  0000a314  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a318  0220a0e3      mov      r2, #2                                      
  0000a31c  002083e5      str      r2, [r3]                                    
  0000a320  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a324  0129a0e3      mov      r2, #0x4000                                 
  0000a328  002083e5      str      r2, [r3]                                    
  0000a32c  160300ea      b        #0xaf8c                                     
  0000a330  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a334  0220a0e3      mov      r2, #2                                      
  0000a338  002083e5      str      r2, [r3]                                    
  0000a33c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a340  0229a0e3      mov      r2, #0x8000                                 
  0000a344  002083e5      str      r2, [r3]                                    
  0000a348  0f0300ea      b        #0xaf8c                                     
  0000a34c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a350  0220a0e3      mov      r2, #2                                      
  0000a354  002083e5      str      r2, [r3]                                    
  0000a358  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a35c  0128a0e3      mov      r2, #0x10000                                
  0000a360  002083e5      str      r2, [r3]                                    
  0000a364  080300ea      b        #0xaf8c                                     
  0000a368  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a36c  0220a0e3      mov      r2, #2                                      
  0000a370  002083e5      str      r2, [r3]                                    
  0000a374  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a378  0228a0e3      mov      r2, #0x20000                                
  0000a37c  002083e5      str      r2, [r3]                                    
  0000a380  010300ea      b        #0xaf8c                                     
  0000a384  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a388  0020a0e3      mov      r2, #0                                      
  0000a38c  002083e5      str      r2, [r3]                                    
  0000a390  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a394  012aa0e3      mov      r2, #0x1000                                 
  0000a398  002083e5      str      r2, [r3]                                    
  0000a39c  fa0200ea      b        #0xaf8c                                     
  0000a3a0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a3a4  0020a0e3      mov      r2, #0                                      
  0000a3a8  002083e5      str      r2, [r3]                                    
  0000a3ac  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a3b0  022aa0e3      mov      r2, #0x2000                                 
  0000a3b4  002083e5      str      r2, [r3]                                    
  0000a3b8  f30200ea      b        #0xaf8c                                     
  0000a3bc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a3c0  0020a0e3      mov      r2, #0                                      
  0000a3c4  002083e5      str      r2, [r3]                                    
  0000a3c8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a3cc  0129a0e3      mov      r2, #0x4000                                 
  0000a3d0  002083e5      str      r2, [r3]                                    
  0000a3d4  ec0200ea      b        #0xaf8c                                     
  0000a3d8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a3dc  0020a0e3      mov      r2, #0                                      
  0000a3e0  002083e5      str      r2, [r3]                                    
  0000a3e4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a3e8  0229a0e3      mov      r2, #0x8000                                 
  0000a3ec  002083e5      str      r2, [r3]                                    
  0000a3f0  e50200ea      b        #0xaf8c                                     
  0000a3f4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a3f8  0020a0e3      mov      r2, #0                                      
  0000a3fc  002083e5      str      r2, [r3]                                    
  0000a400  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a404  0128a0e3      mov      r2, #0x10000                                
  0000a408  002083e5      str      r2, [r3]                                    
  0000a40c  de0200ea      b        #0xaf8c                                     
  0000a410  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a414  0020a0e3      mov      r2, #0                                      
  0000a418  002083e5      str      r2, [r3]                                    
  0000a41c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a420  0228a0e3      mov      r2, #0x20000                                
  0000a424  002083e5      str      r2, [r3]                                    
  0000a428  d70200ea      b        #0xaf8c                                     
  0000a42c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a430  0020a0e3      mov      r2, #0                                      
  0000a434  002083e5      str      r2, [r3]                                    
  0000a438  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a43c  0127a0e3      mov      r2, #0x40000                                
  0000a440  002083e5      str      r2, [r3]                                    
  0000a444  d00200ea      b        #0xaf8c                                     
  0000a448  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a44c  0020a0e3      mov      r2, #0                                      
  0000a450  002083e5      str      r2, [r3]                                    
  0000a454  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a458  0227a0e3      mov      r2, #0x80000                                
  0000a45c  002083e5      str      r2, [r3]                                    
  0000a460  c90200ea      b        #0xaf8c                                     
  0000a464  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a468  0020a0e3      mov      r2, #0                                      
  0000a46c  002083e5      str      r2, [r3]                                    
  0000a470  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a474  0126a0e3      mov      r2, #0x100000                               
  0000a478  002083e5      str      r2, [r3]                                    
  0000a47c  c20200ea      b        #0xaf8c                                     
  0000a480  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a484  0020a0e3      mov      r2, #0                                      
  0000a488  002083e5      str      r2, [r3]                                    
  0000a48c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a490  0226a0e3      mov      r2, #0x200000                               
  0000a494  002083e5      str      r2, [r3]                                    
  0000a498  bb0200ea      b        #0xaf8c                                     
  0000a49c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a4a0  0120a0e3      mov      r2, #1                                      
  0000a4a4  002083e5      str      r2, [r3]                                    
  0000a4a8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a4ac  0128a0e3      mov      r2, #0x10000                                
  0000a4b0  002083e5      str      r2, [r3]                                    
  0000a4b4  b40200ea      b        #0xaf8c                                     
  0000a4b8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a4bc  0120a0e3      mov      r2, #1                                      
  0000a4c0  002083e5      str      r2, [r3]                                    
  0000a4c4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a4c8  0228a0e3      mov      r2, #0x20000                                
  0000a4cc  002083e5      str      r2, [r3]                                    
  0000a4d0  ad0200ea      b        #0xaf8c                                     
  0000a4d4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a4d8  0120a0e3      mov      r2, #1                                      
  0000a4dc  002083e5      str      r2, [r3]                                    
  0000a4e0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a4e4  0127a0e3      mov      r2, #0x40000                                
  0000a4e8  002083e5      str      r2, [r3]                                    
  0000a4ec  a60200ea      b        #0xaf8c                                     
  0000a4f0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a4f4  0120a0e3      mov      r2, #1                                      
  0000a4f8  002083e5      str      r2, [r3]                                    
  0000a4fc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a500  0227a0e3      mov      r2, #0x80000                                
  0000a504  002083e5      str      r2, [r3]                                    
  0000a508  9f0200ea      b        #0xaf8c                                     
  0000a50c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a510  0120a0e3      mov      r2, #1                                      
  0000a514  002083e5      str      r2, [r3]                                    
  0000a518  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a51c  0126a0e3      mov      r2, #0x100000                               
  0000a520  002083e5      str      r2, [r3]                                    
  0000a524  980200ea      b        #0xaf8c                                     
  0000a528  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a52c  0120a0e3      mov      r2, #1                                      
  0000a530  002083e5      str      r2, [r3]                                    
  0000a534  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a538  0226a0e3      mov      r2, #0x200000                               
  0000a53c  002083e5      str      r2, [r3]                                    
  0000a540  910200ea      b        #0xaf8c                                     
  0000a544  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a548  0120a0e3      mov      r2, #1                                      
  0000a54c  002083e5      str      r2, [r3]                                    
  0000a550  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a554  0125a0e3      mov      r2, #0x400000                               
  0000a558  002083e5      str      r2, [r3]                                    
  0000a55c  8a0200ea      b        #0xaf8c                                     
  0000a560  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a564  0120a0e3      mov      r2, #1                                      
  0000a568  002083e5      str      r2, [r3]                                    
  0000a56c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a570  0225a0e3      mov      r2, #0x800000                               
  0000a574  002083e5      str      r2, [r3]                                    
  0000a578  830200ea      b        #0xaf8c                                     
  0000a57c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a580  0120a0e3      mov      r2, #1                                      
  0000a584  002083e5      str      r2, [r3]                                    
  0000a588  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a58c  0124a0e3      mov      r2, #0x1000000                              
  0000a590  002083e5      str      r2, [r3]                                    
  0000a594  7c0200ea      b        #0xaf8c                                     
  0000a598  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a59c  0120a0e3      mov      r2, #1                                      
  0000a5a0  002083e5      str      r2, [r3]                                    
  0000a5a4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a5a8  0224a0e3      mov      r2, #0x2000000                              
  0000a5ac  002083e5      str      r2, [r3]                                    
  0000a5b0  750200ea      b        #0xaf8c                                     
  0000a5b4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a5b8  0220a0e3      mov      r2, #2                                      
  0000a5bc  002083e5      str      r2, [r3]                                    
  0000a5c0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a5c4  0126a0e3      mov      r2, #0x100000                               
  0000a5c8  002083e5      str      r2, [r3]                                    
  0000a5cc  6e0200ea      b        #0xaf8c                                     
  0000a5d0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a5d4  0220a0e3      mov      r2, #2                                      
  0000a5d8  002083e5      str      r2, [r3]                                    
  0000a5dc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a5e0  0226a0e3      mov      r2, #0x200000                               
  0000a5e4  002083e5      str      r2, [r3]                                    
  0000a5e8  670200ea      b        #0xaf8c                                     
  0000a5ec  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a5f0  0220a0e3      mov      r2, #2                                      
  0000a5f4  002083e5      str      r2, [r3]                                    
  0000a5f8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a5fc  0125a0e3      mov      r2, #0x400000                               
  0000a600  002083e5      str      r2, [r3]                                    
  0000a604  600200ea      b        #0xaf8c                                     
  0000a608  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a60c  0220a0e3      mov      r2, #2                                      
  0000a610  002083e5      str      r2, [r3]                                    
  0000a614  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a618  0225a0e3      mov      r2, #0x800000                               
  0000a61c  002083e5      str      r2, [r3]                                    
  0000a620  590200ea      b        #0xaf8c                                     
  0000a624  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a628  0220a0e3      mov      r2, #2                                      
  0000a62c  002083e5      str      r2, [r3]                                    
  0000a630  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a634  0124a0e3      mov      r2, #0x1000000                              
  0000a638  002083e5      str      r2, [r3]                                    
  0000a63c  520200ea      b        #0xaf8c                                     
  0000a640  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a644  0220a0e3      mov      r2, #2                                      
  0000a648  002083e5      str      r2, [r3]                                    
  0000a64c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a650  0224a0e3      mov      r2, #0x2000000                              
  0000a654  002083e5      str      r2, [r3]                                    
  0000a658  4b0200ea      b        #0xaf8c                                     
  0000a65c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a660  0220a0e3      mov      r2, #2                                      
  0000a664  002083e5      str      r2, [r3]                                    
  0000a668  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a66c  0123a0e3      mov      r2, #0x4000000                              
  0000a670  002083e5      str      r2, [r3]                                    
  0000a674  440200ea      b        #0xaf8c                                     
  0000a678  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a67c  0220a0e3      mov      r2, #2                                      
  0000a680  002083e5      str      r2, [r3]                                    
  0000a684  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a688  0223a0e3      mov      r2, #0x8000000                              
  0000a68c  002083e5      str      r2, [r3]                                    
  0000a690  3d0200ea      b        #0xaf8c                                     
  0000a694  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a698  0220a0e3      mov      r2, #2                                      
  0000a69c  002083e5      str      r2, [r3]                                    
  0000a6a0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a6a4  0122a0e3      mov      r2, #0x10000000                             
  0000a6a8  002083e5      str      r2, [r3]                                    
  0000a6ac  360200ea      b        #0xaf8c                                     
  0000a6b0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a6b4  0220a0e3      mov      r2, #2                                      
  0000a6b8  002083e5      str      r2, [r3]                                    
  0000a6bc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a6c0  0222a0e3      mov      r2, #0x20000000                             
  0000a6c4  002083e5      str      r2, [r3]                                    
  0000a6c8  2f0200ea      b        #0xaf8c                                     
  0000a6cc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a6d0  0020a0e3      mov      r2, #0                                      
  0000a6d4  002083e5      str      r2, [r3]                                    
  0000a6d8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a6dc  0124a0e3      mov      r2, #0x1000000                              
  0000a6e0  002083e5      str      r2, [r3]                                    
  0000a6e4  280200ea      b        #0xaf8c                                     
  0000a6e8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a6ec  0020a0e3      mov      r2, #0                                      
  0000a6f0  002083e5      str      r2, [r3]                                    
  0000a6f4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a6f8  0224a0e3      mov      r2, #0x2000000                              
  0000a6fc  002083e5      str      r2, [r3]                                    
  0000a700  210200ea      b        #0xaf8c                                     
  0000a704  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a708  0020a0e3      mov      r2, #0                                      
  0000a70c  002083e5      str      r2, [r3]                                    
  0000a710  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a714  0123a0e3      mov      r2, #0x4000000                              
  0000a718  002083e5      str      r2, [r3]                                    
  0000a71c  1a0200ea      b        #0xaf8c                                     
  0000a720  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a724  0020a0e3      mov      r2, #0                                      
  0000a728  002083e5      str      r2, [r3]                                    
  0000a72c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a730  0223a0e3      mov      r2, #0x8000000                              
  0000a734  002083e5      str      r2, [r3]                                    
  0000a738  130200ea      b        #0xaf8c                                     
  0000a73c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a740  0020a0e3      mov      r2, #0                                      
  0000a744  002083e5      str      r2, [r3]                                    
  0000a748  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a74c  0122a0e3      mov      r2, #0x10000000                             
  0000a750  002083e5      str      r2, [r3]                                    
  0000a754  0c0200ea      b        #0xaf8c                                     
  0000a758  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a75c  0020a0e3      mov      r2, #0                                      
  0000a760  002083e5      str      r2, [r3]                                    
  0000a764  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a768  0222a0e3      mov      r2, #0x20000000                             
  0000a76c  002083e5      str      r2, [r3]                                    
  0000a770  050200ea      b        #0xaf8c                                     
  0000a774  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a778  0020a0e3      mov      r2, #0                                      
  0000a77c  002083e5      str      r2, [r3]                                    
  0000a780  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a784  0121a0e3      mov      r2, #0x40000000                             
  0000a788  002083e5      str      r2, [r3]                                    
  0000a78c  fe0100ea      b        #0xaf8c                                     
  0000a790  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a794  0020a0e3      mov      r2, #0                                      
  0000a798  002083e5      str      r2, [r3]                                    
  0000a79c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a7a0  0221a0e3      mov      r2, #0x80000000                             
  0000a7a4  002083e5      str      r2, [r3]                                    
  0000a7a8  f70100ea      b        #0xaf8c                                     
  0000a7ac  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a7b0  0120a0e3      mov      r2, #1                                      
  0000a7b4  002083e5      str      r2, [r3]                                    
  0000a7b8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a7bc  0120a0e3      mov      r2, #1                                      
  0000a7c0  002083e5      str      r2, [r3]                                    
  0000a7c4  f00100ea      b        #0xaf8c                                     
  0000a7c8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a7cc  0120a0e3      mov      r2, #1                                      
  0000a7d0  002083e5      str      r2, [r3]                                    
  0000a7d4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a7d8  0220a0e3      mov      r2, #2                                      
  0000a7dc  002083e5      str      r2, [r3]                                    
  0000a7e0  e90100ea      b        #0xaf8c                                     
  0000a7e4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a7e8  0120a0e3      mov      r2, #1                                      
  0000a7ec  002083e5      str      r2, [r3]                                    
  0000a7f0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a7f4  0122a0e3      mov      r2, #0x10000000                             
  0000a7f8  002083e5      str      r2, [r3]                                    
  0000a7fc  e20100ea      b        #0xaf8c                                     
  0000a800  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a804  0120a0e3      mov      r2, #1                                      
  0000a808  002083e5      str      r2, [r3]                                    
  0000a80c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a810  0222a0e3      mov      r2, #0x20000000                             
  0000a814  002083e5      str      r2, [r3]                                    
  0000a818  db0100ea      b        #0xaf8c                                     
  0000a81c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a820  0120a0e3      mov      r2, #1                                      
  0000a824  002083e5      str      r2, [r3]                                    
  0000a828  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a82c  0121a0e3      mov      r2, #0x40000000                             
  0000a830  002083e5      str      r2, [r3]                                    
  0000a834  d40100ea      b        #0xaf8c                                     
  0000a838  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a83c  0120a0e3      mov      r2, #1                                      
  0000a840  002083e5      str      r2, [r3]                                    
  0000a844  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a848  0221a0e3      mov      r2, #0x80000000                             
  0000a84c  002083e5      str      r2, [r3]                                    
  0000a850  cd0100ea      b        #0xaf8c                                     
  0000a854  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a858  0220a0e3      mov      r2, #2                                      
  0000a85c  002083e5      str      r2, [r3]                                    
  0000a860  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a864  0120a0e3      mov      r2, #1                                      
  0000a868  002083e5      str      r2, [r3]                                    
  0000a86c  c60100ea      b        #0xaf8c                                     
  0000a870  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a874  0220a0e3      mov      r2, #2                                      
  0000a878  002083e5      str      r2, [r3]                                    
  0000a87c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a880  0220a0e3      mov      r2, #2                                      
  0000a884  002083e5      str      r2, [r3]                                    
  0000a888  bf0100ea      b        #0xaf8c                                     
  0000a88c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a890  0220a0e3      mov      r2, #2                                      
  0000a894  002083e5      str      r2, [r3]                                    
  0000a898  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a89c  0420a0e3      mov      r2, #4                                      
  0000a8a0  002083e5      str      r2, [r3]                                    
  0000a8a4  b80100ea      b        #0xaf8c                                     
  0000a8a8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a8ac  0220a0e3      mov      r2, #2                                      
  0000a8b0  002083e5      str      r2, [r3]                                    
  0000a8b4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a8b8  0820a0e3      mov      r2, #8                                      
  0000a8bc  002083e5      str      r2, [r3]                                    
  0000a8c0  b10100ea      b        #0xaf8c                                     
  0000a8c4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a8c8  0220a0e3      mov      r2, #2                                      
  0000a8cc  002083e5      str      r2, [r3]                                    
  0000a8d0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a8d4  1020a0e3      mov      r2, #0x10                                   
  0000a8d8  002083e5      str      r2, [r3]                                    
  0000a8dc  aa0100ea      b        #0xaf8c                                     
  0000a8e0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a8e4  0220a0e3      mov      r2, #2                                      
  0000a8e8  002083e5      str      r2, [r3]                                    
  0000a8ec  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a8f0  2020a0e3      mov      r2, #0x20                                   
  0000a8f4  002083e5      str      r2, [r3]                                    
  0000a8f8  a30100ea      b        #0xaf8c                                     
  0000a8fc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a900  0320a0e3      mov      r2, #3                                      
  0000a904  002083e5      str      r2, [r3]                                    
  0000a908  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a90c  0120a0e3      mov      r2, #1                                      
  0000a910  002083e5      str      r2, [r3]                                    
  0000a914  9c0100ea      b        #0xaf8c                                     
  0000a918  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a91c  0320a0e3      mov      r2, #3                                      
  0000a920  002083e5      str      r2, [r3]                                    
  0000a924  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a928  0220a0e3      mov      r2, #2                                      
  0000a92c  002083e5      str      r2, [r3]                                    
  0000a930  950100ea      b        #0xaf8c                                     
  0000a934  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a938  0320a0e3      mov      r2, #3                                      
  0000a93c  002083e5      str      r2, [r3]                                    
  0000a940  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a944  0420a0e3      mov      r2, #4                                      
  0000a948  002083e5      str      r2, [r3]                                    
  0000a94c  8e0100ea      b        #0xaf8c                                     
  0000a950  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a954  0320a0e3      mov      r2, #3                                      
  0000a958  002083e5      str      r2, [r3]                                    
  0000a95c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a960  0820a0e3      mov      r2, #8                                      
  0000a964  002083e5      str      r2, [r3]                                    
  0000a968  870100ea      b        #0xaf8c                                     
  0000a96c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a970  0320a0e3      mov      r2, #3                                      
  0000a974  002083e5      str      r2, [r3]                                    
  0000a978  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a97c  1020a0e3      mov      r2, #0x10                                   
  0000a980  002083e5      str      r2, [r3]                                    
  0000a984  800100ea      b        #0xaf8c                                     
  0000a988  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a98c  0320a0e3      mov      r2, #3                                      
  0000a990  002083e5      str      r2, [r3]                                    
  0000a994  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a998  2020a0e3      mov      r2, #0x20                                   
  0000a99c  002083e5      str      r2, [r3]                                    
  0000a9a0  790100ea      b        #0xaf8c                                     
  0000a9a4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a9a8  0320a0e3      mov      r2, #3                                      
  0000a9ac  002083e5      str      r2, [r3]                                    
  0000a9b0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a9b4  4020a0e3      mov      r2, #0x40                                   
  0000a9b8  002083e5      str      r2, [r3]                                    
  0000a9bc  720100ea      b        #0xaf8c                                     
  0000a9c0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a9c4  0320a0e3      mov      r2, #3                                      
  0000a9c8  002083e5      str      r2, [r3]                                    
  0000a9cc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a9d0  8020a0e3      mov      r2, #0x80                                   
  0000a9d4  002083e5      str      r2, [r3]                                    
  0000a9d8  6b0100ea      b        #0xaf8c                                     
  0000a9dc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a9e0  0320a0e3      mov      r2, #3                                      
  0000a9e4  002083e5      str      r2, [r3]                                    
  0000a9e8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000a9ec  012ca0e3      mov      r2, #0x100                                  
  0000a9f0  002083e5      str      r2, [r3]                                    
  0000a9f4  640100ea      b        #0xaf8c                                     
  0000a9f8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000a9fc  0320a0e3      mov      r2, #3                                      
  0000aa00  002083e5      str      r2, [r3]                                    
  0000aa04  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa08  022ca0e3      mov      r2, #0x200                                  
  0000aa0c  002083e5      str      r2, [r3]                                    
  0000aa10  5d0100ea      b        #0xaf8c                                     
  0000aa14  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aa18  0020a0e3      mov      r2, #0                                      
  0000aa1c  002083e5      str      r2, [r3]                                    
  0000aa20  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa24  0120a0e3      mov      r2, #1                                      
  0000aa28  002083e5      str      r2, [r3]                                    
  0000aa2c  560100ea      b        #0xaf8c                                     
  0000aa30  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aa34  0020a0e3      mov      r2, #0                                      
  0000aa38  002083e5      str      r2, [r3]                                    
  0000aa3c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa40  0220a0e3      mov      r2, #2                                      
  0000aa44  002083e5      str      r2, [r3]                                    
  0000aa48  4f0100ea      b        #0xaf8c                                     
  0000aa4c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aa50  0020a0e3      mov      r2, #0                                      
  0000aa54  002083e5      str      r2, [r3]                                    
  0000aa58  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa5c  0420a0e3      mov      r2, #4                                      
  0000aa60  002083e5      str      r2, [r3]                                    
  0000aa64  480100ea      b        #0xaf8c                                     
  0000aa68  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aa6c  0020a0e3      mov      r2, #0                                      
  0000aa70  002083e5      str      r2, [r3]                                    
  0000aa74  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa78  0820a0e3      mov      r2, #8                                      
  0000aa7c  002083e5      str      r2, [r3]                                    
  0000aa80  410100ea      b        #0xaf8c                                     
  0000aa84  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aa88  0020a0e3      mov      r2, #0                                      
  0000aa8c  002083e5      str      r2, [r3]                                    
  0000aa90  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aa94  1020a0e3      mov      r2, #0x10                                   
  0000aa98  002083e5      str      r2, [r3]                                    
  0000aa9c  3a0100ea      b        #0xaf8c                                     
  0000aaa0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aaa4  0020a0e3      mov      r2, #0                                      
  0000aaa8  002083e5      str      r2, [r3]                                    
  0000aaac  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aab0  2020a0e3      mov      r2, #0x20                                   
  0000aab4  002083e5      str      r2, [r3]                                    
  0000aab8  330100ea      b        #0xaf8c                                     
  0000aabc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aac0  0020a0e3      mov      r2, #0                                      
  0000aac4  002083e5      str      r2, [r3]                                    
  0000aac8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aacc  4020a0e3      mov      r2, #0x40                                   
  0000aad0  002083e5      str      r2, [r3]                                    
  0000aad4  2c0100ea      b        #0xaf8c                                     
  0000aad8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aadc  0020a0e3      mov      r2, #0                                      
  0000aae0  002083e5      str      r2, [r3]                                    
  0000aae4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aae8  8020a0e3      mov      r2, #0x80                                   
  0000aaec  002083e5      str      r2, [r3]                                    
  0000aaf0  250100ea      b        #0xaf8c                                     
  0000aaf4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aaf8  0020a0e3      mov      r2, #0                                      
  0000aafc  002083e5      str      r2, [r3]                                    
  0000ab00  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab04  012ca0e3      mov      r2, #0x100                                  
  0000ab08  002083e5      str      r2, [r3]                                    
  0000ab0c  1e0100ea      b        #0xaf8c                                     
  0000ab10  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ab14  0020a0e3      mov      r2, #0                                      
  0000ab18  002083e5      str      r2, [r3]                                    
  0000ab1c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab20  022ca0e3      mov      r2, #0x200                                  
  0000ab24  002083e5      str      r2, [r3]                                    
  0000ab28  170100ea      b        #0xaf8c                                     
  0000ab2c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ab30  0020a0e3      mov      r2, #0                                      
  0000ab34  002083e5      str      r2, [r3]                                    
  0000ab38  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab3c  012ba0e3      mov      r2, #0x400                                  
  0000ab40  002083e5      str      r2, [r3]                                    
  0000ab44  100100ea      b        #0xaf8c                                     
  0000ab48  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ab4c  0020a0e3      mov      r2, #0                                      
  0000ab50  002083e5      str      r2, [r3]                                    
  0000ab54  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab58  022ba0e3      mov      r2, #0x800                                  
  0000ab5c  002083e5      str      r2, [r3]                                    
  0000ab60  090100ea      b        #0xaf8c                                     
  0000ab64  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ab68  0020a0e3      mov      r2, #0                                      
  0000ab6c  002083e5      str      r2, [r3]                                    
  0000ab70  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab74  012aa0e3      mov      r2, #0x1000                                 
  0000ab78  002083e5      str      r2, [r3]                                    
  0000ab7c  020100ea      b        #0xaf8c                                     
  0000ab80  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ab84  0020a0e3      mov      r2, #0                                      
  0000ab88  002083e5      str      r2, [r3]                                    
  0000ab8c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ab90  022aa0e3      mov      r2, #0x2000                                 
  0000ab94  002083e5      str      r2, [r3]                                    
  0000ab98  fb0000ea      b        #0xaf8c                                     
  0000ab9c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aba0  0020a0e3      mov      r2, #0                                      
  0000aba4  002083e5      str      r2, [r3]                                    
  0000aba8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000abac  0129a0e3      mov      r2, #0x4000                                 
  0000abb0  002083e5      str      r2, [r3]                                    
  0000abb4  f40000ea      b        #0xaf8c                                     
  0000abb8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000abbc  0020a0e3      mov      r2, #0                                      
  0000abc0  002083e5      str      r2, [r3]                                    
  0000abc4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000abc8  0229a0e3      mov      r2, #0x8000                                 
  0000abcc  002083e5      str      r2, [r3]                                    
  0000abd0  ed0000ea      b        #0xaf8c                                     
  0000abd4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000abd8  0020a0e3      mov      r2, #0                                      
  0000abdc  002083e5      str      r2, [r3]                                    
  0000abe0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000abe4  0128a0e3      mov      r2, #0x10000                                
  0000abe8  002083e5      str      r2, [r3]                                    
  0000abec  e60000ea      b        #0xaf8c                                     
  0000abf0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000abf4  0020a0e3      mov      r2, #0                                      
  0000abf8  002083e5      str      r2, [r3]                                    
  0000abfc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac00  0228a0e3      mov      r2, #0x20000                                
  0000ac04  002083e5      str      r2, [r3]                                    
  0000ac08  df0000ea      b        #0xaf8c                                     
  0000ac0c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac10  0020a0e3      mov      r2, #0                                      
  0000ac14  002083e5      str      r2, [r3]                                    
  0000ac18  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac1c  0127a0e3      mov      r2, #0x40000                                
  0000ac20  002083e5      str      r2, [r3]                                    
  0000ac24  d80000ea      b        #0xaf8c                                     
  0000ac28  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac2c  0020a0e3      mov      r2, #0                                      
  0000ac30  002083e5      str      r2, [r3]                                    
  0000ac34  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac38  0227a0e3      mov      r2, #0x80000                                
  0000ac3c  002083e5      str      r2, [r3]                                    
  0000ac40  d10000ea      b        #0xaf8c                                     
  0000ac44  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac48  0020a0e3      mov      r2, #0                                      
  0000ac4c  002083e5      str      r2, [r3]                                    
  0000ac50  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac54  0126a0e3      mov      r2, #0x100000                               
  0000ac58  002083e5      str      r2, [r3]                                    
  0000ac5c  ca0000ea      b        #0xaf8c                                     
  0000ac60  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac64  0020a0e3      mov      r2, #0                                      
  0000ac68  002083e5      str      r2, [r3]                                    
  0000ac6c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac70  0226a0e3      mov      r2, #0x200000                               
  0000ac74  002083e5      str      r2, [r3]                                    
  0000ac78  c30000ea      b        #0xaf8c                                     
  0000ac7c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac80  0020a0e3      mov      r2, #0                                      
  0000ac84  002083e5      str      r2, [r3]                                    
  0000ac88  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ac8c  0125a0e3      mov      r2, #0x400000                               
  0000ac90  002083e5      str      r2, [r3]                                    
  0000ac94  bc0000ea      b        #0xaf8c                                     
  0000ac98  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ac9c  0020a0e3      mov      r2, #0                                      
  0000aca0  002083e5      str      r2, [r3]                                    
  0000aca4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aca8  0225a0e3      mov      r2, #0x800000                               
  0000acac  002083e5      str      r2, [r3]                                    
  0000acb0  b50000ea      b        #0xaf8c                                     
  0000acb4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000acb8  0020a0e3      mov      r2, #0                                      
  0000acbc  002083e5      str      r2, [r3]                                    
  0000acc0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000acc4  0124a0e3      mov      r2, #0x1000000                              
  0000acc8  002083e5      str      r2, [r3]                                    
  0000accc  ae0000ea      b        #0xaf8c                                     
  0000acd0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000acd4  0020a0e3      mov      r2, #0                                      
  0000acd8  002083e5      str      r2, [r3]                                    
  0000acdc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ace0  0224a0e3      mov      r2, #0x2000000                              
  0000ace4  002083e5      str      r2, [r3]                                    
  0000ace8  a70000ea      b        #0xaf8c                                     
  0000acec  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000acf0  0020a0e3      mov      r2, #0                                      
  0000acf4  002083e5      str      r2, [r3]                                    
  0000acf8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000acfc  0123a0e3      mov      r2, #0x4000000                              
  0000ad00  002083e5      str      r2, [r3]                                    
  0000ad04  a00000ea      b        #0xaf8c                                     
  0000ad08  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad0c  0020a0e3      mov      r2, #0                                      
  0000ad10  002083e5      str      r2, [r3]                                    
  0000ad14  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ad18  0223a0e3      mov      r2, #0x8000000                              
  0000ad1c  002083e5      str      r2, [r3]                                    
  0000ad20  990000ea      b        #0xaf8c                                     
  0000ad24  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad28  0020a0e3      mov      r2, #0                                      
  0000ad2c  002083e5      str      r2, [r3]                                    
  0000ad30  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ad34  0122a0e3      mov      r2, #0x10000000                             
  0000ad38  002083e5      str      r2, [r3]                                    
  0000ad3c  920000ea      b        #0xaf8c                                     
  0000ad40  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad44  0020a0e3      mov      r2, #0                                      
  0000ad48  002083e5      str      r2, [r3]                                    
  0000ad4c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ad50  0222a0e3      mov      r2, #0x20000000                             
  0000ad54  002083e5      str      r2, [r3]                                    
  0000ad58  8b0000ea      b        #0xaf8c                                     
  0000ad5c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad60  0720a0e3      mov      r2, #7                                      
  0000ad64  002083e5      str      r2, [r3]                                    
  0000ad68  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ad6c  0120a0e3      mov      r2, #1                                      
  0000ad70  002083e5      str      r2, [r3]                                    
  0000ad74  840000ea      b        #0xaf8c                                     
  0000ad78  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad7c  0720a0e3      mov      r2, #7                                      
  0000ad80  002083e5      str      r2, [r3]                                    
  0000ad84  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ad88  0220a0e3      mov      r2, #2                                      
  0000ad8c  002083e5      str      r2, [r3]                                    
  0000ad90  7d0000ea      b        #0xaf8c                                     
  0000ad94  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ad98  0720a0e3      mov      r2, #7                                      
  0000ad9c  002083e5      str      r2, [r3]                                    
  0000ada0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ada4  0420a0e3      mov      r2, #4                                      
  0000ada8  002083e5      str      r2, [r3]                                    
  0000adac  760000ea      b        #0xaf8c                                     
  0000adb0  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000adb4  0720a0e3      mov      r2, #7                                      
  0000adb8  002083e5      str      r2, [r3]                                    
  0000adbc  10301be5      ldr      r3, [fp, #-0x10]                            
  0000adc0  0820a0e3      mov      r2, #8                                      
  0000adc4  002083e5      str      r2, [r3]                                    
  0000adc8  6f0000ea      b        #0xaf8c                                     
  0000adcc  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000add0  0720a0e3      mov      r2, #7                                      
  0000add4  002083e5      str      r2, [r3]                                    
  0000add8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000addc  1020a0e3      mov      r2, #0x10                                   
  0000ade0  002083e5      str      r2, [r3]                                    
  0000ade4  680000ea      b        #0xaf8c                                     
  0000ade8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000adec  0720a0e3      mov      r2, #7                                      
  0000adf0  002083e5      str      r2, [r3]                                    
  0000adf4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000adf8  2020a0e3      mov      r2, #0x20                                   
  0000adfc  002083e5      str      r2, [r3]                                    
  0000ae00  610000ea      b        #0xaf8c                                     
  0000ae04  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae08  0720a0e3      mov      r2, #7                                      
  0000ae0c  002083e5      str      r2, [r3]                                    
  0000ae10  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ae14  4020a0e3      mov      r2, #0x40                                   
  0000ae18  002083e5      str      r2, [r3]                                    
  0000ae1c  5a0000ea      b        #0xaf8c                                     
  0000ae20  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae24  0720a0e3      mov      r2, #7                                      
  0000ae28  002083e5      str      r2, [r3]                                    
  0000ae2c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ae30  8020a0e3      mov      r2, #0x80                                   
  0000ae34  002083e5      str      r2, [r3]                                    
  0000ae38  530000ea      b        #0xaf8c                                     
  0000ae3c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae40  0720a0e3      mov      r2, #7                                      
  0000ae44  002083e5      str      r2, [r3]                                    
  0000ae48  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ae4c  012ca0e3      mov      r2, #0x100                                  
  0000ae50  002083e5      str      r2, [r3]                                    
  0000ae54  4c0000ea      b        #0xaf8c                                     
  0000ae58  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae5c  0720a0e3      mov      r2, #7                                      
  0000ae60  002083e5      str      r2, [r3]                                    
  0000ae64  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ae68  022ca0e3      mov      r2, #0x200                                  
  0000ae6c  002083e5      str      r2, [r3]                                    
  0000ae70  450000ea      b        #0xaf8c                                     
  0000ae74  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae78  0720a0e3      mov      r2, #7                                      
  0000ae7c  002083e5      str      r2, [r3]                                    
  0000ae80  10301be5      ldr      r3, [fp, #-0x10]                            
  0000ae84  012ba0e3      mov      r2, #0x400                                  
  0000ae88  002083e5      str      r2, [r3]                                    
  0000ae8c  3e0000ea      b        #0xaf8c                                     
  0000ae90  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000ae94  0720a0e3      mov      r2, #7                                      
  0000ae98  002083e5      str      r2, [r3]                                    
  0000ae9c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aea0  022ba0e3      mov      r2, #0x800                                  
  0000aea4  002083e5      str      r2, [r3]                                    
  0000aea8  370000ea      b        #0xaf8c                                     
  0000aeac  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aeb0  0720a0e3      mov      r2, #7                                      
  0000aeb4  002083e5      str      r2, [r3]                                    
  0000aeb8  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aebc  012aa0e3      mov      r2, #0x1000                                 
  0000aec0  002083e5      str      r2, [r3]                                    
  0000aec4  300000ea      b        #0xaf8c                                     
  0000aec8  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aecc  0720a0e3      mov      r2, #7                                      
  0000aed0  002083e5      str      r2, [r3]                                    
  0000aed4  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aed8  022aa0e3      mov      r2, #0x2000                                 
  0000aedc  002083e5      str      r2, [r3]                                    
  0000aee0  290000ea      b        #0xaf8c                                     
  0000aee4  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000aee8  0720a0e3      mov      r2, #7                                      
  0000aeec  002083e5      str      r2, [r3]                                    
  0000aef0  10301be5      ldr      r3, [fp, #-0x10]                            
  0000aef4  0129a0e3      mov      r2, #0x4000                                 
  0000aef8  002083e5      str      r2, [r3]                                    
  0000aefc  220000ea      b        #0xaf8c                                     
  0000af00  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000af04  0720a0e3      mov      r2, #7                                      
  0000af08  002083e5      str      r2, [r3]                                    
  0000af0c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000af10  0229a0e3      mov      r2, #0x8000                                 
  0000af14  002083e5      str      r2, [r3]                                    
  0000af18  1b0000ea      b        #0xaf8c                                     
  0000af1c  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000af20  0720a0e3      mov      r2, #7                                      
  0000af24  002083e5      str      r2, [r3]                                    
  0000af28  10301be5      ldr      r3, [fp, #-0x10]                            
  0000af2c  0128a0e3      mov      r2, #0x10000                                
  0000af30  002083e5      str      r2, [r3]                                    
  0000af34  140000ea      b        #0xaf8c                                     
  0000af38  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000af3c  0720a0e3      mov      r2, #7                                      
  0000af40  002083e5      str      r2, [r3]                                    
  0000af44  10301be5      ldr      r3, [fp, #-0x10]                            
  0000af48  0228a0e3      mov      r2, #0x20000                                
  0000af4c  002083e5      str      r2, [r3]                                    
  0000af50  0d0000ea      b        #0xaf8c                                     
  0000af54  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000af58  0720a0e3      mov      r2, #7                                      
  0000af5c  002083e5      str      r2, [r3]                                    
  0000af60  10301be5      ldr      r3, [fp, #-0x10]                            
  0000af64  0127a0e3      mov      r2, #0x40000                                
  0000af68  002083e5      str      r2, [r3]                                    
  0000af6c  060000ea      b        #0xaf8c                                     
  0000af70  0c301be5      ldr      r3, [fp, #-0xc]                             
  0000af74  0720a0e3      mov      r2, #7                                      
  0000af78  002083e5      str      r2, [r3]                                    
  0000af7c  10301be5      ldr      r3, [fp, #-0x10]                            
  0000af80  0227a0e3      mov      r2, #0x80000                                
  0000af84  002083e5      str      r2, [r3]                                    
  0000af88  0000a0e1      mov      r0, r0                                      
  0000af8c  04d04be2      sub      sp, fp, #4                                  
  0000af90  0088bde8      pop      {fp, pc}                                    
  0000af94  00482de9      push     {fp, lr}                                    
  0000af98  04b08de2      add      fp, sp, #4                                  
  0000af9c  10d04de2      sub      sp, sp, #0x10                               
  0000afa0  08000be5      str      r0, [fp, #-8]                               
  0000afa4  10200be5      str      r2, [fp, #-0x10]                            
  0000afa8  14300be5      str      r3, [fp, #-0x14]                            
  0000afac  0130a0e1      mov      r3, r1                                      
  0000afb0  09304be5      strb     r3, [fp, #-9]                               
  0000afb4  14304be2      sub      r3, fp, #0x14                               
  0000afb8  10001be5      ldr      r0, [fp, #-0x10]                            
  0000afbc  0310a0e1      mov      r1, r3                                      
  0000afc0  b0f8ffeb      bl       #0x9288                                       ; → addParameterToCommand
  0000afc4  04d04be2      sub      sp, fp, #4                                  
  0000afc8  0088bde8      pop      {fp, pc}                                    
  0000afcc  00482de9      push     {fp, lr}                                    
  0000afd0  04b08de2      add      fp, sp, #4                                  
  0000afd4  10d04de2      sub      sp, sp, #0x10                               
  0000afd8  08000be5      str      r0, [fp, #-8]                               
  0000afdc  0c100be5      str      r1, [fp, #-0xc]                             
  0000afe0  10200be5      str      r2, [fp, #-0x10]                            
  0000afe4  10304be2      sub      r3, fp, #0x10                               
  0000afe8  0c001be5      ldr      r0, [fp, #-0xc]                             
  0000afec  0310a0e1      mov      r1, r3                                      
  0000aff0  a4f8ffeb      bl       #0x9288                                       ; → addParameterToCommand
  0000aff4  04d04be2      sub      sp, fp, #4                                  
  0000aff8  0088bde8      pop      {fp, pc}                                    
  0000affc  00482de9      push     {fp, lr}                                    
  0000b000  04b08de2      add      fp, sp, #4                                  
  0000b004  10d04de2      sub      sp, sp, #0x10                               
  0000b008  08000be5      str      r0, [fp, #-8]                               
  0000b00c  0c100be5      str      r1, [fp, #-0xc]                             
  0000b010  10200be5      str      r2, [fp, #-0x10]                            
  0000b014  14300be5      str      r3, [fp, #-0x14]                            
  0000b018  0c001be5      ldr      r0, [fp, #-0xc]                             
  0000b01c  10101be5      ldr      r1, [fp, #-0x10]                            
  0000b020  98f8ffeb      bl       #0x9288                                       ; → addParameterToCommand
  0000b024  04d04be2      sub      sp, fp, #4                                  
  0000b028  0088bde8      pop      {fp, pc}                                    
  0000b02c  30482de9      push     {r4, r5, fp, lr}                            
  0000b030  0cb08de2      add      fp, sp, #0xc                                
  0000b034  4bdd4de2      sub      sp, sp, #0x12c0                             
  0000b038  10d04de2      sub      sp, sp, #0x10                               
  0000b03c  ac3d0ee3      movw     r3, #0xedac                                 
  0000b040  ff3f4fe3      movt     r3, #0xffff                                 
  0000b044  0c204be2      sub      r2, fp, #0xc                                
  0000b048  030082e7      str      r0, [r2, r3]                                
  0000b04c  a83d0ee3      movw     r3, #0xeda8                                 
  0000b050  ff3f4fe3      movt     r3, #0xffff                                 
  0000b054  0c504be2      sub      r5, fp, #0xc                                
  0000b058  031085e7      str      r1, [r5, r3]                                
  0000b05c  0030a0e3      mov      r3, #0                                      
  0000b060  a8380be5      str      r3, [fp, #-0x8a8]                           
  0000b064  0030a0e3      mov      r3, #0                                      
  0000b068  ac380be5      str      r3, [fp, #-0x8ac]                           
  0000b06c  0130a0e3      mov      r3, #1                                      
  0000b070  14300be5      str      r3, [fp, #-0x14]                            
  0000b074  0030a0e3      mov      r3, #0                                      
  0000b078  b0380be5      str      r3, [fp, #-0x8b0]                           
  0000b07c  0030a0e3      mov      r3, #0                                      
  0000b080  18300be5      str      r3, [fp, #-0x18]                            
  0000b084  0030a0e3      mov      r3, #0                                      
  0000b088  1c300be5      str      r3, [fp, #-0x1c]                            
  0000b08c  0030a0e3      mov      r3, #0                                      
  0000b090  20300be5      str      r3, [fp, #-0x20]                            
  0000b094  0030a0e3      mov      r3, #0                                      
  0000b098  24300be5      str      r3, [fp, #-0x24]                            
  0000b09c  0030a0e3      mov      r3, #0                                      
  0000b0a0  68300be5      str      r3, [fp, #-0x68]                            
  0000b0a4  0030a0e3      mov      r3, #0                                      
  0000b0a8  b8380be5      str      r3, [fp, #-0x8b8]                           
  0000b0ac  0130a0e3      mov      r3, #1                                      
  0000b0b0  28300be5      str      r3, [fp, #-0x28]                            
  0000b0b4  0030a0e3      mov      r3, #0                                      
  0000b0b8  2c300be5      str      r3, [fp, #-0x2c]                            
  0000b0bc  0030a0e3      mov      r3, #0                                      
  0000b0c0  30300be5      str      r3, [fp, #-0x30]                            
  0000b0c4  0030a0e3      mov      r3, #0                                      
  0000b0c8  6c300be5      str      r3, [fp, #-0x6c]                            
  0000b0cc  0130a0e3      mov      r3, #1                                      
  0000b0d0  34300be5      str      r3, [fp, #-0x34]                            
  0000b0d4  0030a0e3      mov      r3, #0                                      
  0000b0d8  38300be5      str      r3, [fp, #-0x38]                            
  0000b0dc  a83d0ee3      movw     r3, #0xeda8                                 
  0000b0e0  ff3f4fe3      movt     r3, #0xffff                                 
  0000b0e4  0c004be2      sub      r0, fp, #0xc                                
  0000b0e8  033090e7      ldr      r3, [r0, r3]                                
  0000b0ec  002093e5      ldr      r2, [r3]                                    
  0000b0f0  803803e3      movw     r3, #0x3880                                 
  0000b0f4  023040e3      movt     r3, #2                                      
  0000b0f8  002083e5      str      r2, [r3]                                    
  0000b0fc  893e4be2      sub      r3, fp, #0x890                              
  0000b100  0c3043e2      sub      r3, r3, #0xc                                
  0000b104  083043e2      sub      r3, r3, #8                                  
  0000b108  0300a0e1      mov      r0, r3                                      
  0000b10c  0010a0e3      mov      r1, #0                                      
  0000b110  082800e3      movw     r2, #0x808                                  
  0000b114  2ef8ffeb      bl       #0x91d4                                       ; → memset
  0000b118  ac3d0ee3      movw     r3, #0xedac                                 
  0000b11c  ff3f4fe3      movt     r3, #0xffff                                 
  0000b120  0c104be2      sub      r1, fp, #0xc                                
  0000b124  033091e7      ldr      r3, [r1, r3]                                
  0000b128  010053e3      cmp      r3, #1                                      
  0000b12c  0000001a      bne      #0xb134                                     
  0000b130  d8f8ffeb      bl       #0x9498                                     
  0000b134  9c304be2      sub      r3, fp, #0x9c                               
  0000b138  0300a0e1      mov      r0, r3                                      
  0000b13c  0010a0e3      mov      r1, #0                                      
  0000b140  1020a0e3      mov      r2, #0x10                                   
  0000b144  22f8ffeb      bl       #0x91d4                                       ; → memset
  0000b148  9c304be2      sub      r3, fp, #0x9c                               
  0000b14c  ec2406e3      movw     r2, #0x64ec                                 
  0000b150  012040e3      movt     r2, #1                                      
  0000b154  030092e8      ldm      r2, {r0, r1}                                
  0000b158  000083e5      str      r0, [r3]                                    
  0000b15c  043083e2      add      r3, r3, #4                                  
  0000b160  b010c3e1      strh     r1, [r3]                                    
  0000b164  26f8ffeb      bl       #0x9204                                       ; → addTLV2p0BinCmdParser
  0000b168  b9f7ffeb      bl       #0x9054                                       ; → addTLV2p0Encoder
  0000b16c  500f01e3      movw     r0, #0x1f50                                 
  0000b170  010040e3      movt     r0, #1                                      
  0000b174  d1f7ffeb      bl       #0x90c0                                       ; → registerTPCCALRSPHandler
  0000b178  580302e3      movw     r0, #0x2358                                 
  0000b17c  010040e3      movt     r0, #1                                      
  0000b180  f2f7ffeb      bl       #0x9150                                       ; → registerTPCCALDATAHandler
  0000b184  280502e3      movw     r0, #0x2528                                 
  0000b188  010040e3      movt     r0, #1                                      
  0000b18c  a7f7ffeb      bl       #0x9030                                       ; → registerREGREADRSPHandler
  0000b190  a40502e3      movw     r0, #0x25a4                                 
  0000b194  010040e3      movt     r0, #1                                      
  0000b198  e9f7ffeb      bl       #0x9144                                       ; → registerREGWRITERSPHandler
  0000b19c  040602e3      movw     r0, #0x2604                                 
  0000b1a0  010040e3      movt     r0, #1                                      
  0000b1a4  cef7ffeb      bl       #0x90e4                                       ; → registerBASICRSPHandler
  0000b1a8  480602e3      movw     r0, #0x2648                                 
  0000b1ac  010040e3      movt     r0, #1                                      
  0000b1b0  bcf7ffeb      bl       #0x90a8                                       ; → registerTXSTATUSRSPHandler
  0000b1b4  a40a02e3      movw     r0, #0x2aa4                                 
  0000b1b8  010040e3      movt     r0, #1                                      
  0000b1bc  ddf7ffeb      bl       #0x9138                                       ; → registerRXSTATUSRSPHandler
  0000b1c0  f40103e3      movw     r0, #0x31f4                                 
  0000b1c4  010040e3      movt     r0, #1                                      
  0000b1c8  cbf7ffeb      bl       #0x90fc                                       ; → registerRXRSPHandler
  0000b1cc  800302e3      movw     r0, #0x2380                                 
  0000b1d0  010040e3      movt     r0, #1                                      
  0000b1d4  adf7ffeb      bl       #0x9090                                       ; → registerMEMREADRSPHandler
  0000b1d8  dc0402e3      movw     r0, #0x24dc                                 
  0000b1dc  010040e3      movt     r0, #1                                      
  0000b1e0  d1f7ffeb      bl       #0x912c                                       ; → registerMEMWRITERSPHandler
  0000b1e4  e00002e3      movw     r0, #0x20e0                                 
  0000b1e8  010040e3      movt     r0, #1                                      
  0000b1ec  fef7ffeb      bl       #0x91ec                                       ; → registerLMGORSPHandler
  0000b1f0  000302e3      movw     r0, #0x2300                                 
  0000b1f4  010040e3      movt     r0, #1                                      
  0000b1f8  1cf8ffeb      bl       #0x9270                                       ; → registerLMQUERYRSPHandler
  0000b1fc  880102e3      movw     r0, #0x2188                                 
  0000b200  010040e3      movt     r0, #1                                      
  0000b204  86f7ffeb      bl       #0x9024                                       ; → registerLMTXINITRSPHandler
  0000b208  f00102e3      movw     r0, #0x21f0                                 
  0000b20c  010040e3      movt     r0, #1                                      
  0000b210  bcf7ffeb      bl       #0x9108                                       ; → registerLMRXINITRSPHandler
  0000b214  580202e3      movw     r0, #0x2258                                 
  0000b218  010040e3      movt     r0, #1                                      
  0000b21c  e0f7ffeb      bl       #0x91a4                                       ; → registerLMCHANNELLISTRSPHandler
  0000b220  0030a0e3      mov      r3, #0                                      
  0000b224  c03c0be5      str      r3, [fp, #-0xcc0]                           
  0000b228  ac2d0ee3      movw     r2, #0xedac                                 
  0000b22c  ff2f4fe3      movt     r2, #0xffff                                 
  0000b230  a83d0ee3      movw     r3, #0xeda8                                 
  0000b234  ff3f4fe3      movt     r3, #0xffff                                 
  0000b238  cb1e4be2      sub      r1, fp, #0xcb0                              
  0000b23c  0c1041e2      sub      r1, r1, #0xc                                
  0000b240  041041e2      sub      r1, r1, #4                                  
  0000b244  00108de5      str      r1, [sp]                                    
  0000b248  0c504be2      sub      r5, fp, #0xc                                
  0000b24c  020095e7      ldr      r0, [r5, r2]                                
  0000b250  0c204be2      sub      r2, fp, #0xc                                
  0000b254  031092e7      ldr      r1, [r2, r3]                                
  0000b258  f42406e3      movw     r2, #0x64f4                                 
  0000b25c  012040e3      movt     r2, #1                                      
  0000b260  743302e3      movw     r3, #0x2374                                 
  0000b264  023040e3      movt     r3, #2                                      
  0000b268  73f7ffeb      bl       #0x903c                                       ; → getopt_long
  0000b26c  70000be5      str      r0, [fp, #-0x70]                            
  0000b270  70301be5      ldr      r3, [fp, #-0x70]                            
  0000b274  010073e3      cmn      r3, #1                                      
  0000b278  6f13000a      beq      #0x1003c                                    
  0000b27c  70301be5      ldr      r3, [fp, #-0x70]                            
  0000b280  3f3043e2      sub      r3, r3, #0x3f                               
  0000b284  7e0f53e3      cmp      r3, #0x1f8                                  
  0000b288  03f19f97      ldrls    pc, [pc, r3, lsl #2]                        
  0000b28c  5e1300ea      b        #0x1000c                                    
  0000b290  14000100      andeq    r0, r1, r4, lsl r0                          
  0000b294  0c000100      andeq    r0, r1, ip                                  
  0000b298  e4dc0000      andeq    sp, r0, r4, ror #25                         
  0000b29c  f0de0000      strdeq   sp, lr, [r0], -r0                           
  0000b2a0  f0ce0000      strdeq   ip, sp, [r0], -r0                           
  0000b2a4  70d00000      andeq    sp, r0, r0, ror r0                          
  0000b2a8  48de0000      andeq    sp, r0, r8, asr #28                         
  0000b2ac  e8bc0000      andeq    fp, r0, r8, ror #25                         
  0000b2b0  40bd0000      andeq    fp, r0, r0, asr #26                         
  0000b2b4  14cd0000      andeq    ip, r0, r4, lsl sp                          
  0000b2b8  50cd0000      andeq    ip, r0, r0, asr sp                          
  0000b2bc  0c000100      andeq    r0, r1, ip                                  
  0000b2c0  78d20000      andeq    sp, r0, r8, ror r2                          
  0000b2c4  e8bc0000      andeq    fp, r0, r8, ror #25                         
  0000b2c8  c0be0000      andeq    fp, r0, r0, asr #29                         
  0000b2cc  20c60000      andeq    ip, r0, r0, lsr #12                         
  0000b2d0  0c000100      andeq    r0, r1, ip                                  
  0000b2d4  64bd0000      andeq    fp, r0, r4, ror #26                         
  0000b2d8  0c000100      andeq    r0, r1, ip                                  
  0000b2dc  58d40000      andeq    sp, r0, r8, asr r4                          
  0000b2e0  38dd0000      andeq    sp, r0, r8, lsr sp                          
  0000b2e4  0c000100      andeq    r0, r1, ip                                  
  0000b2e8  84db0000      andeq    sp, r0, r4, lsl #23                         
  0000b2ec  68d40000      andeq    sp, r0, r8, ror #8                          
  0000b2f0  0c000100      andeq    r0, r1, ip                                  
  0000b2f4  34da0000      andeq    sp, r0, r4, lsr sl                          
  0000b2f8  f4dc0000      strdeq   sp, lr, [r0], -r4                           
  0000b2fc  04dd0000      andeq    sp, r0, r4, lsl #26                         
  0000b300  0c000100      andeq    r0, r1, ip                                  
  0000b304  0c000100      andeq    r0, r1, ip                                  
  0000b308  0c000100      andeq    r0, r1, ip                                  
  0000b30c  0c000100      andeq    r0, r1, ip                                  
  0000b310  0c000100      andeq    r0, r1, ip                                  
  0000b314  0c000100      andeq    r0, r1, ip                                  
  0000b318  c0dc0000      andeq    sp, r0, r0, asr #25                         
  0000b31c  28cf0000      andeq    ip, r0, r8, lsr #30                         
  0000b320  b8ce0000      strheq   ip, [r0], -r8                               
  0000b324  c8cf0000      andeq    ip, r0, r8, asr #31                         
  0000b328  80ce0000      andeq    ip, r0, r0, lsl #29                         
  0000b32c  90bc0000      muleq    r0, r0, ip                                  
  0000b330  58c60000      andeq    ip, r0, r8, asr r6                          
  0000b334  14cd0000      andeq    ip, r0, r4, lsl sp                          
  0000b338  74ba0000      andeq    fp, r0, r4, ror sl                          
  0000b33c  f8cd0000      strdeq   ip, sp, [r0], -r8                           
  0000b340  40d20000      andeq    sp, r0, r0, asr #4                          
  0000b344  18d30000      andeq    sp, r0, r8, lsl r3                          
  0000b348  a4c40000      andeq    ip, r0, r4, lsr #9                          
  0000b34c  e8c50000      andeq    ip, r0, r8, ror #11                         
  0000b350  14dd0000      andeq    sp, r0, r4, lsl sp                          
  0000b354  90bc0000      muleq    r0, r0, ip                                  
  0000b358  f8cd0000      strdeq   ip, sp, [r0], -r8                           
  0000b35c  30d10000      andeq    sp, r0, r0, lsr r1                          
  0000b360  78d40000      andeq    sp, r0, r8, ror r4                          
  0000b364  d4ba0000      ldrdeq   fp, ip, [r0], -r4                           
  0000b368  34db0000      andeq    sp, r0, r4, lsr fp                          
  0000b36c  0c000100      andeq    r0, r1, ip                                  
  0000b370  24de0000      andeq    sp, r0, r4, lsr #28                         
  0000b374  28d30000      andeq    sp, r0, r8, lsr #6                          
  0000b378  0c000100      andeq    r0, r1, ip                                  
  0000b37c  3cce0000      andeq    ip, r0, ip, lsr lr                          
  0000b380  0c000100      andeq    r0, r1, ip                                  
  0000b384  0c000100      andeq    r0, r1, ip                                  
  0000b388  0c000100      andeq    r0, r1, ip                                  
  0000b38c  0c000100      andeq    r0, r1, ip                                  
  0000b390  0c000100      andeq    r0, r1, ip                                  
  0000b394  0c000100      andeq    r0, r1, ip                                  
  0000b398  0c000100      andeq    r0, r1, ip                                  
  0000b39c  0c000100      andeq    r0, r1, ip                                  
  0000b3a0  0c000100      andeq    r0, r1, ip                                  
  0000b3a4  0c000100      andeq    r0, r1, ip                                  
  0000b3a8  0c000100      andeq    r0, r1, ip                                  
  0000b3ac  0c000100      andeq    r0, r1, ip                                  
  0000b3b0  0c000100      andeq    r0, r1, ip                                  
  0000b3b4  0c000100      andeq    r0, r1, ip                                  
  0000b3b8  0c000100      andeq    r0, r1, ip                                  
  0000b3bc  0c000100      andeq    r0, r1, ip                                  
  0000b3c0  0c000100      andeq    r0, r1, ip                                  
  0000b3c4  0c000100      andeq    r0, r1, ip                                  
  0000b3c8  0c000100      andeq    r0, r1, ip                                  
  0000b3cc  0c000100      andeq    r0, r1, ip                                  
  0000b3d0  0c000100      andeq    r0, r1, ip                                  
  0000b3d4  0c000100      andeq    r0, r1, ip                                  
  0000b3d8  0c000100      andeq    r0, r1, ip                                  
  0000b3dc  0c000100      andeq    r0, r1, ip                                  
  0000b3e0  0c000100      andeq    r0, r1, ip                                  
  0000b3e4  0c000100      andeq    r0, r1, ip                                  
  0000b3e8  0c000100      andeq    r0, r1, ip                                  
  0000b3ec  0c000100      andeq    r0, r1, ip                                  
  0000b3f0  0c000100      andeq    r0, r1, ip                                  
  0000b3f4  0c000100      andeq    r0, r1, ip                                  
  0000b3f8  0c000100      andeq    r0, r1, ip                                  
  0000b3fc  0c000100      andeq    r0, r1, ip                                  
  0000b400  0c000100      andeq    r0, r1, ip                                  
  0000b404  0c000100      andeq    r0, r1, ip                                  
  0000b408  0c000100      andeq    r0, r1, ip                                  
  0000b40c  0c000100      andeq    r0, r1, ip                                  
  0000b410  0c000100      andeq    r0, r1, ip                                  
  0000b414  0c000100      andeq    r0, r1, ip                                  
  0000b418  0c000100      andeq    r0, r1, ip                                  
  0000b41c  0c000100      andeq    r0, r1, ip                                  
  0000b420  0c000100      andeq    r0, r1, ip                                  
  0000b424  0c000100      andeq    r0, r1, ip                                  
  0000b428  0c000100      andeq    r0, r1, ip                                  
  0000b42c  0c000100      andeq    r0, r1, ip                                  
  0000b430  0c000100      andeq    r0, r1, ip                                  
  0000b434  0c000100      andeq    r0, r1, ip                                  
  0000b438  0c000100      andeq    r0, r1, ip                                  
  0000b43c  0c000100      andeq    r0, r1, ip                                  
  0000b440  0c000100      andeq    r0, r1, ip                                  
  0000b444  0c000100      andeq    r0, r1, ip                                  
  0000b448  0c000100      andeq    r0, r1, ip                                  
  0000b44c  0c000100      andeq    r0, r1, ip                                  
  0000b450  0c000100      andeq    r0, r1, ip                                  
  0000b454  0c000100      andeq    r0, r1, ip                                  
  0000b458  0c000100      andeq    r0, r1, ip                                  
  0000b45c  0c000100      andeq    r0, r1, ip                                  
  0000b460  0c000100      andeq    r0, r1, ip                                  
  0000b464  0c000100      andeq    r0, r1, ip                                  
  0000b468  0c000100      andeq    r0, r1, ip                                  
  0000b46c  0c000100      andeq    r0, r1, ip                                  
  0000b470  0c000100      andeq    r0, r1, ip                                  
  0000b474  0c000100      andeq    r0, r1, ip                                  
  0000b478  0c000100      andeq    r0, r1, ip                                  
  0000b47c  0c000100      andeq    r0, r1, ip                                  
  0000b480  0c000100      andeq    r0, r1, ip                                  
  0000b484  0c000100      andeq    r0, r1, ip                                  
  0000b488  0c000100      andeq    r0, r1, ip                                  
  0000b48c  0c000100      andeq    r0, r1, ip                                  
  0000b490  0c000100      andeq    r0, r1, ip                                  
  0000b494  0c000100      andeq    r0, r1, ip                                  
  0000b498  0c000100      andeq    r0, r1, ip                                  
  0000b49c  0c000100      andeq    r0, r1, ip                                  
  0000b4a0  0c000100      andeq    r0, r1, ip                                  
  0000b4a4  0c000100      andeq    r0, r1, ip                                  
  0000b4a8  0c000100      andeq    r0, r1, ip                                  
  0000b4ac  0c000100      andeq    r0, r1, ip                                  
  0000b4b0  0c000100      andeq    r0, r1, ip                                  
  0000b4b4  0c000100      andeq    r0, r1, ip                                  
  0000b4b8  0c000100      andeq    r0, r1, ip                                  
  0000b4bc  0c000100      andeq    r0, r1, ip                                  
  0000b4c0  0c000100      andeq    r0, r1, ip                                  
  0000b4c4  0c000100      andeq    r0, r1, ip                                  
  0000b4c8  0c000100      andeq    r0, r1, ip                                  
  0000b4cc  0c000100      andeq    r0, r1, ip                                  
  0000b4d0  0c000100      andeq    r0, r1, ip                                  
  0000b4d4  0c000100      andeq    r0, r1, ip                                  
  0000b4d8  0c000100      andeq    r0, r1, ip                                  
  0000b4dc  0c000100      andeq    r0, r1, ip                                  
  0000b4e0  0c000100      andeq    r0, r1, ip                                  
  0000b4e4  0c000100      andeq    r0, r1, ip                                  
  0000b4e8  0c000100      andeq    r0, r1, ip                                  
  0000b4ec  0c000100      andeq    r0, r1, ip                                  
  0000b4f0  0c000100      andeq    r0, r1, ip                                  
  0000b4f4  0c000100      andeq    r0, r1, ip                                  
  0000b4f8  0c000100      andeq    r0, r1, ip                                  
  0000b4fc  0c000100      andeq    r0, r1, ip                                  
  0000b500  0c000100      andeq    r0, r1, ip                                  
  0000b504  0c000100      andeq    r0, r1, ip                                  
  0000b508  0c000100      andeq    r0, r1, ip                                  
  0000b50c  0c000100      andeq    r0, r1, ip                                  
  0000b510  0c000100      andeq    r0, r1, ip                                  
  0000b514  0c000100      andeq    r0, r1, ip                                  
  0000b518  0c000100      andeq    r0, r1, ip                                  
  0000b51c  0c000100      andeq    r0, r1, ip                                  
  0000b520  0c000100      andeq    r0, r1, ip                                  
  0000b524  0c000100      andeq    r0, r1, ip                                  
  0000b528  0c000100      andeq    r0, r1, ip                                  
  0000b52c  0c000100      andeq    r0, r1, ip                                  
  0000b530  0c000100      andeq    r0, r1, ip                                  
  0000b534  0c000100      andeq    r0, r1, ip                                  
  0000b538  0c000100      andeq    r0, r1, ip                                  
  0000b53c  0c000100      andeq    r0, r1, ip                                  
  0000b540  0c000100      andeq    r0, r1, ip                                  
  0000b544  0c000100      andeq    r0, r1, ip                                  
  0000b548  0c000100      andeq    r0, r1, ip                                  
  0000b54c  0c000100      andeq    r0, r1, ip                                  
  0000b550  0c000100      andeq    r0, r1, ip                                  
  0000b554  0c000100      andeq    r0, r1, ip                                  
  0000b558  0c000100      andeq    r0, r1, ip                                  
  0000b55c  0c000100      andeq    r0, r1, ip                                  
  0000b560  0c000100      andeq    r0, r1, ip                                  
  0000b564  0c000100      andeq    r0, r1, ip                                  
  0000b568  0c000100      andeq    r0, r1, ip                                  
  0000b56c  0c000100      andeq    r0, r1, ip                                  
  0000b570  0c000100      andeq    r0, r1, ip                                  
  0000b574  0c000100      andeq    r0, r1, ip                                  
  0000b578  0c000100      andeq    r0, r1, ip                                  
  0000b57c  0c000100      andeq    r0, r1, ip                                  
  0000b580  0c000100      andeq    r0, r1, ip                                  
  0000b584  0c000100      andeq    r0, r1, ip                                  
  0000b588  0c000100      andeq    r0, r1, ip                                  
  0000b58c  0c000100      andeq    r0, r1, ip                                  
  0000b590  0c000100      andeq    r0, r1, ip                                  
  0000b594  0c000100      andeq    r0, r1, ip                                  
  0000b598  0c000100      andeq    r0, r1, ip                                  
  0000b59c  0c000100      andeq    r0, r1, ip                                  
  0000b5a0  0c000100      andeq    r0, r1, ip                                  
  0000b5a4  0c000100      andeq    r0, r1, ip                                  
  0000b5a8  0c000100      andeq    r0, r1, ip                                  
  0000b5ac  0c000100      andeq    r0, r1, ip                                  
  0000b5b0  0c000100      andeq    r0, r1, ip                                  
  0000b5b4  0c000100      andeq    r0, r1, ip                                  
  0000b5b8  0c000100      andeq    r0, r1, ip                                  
  0000b5bc  0c000100      andeq    r0, r1, ip                                  
  0000b5c0  0c000100      andeq    r0, r1, ip                                  
  0000b5c4  0c000100      andeq    r0, r1, ip                                  
  0000b5c8  0c000100      andeq    r0, r1, ip                                  
  0000b5cc  0c000100      andeq    r0, r1, ip                                  
  0000b5d0  0c000100      andeq    r0, r1, ip                                  
  0000b5d4  0c000100      andeq    r0, r1, ip                                  
  0000b5d8  0c000100      andeq    r0, r1, ip                                  
  0000b5dc  0c000100      andeq    r0, r1, ip                                  
  0000b5e0  0c000100      andeq    r0, r1, ip                                  
  0000b5e4  0c000100      andeq    r0, r1, ip                                  
  0000b5e8  0c000100      andeq    r0, r1, ip                                  
  0000b5ec  0c000100      andeq    r0, r1, ip                                  
  0000b5f0  0c000100      andeq    r0, r1, ip                                  
  0000b5f4  0c000100      andeq    r0, r1, ip                                  
  0000b5f8  0c000100      andeq    r0, r1, ip                                  
  0000b5fc  0c000100      andeq    r0, r1, ip                                  
  0000b600  0c000100      andeq    r0, r1, ip                                  
  0000b604  0c000100      andeq    r0, r1, ip                                  
  0000b608  0c000100      andeq    r0, r1, ip                                  
  0000b60c  0c000100      andeq    r0, r1, ip                                  
  0000b610  0c000100      andeq    r0, r1, ip                                  
  0000b614  0c000100      andeq    r0, r1, ip                                  
  0000b618  0c000100      andeq    r0, r1, ip                                  
  0000b61c  0c000100      andeq    r0, r1, ip                                  
  0000b620  0c000100      andeq    r0, r1, ip                                  
  0000b624  0c000100      andeq    r0, r1, ip                                  
  0000b628  0c000100      andeq    r0, r1, ip                                  
  0000b62c  0c000100      andeq    r0, r1, ip                                  
  0000b630  0c000100      andeq    r0, r1, ip                                  
  0000b634  0c000100      andeq    r0, r1, ip                                  
  0000b638  0c000100      andeq    r0, r1, ip                                  
  0000b63c  0c000100      andeq    r0, r1, ip                                  
  0000b640  0c000100      andeq    r0, r1, ip                                  
  0000b644  0c000100      andeq    r0, r1, ip                                  
  0000b648  0c000100      andeq    r0, r1, ip                                  
  0000b64c  0c000100      andeq    r0, r1, ip                                  
  0000b650  0c000100      andeq    r0, r1, ip                                  
  0000b654  0c000100      andeq    r0, r1, ip                                  
  0000b658  0c000100      andeq    r0, r1, ip                                  
  0000b65c  0c000100      andeq    r0, r1, ip                                  
  0000b660  0c000100      andeq    r0, r1, ip                                  
  0000b664  0c000100      andeq    r0, r1, ip                                  
  0000b668  0c000100      andeq    r0, r1, ip                                  
  0000b66c  0c000100      andeq    r0, r1, ip                                  
  0000b670  0c000100      andeq    r0, r1, ip                                  
  0000b674  0c000100      andeq    r0, r1, ip                                  
  0000b678  0c000100      andeq    r0, r1, ip                                  
  0000b67c  0c000100      andeq    r0, r1, ip                                  
  0000b680  0c000100      andeq    r0, r1, ip                                  
  0000b684  0c000100      andeq    r0, r1, ip                                  
  0000b688  0c000100      andeq    r0, r1, ip                                  
  0000b68c  0c000100      andeq    r0, r1, ip                                  
  0000b690  0c000100      andeq    r0, r1, ip                                  
  0000b694  0c000100      andeq    r0, r1, ip                                  
  0000b698  0c000100      andeq    r0, r1, ip                                  
  0000b69c  0c000100      andeq    r0, r1, ip                                  
  0000b6a0  0c000100      andeq    r0, r1, ip                                  
  0000b6a4  0c000100      andeq    r0, r1, ip                                  
  0000b6a8  0c000100      andeq    r0, r1, ip                                  
  0000b6ac  0c000100      andeq    r0, r1, ip                                  
  0000b6b0  0c000100      andeq    r0, r1, ip                                  
  0000b6b4  0c000100      andeq    r0, r1, ip                                  
  0000b6b8  0c000100      andeq    r0, r1, ip                                  
  0000b6bc  0c000100      andeq    r0, r1, ip                                  
  0000b6c0  0c000100      andeq    r0, r1, ip                                  
  0000b6c4  0c000100      andeq    r0, r1, ip                                  
  0000b6c8  0c000100      andeq    r0, r1, ip                                  
  0000b6cc  0c000100      andeq    r0, r1, ip                                  
  0000b6d0  0c000100      andeq    r0, r1, ip                                  
  0000b6d4  0c000100      andeq    r0, r1, ip                                  
  0000b6d8  0c000100      andeq    r0, r1, ip                                  
  0000b6dc  0c000100      andeq    r0, r1, ip                                  
  0000b6e0  0c000100      andeq    r0, r1, ip                                  
  0000b6e4  0c000100      andeq    r0, r1, ip                                  
  0000b6e8  0c000100      andeq    r0, r1, ip                                  
  0000b6ec  0c000100      andeq    r0, r1, ip                                  
  0000b6f0  0c000100      andeq    r0, r1, ip                                  
  0000b6f4  0c000100      andeq    r0, r1, ip                                  
  0000b6f8  0c000100      andeq    r0, r1, ip                                  
  0000b6fc  0c000100      andeq    r0, r1, ip                                  
  0000b700  0c000100      andeq    r0, r1, ip                                  
  0000b704  0c000100      andeq    r0, r1, ip                                  
  0000b708  0c000100      andeq    r0, r1, ip                                  
  0000b70c  0c000100      andeq    r0, r1, ip                                  
  0000b710  0c000100      andeq    r0, r1, ip                                  
  0000b714  0c000100      andeq    r0, r1, ip                                  
  0000b718  0c000100      andeq    r0, r1, ip                                  
  0000b71c  0c000100      andeq    r0, r1, ip                                  
  0000b720  0c000100      andeq    r0, r1, ip                                  
  0000b724  0c000100      andeq    r0, r1, ip                                  
  0000b728  0c000100      andeq    r0, r1, ip                                  
  0000b72c  0c000100      andeq    r0, r1, ip                                  
  0000b730  0c000100      andeq    r0, r1, ip                                  
  0000b734  0c000100      andeq    r0, r1, ip                                  
  0000b738  0c000100      andeq    r0, r1, ip                                  
  0000b73c  0c000100      andeq    r0, r1, ip                                  
  0000b740  0c000100      andeq    r0, r1, ip                                  
  0000b744  0c000100      andeq    r0, r1, ip                                  
  0000b748  0c000100      andeq    r0, r1, ip                                  
  0000b74c  0c000100      andeq    r0, r1, ip                                  
  0000b750  0c000100      andeq    r0, r1, ip                                  
  0000b754  0c000100      andeq    r0, r1, ip                                  
  0000b758  0c000100      andeq    r0, r1, ip                                  
  0000b75c  0c000100      andeq    r0, r1, ip                                  
  0000b760  0c000100      andeq    r0, r1, ip                                  
  0000b764  0c000100      andeq    r0, r1, ip                                  
  0000b768  0c000100      andeq    r0, r1, ip                                  
  0000b76c  0c000100      andeq    r0, r1, ip                                  
  0000b770  0c000100      andeq    r0, r1, ip                                  
  0000b774  0c000100      andeq    r0, r1, ip                                  
  0000b778  0c000100      andeq    r0, r1, ip                                  
  0000b77c  0c000100      andeq    r0, r1, ip                                  
  0000b780  0c000100      andeq    r0, r1, ip                                  
  0000b784  0c000100      andeq    r0, r1, ip                                  
  0000b788  0c000100      andeq    r0, r1, ip                                  
  0000b78c  0c000100      andeq    r0, r1, ip                                  
  0000b790  0c000100      andeq    r0, r1, ip                                  
  0000b794  0c000100      andeq    r0, r1, ip                                  
  0000b798  0c000100      andeq    r0, r1, ip                                  
  0000b79c  0c000100      andeq    r0, r1, ip                                  
  0000b7a0  0c000100      andeq    r0, r1, ip                                  
  0000b7a4  0c000100      andeq    r0, r1, ip                                  
  0000b7a8  0c000100      andeq    r0, r1, ip                                  
  0000b7ac  0c000100      andeq    r0, r1, ip                                  
  0000b7b0  0c000100      andeq    r0, r1, ip                                  
  0000b7b4  0c000100      andeq    r0, r1, ip                                  
  0000b7b8  0c000100      andeq    r0, r1, ip                                  
  0000b7bc  0c000100      andeq    r0, r1, ip                                  
  0000b7c0  0c000100      andeq    r0, r1, ip                                  
  0000b7c4  0c000100      andeq    r0, r1, ip                                  
  0000b7c8  0c000100      andeq    r0, r1, ip                                  
  0000b7cc  0c000100      andeq    r0, r1, ip                                  
  0000b7d0  0c000100      andeq    r0, r1, ip                                  
  0000b7d4  0c000100      andeq    r0, r1, ip                                  
  0000b7d8  0c000100      andeq    r0, r1, ip                                  
  0000b7dc  0c000100      andeq    r0, r1, ip                                  
  0000b7e0  0c000100      andeq    r0, r1, ip                                  
  0000b7e4  0c000100      andeq    r0, r1, ip                                  
  0000b7e8  0c000100      andeq    r0, r1, ip                                  
  0000b7ec  0c000100      andeq    r0, r1, ip                                  
  0000b7f0  0c000100      andeq    r0, r1, ip                                  
  0000b7f4  0c000100      andeq    r0, r1, ip                                  
  0000b7f8  0c000100      andeq    r0, r1, ip                                  
  0000b7fc  0c000100      andeq    r0, r1, ip                                  
  0000b800  0c000100      andeq    r0, r1, ip                                  
  0000b804  0c000100      andeq    r0, r1, ip                                  
  0000b808  0c000100      andeq    r0, r1, ip                                  
  0000b80c  0c000100      andeq    r0, r1, ip                                  
  0000b810  0c000100      andeq    r0, r1, ip                                  
  0000b814  0c000100      andeq    r0, r1, ip                                  
  0000b818  0c000100      andeq    r0, r1, ip                                  
  0000b81c  0c000100      andeq    r0, r1, ip                                  
  0000b820  0c000100      andeq    r0, r1, ip                                  
  0000b824  0c000100      andeq    r0, r1, ip                                  
  0000b828  0c000100      andeq    r0, r1, ip                                  
  0000b82c  0c000100      andeq    r0, r1, ip                                  
  0000b830  0c000100      andeq    r0, r1, ip                                  
  0000b834  0c000100      andeq    r0, r1, ip                                  
  0000b838  0c000100      andeq    r0, r1, ip                                  
  0000b83c  0c000100      andeq    r0, r1, ip                                  
  0000b840  0c000100      andeq    r0, r1, ip                                  
  0000b844  0c000100      andeq    r0, r1, ip                                  
  0000b848  0c000100      andeq    r0, r1, ip                                  
  0000b84c  0c000100      andeq    r0, r1, ip                                  
  0000b850  0c000100      andeq    r0, r1, ip                                  
  0000b854  0c000100      andeq    r0, r1, ip                                  
  0000b858  0c000100      andeq    r0, r1, ip                                  
  0000b85c  0c000100      andeq    r0, r1, ip                                  
  0000b860  0c000100      andeq    r0, r1, ip                                  
  0000b864  0c000100      andeq    r0, r1, ip                                  
  0000b868  0c000100      andeq    r0, r1, ip                                  
  0000b86c  0c000100      andeq    r0, r1, ip                                  
  0000b870  0c000100      andeq    r0, r1, ip                                  
  0000b874  0c000100      andeq    r0, r1, ip                                  
  0000b878  0c000100      andeq    r0, r1, ip                                  
  0000b87c  0c000100      andeq    r0, r1, ip                                  
  0000b880  0c000100      andeq    r0, r1, ip                                  
  0000b884  0c000100      andeq    r0, r1, ip                                  
  0000b888  0c000100      andeq    r0, r1, ip                                  
  0000b88c  0c000100      andeq    r0, r1, ip                                  
  0000b890  0c000100      andeq    r0, r1, ip                                  
  0000b894  0c000100      andeq    r0, r1, ip                                  
  0000b898  0c000100      andeq    r0, r1, ip                                  
  0000b89c  0c000100      andeq    r0, r1, ip                                  
  0000b8a0  0c000100      andeq    r0, r1, ip                                  
  0000b8a4  0c000100      andeq    r0, r1, ip                                  
  0000b8a8  0c000100      andeq    r0, r1, ip                                  
  0000b8ac  0c000100      andeq    r0, r1, ip                                  
  0000b8b0  0c000100      andeq    r0, r1, ip                                  
  0000b8b4  0c000100      andeq    r0, r1, ip                                  
  0000b8b8  0c000100      andeq    r0, r1, ip                                  
  0000b8bc  0c000100      andeq    r0, r1, ip                                  
  0000b8c0  0c000100      andeq    r0, r1, ip                                  
  0000b8c4  0c000100      andeq    r0, r1, ip                                  
  0000b8c8  0c000100      andeq    r0, r1, ip                                  
  0000b8cc  0c000100      andeq    r0, r1, ip                                  
  0000b8d0  0c000100      andeq    r0, r1, ip                                  
  0000b8d4  0c000100      andeq    r0, r1, ip                                  
  0000b8d8  0c000100      andeq    r0, r1, ip                                  
  0000b8dc  0c000100      andeq    r0, r1, ip                                  
  0000b8e0  0c000100      andeq    r0, r1, ip                                  
  0000b8e4  0c000100      andeq    r0, r1, ip                                  
  0000b8e8  0c000100      andeq    r0, r1, ip                                  
  0000b8ec  0c000100      andeq    r0, r1, ip                                  
  0000b8f0  0c000100      andeq    r0, r1, ip                                  
  0000b8f4  0c000100      andeq    r0, r1, ip                                  
  0000b8f8  0c000100      andeq    r0, r1, ip                                  
  0000b8fc  0c000100      andeq    r0, r1, ip                                  
  0000b900  0c000100      andeq    r0, r1, ip                                  
  0000b904  0c000100      andeq    r0, r1, ip                                  
  0000b908  0c000100      andeq    r0, r1, ip                                  
  0000b90c  0c000100      andeq    r0, r1, ip                                  
  0000b910  0c000100      andeq    r0, r1, ip                                  
  0000b914  0c000100      andeq    r0, r1, ip                                  
  0000b918  0c000100      andeq    r0, r1, ip                                  
  0000b91c  0c000100      andeq    r0, r1, ip                                  
  0000b920  0c000100      andeq    r0, r1, ip                                  
  0000b924  0c000100      andeq    r0, r1, ip                                  
  0000b928  0c000100      andeq    r0, r1, ip                                  
  0000b92c  0c000100      andeq    r0, r1, ip                                  
  0000b930  0c000100      andeq    r0, r1, ip                                  
  0000b934  0c000100      andeq    r0, r1, ip                                  
  0000b938  0c000100      andeq    r0, r1, ip                                  
  0000b93c  0c000100      andeq    r0, r1, ip                                  
  0000b940  0c000100      andeq    r0, r1, ip                                  
  0000b944  0c000100      andeq    r0, r1, ip                                  
  0000b948  0c000100      andeq    r0, r1, ip                                  
  0000b94c  0c000100      andeq    r0, r1, ip                                  
  0000b950  0c000100      andeq    r0, r1, ip                                  
  0000b954  0c000100      andeq    r0, r1, ip                                  
  0000b958  0c000100      andeq    r0, r1, ip                                  
  0000b95c  0c000100      andeq    r0, r1, ip                                  
  0000b960  0c000100      andeq    r0, r1, ip                                  
  0000b964  0c000100      andeq    r0, r1, ip                                  
  0000b968  e0d20000      andeq    sp, r0, r0, ror #5                          
  0000b96c  78e10000      andeq    lr, r0, r8, ror r1                          
  0000b970  bce10000      strheq   lr, [r0], -ip                               
  0000b974  0c000100      andeq    r0, r1, ip                                  
  0000b978  14e10000      andeq    lr, r0, r4, lsl r1                          
  0000b97c  08e20000      andeq    lr, r0, r8, lsl #4                          
  0000b980  a0df0000      andeq    sp, r0, r0, lsr #31                         
  0000b984  b8e40000      strheq   lr, [r0], -r8                               
  0000b988  90df0000      muleq    r0, r0, pc                                  
  0000b98c  0c000100      andeq    r0, r1, ip                                  
  0000b990  a4cd0000      andeq    ip, r0, r4, lsr #27                         
  0000b994  40c50000      andeq    ip, r0, r0, asr #10                         
  0000b998  78c50000      andeq    ip, r0, r8, ror r5                          
  0000b99c  c0e90000      andeq    lr, r0, r0, asr #19                         
  0000b9a0  b0c50000      strheq   ip, [r0], -r0                               
  0000b9a4  00eb0000      andeq    lr, r0, r0, lsl #22                         
  0000b9a8  58eb0000      andeq    lr, r0, r8, asr fp                          
  0000b9ac  b8eb0000      strheq   lr, [r0], -r8                               
  0000b9b0  f4eb0000      strdeq   lr, pc, [r0], -r4                           
  0000b9b4  38ec0000      andeq    lr, r0, r8, lsr ip                          
  0000b9b8  eced0000      andeq    lr, r0, ip, ror #27                         
  0000b9bc  28e90000      andeq    lr, r0, r8, lsr #18                         
  0000b9c0  60ef0000      andeq    lr, r0, r0, ror #30                         
  0000b9c4  50f30000      andeq    pc, r0, r0, asr r3                          
  0000b9c8  50fc0000      andeq    pc, r0, r0, asr ip                          
  0000b9cc  20fd0000      andeq    pc, r0, r0, lsr #26                         
  0000b9d0  3cfd0000      andeq    pc, r0, ip, lsr sp                          
  0000b9d4  58fd0000      andeq    pc, r0, r8, asr sp                          
  0000b9d8  a4fd0000      andeq    pc, r0, r4, lsr #27                         
  0000b9dc  e8fd0000      andeq    pc, r0, r8, ror #27                         
  0000b9e0  24ff0000      andeq    pc, r0, r4, lsr #30                         
  0000b9e4  b4d80000      strheq   sp, [r0], -r4                               
  0000b9e8  78d50000      andeq    sp, r0, r8, ror r5                          
  0000b9ec  00d90000      andeq    sp, r0, r0, lsl #18                         
  0000b9f0  4cd90000      andeq    sp, r0, ip, asr #18                         
  0000b9f4  98d90000      muleq    r0, r8, sb                                  
  0000b9f8  e8d90000      andeq    sp, r0, r8, ror #19                         
  0000b9fc  0c000100      andeq    r0, r1, ip                                  
  0000ba00  0c000100      andeq    r0, r1, ip                                  
  0000ba04  0c000100      andeq    r0, r1, ip                                  
  0000ba08  0c000100      andeq    r0, r1, ip                                  
  0000ba0c  0c000100      andeq    r0, r1, ip                                  
  0000ba10  44ed0000      andeq    lr, r0, r4, asr #26                         
  0000ba14  98ed0000      muleq    r0, r8, sp                                  
  0000ba18  e8f20000      andeq    pc, r0, r8, ror #5                          