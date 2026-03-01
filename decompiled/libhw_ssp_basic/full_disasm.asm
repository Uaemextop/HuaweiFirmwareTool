# libhw_ssp_basic.so  –  Full ARM32 Disassembly
# Size:      751,728 bytes
# .text:     0x000214dc  size=499,492  (390 instructions)
# Exports:   2134
# PLT imps:  1592

  000214dc  0dc0a0e1      mov      ip, sp                                      
  000214e0  0230a0e1      mov      r3, r2                                      
  000214e4  10d82de9      push     {r4, fp, ip, lr, pc}                        
  000214e8  0040a0e1      mov      r4, r0                                      
  000214ec  14d04de2      sub      sp, sp, #0x14                               
  000214f0  2c009fe5      ldr      r0, [pc, #0x2c]                             
  000214f4  04b04ce2      sub      fp, ip, #4                                  
  000214f8  01e0a0e1      mov      lr, r1                                      
  000214fc  00c0a0e3      mov      ip, #0                                      
  00021500  00008fe0      add      r0, pc, r0                                  
  00021504  00c08de5      str      ip, [sp]                                    
  00021508  04c08de5      str      ip, [sp, #4]                                
  0002150c  0410a0e1      mov      r1, r4                                      
  00021510  08c08de5      str      ip, [sp, #8]                                
  00021514  0e20a0e1      mov      r2, lr                                      
  00021518  8afeffeb      bl       #0x20f48                                    
  0002151c  10d04be2      sub      sp, fp, #0x10                               
  00021520  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  00021524  82ea0700      andeq    lr, r7, r2, lsl #21                         

; ─── HW_OS_GetLastSocketErr @ 0x00021528 ───
  00021528  0dc0a0e1      mov      ip, sp                                      
  0002152c  00d82de9      push     {fp, ip, lr, pc}                            
  00021530  04b04ce2      sub      fp, ip, #4                                  
  00021534  f7fcffeb      bl       #0x20918                                    
  00021538  000090e5      ldr      r0, [r0]                                    
  0002153c  00a89de8      ldm      sp, {fp, sp, pc}                            

; ─── HW_OS_SetLastErr @ 0x00021540 ───
  00021540  0dc0a0e1      mov      ip, sp                                      
  00021544  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  00021548  04b04ce2      sub      fp, ip, #4                                  
  0002154c  0040a0e1      mov      r4, r0                                      
  00021550  f0fcffeb      bl       #0x20918                                    
  00021554  004080e5      str      r4, [r0]                                    
  00021558  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    

; ─── HW_OS_StrError @ 0x0002155c ───
  0002155c  92eeffea      b        #0x1cfac                                    

; ─── HW_OS_MemMallocD @ 0x00021560 ───
  00021560  003050e2      subs     r3, r0, #0                                  
  00021564  0dc0a0e1      mov      ip, sp                                      
  00021568  00d82de9      push     {fp, ip, lr, pc}                            
  0002156c  04b04ce2      sub      fp, ip, #4                                  
  00021570  10d04de2      sub      sp, sp, #0x10                               
  00021574  0300a011      movne    r0, r3                                      
  00021578  0900001a      bne      #0x215a4                                    
  0002157c  2c009fe5      ldr      r0, [pc, #0x2c]                             
  00021580  a810a0e3      mov      r1, #0xa8                                   
  00021584  00308de5      str      r3, [sp]                                    
  00021588  0020e0e3      mvn      r2, #0                                      
  0002158c  00008fe0      add      r0, pc, r0                                  
  00021590  04308de5      str      r3, [sp, #4]                                
  00021594  08308de5      str      r3, [sp, #8]                                
  00021598  6afeffeb      bl       #0x20f48                                    
  0002159c  0100a0e3      mov      r0, #1                                      
  000215a0  ffffffea      b        #0x215a4                                    
  000215a4  0cd04be2      sub      sp, fp, #0xc                                
  000215a8  00689de8      ldm      sp, {fp, sp, lr}                            
  000215ac  54f1ffea      b        #0x1db04                                    
  000215b0  6c9e0700      andeq    sb, r7, ip, ror #28                         

; ─── HW_OS_MemMallocSet @ 0x000215b4 ───
  000215b4  0dc0a0e1      mov      ip, sp                                      
  000215b8  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  000215bc  04b04ce2      sub      fp, ip, #4                                  
  000215c0  0040a0e1      mov      r4, r0                                      
  000215c4  4ef1ffeb      bl       #0x1db04                                    
  000215c8  005050e2      subs     r5, r0, #0                                  
  000215cc  0800000a      beq      #0x215f4                                    
  000215d0  0410a0e1      mov      r1, r4                                      
  000215d4  0020a0e3      mov      r2, #0                                      
  000215d8  0430a0e1      mov      r3, r4                                      
  000215dc  a4f2ffeb      bl       #0x1e074                                    
  000215e0  0500a0e1      mov      r0, r5                                      
  000215e4  0410a0e1      mov      r1, r4                                      
  000215e8  0020a0e3      mov      r2, #0                                      
  000215ec  0430a0e1      mov      r3, r4                                      
  000215f0  9ff2ffeb      bl       #0x1e074                                    
  000215f4  0500a0e1      mov      r0, r5                                      
  000215f8  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    

; ─── HW_OS_MemReallocD @ 0x000215fc ───
  000215fc  07f7ffea      b        #0x1f220                                    

; ─── HW_OS_OnlyMemFree @ 0x00021600 ───
  00021600  91ffffea      b        #0x2144c                                    

; ─── HW_OS_MemFreeD @ 0x00021604 ───
  00021604  90ffffea      b        #0x2144c                                    

; ─── HW_OS_MemCmp @ 0x00021608 ───
  00021608  67f7ffea      b        #0x1f3ac                                    

; ─── HW_OS_DropCaches @ 0x0002160c ───
  0002160c  0dc0a0e1      mov      ip, sp                                      
  00021610  00d82de9      push     {fp, ip, lr, pc}                            
  00021614  04b04ce2      sub      fp, ip, #4                                  
  00021618  18f1ffeb      bl       #0x1da80                                    
  0002161c  000050e3      cmp      r0, #0                                      
  00021620  10009f15      ldrne    r0, [pc, #0x10]                             
  00021624  00008f10      addne    r0, pc, r0                                  
  00021628  0c009f05      ldreq    r0, [pc, #0xc]                              
  0002162c  00008f00      addeq    r0, pc, r0                                  
  00021630  00689de8      ldm      sp, {fp, sp, lr}                            
  00021634  20fdffea      b        #0x20abc                                    
  00021638  ea9d0700      andeq    sb, r7, sl, ror #27                         
  0002163c  089e0700      andeq    sb, r7, r8, lsl #28                         

; ─── HW_OS_MsgGet @ 0x00021640 ───
  00021640  0dc0a0e1      mov      ip, sp                                      
  00021644  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  00021648  04b04ce2      sub      fp, ip, #4                                  
  0002164c  14d04de2      sub      sp, sp, #0x14                               
  00021650  0040a0e1      mov      r4, r0                                      
  00021654  0150a0e1      mov      r5, r1                                      
  00021658  15ffffeb      bl       #0x212b4                                    
  0002165c  006050e2      subs     r6, r0, #0                                  
  00021660  0b0000aa      bge      #0x21694                                    
  00021664  abfcffeb      bl       #0x20918                                    
  00021668  0020a0e3      mov      r2, #0                                      
  0002166c  00508de5      str      r5, [sp]                                    
  00021670  2510a0e3      mov      r1, #0x25                                   
  00021674  04208de5      str      r2, [sp, #4]                                
  00021678  08208de5      str      r2, [sp, #8]                                
  0002167c  0030a0e1      mov      r3, r0                                      
  00021680  18009fe5      ldr      r0, [pc, #0x18]                             
  00021684  002093e5      ldr      r2, [r3]                                    
  00021688  0430a0e1      mov      r3, r4                                      
  0002168c  00008fe0      add      r0, pc, r0                                  
  00021690  2cfeffeb      bl       #0x20f48                                    
  00021694  0600a0e1      mov      r0, r6                                      
  00021698  18d04be2      sub      sp, fp, #0x18                               
  0002169c  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  000216a0  ca9d0700      andeq    sb, r7, sl, asr #27                         

; ─── HW_OS_MsgCtl @ 0x000216a4 ───
  000216a4  0dc0a0e1      mov      ip, sp                                      
  000216a8  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  000216ac  04b04ce2      sub      fp, ip, #4                                  
  000216b0  10d04de2      sub      sp, sp, #0x10                               
  000216b4  0040a0e1      mov      r4, r0                                      
  000216b8  0160a0e1      mov      r6, r1                                      
  000216bc  0250a0e1      mov      r5, r2                                      
  000216c0  58f9ffeb      bl       #0x1fc28                                    
  000216c4  007050e2      subs     r7, r0, #0                                  
  000216c8  0b0000aa      bge      #0x216fc                                    
  000216cc  91fcffeb      bl       #0x20918                                    
  000216d0  0020a0e3      mov      r2, #0                                      
  000216d4  00608de5      str      r6, [sp]                                    
  000216d8  3d10a0e3      mov      r1, #0x3d                                   
  000216dc  04508de5      str      r5, [sp, #4]                                
  000216e0  08208de5      str      r2, [sp, #8]                                
  000216e4  0030a0e1      mov      r3, r0                                      
  000216e8  18009fe5      ldr      r0, [pc, #0x18]                             
  000216ec  002093e5      ldr      r2, [r3]                                    
  000216f0  0430a0e1      mov      r3, r4                                      
  000216f4  00008fe0      add      r0, pc, r0                                  
  000216f8  12feffeb      bl       #0x20f48                                    
  000216fc  0700a0e1      mov      r0, r7                                      
  00021700  1cd04be2      sub      sp, fp, #0x1c                               
  00021704  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  00021708  629d0700      andeq    sb, r7, r2, ror #26                         

; ─── HW_OS_MsgSnd @ 0x0002170c ───
  0002170c  0dc0a0e1      mov      ip, sp                                      
  00021710  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  00021714  04b04ce2      sub      fp, ip, #4                                  
  00021718  6cd04de2      sub      sp, sp, #0x6c                               
  0002171c  0040a0e1      mov      r4, r0                                      
  00021720  0180a0e1      mov      r8, r1                                      
  00021724  0260a0e1      mov      r6, r2                                      
  00021728  0370a0e1      mov      r7, r3                                      
  0002172c  93f7ffeb      bl       #0x1f580                                    
  00021730  005050e2      subs     r5, r0, #0                                  
  00021734  1d00000a      beq      #0x217b0                                    
  00021738  090000aa      bge      #0x21764                                    
  0002173c  75fcffeb      bl       #0x20918                                    
  00021740  00808de5      str      r8, [sp]                                    
  00021744  c0008de9      stmib    sp, {r6, r7}                                
  00021748  5810a0e3      mov      r1, #0x58                                   
  0002174c  0030a0e1      mov      r3, r0                                      
  00021750  64009fe5      ldr      r0, [pc, #0x64]                             
  00021754  002093e5      ldr      r2, [r3]                                    
  00021758  0430a0e1      mov      r3, r4                                      
  0002175c  00008fe0      add      r0, pc, r0                                  
  00021760  f8fdffeb      bl       #0x20f48                                    
  00021764  5810a0e3      mov      r1, #0x58                                   
  00021768  0020a0e3      mov      r2, #0                                      
  0002176c  0130a0e1      mov      r3, r1                                      
  00021770  7c004be2      sub      r0, fp, #0x7c                               
  00021774  3ef2ffeb      bl       #0x1e074                                    
  00021778  0210a0e3      mov      r1, #2                                      
  0002177c  7c204be2      sub      r2, fp, #0x7c                               
  00021780  0400a0e1      mov      r0, r4                                      
  00021784  6fedffeb      bl       #0x1cd48                                    
  00021788  35f3ffeb      bl       #0x1e464                                    
  0002178c  40201be5      ldr      r2, [fp, #-0x40]                            
  00021790  00608de5      str      r6, [sp]                                    
  00021794  0510a0e1      mov      r1, r5                                      
  00021798  04208de5      str      r2, [sp, #4]                                
  0002179c  0420a0e1      mov      r2, r4                                      
  000217a0  0030a0e1      mov      r3, r0                                      
  000217a4  14009fe5      ldr      r0, [pc, #0x14]                             
  000217a8  00008fe0      add      r0, pc, r0                                  
  000217ac  8bfdffeb      bl       #0x20de0                                    
  000217b0  0500a0e1      mov      r0, r5                                      
  000217b4  20d04be2      sub      sp, fp, #0x20                               
  000217b8  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  000217bc  fa9c0700      strdeq   sb, sl, [r7], -sl                           
  000217c0  c19c0700      andeq    sb, r7, r1, asr #25                         

; ─── HW_OS_MsgRcv @ 0x000217c4 ───
  000217c4  0dc0a0e1      mov      ip, sp                                      
  000217c8  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  000217cc  04b04ce2      sub      fp, ip, #4                                  
  000217d0  14d04de2      sub      sp, sp, #0x14                               
  000217d4  0060a0e1      mov      r6, r0                                      
  000217d8  01a0a0e1      mov      sl, r1                                      
  000217dc  04509be5      ldr      r5, [fp, #4]                                
  000217e0  0270a0e1      mov      r7, r2                                      
  000217e4  0380a0e1      mov      r8, r3                                      
  000217e8  029b05e2      and      sb, r5, #0x800                              
  000217ec  00508de5      str      r5, [sp]                                    
  000217f0  0600a0e1      mov      r0, r6                                      
  000217f4  0a10a0e1      mov      r1, sl                                      
  000217f8  0720a0e1      mov      r2, r7                                      
  000217fc  0830a0e1      mov      r3, r8                                      
  00021800  05f0ffeb      bl       #0x1d81c                                    
  00021804  000059e3      cmp      sb, #0                                      
  00021808  0040a0e1      mov      r4, r0                                      
  0002180c  0200000a      beq      #0x2181c                                    
  00021810  000050e3      cmp      r0, #0                                      
  00021814  120000aa      bge      #0x21864                                    
  00021818  050000ea      b        #0x21834                                    
  0002181c  000050e3      cmp      r0, #0                                      
  00021820  0f0000aa      bge      #0x21864                                    
  00021824  3bfcffeb      bl       #0x20918                                    
  00021828  003090e5      ldr      r3, [r0]                                    
  0002182c  040053e3      cmp      r3, #4                                      
  00021830  edffff0a      beq      #0x217ec                                    
  00021834  37fcffeb      bl       #0x20918                                    
  00021838  002090e5      ldr      r2, [r0]                                    
  0002183c  040052e3      cmp      r2, #4                                      
  00021840  0700000a      beq      #0x21864                                    
  00021844  24009fe5      ldr      r0, [pc, #0x24]                             
  00021848  8110a0e3      mov      r1, #0x81                                   
  0002184c  00808de5      str      r8, [sp]                                    
  00021850  0630a0e1      mov      r3, r6                                      
  00021854  04708de5      str      r7, [sp, #4]                                
  00021858  00008fe0      add      r0, pc, r0                                  
  0002185c  08508de5      str      r5, [sp, #8]                                
  00021860  b8fdffeb      bl       #0x20f48                                    
  00021864  0400a0e1      mov      r0, r4                                      
  00021868  28d04be2      sub      sp, fp, #0x28                               
  0002186c  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  00021870  fe9b0700      strdeq   sb, sl, [r7], -lr                           

; ─── HW_OS_SafeMsgRcv @ 0x00021874 ───
  00021874  e8efffea      b        #0x1d81c                                    
  00021878  0dc0a0e1      mov      ip, sp                                      
  0002187c  30d82de9      push     {r4, r5, fp, ip, lr, pc}                    
  00021880  0050a0e1      mov      r5, r0                                      
  00021884  10d04de2      sub      sp, sp, #0x10                               
  00021888  34009fe5      ldr      r0, [pc, #0x34]                             
  0002188c  04b04ce2      sub      fp, ip, #4                                  
  00021890  0140a0e1      mov      r4, r1                                      
  00021894  02e0a0e1      mov      lr, r2                                      
  00021898  00c0a0e3      mov      ip, #0                                      
  0002189c  00308de5      str      r3, [sp]                                    
  000218a0  04c08de5      str      ip, [sp, #4]                                
  000218a4  00008fe0      add      r0, pc, r0                                  
  000218a8  08c08de5      str      ip, [sp, #8]                                
  000218ac  0510a0e1      mov      r1, r5                                      
  000218b0  0420a0e1      mov      r2, r4                                      
  000218b4  0e30a0e1      mov      r3, lr                                      
  000218b8  a2fdffeb      bl       #0x20f48                                    
  000218bc  14d04be2      sub      sp, fp, #0x14                               
  000218c0  30a89de8      ldm      sp, {r4, r5, fp, sp, pc}                    
  000218c4  1b9c0700      andeq    sb, r7, fp, lsl ip                          
  000218c8  0dc0a0e1      mov      ip, sp                                      
  000218cc  0230a0e1      mov      r3, r2                                      
  000218d0  10d82de9      push     {r4, fp, ip, lr, pc}                        
  000218d4  0040a0e1      mov      r4, r0                                      
  000218d8  14d04de2      sub      sp, sp, #0x14                               
  000218dc  2c009fe5      ldr      r0, [pc, #0x2c]                             
  000218e0  04b04ce2      sub      fp, ip, #4                                  
  000218e4  01e0a0e1      mov      lr, r1                                      
  000218e8  00c0a0e3      mov      ip, #0                                      
  000218ec  00008fe0      add      r0, pc, r0                                  
  000218f0  00c08de5      str      ip, [sp]                                    
  000218f4  04c08de5      str      ip, [sp, #4]                                
  000218f8  0410a0e1      mov      r1, r4                                      
  000218fc  08c08de5      str      ip, [sp, #8]                                
  00021900  0e20a0e1      mov      r2, lr                                      
  00021904  8ffdffeb      bl       #0x20f48                                    
  00021908  10d04be2      sub      sp, fp, #0x10                               
  0002190c  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  00021910  d39b0700      ldrdeq   sb, sl, [r7], -r3                           
  00021914  0dc0a0e1      mov      ip, sp                                      
  00021918  0030a0e3      mov      r3, #0                                      
  0002191c  00d82de9      push     {fp, ip, lr, pc}                            
  00021920  04b04ce2      sub      fp, ip, #4                                  
  00021924  10d04de2      sub      sp, sp, #0x10                               
  00021928  00c0a0e1      mov      ip, r0                                      
  0002192c  20009fe5      ldr      r0, [pc, #0x20]                             
  00021930  0120a0e1      mov      r2, r1                                      
  00021934  00308de5      str      r3, [sp]                                    
  00021938  04308de5      str      r3, [sp, #4]                                
  0002193c  00008fe0      add      r0, pc, r0                                  
  00021940  08308de5      str      r3, [sp, #8]                                
  00021944  0c10a0e1      mov      r1, ip                                      
  00021948  7efdffeb      bl       #0x20f48                                    
  0002194c  0cd04be2      sub      sp, fp, #0xc                                
  00021950  00a89de8      ldm      sp, {fp, sp, pc}                            
  00021954  839b0700      andeq    sb, r7, r3, lsl #23                         

; ─── HW_OS_CheckPath @ 0x00021958 ───
  00021958  000050e3      cmp      r0, #0                                      
  0002195c  0dc0a0e1      mov      ip, sp                                      
  00021960  00d82de9      push     {fp, ip, lr, pc}                            
  00021964  04b04ce2      sub      fp, ip, #4                                  
  00021968  0100001a      bne      #0x21974                                    
  0002196c  0000e0e3      mvn      r0, #0                                      
  00021970  00a89de8      ldm      sp, {fp, sp, pc}                            
  00021974  10109fe5      ldr      r1, [pc, #0x10]                             
  00021978  01108fe0      add      r1, pc, r1                                  
  0002197c  a4f4ffeb      bl       #0x1ec14                                    
  00021980  000050e3      cmp      r0, #0                                      
  00021984  f8ffff1a      bne      #0x2196c                                    
  00021988  00a89de8      ldm      sp, {fp, sp, pc}                            
  0002198c  599b0700      andeq    sb, r7, sb, asr fp                          

; ─── HW_OS_CopyFile_Inner @ 0x00021990 ───
  00021990  0dc0a0e1      mov      ip, sp                                      
  00021994  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  00021998  04b04ce2      sub      fp, ip, #4                                  
  0002199c  4c419fe5      ldr      r4, [pc, #0x14c]                            
  000219a0  50d04de2      sub      sp, sp, #0x50                               
  000219a4  0050a0e1      mov      r5, r0                                      
  000219a8  04408fe0      add      r4, pc, r4                                  
  000219ac  0160a0e1      mov      r6, r1                                      
  000219b0  0400a0e1      mov      r0, r4                                      
  000219b4  78f1ffeb      bl       #0x1df9c                                    
  000219b8  0410a0e1      mov      r1, r4                                      
  000219bc  0020a0e1      mov      r2, r0                                      
  000219c0  0500a0e1      mov      r0, r5                                      
  000219c4  9df2ffeb      bl       #0x1e440                                    
  000219c8  000050e3      cmp      r0, #0                                      
  000219cc  ad010003      movweq   r0, #0x1ad                                  
  000219d0  0f00000a      beq      #0x21a14                                    
  000219d4  5010a0e3      mov      r1, #0x50                                   
  000219d8  0020a0e3      mov      r2, #0                                      
  000219dc  0130a0e1      mov      r3, r1                                      
  000219e0  6c004be2      sub      r0, fp, #0x6c                               
  000219e4  a2f1ffeb      bl       #0x1e074                                    
  000219e8  0500a0e1      mov      r0, r5                                      
  000219ec  6c104be2      sub      r1, fp, #0x6c                               
  000219f0  68efffeb      bl       #0x1d798                                    
  000219f4  004050e2      subs     r4, r0, #0                                  
  000219f8  6d0fa013      movne    r0, #0x1b4                                  
  000219fc  2200001a      bne      #0x21a8c                                    
  00021a00  58301be5      ldr      r3, [fp, #-0x58]                            
  00021a04  0f3a03e2      and      r3, r3, #0xf000                             
  00021a08  010953e3      cmp      r3, #0x4000                                 
  00021a0c  0400001a      bne      #0x21a24                                    
  00021a10  6e0fa0e3      mov      r0, #0x1b8                                  
  00021a14  d8109fe5      ldr      r1, [pc, #0xd8]                             
  00021a18  bdffffeb      bl       #0x21914                                    
  00021a1c  d0409fe5      ldr      r4, [pc, #0xd0]                             
  00021a20  2f0000ea      b        #0x21ae4                                    
  00021a24  0500a0e1      mov      r0, r5                                      
  00021a28  0410a0e1      mov      r1, r4                                      
  00021a2c  0420a0e1      mov      r2, r4                                      
  00021a30  ecf1ffeb      bl       #0x1e1e8                                    
  00021a34  005050e2      subs     r5, r0, #0                                  
  00021a38  060000aa      bge      #0x21a58                                    
  00021a3c  88f2ffeb      bl       #0x1e464                                    
  00021a40  0010a0e1      mov      r1, r0                                      
  00021a44  be0100e3      movw     r0, #0x1be                                  
  00021a48  b1ffffeb      bl       #0x21914                                    
  00021a4c  84f2ffeb      bl       #0x1e464                                    
  00021a50  0040a0e1      mov      r4, r0                                      
  00021a54  220000ea      b        #0x21ae4                                    
  00021a58  0600a0e1      mov      r0, r6                                      
  00021a5c  2bf0ffeb      bl       #0x1db10                                    
  00021a60  0600a0e1      mov      r0, r6                                      
  00021a64  4110a0e3      mov      r1, #0x41                                   
  00021a68  58201be5      ldr      r2, [fp, #-0x58]                            
  00021a6c  ddf1ffeb      bl       #0x1e1e8                                    
  00021a70  007050e2      subs     r7, r0, #0                                  
  00021a74  070000aa      bge      #0x21a98                                    
  00021a78  0500a0e1      mov      r0, r5                                      
  00021a7c  49fdffeb      bl       #0x20fa8                                    
  00021a80  77f2ffeb      bl       #0x1e464                                    
  00021a84  0040a0e1      mov      r4, r0                                      
  00021a88  c70100e3      movw     r0, #0x1c7                                  
  00021a8c  0410a0e1      mov      r1, r4                                      
  00021a90  9fffffeb      bl       #0x21914                                    
  00021a94  120000ea      b        #0x21ae4                                    
  00021a98  48301be5      ldr      r3, [fp, #-0x48]                            
  00021a9c  0510a0e1      mov      r1, r5                                      
  00021aa0  0420a0e1      mov      r2, r4                                      
  00021aa4  40f3ffeb      bl       #0x1e7ac                                    
  00021aa8  0060a0e1      mov      r6, r0                                      
  00021aac  0500a0e1      mov      r0, r5                                      
  00021ab0  3cfdffeb      bl       #0x20fa8                                    
  00021ab4  0700a0e1      mov      r0, r7                                      
  00021ab8  3afdffeb      bl       #0x20fa8                                    
  00021abc  48301be5      ldr      r3, [fp, #-0x48]                            
  00021ac0  030056e1      cmp      r6, r3                                      
  00021ac4  0600000a      beq      #0x21ae4                                    
  00021ac8  65f2ffeb      bl       #0x1e464                                    
  00021acc  48201be5      ldr      r2, [fp, #-0x48]                            
  00021ad0  0630a0e1      mov      r3, r6                                      
  00021ad4  0040a0e1      mov      r4, r0                                      
  00021ad8  d10100e3      movw     r0, #0x1d1                                  
  00021adc  0410a0e1      mov      r1, r4                                      
  00021ae0  64ffffeb      bl       #0x21878                                    
  00021ae4  0400a0e1      mov      r0, r4                                      
  00021ae8  1cd04be2      sub      sp, fp, #0x1c                               
  00021aec  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  00021af0  2d9b0700      andeq    sb, r7, sp, lsr #22                         