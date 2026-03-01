# cfgtool  –  Full ARM32 Disassembly
# Size:      14,104 bytes
# .text:     0x00000fbc  size=4,340  (347 instructions)
# Exports:   28
# PLT imps:  33


; ─── main @ 0x00000fbc ───
  00000fbc  0dc0a0e1      mov      ip, sp                                      
  00000fc0  012ca0e3      mov      r2, #0x100                                  
  00000fc4  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  00000fc8  04b04ce2      sub      fp, ip, #4                                  
  00000fcc  8bdf4de2      sub      sp, sp, #0x22c                              
  00000fd0  0070a0e1      mov      r7, r0                                      
  00000fd4  0160a0e1      mov      r6, r1                                      
  00000fd8  890f4be2      sub      r0, fp, #0x224                              
  00000fdc  0010a0e3      mov      r1, #0                                      
  00000fe0  b0ffffeb      bl       #0xea8                                      
  00000fe4  0040a0e3      mov      r4, #0                                      
  00000fe8  0010a0e3      mov      r1, #0                                      
  00000fec  012ca0e3      mov      r2, #0x100                                  
  00000ff0  490f4be2      sub      r0, fp, #0x124                              
  00000ff4  abffffeb      bl       #0xea8                                      
  00000ff8  230e4be2      sub      r0, fp, #0x230                              
  00000ffc  0410a0e1      mov      r1, r4                                      
  00001000  0c20a0e3      mov      r2, #0xc                                    
  00001004  3c420be5      str      r4, [fp, #-0x23c]                           
  00001008  38420be5      str      r4, [fp, #-0x238]                           
  0000100c  34420be5      str      r4, [fp, #-0x234]                           
  00001010  a4ffffeb      bl       #0xea8                                      
  00001014  043047e2      sub      r3, r7, #4                                  
  00001018  030053e3      cmp      r3, #3                                      
  0000101c  0700009a      bls      #0x1040                                     
  00001020  130100eb      bl       #0x1474                                       ; → HW_CFGTOOL_ShowUsage
  00001024  24029fe5      ldr      r0, [pc, #0x224]                            
  00001028  00408de5      str      r4, [sp]                                    
  0000102c  671300e3      movw     r1, #0x367                                  
  00001030  04408de5      str      r4, [sp, #4]                                
  00001034  00008fe0      add      r0, pc, r0                                  
  00001038  08408de5      str      r4, [sp, #8]                                
  0000103c  1c0000ea      b        #0x10b4                                     
  00001040  080096e5      ldr      r0, [r6, #8]                                
  00001044  891f4be2      sub      r1, fp, #0x224                              
  00001048  3b0100eb      bl       #0x153c                                       ; → HW_CFGTOOL_GetOptFile
  0000104c  011ca0e3      mov      r1, #0x100                                  
  00001050  0c2096e5      ldr      r2, [r6, #0xc]                              
  00001054  ff30a0e3      mov      r3, #0xff                                   
  00001058  490f4be2      sub      r0, fp, #0x124                              
  0000105c  73ffffeb      bl       #0xe30                                      
  00001060  040096e5      ldr      r0, [r6, #4]                                
  00001064  4b0100eb      bl       #0x1598                                       ; → HW_CFGTOOL_GetOptType
  00001068  0050a0e1      mov      r5, r0                                      
  0000106c  050055e3      cmp      r5, #5                                      
  00001070  890f4be2      sub      r0, fp, #0x224                              
  00001074  0300001a      bne      #0x1088                                     
  00001078  491f4be2      sub      r1, fp, #0x124                              
  0000107c  6d0100eb      bl       #0x1638                                       ; → HW_CFGTOOL_XmlCreate
  00001080  3c020be5      str      r0, [fp, #-0x23c]                           
  00001084  0f0000ea      b        #0x10c8                                     
  00001088  8f1f4be2      sub      r1, fp, #0x23c                              
  0000108c  a9ffffeb      bl       #0xf38                                      
  00001090  000050e3      cmp      r0, #0                                      
  00001094  0b00000a      beq      #0x10c8                                     
  00001098  f50000eb      bl       #0x1474                                       ; → HW_CFGTOOL_ShowUsage
  0000109c  b0019fe5      ldr      r0, [pc, #0x1b0]                            
  000010a0  811300e3      movw     r1, #0x381                                  
  000010a4  00408de5      str      r4, [sp]                                    
  000010a8  00008fe0      add      r0, pc, r0                                  
  000010ac  04408de5      str      r4, [sp, #4]                                
  000010b0  08408de5      str      r4, [sp, #8]                                
  000010b4  0020e0e3      mvn      r2, #0                                      
  000010b8  0430a0e1      mov      r3, r4                                      
  000010bc  b8ffffeb      bl       #0xfa4                                      
  000010c0  0000e0e3      mvn      r0, #0                                      
  000010c4  5f0000ea      b        #0x1248                                     
  000010c8  3c421be5      ldr      r4, [fp, #-0x23c]                           
  000010cc  000054e3      cmp      r4, #0                                      
  000010d0  0900001a      bne      #0x10fc                                     
  000010d4  e60000eb      bl       #0x1474                                       ; → HW_CFGTOOL_ShowUsage
  000010d8  78019fe5      ldr      r0, [pc, #0x178]                            
  000010dc  00408de5      str      r4, [sp]                                    
  000010e0  891300e3      movw     r1, #0x389                                  
  000010e4  04408de5      str      r4, [sp, #4]                                
  000010e8  00008fe0      add      r0, pc, r0                                  
  000010ec  08408de5      str      r4, [sp, #8]                                
  000010f0  0420a0e1      mov      r2, r4                                      
  000010f4  0430a0e1      mov      r3, r4                                      
  000010f8  500000ea      b        #0x1240                                     
  000010fc  020aa0e3      mov      r0, #0x2000                                 
  00001100  8e1f4be2      sub      r1, fp, #0x238                              
  00001104  8d2f4be2      sub      r2, fp, #0x234                              
  00001108  150200eb      bl       #0x1964                                       ; → HW_CFGTOOL_MallocArgs
  0000110c  004050e2      subs     r4, r0, #0                                  
  00001110  0900000a      beq      #0x113c                                     
  00001114  3c021be5      ldr      r0, [fp, #-0x23c]                           
  00001118  7affffeb      bl       #0xf08                                      
  0000111c  38019fe5      ldr      r0, [pc, #0x138]                            
  00001120  0030a0e3      mov      r3, #0                                      
  00001124  911300e3      movw     r1, #0x391                                  
  00001128  00308de5      str      r3, [sp]                                    
  0000112c  00008fe0      add      r0, pc, r0                                  
  00001130  04308de5      str      r3, [sp, #4]                                
  00001134  08308de5      str      r3, [sp, #8]                                
  00001138  3f0000ea      b        #0x123c                                     
  0000113c  34321be5      ldr      r3, [fp, #-0x234]                           
  00001140  070055e3      cmp      r5, #7                                      
  00001144  00308de5      str      r3, [sp]                                    
  00001148  2200000a      beq      #0x11d8                                     
  0000114c  0620a0e1      mov      r2, r6                                      
  00001150  238e4be2      sub      r8, fp, #0x230                              
  00001154  0500a0e1      mov      r0, r5                                      
  00001158  04808de5      str      r8, [sp, #4]                                
  0000115c  0710a0e1      mov      r1, r7                                      
  00001160  38321be5      ldr      r3, [fp, #-0x238]                           
  00001164  2b0200eb      bl       #0x1a18                                       ; → HW_CFGTOOL_CheckArg
  00001168  006050e2      subs     r6, r0, #0                                  
  0000116c  0f00000a      beq      #0x11b0                                     
  00001170  34121be5      ldr      r1, [fp, #-0x234]                           
  00001174  38021be5      ldr      r0, [fp, #-0x238]                           
  00001178  ed0100eb      bl       #0x1934                                       ; → HW_CFGTOOL_FreeArgs
  0000117c  3c021be5      ldr      r0, [fp, #-0x23c]                           
  00001180  60ffffeb      bl       #0xf08                                      
  00001184  d4009fe5      ldr      r0, [pc, #0xd4]                             
  00001188  00408de5      str      r4, [sp]                                    
  0000118c  9d1300e3      movw     r1, #0x39d                                  
  00001190  00008fe0      add      r0, pc, r0                                  
  00001194  04408de5      str      r4, [sp, #4]                                
  00001198  08408de5      str      r4, [sp, #8]                                
  0000119c  0620a0e1      mov      r2, r6                                      
  000011a0  0430a0e1      mov      r3, r4                                      
  000011a4  7effffeb      bl       #0xfa4                                      
  000011a8  0600a0e1      mov      r0, r6                                      
  000011ac  250000ea      b        #0x1248                                     
  000011b0  38321be5      ldr      r3, [fp, #-0x238]                           
  000011b4  0500a0e1      mov      r0, r5                                      
  000011b8  3c121be5      ldr      r1, [fp, #-0x23c]                           
  000011bc  892f4be2      sub      r2, fp, #0x224                              
  000011c0  00308de5      str      r3, [sp]                                    
  000011c4  34321be5      ldr      r3, [fp, #-0x234]                           
  000011c8  08018de9      stmib    sp, {r3, r8}                                
  000011cc  493f4be2      sub      r3, fp, #0x124                              
  000011d0  690200eb      bl       #0x1b7c                                       ; → HW_CFGTOOL_OperByType
  000011d4  060000ea      b        #0x11f4                                     
  000011d8  233e4be2      sub      r3, fp, #0x230                              
  000011dc  3c021be5      ldr      r0, [fp, #-0x23c]                           
  000011e0  04308de5      str      r3, [sp, #4]                                
  000011e4  891f4be2      sub      r1, fp, #0x224                              
  000011e8  492f4be2      sub      r2, fp, #0x124                              
  000011ec  38321be5      ldr      r3, [fp, #-0x238]                           
  000011f0  f20200eb      bl       #0x1dc0                                       ; → HW_CFGTOOL_DealBatchType
  000011f4  891f4be2      sub      r1, fp, #0x224                              
  000011f8  0040a0e1      mov      r4, r0                                      
  000011fc  3c021be5      ldr      r0, [fp, #-0x23c]                           
  00001200  3affffeb      bl       #0xef0                                      
  00001204  3c021be5      ldr      r0, [fp, #-0x23c]                           
  00001208  3effffeb      bl       #0xf08                                      
  0000120c  38021be5      ldr      r0, [fp, #-0x238]                           
  00001210  34121be5      ldr      r1, [fp, #-0x234]                           
  00001214  c60100eb      bl       #0x1934                                       ; → HW_CFGTOOL_FreeArgs
  00001218  000054e3      cmp      r4, #0                                      
  0000121c  0800000a      beq      #0x1244                                     
  00001220  3c009fe5      ldr      r0, [pc, #0x3c]                             
  00001224  b51300e3      movw     r1, #0x3b5                                  
  00001228  0030a0e3      mov      r3, #0                                      
  0000122c  00308de5      str      r3, [sp]                                    
  00001230  00008fe0      add      r0, pc, r0                                  
  00001234  04308de5      str      r3, [sp, #4]                                
  00001238  08308de5      str      r3, [sp, #8]                                
  0000123c  0420a0e1      mov      r2, r4                                      
  00001240  57ffffeb      bl       #0xfa4                                      
  00001244  0400a0e1      mov      r0, r4                                      
  00001248  20d04be2      sub      sp, fp, #0x20                               
  0000124c  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  00001250  f1120000      strdeq   r1, r2, [r0], -r1                           
  00001254  7d120000      andeq    r1, r0, sp, ror r2                          
  00001258  3d120000      andeq    r1, r0, sp, lsr r2                          
  0000125c  f9110000      strdeq   r1, r2, [r0], -sb                           
  00001260  95110000      muleq    r0, r5, r1                                  
  00001264  f5100000      strdeq   r1, r2, [r0], -r5                           

; ─── _start @ 0x00001268 ───
  00001268  00b0a0e3      mov      fp, #0                                      
  0000126c  00e0a0e3      mov      lr, #0                                      
  00001270  04109de4      pop      {r1}                                        
  00001274  0d20a0e1      mov      r2, sp                                      
  00001278  04202de5      str      r2, [sp, #-4]!                              
  0000127c  04002de5      str      r0, [sp, #-4]!                              
  00001280  28a09fe5      ldr      sl, [pc, #0x28]                             
  00001284  24308fe2      add      r3, pc, #0x24                               
  00001288  03a08ae0      add      sl, sl, r3                                  
  0000128c  20c09fe5      ldr      ip, [pc, #0x20]                             
  00001290  0c009ae7      ldr      r0, [sl, ip]                                
  00001294  04002de5      str      r0, [sp, #-4]!                              
  00001298  18c09fe5      ldr      ip, [pc, #0x18]                             
  0000129c  0c309ae7      ldr      r3, [sl, ip]                                
  000012a0  14c09fe5      ldr      ip, [pc, #0x14]                             
  000012a4  0c009ae7      ldr      r0, [sl, ip]                                
  000012a8  effeffea      b        #0xe6c                                      
  000012ac  e5feffeb      bl       #0xe48                                      
  000012b0  509d0000      andeq    sb, r0, r0, asr sp                          
  000012b4  94000000      muleq    r0, r4, r0                                  
  000012b8  a8000000      andeq    r0, r0, r8, lsr #1                          
  000012bc  90000000      muleq    r0, r0, r0                                  
  000012c0  3c209fe5      ldr      r2, [pc, #0x3c]                             
  000012c4  3c009fe5      ldr      r0, [pc, #0x3c]                             
  000012c8  02208fe0      add      r2, pc, r2                                  
  000012cc  00008fe0      add      r0, pc, r0                                  
  000012d0  032082e2      add      r2, r2, #3                                  
  000012d4  022060e0      rsb      r2, r0, r2                                  
  000012d8  08402de9      push     {r3, lr}                                    
  000012dc  060052e3      cmp      r2, #6                                      
  000012e0  24309fe5      ldr      r3, [pc, #0x24]                             
  000012e4  03308fe0      add      r3, pc, r3                                  
  000012e8  0880bd98      popls    {r3, pc}                                    
  000012ec  1c209fe5      ldr      r2, [pc, #0x1c]                             
  000012f0  023093e7      ldr      r3, [r3, r2]                                
  000012f4  000053e3      cmp      r3, #0                                      
  000012f8  0880bd08      popeq    {r3, pc}                                    
  000012fc  33ff2fe1      blx      r3                                          
  00001300  0880bde8      pop      {r3, pc}                                    
  00001304  349f0000      andeq    sb, r0, r4, lsr pc                          
  00001308  309f0000      andeq    sb, r0, r0, lsr pc                          
  0000130c  149d0000      andeq    sb, r0, r4, lsl sp                          
  00001310  a4000000      andeq    r0, r0, r4, lsr #1                          
  00001314  08402de9      push     {r3, lr}                                    
  00001318  40009fe5      ldr      r0, [pc, #0x40]                             
  0000131c  40309fe5      ldr      r3, [pc, #0x40]                             
  00001320  00008fe0      add      r0, pc, r0                                  
  00001324  3c209fe5      ldr      r2, [pc, #0x3c]                             
  00001328  03308fe0      add      r3, pc, r3                                  
  0000132c  033060e0      rsb      r3, r0, r3                                  
  00001330  02208fe0      add      r2, pc, r2                                  
  00001334  4331a0e1      asr      r3, r3, #2                                  
  00001338  a33f83e0      add      r3, r3, r3, lsr #31                         
  0000133c  c330b0e1      asrs     r3, r3, #1                                  
  00001340  0880bd08      popeq    {r3, pc}                                    
  00001344  20109fe5      ldr      r1, [pc, #0x20]                             
  00001348  012092e7      ldr      r2, [r2, r1]                                
  0000134c  000052e3      cmp      r2, #0                                      
  00001350  0880bd08      popeq    {r3, pc}                                    
  00001354  0310a0e1      mov      r1, r3                                      
  00001358  32ff2fe1      blx      r2                                          
  0000135c  0880bde8      pop      {r3, pc}                                    
  00001360  dc9e0000      ldrdeq   sb, sl, [r0], -ip                           
  00001364  d49e0000      ldrdeq   sb, sl, [r0], -r4                           
  00001368  c89c0000      andeq    sb, r0, r8, asr #25                         
  0000136c  b4000000      strheq   r0, [r0], -r4                               
  00001370  68309fe5      ldr      r3, [pc, #0x68]                             
  00001374  10402de9      push     {r4, lr}                                    
  00001378  03308fe0      add      r3, pc, r3                                  
  0000137c  60409fe5      ldr      r4, [pc, #0x60]                             
  00001380  0030d3e5      ldrb     r3, [r3]                                    
  00001384  04408fe0      add      r4, pc, r4                                  
  00001388  000053e3      cmp      r3, #0                                      
  0000138c  1080bd18      popne    {r4, pc}                                    
  00001390  50309fe5      ldr      r3, [pc, #0x50]                             
  00001394  033094e7      ldr      r3, [r4, r3]                                
  00001398  000053e3      cmp      r3, #0                                      
  0000139c  0200000a      beq      #0x13ac                                     
  000013a0  44309fe5      ldr      r3, [pc, #0x44]                             
  000013a4  03009fe7      ldr      r0, [pc, r3]                                
  000013a8  d9feffeb      bl       #0xf14                                      
  000013ac  c3ffffeb      bl       #0x12c0                                     
  000013b0  38309fe5      ldr      r3, [pc, #0x38]                             
  000013b4  033094e7      ldr      r3, [r4, r3]                                
  000013b8  000053e3      cmp      r3, #0                                      
  000013bc  0200000a      beq      #0x13cc                                     
  000013c0  2c009fe5      ldr      r0, [pc, #0x2c]                             
  000013c4  00008fe0      add      r0, pc, r0                                  
  000013c8  b3feffeb      bl       #0xe9c                                      
  000013cc  24309fe5      ldr      r3, [pc, #0x24]                             
  000013d0  0120a0e3      mov      r2, #1                                      
  000013d4  03308fe0      add      r3, pc, r3                                  
  000013d8  0020c3e5      strb     r2, [r3]                                    
  000013dc  1080bde8      pop      {r4, pc}                                    
  000013e0  849e0000      andeq    sb, r0, r4, lsl #29                         
  000013e4  749c0000      andeq    sb, r0, r4, ror ip                          
  000013e8  ac000000      andeq    r0, r0, ip, lsr #1                          
  000013ec  109d0000      andeq    sb, r0, r0, lsl sp                          
  000013f0  98000000      muleq    r0, r8, r0                                  
  000013f4  04110000      andeq    r1, r0, r4, lsl #2                          
  000013f8  289e0000      andeq    sb, r0, r8, lsr #28                         
  000013fc  10402de9      push     {r4, lr}                                    
  00001400  54409fe5      ldr      r4, [pc, #0x54]                             
  00001404  54309fe5      ldr      r3, [pc, #0x54]                             
  00001408  04408fe0      add      r4, pc, r4                                  
  0000140c  033094e7      ldr      r3, [r4, r3]                                
  00001410  000053e3      cmp      r3, #0                                      
  00001414  0400000a      beq      #0x142c                                     
  00001418  44009fe5      ldr      r0, [pc, #0x44]                             
  0000141c  44109fe5      ldr      r1, [pc, #0x44]                             
  00001420  00008fe0      add      r0, pc, r0                                  
  00001424  01108fe0      add      r1, pc, r1                                  
  00001428  bcfeffeb      bl       #0xf20                                      
  0000142c  38009fe5      ldr      r0, [pc, #0x38]                             
  00001430  00008fe0      add      r0, pc, r0                                  
  00001434  003090e5      ldr      r3, [r0]                                    
  00001438  000053e3      cmp      r3, #0                                      
  0000143c  0400000a      beq      #0x1454                                     
  00001440  28309fe5      ldr      r3, [pc, #0x28]                             
  00001444  033094e7      ldr      r3, [r4, r3]                                
  00001448  000053e3      cmp      r3, #0                                      
  0000144c  0000000a      beq      #0x1454                                     
  00001450  33ff2fe1      blx      r3                                          
  00001454  1040bde8      pop      {r4, lr}                                    
  00001458  adffffea      b        #0x1314                                     
  0000145c  f09b0000      strdeq   sb, sl, [r0], -r0                           
  00001460  b0000000      strheq   r0, [r0], -r0                               
  00001464  a8100000      andeq    r1, r0, r8, lsr #1                          
  00001468  dc9d0000      ldrdeq   sb, sl, [r0], -ip                           
  0000146c  b49a0000      strheq   sb, [r0], -r4                               
  00001470  9c000000      muleq    r0, ip, r0                                  

; ─── HW_CFGTOOL_ShowUsage @ 0x00001474 ───
  00001474  34109fe5      ldr      r1, [pc, #0x34]                             
  00001478  0dc0a0e1      mov      ip, sp                                      
  0000147c  00d82de9      push     {fp, ip, lr, pc}                            
  00001480  04b04ce2      sub      fp, ip, #4                                  
  00001484  21de4de2      sub      sp, sp, #0x210                              
  00001488  870f4be2      sub      r0, fp, #0x21c                              
  0000148c  01108fe0      add      r1, pc, r1                                  
  00001490  212ea0e3      mov      r2, #0x210                                  
  00001494  c5feffeb      bl       #0xfb0                                      
  00001498  14009fe5      ldr      r0, [pc, #0x14]                             
  0000149c  871f4be2      sub      r1, fp, #0x21c                              
  000014a0  00008fe0      add      r0, pc, r0                                  
  000014a4  82feffeb      bl       #0xeb4                                      
  000014a8  0cd04be2      sub      sp, fp, #0xc                                
  000014ac  00a89de8      ldm      sp, {fp, sp, pc}                            
  000014b0  2f0c0000      andeq    r0, r0, pc, lsr #24                         
  000014b4  180c0000      andeq    r0, r0, r8, lsl ip                          

; ─── HW_CFGTOOL_BatchChangeRet @ 0x000014b8 ───
  000014b8  0dc0a0e1      mov      ip, sp                                      
  000014bc  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  000014c0  04b04ce2      sub      fp, ip, #4                                  
  000014c4  58309fe5      ldr      r3, [pc, #0x58]                             
  000014c8  0140a0e1      mov      r4, r1                                      
  000014cc  030050e1      cmp      r0, r3                                      
  000014d0  0600001a      bne      #0x14f0                                     
  000014d4  002091e5      ldr      r2, [r1]                                    
  000014d8  48309fe5      ldr      r3, [pc, #0x48]                             
  000014dc  030052e1      cmp      r2, r3                                      
  000014e0  18a89d18      ldmne    sp, {r3, r4, fp, sp, pc}                    
  000014e4  40009fe5      ldr      r0, [pc, #0x40]                             
  000014e8  00008fe0      add      r0, pc, r0                                  
  000014ec  080000ea      b        #0x1514                                     
  000014f0  38309fe5      ldr      r3, [pc, #0x38]                             
  000014f4  030050e1      cmp      r0, r3                                      
  000014f8  18a89d18      ldmne    sp, {r3, r4, fp, sp, pc}                    
  000014fc  002091e5      ldr      r2, [r1]                                    
  00001500  2c309fe5      ldr      r3, [pc, #0x2c]                             
  00001504  030052e1      cmp      r2, r3                                      
  00001508  18a89d18      ldmne    sp, {r3, r4, fp, sp, pc}                    
  0000150c  24009fe5      ldr      r0, [pc, #0x24]                             
  00001510  00008fe0      add      r0, pc, r0                                  
  00001514  66feffeb      bl       #0xeb4                                      
  00001518  0030a0e3      mov      r3, #0                                      
  0000151c  003084e5      str      r3, [r4]                                    
  00001520  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    
  00001524  03000100      andeq    r0, r1, r3                                  