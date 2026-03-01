
### HW_SSL_LoadCertFile @ 0x11dc
  000011dc  000050e3      cmp      r0, #0                                    
  000011e0  00005113      cmpne    r1, #0                                    
  000011e4  0dc0a0e1      mov      ip, sp                                    
  000011e8  00d82de9      push     {fp, ip, lr, pc}                          
  000011ec  04b04ce2      sub      fp, ip, #4                                
  000011f0  10d04de2      sub      sp, sp, #0x10                             
  000011f4  0120a0e1      mov      r2, r1                                    
  000011f8  0030a0e1      mov      r3, r0                                    
  000011fc  0400000a      beq      #0x1214                                   
  00001200  011c81e2      add      r1, r1, #0x100                            
  00001204  063d82e2      add      r3, r2, #0x180                            
  00001208  0cd04be2      sub      sp, fp, #0xc                              
  0000120c  00689de8      ldm      sp, {fp, sp, lr}                          
  00001210  b7ffffea      b        #0x10f4                                   
  00001214  28009fe5      ldr      r0, [pc, #0x28]                           
  00001218  0020a0e3      mov      r2, #0                                    
  0000121c  00108de5      str      r1, [sp]                                  
  00001220  7810a0e3      mov      r1, #0x78                                 
  00001224  04208de5      str      r2, [sp, #4]                              
  00001228  00008fe0      add      r0, pc, r0                                
  0000122c  08208de5      str      r2, [sp, #8]                              
  00001230  0020e0e3      mvn      r2, #0                                    
  00001234  57ffffeb      bl       #0xf98                                    
  00001238  0000e0e3      mvn      r0, #0                                    
  0000123c  0cd04be2      sub      sp, fp, #0xc                              
  00001240  00a89de8      ldm      sp, {fp, sp, pc}                          
  00001244  d00b0000      ldrdeq   r0, r1, [r0], -r0                         
  00001248  003050e2      subs     r3, r0, #0                                
  0000124c  0dc0a0e1      mov      ip, sp                                    
  00001250  10d82de9      push     {r4, fp, ip, lr, pc}                      
  00001254  04b04ce2      sub      fp, ip, #4                                
  00001258  14d04de2      sub      sp, sp, #0x14                             
  0000125c  01c0a0e1      mov      ip, r1                                    
  00001260  0240a0e1      mov      r4, r2                                    
  00001264  0500000a      beq      #0x1280                                   
  00001268  000052e3      cmp      r2, #0                                    
  0000126c  00005103      cmpeq    r1, #0                                    
  00001270  0200000a      beq      #0x1280                                   
  00001274  10d04be2      sub      sp, fp, #0x10                             
  00001278  10689de8      ldm      sp, {r4, fp, sp, lr}                      
  0000127c  8dffffea      b        #0x10b8                                   
  00001280  28009fe5      ldr      r0, [pc, #0x28]                             ; r0='larssl_conf_authmode'
  00001284  0020a0e3      mov      r2, #0                                    
  00001288  00c08de5      str      ip, [sp]                                  
  0000128c  9410a0e3      mov      r1, #0x94                                 
  00001290  08208de5      str      r2, [sp, #8]                              
  00001294  00008fe0      add      r0, pc, r0                                
  00001298  04408de5      str      r4, [sp, #4]                              
  0000129c  10209fe5      ldr      r2, [pc, #0x10]                           
  000012a0  3cffffeb      bl       #0xf98                                    
  000012a4  0000e0e3      mvn      r0, #0                                    
  000012a8  10d04be2      sub      sp, fp, #0x10                             
  000012ac  10a89de8      ldm      sp, {r4, fp, sp, pc}                      
  000012b0  640b0000      andeq    r0, r0, r4, ror #22                       

### HW_SSL_X509ParseCommixFileEx @ 0x16a8
  000016a8  0dc0a0e1      mov      ip, sp                                    
  000016ac  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  000016b0  04b04ce2      sub      fp, ip, #4                                
  000016b4  4cd04de2      sub      sp, sp, #0x4c                             
  000016b8  0050a0e1      mov      r5, r0                                    
  000016bc  0180a0e1      mov      r8, r1                                    
  000016c0  02a0a0e1      mov      sl, r2                                    
  000016c4  0010a0e3      mov      r1, #0                                    
  000016c8  4c004be2      sub      r0, fp, #0x4c                             
  000016cc  2020a0e3      mov      r2, #0x20                                 
  000016d0  58300be5      str      r3, [fp, #-0x58]                          
  000016d4  50100be5      str      r1, [fp, #-0x50]                          
  000016d8  1ffeffeb      bl       #0xf5c                                    
  000016dc  000055e3      cmp      r5, #0                                    
  000016e0  00005813      cmpne    r8, #0                                    
  000016e4  0100001a      bne      #0x16f0                                   
  000016e8  730200e3      movw     r0, #0x273                                
  000016ec  090000ea      b        #0x1718                                   
  000016f0  58301be5      ldr      r3, [fp, #-0x58]                          
  000016f4  00005ae3      cmp      sl, #0                                    
  000016f8  00005313      cmpne    r3, #0                                    
  000016fc  f9ffff0a      beq      #0x16e8                                   
  00001700  0500a0e1      mov      r0, r5                                    
  00001704  50104be2      sub      r1, fp, #0x50                             
  00001708  4cfeffeb      bl       #0x1040                                   
  0000170c  000050e3      cmp      r0, #0                                    
  00001710  0400000a      beq      #0x1728                                   
  00001714  760200e3      movw     r0, #0x276                                
  00001718  0010e0e3      mvn      r1, #0                                    
  0000171c  7dfeffeb      bl       #0x1118                                   
  00001720  0000e0e3      mvn      r0, #0                                    
  00001724  af0000ea      b        #0x19e8                                   
  00001728  50001be5      ldr      r0, [fp, #-0x50]                          
  0000172c  000050e3      cmp      r0, #0                                    
  00001730  f7ffff0a      beq      #0x1714                                   
  00001734  010080e2      add      r0, r0, #1                                
  00001738  58feffeb      bl       #0x10a0                                   
  0000173c  004050e2      subs     r4, r0, #0                                
  00001740  79020003      movweq   r0, #0x279                                
  00001744  f3ffff0a      beq      #0x1718                                   
  00001748  a0129fe5      ldr      r1, [pc, #0x2a0]                          
  0000174c  0500a0e1      mov      r0, r5                                    
  00001750  01108fe0      add      r1, pc, r1                                
  00001754  f1fdffeb      bl       #0xf20                                    
  00001758  005050e2      subs     r5, r0, #0                                
  0000175c  0400a0e1      mov      r0, r4                                    
  00001760  0500001a      bne      #0x177c                                   
  00001764  1dfeffeb      bl       #0xfe0                                    
  00001768  84029fe5      ldr      r0, [pc, #0x284]                          
  0000176c  00008fe0      add      r0, pc, r0                                
  00001770  14feffeb      bl       #0xfc8                                    
  00001774  9f0fa0e3      mov      r0, #0x27c                                
  00001778  4f0000ea      b        #0x18bc                                   
  0000177c  0530a0e1      mov      r3, r5                                    
  00001780  0110a0e3      mov      r1, #1                                    
  00001784  50201be5      ldr      r2, [fp, #-0x50]                          
  00001788  11feffeb      bl       #0xfd4                                    
  0000178c  0060a0e1      mov      r6, r0                                    
  00001790  0500a0e1      mov      r0, r5                                    
  00001794  4dfeffeb      bl       #0x10d0                                   
  00001798  50301be5      ldr      r3, [fp, #-0x50]                          
  0000179c  030056e1      cmp      r6, r3                                    
  000017a0  0200000a      beq      #0x17b0                                   
  000017a4  0400a0e1      mov      r0, r4                                    
  000017a8  0cfeffeb      bl       #0xfe0                                    
  000017ac  dbffffea      b        #0x1720                                   
  000017b0  40729fe5      ldr      r7, [pc, #0x240]                          
  000017b4  0400a0e1      mov      r0, r4                                    
  000017b8  07708fe0      add      r7, pc, r7                                
  000017bc  0710a0e1      mov      r1, r7                                    
  000017c0  48feffeb      bl       #0x10e8                                   
  000017c4  30129fe5      ldr      r1, [pc, #0x230]                          
  000017c8  01108fe0      add      r1, pc, r1                                
  000017cc  0050a0e1      mov      r5, r0                                    
  000017d0  0400a0e1      mov      r0, r4                                    
  000017d4  43feffeb      bl       #0x10e8                                   
  000017d8  000055e3      cmp      r5, #0                                    
  000017dc  00005013      cmpne    r0, #0                                    
  000017e0  0000a013      movne    r0, #0                                    
  000017e4  0100a003      moveq    r0, #1                                    
  000017e8  5100001a      bne      #0x1934                                   
  000017ec  0400a0e1      mov      r0, r4                                    
  000017f0  fafdffeb      bl       #0xfe0                                    
  000017f4  04029fe5      ldr      r0, [pc, #0x204]                          
  000017f8  00008fe0      add      r0, pc, r0                                
  000017fc  f1fdffeb      bl       #0xfc8                                    
  00001800  8e0200e3      movw     r0, #0x28e                                
  00001804  2c0000ea      b        #0x18bc                                   
  00001808  0600a0e1      mov      r0, r6                                    
  0000180c  5c101be5      ldr      r1, [fp, #-0x5c]                          
  00001810  34feffeb      bl       #0x10e8                                   
  00001814  60101be5      ldr      r1, [fp, #-0x60]                          
  00001818  0090a0e1      mov      sb, r0                                    
  0000181c  0600a0e1      mov      r0, r6                                    
  00001820  30feffeb      bl       #0x10e8                                   
  00001824  000050e3      cmp      r0, #0                                    
  00001828  09005011      cmpne    r0, sb                                    
  0000182c  0060a0e1      mov      r6, r0                                    
  00001830  0600008a      bhi      #0x1850                                   
  00001834  0400a0e1      mov      r0, r4                                    
  00001838  e8fdffeb      bl       #0xfe0                                    
  0000183c  c0019fe5      ldr      r0, [pc, #0x1c0]                          
  00001840  00008fe0      add      r0, pc, r0                                
  00001844  dffdffeb      bl       #0xfc8                                    
  00001848  9a0200e3      movw     r0, #0x29a                                
  0000184c  1a0000ea      b        #0x18bc                                   
  00001850  001069e0      rsb      r1, sb, r0                                
  00001854  60001be5      ldr      r0, [fp, #-0x60]                          
  00001858  6c100be5      str      r1, [fp, #-0x6c]                          
  0000185c  0cfeffeb      bl       #0x1094                                   
  00001860  6c101be5      ldr      r1, [fp, #-0x6c]                          
  00001864  001081e0      add      r1, r1, r0                                
  00001868  000051e3      cmp      r1, #0                                    
  0000186c  060000ca      bgt      #0x188c                                   
  00001870  0400a0e1      mov      r0, r4                                    
  00001874  d9fdffeb      bl       #0xfe0                                    
  00001878  88019fe5      ldr      r0, [pc, #0x188]                          
  0000187c  00008fe0      add      r0, pc, r0                                
  00001880  d0fdffeb      bl       #0xfc8                                    
  00001884  9e0200e3      movw     r0, #0x29e                                
  00001888  0b0000ea      b        #0x18bc                                   
  0000188c  0900a0e1      mov      r0, sb                                    
  00001890  0720a0e1      mov      r2, r7                                    
  00001894  4bffffeb      bl       #0x15c8                                   
  00001898  0700a0e1      mov      r0, r7                                    
  0000189c  edfdffeb      bl       #0x1058                                   
  000018a0  009050e2      subs     sb, r0, #0                                
  000018a4  0600001a      bne      #0x18c4                                   
  000018a8  0400a0e1      mov      r0, r4                                    
  000018ac  cbfdffeb      bl       #0xfe0                                    
  000018b0  0700a0e1      mov      r0, r7                                    
  000018b4  c3fdffeb      bl       #0xfc8                                    
  000018b8  a30200e3      movw     r0, #0x2a3                                
  000018bc  0110a0e3      mov      r1, #1                                    
  000018c0  95ffffea      b        #0x171c                                   
  000018c4  fc3099e5      ldr      r3, [sb, #0xfc]                           
  000018c8  010053e3      cmp      r3, #1                                    
  000018cc  0700a011      movne    r0, r7                                    
  000018d0  0a10a011      movne    r1, sl                                    
  000018d4  0e00001a      bne      #0x1914                                   
  000018d8  015085e2      add      r5, r5, #1                                
  000018dc  010055e3      cmp      r5, #1                                    
  000018e0  0100001a      bne      #0x18ec                                   
  000018e4  0800a0e1      mov      r0, r8                                    
  000018e8  d7fdffeb      bl       #0x104c                                   
  000018ec  2010a0e3      mov      r1, #0x20                                 
  000018f0  00808de5      str      r8, [sp]                                  
  000018f4  04508de5      str      r5, [sp, #4]                              
  000018f8  4c004be2      sub      r0, fp, #0x4c                             
  000018fc  1f20a0e3      mov      r2, #0x1f                                 
  00001900  64301be5      ldr      r3, [fp, #-0x64]                          
  00001904  c1fdffeb      bl       #0x1010                                   
  00001908  68001be5      ldr      r0, [fp, #-0x68]                          
  0000190c  4c104be2      sub      r1, fp, #0x4c                             
  00001910  ffffffea      b        #0x1914                                   
  00001914  96fdffeb      bl       #0xf74                                    
  00001918  ec009fe5      ldr      r0, [pc, #0xec]                           
  0000191c  00008fe0      add      r0, pc, r0                                
  00001920  dbfdffeb      bl       #0x1094                                   
  00001924  006086e0      add      r6, r6, r0                                
  00001928  0900a0e1      mov      r0, sb                                    
  0000192c  aefdffeb      bl       #0xfec                                    
  00001930  0d0000ea      b        #0x196c                                   
  00001934  d4309fe5      ldr      r3, [pc, #0xd4]                           
  00001938  0460a0e1      mov      r6, r4                                    
  0000193c  5c700be5      str      r7, [fp, #-0x5c]                          
  00001940  0050a0e1      mov      r5, r0                                    
  00001944  03308fe0      add      r3, pc, r3                                
  00001948  c4709fe5      ldr      r7, [pc, #0xc4]                           
  0000194c  60300be5      str      r3, [fp, #-0x60]                          
  00001950  c0309fe5      ldr      r3, [pc, #0xc0]                           
  00001954  07708fe0      add      r7, pc, r7                                
  00001958  03308fe0      add      r3, pc, r3                                
  0000195c  64300be5      str      r3, [fp, #-0x64]                          
  00001960  b4309fe5      ldr      r3, [pc, #0xb4]                           
  00001964  03308fe0      add      r3, pc, r3                                
  00001968  68300be5      str      r3, [fp, #-0x68]                          
  0000196c  0600a0e1      mov      r0, r6                                    
  00001970  5c101be5      ldr      r1, [fp, #-0x5c]                          
  00001974  dbfdffeb      bl       #0x10e8                                   
  00001978  000050e3      cmp      r0, #0                                    
  0000197c  0100000a      beq      #0x1988                                   
  00001980  7f0055e3      cmp      r5, #0x7f                                 
  00001984  9fffff9a      bls      #0x1808                                   
  00001988  90109fe5      ldr      r1, [pc, #0x90]                           
  0000198c  0400a0e1      mov      r0, r4                                    
  00001990  01108fe0      add      r1, pc, r1                                
  00001994  d3fdffeb      bl       #0x10e8                                   
  00001998  005050e2      subs     r5, r0, #0                                
  0000199c  0e00000a      beq      #0x19dc                                   
  000019a0  7c609fe5      ldr      r6, [pc, #0x7c]                           
  000019a4  06608fe0      add      r6, pc, r6                                
  000019a8  0610a0e1      mov      r1, r6                                    
  000019ac  cdfdffeb      bl       #0x10e8                                   
  000019b0  000050e3      cmp      r0, #0                                    
  000019b4  0800000a      beq      #0x19dc                                   
  000019b8  007065e0      rsb      r7, r5, r0                                
  000019bc  0600a0e1      mov      r0, r6                                    
  000019c0  b3fdffeb      bl       #0x1094                                   
  000019c4  001087e0      add      r1, r7, r0                                
  000019c8  000051e3      cmp      r1, #0                                    
  000019cc  020000da      ble      #0x19dc                                   
  000019d0  0500a0e1      mov      r0, r5                                    
  000019d4  58201be5      ldr      r2, [fp, #-0x58]                          
  000019d8  fafeffeb      bl       #0x15c8                                   
  000019dc  0400a0e1      mov      r0, r4                                    
  000019e0  7efdffeb      bl       #0xfe0                                    
  000019e4  0000a0e3      mov      r0, #0                                    
  000019e8  28d04be2      sub      sp, fp, #0x28                             
  000019ec  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  000019f0  bb060000      strheq   r0, [r0], -fp                             
  000019f4  a2060000      andeq    r0, r0, r2, lsr #13                       
  000019f8  6e060000      andeq    r0, r0, lr, ror #12                       
  000019fc  7a060000      andeq    r0, r0, sl, ror r6                        
  00001a00  16060000      andeq    r0, r0, r6, lsl r6                        
  00001a04  ce050000      andeq    r0, r0, lr, asr #11                       
  00001a08  92050000      muleq    r0, r2, r5                                
  00001a0c  26050000      andeq    r0, r0, r6, lsr #10                       
  00001a10  fe040000      strdeq   r0, r1, [r0], -lr                         
  00001a14  ba040000      strheq   r0, [r0], -sl                             
  00001a18  04050000      andeq    r0, r0, r4, lsl #10                       
  00001a1c  aa040000      andeq    r0, r0, sl, lsr #9                        
  00001a20  da040000      ldrdeq   r0, r1, [r0], -sl                         
  00001a24  e6040000      andeq    r0, r0, r6, ror #9                        
  00001a28  0dc0a0e1      mov      ip, sp                                    
  00001a2c  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  00001a30  04b04ce2      sub      fp, ip, #4                                
  00001a34  24d04de2      sub      sp, sp, #0x24                             
  00001a38  0260a0e1      mov      r6, r2                                    
  00001a3c  44300be5      str      r3, [fp, #-0x44]                          
  00001a40  0030a0e3      mov      r3, #0                                    
  00001a44  030050e1      cmp      r0, r3                                    
  00001a48  03005111      cmpne    r1, r3                                    
  00001a4c  30300be5      str      r3, [fp, #-0x30]                          
  00001a50  0170a0e1      mov      r7, r1                                    
  00001a54  0050a0e1      mov      r5, r0                                    
  00001a58  0100001a      bne      #0x1a64                                   
  00001a5c  060300e3      movw     r0, #0x306                                
  00001a60  080000ea      b        #0x1a88                                   
  00001a64  44201be5      ldr      r2, [fp, #-0x44]                          
  00001a68  000056e3      cmp      r6, #0                                    
  00001a6c  00005213      cmpne    r2, #0                                    
  00001a70  f9ffff0a      beq      #0x1a5c                                   
  00001a74  30104be2      sub      r1, fp, #0x30                             
  00001a78  70fdffeb      bl       #0x1040                                   
  00001a7c  000050e3      cmp      r0, #0                                    
  00001a80  0400000a      beq      #0x1a98                                   
  00001a84  090300e3      movw     r0, #0x309                                
  00001a88  0010e0e3      mvn      r1, #0                                    
  00001a8c  a1fdffeb      bl       #0x1118                                   
  00001a90  0000e0e3      mvn      r0, #0                                    
  00001a94  950000ea      b        #0x1cf0                                   
  00001a98  30001be5      ldr      r0, [fp, #-0x30]                          
  00001a9c  000050e3      cmp      r0, #0                                    
  00001aa0  f7ffff0a      beq      #0x1a84                                   
  00001aa4  010080e2      add      r0, r0, #1                                
  00001aa8  7cfdffeb      bl       #0x10a0                                   
  00001aac  004050e2      subs     r4, r0, #0                                
  00001ab0  c30fa003      moveq    r0, #0x30c                                
  00001ab4  f3ffff0a      beq      #0x1a88                                   
  00001ab8  38129fe5      ldr      r1, [pc, #0x238]                          
  00001abc  0500a0e1      mov      r0, r5                                    
  00001ac0  01108fe0      add      r1, pc, r1                                
  00001ac4  15fdffeb      bl       #0xf20                                    
  00001ac8  005050e2      subs     r5, r0, #0                                
  00001acc  0400a0e1      mov      r0, r4                                    
  00001ad0  1800000a      beq      #0x1b38                                   
  00001ad4  0530a0e1      mov      r3, r5                                    
  00001ad8  0110a0e3      mov      r1, #1                                    
  00001adc  30201be5      ldr      r2, [fp, #-0x30]                          
  00001ae0  3bfdffeb      bl       #0xfd4                                    
  00001ae4  30301be5      ldr      r3, [fp, #-0x30]                          
  00001ae8  030050e1      cmp      r0, r3                                    
  00001aec  0500a0e1      mov      r0, r5                                    
  00001af0  0100000a      beq      #0x1afc                                   
  00001af4  75fdffeb      bl       #0x10d0                                   
  00001af8  0d0000ea      b        #0x1b34                                   
  00001afc  f8519fe5      ldr      r5, [pc, #0x1f8]                          
  00001b00  72fdffeb      bl       #0x10d0                                   
  00001b04  0400a0e1      mov      r0, r4                                    
  00001b08  05508fe0      add      r5, pc, r5                                
  00001b0c  0510a0e1      mov      r1, r5                                    
  00001b10  74fdffeb      bl       #0x10e8                                   
  00001b14  009050e2      subs     sb, r0, #0                                
  00001b18  0500000a      beq      #0x1b34                                   
  00001b1c  dc819fe5      ldr      r8, [pc, #0x1dc]                          
  00001b20  08808fe0      add      r8, pc, r8                                
  00001b24  0810a0e1      mov      r1, r8                                    
  00001b28  6efdffeb      bl       #0x10e8                                   
  00001b2c  00a050e2      subs     sl, r0, #0                                
  00001b30  0200001a      bne      #0x1b40                                   
  00001b34  0400a0e1      mov      r0, r4                                    
  00001b38  28fdffeb      bl       #0xfe0                                    
  00001b3c  d3ffffea      b        #0x1a90                                   
  00001b40  0800a0e1      mov      r0, r8                                    
  00001b44  0a3069e0      rsb      r3, sb, sl                                
  00001b48  48300be5      str      r3, [fp, #-0x48]                          
  00001b4c  50fdffeb      bl       #0x1094                                   
  00001b50  48301be5      ldr      r3, [fp, #-0x48]                          
  00001b54  0510a0e1      mov      r1, r5                                    
  00001b58  003083e0      add      r3, r3, r0                                
  00001b5c  0a00a0e1      mov      r0, sl                                    
  00001b60  3c300be5      str      r3, [fp, #-0x3c]                          
  00001b64  5ffdffeb      bl       #0x10e8                                   
  00001b68  00a050e2      subs     sl, r0, #0                                
  00001b6c  0100001a      bne      #0x1b78                                   
  00001b70  0080a0e3      mov      r8, #0                                    
  00001b74  0a0000ea      b        #0x1ba4                                   
  00001b78  84519fe5      ldr      r5, [pc, #0x184]                          
  00001b7c  0a00a0e1      mov      r0, sl                                    
  00001b80  05508fe0      add      r5, pc, r5                                
  00001b84  0510a0e1      mov      r1, r5                                    
  00001b88  56fdffeb      bl       #0x10e8                                   
  00001b8c  000050e3      cmp      r0, #0                                    
  00001b90  f6ffff0a      beq      #0x1b70                                   
  00001b94  00806ae0      rsb      r8, sl, r0                                
  00001b98  0500a0e1      mov      r0, r5                                    
  00001b9c  3cfdffeb      bl       #0x1094                                   
  00001ba0  008088e0      add      r8, r8, r0                                
  00001ba4  5c119fe5      ldr      r1, [pc, #0x15c]                          
  00001ba8  0400a0e1      mov      r0, r4                                    
  00001bac  01108fe0      add      r1, pc, r1                                
  00001bb0  4cfdffeb      bl       #0x10e8                                   
  00001bb4  003050e2      subs     r3, r0, #0                                
  00001bb8  40300be5      str      r3, [fp, #-0x40]                          
  00001bbc  0100001a      bne      #0x1bc8                                   
  00001bc0  0030a0e3      mov      r3, #0                                    
  00001bc4  0c0000ea      b        #0x1bfc                                   
  00001bc8  3c519fe5      ldr      r5, [pc, #0x13c]                          
  00001bcc  05508fe0      add      r5, pc, r5                                
  00001bd0  0510a0e1      mov      r1, r5                                    
  00001bd4  43fdffeb      bl       #0x10e8                                   
  00001bd8  000050e3      cmp      r0, #0                                    
  00001bdc  f7ffff0a      beq      #0x1bc0                                   
  00001be0  40201be5      ldr      r2, [fp, #-0x40]                          
  00001be4  003062e0      rsb      r3, r2, r0                                
  00001be8  0500a0e1      mov      r0, r5                                    
  00001bec  48300be5      str      r3, [fp, #-0x48]                          
  00001bf0  27fdffeb      bl       #0x1094                                   
  00001bf4  48301be5      ldr      r3, [fp, #-0x48]                          
  00001bf8  003083e0      add      r3, r3, r0                                
  00001bfc  38300be5      str      r3, [fp, #-0x38]                          
  00001c00  3c301be5      ldr      r3, [fp, #-0x3c]                          
  00001c04  000053e3      cmp      r3, #0                                    
  00001c08  150000da      ble      #0x1c64                                   
  00001c0c  fc509fe5      ldr      r5, [pc, #0xfc]                           
  00001c10  0900a0e1      mov      r0, sb                                    
  00001c14  0310a0e1      mov      r1, r3                                    
  00001c18  05508fe0      add      r5, pc, r5                                
  00001c1c  0520a0e1      mov      r2, r5                                    
  00001c20  68feffeb      bl       #0x15c8                                   
  00001c24  0500a0e1      mov      r0, r5                                    
  00001c28  0afdffeb      bl       #0x1058                                   
  00001c2c  009050e2      subs     sb, r0, #0                                
  00001c30  0300001a      bne      #0x1c44                                   
  00001c34  0400a0e1      mov      r0, r4                                    
  00001c38  e8fcffeb      bl       #0xfe0                                    
  00001c3c  0500a0e1      mov      r0, r5                                    
  00001c40  160000ea      b        #0x1ca0                                   
  00001c44  fc2099e5      ldr      r2, [sb, #0xfc]                           
  00001c48  0500a0e1      mov      r0, r5                                    
  00001c4c  010052e3      cmp      r2, #1                                    
  00001c50  0710a001      moveq    r1, r7                                    
  00001c54  0610a011      movne    r1, r6                                    
  00001c58  c5fcffeb      bl       #0xf74                                    
  00001c5c  0900a0e1      mov      r0, sb                                    
  00001c60  e1fcffeb      bl       #0xfec                                    
  00001c64  000058e3      cmp      r8, #0                                    
  00001c68  160000da      ble      #0x1cc8                                   
  00001c6c  a0909fe5      ldr      sb, [pc, #0xa0]                           
  00001c70  0810a0e1      mov      r1, r8                                    
  00001c74  0a00a0e1      mov      r0, sl                                    
  00001c78  09908fe0      add      sb, pc, sb                                
  00001c7c  0920a0e1      mov      r2, sb                                    
  00001c80  50feffeb      bl       #0x15c8                                   
  00001c84  0900a0e1      mov      r0, sb                                    
  00001c88  f2fcffeb      bl       #0x1058                                   
  00001c8c  008050e2      subs     r8, r0, #0                                
  00001c90  0400001a      bne      #0x1ca8                                   
  00001c94  0400a0e1      mov      r0, r4                                    
  00001c98  d0fcffeb      bl       #0xfe0                                    
  00001c9c  0900a0e1      mov      r0, sb                                    
  00001ca0  c8fcffeb      bl       #0xfc8                                    
  00001ca4  79ffffea      b        #0x1a90                                   
  00001ca8  fc3098e5      ldr      r3, [r8, #0xfc]                           
  00001cac  0900a0e1      mov      r0, sb                                    
  00001cb0  010053e3      cmp      r3, #1                                    
  00001cb4  0710a001      moveq    r1, r7                                    
  00001cb8  0610a011      movne    r1, r6                                    
  00001cbc  acfcffeb      bl       #0xf74                                    
  00001cc0  0800a0e1      mov      r0, r8                                    
  00001cc4  c8fcffeb      bl       #0xfec                                    
  00001cc8  38301be5      ldr      r3, [fp, #-0x38]                          
  00001ccc  000053e3      cmp      r3, #0                                    
  00001cd0  030000da      ble      #0x1ce4                                   
  00001cd4  40001be5      ldr      r0, [fp, #-0x40]                          
  00001cd8  0310a0e1      mov      r1, r3                                    
  00001cdc  44201be5      ldr      r2, [fp, #-0x44]                          
  00001ce0  38feffeb      bl       #0x15c8                                   
  00001ce4  0400a0e1      mov      r0, r4                                    
  00001ce8  bcfcffeb      bl       #0xfe0                                    
  00001cec  0000a0e3      mov      r0, #0                                    
  00001cf0  28d04be2      sub      sp, fp, #0x28                             
  00001cf4  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  00001cf8  4b030000      andeq    r0, r0, fp, asr #6                        
  00001cfc  1e030000      andeq    r0, r0, lr, lsl r3                        
  00001d00  22030000      andeq    r0, r0, r2, lsr #6                        
  00001d04  c2020000      andeq    r0, r0, r2, asr #5                        
  00001d08  be020000      strheq   r0, [r0], -lr                             
  00001d0c  be020000      strheq   r0, [r0], -lr                             
  00001d10  f6010000      strdeq   r0, r1, [r0], -r6                         
  00001d14  96010000      muleq    r0, r6, r1                                
  00001d18  000050e3      cmp      r0, #0                                    
  00001d1c  0dc0a0e1      mov      ip, sp                                    
  00001d20  18d82de9      push     {r3, r4, fp, ip, lr, pc}                  
  00001d24  04b04ce2      sub      fp, ip, #4                                
  00001d28  0100001a      bne      #0x1d34                                   
  00001d2c  0040a0e3      mov      r4, #0                                    
  00001d30  070000ea      b        #0x1d54                                   
  00001d34  94fcffeb      bl       #0xf8c                                    
  00001d38  010050e3      cmp      r0, #1                                    
  00001d3c  020c5013      cmpne    r0, #0x200                                
  00001d40  0040a0e1      mov      r4, r0                                    
  00001d44  f8ffff1a      bne      #0x1d2c                                   
  00001d48  970300e3      movw     r0, #0x397                                
  00001d4c  0410a0e1      mov      r1, r4                                    
  00001d50  f0fcffeb      bl       #0x1118                                   
  00001d54  0400a0e1      mov      r0, r4                                    
  00001d58  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                  
  00001d5c  0210a0e1      mov      r1, r2                                    
  00001d60  c8fcffea      b        #0x1088                                   
  00001d64  000050e3      cmp      r0, #0                                    
  00001d68  00005213      cmpne    r2, #0                                    
  00001d6c  0dc0a0e1      mov      ip, sp                                    
  00001d70  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}              
  00001d74  04b04ce2      sub      fp, ip, #4                                
  00001d78  14d04de2      sub      sp, sp, #0x14                             
  00001d7c  0340a0e1      mov      r4, r3                                    
  00001d80  01c0a0e1      mov      ip, r1                                    
  00001d84  0230a0e1      mov      r3, r2                                    
  00001d88  00e0a0e1      mov      lr, r0                                    
  00001d8c  0700000a      beq      #0x1db0                                   
  00001d90  000051e3      cmp      r1, #0                                    
  00001d94  00005413      cmpne    r4, #0                                    
  00001d98  0050a013      movne    r5, #0                                    
  00001d9c  0150a003      moveq    r5, #1                                    
  00001da0  0200000a      beq      #0x1db0                                   
  00001da4  006094e5      ldr      r6, [r4]                                  
  00001da8  3f0056e3      cmp      r6, #0x3f                                 
  00001dac  0b0000ca      bgt      #0x1de0                                   
  00001db0  000054e3      cmp      r4, #0                                    
  00001db4  40009fe5      ldr      r0, [pc, #0x40]                           
  00001db8  10108de8      stm      sp, {r4, ip}                              
  00001dbc  0e20a0e1      mov      r2, lr                                    
  00001dc0  00109415      ldrne    r1, [r4]                                  
  00001dc4  0410a001      moveq    r1, r4                                    
  00001dc8  00008fe0      add      r0, pc, r0                                
  00001dcc  08108de5      str      r1, [sp, #8]                              
  00001dd0  2410a0e3      mov      r1, #0x24                                 
  00001dd4  6ffcffeb      bl       #0xf98                                    
  00001dd8  0100a0e3      mov      r0, #1                                    
  00001ddc  040000ea      b        #0x1df4                                   
  00001de0  0530a0e1      mov      r3, r5                                    
  00001de4  86fcffeb      bl       #0x1004                                   
  00001de8  0500a0e1      mov      r0, r5                                    
  00001dec  4030a0e3      mov      r3, #0x40                                 
  00001df0  003084e5      str      r3, [r4]                                  
  00001df4  18d04be2      sub      sp, fp, #0x18                             
  00001df8  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}              
  00001dfc  e0000000      andeq    r0, r0, r0, ror #1                        
  00001e00  68775f73      cmpvc    pc, #104, #14                             
  00001e04  736c5f61      cmpvs    pc, r3, ror ip                            

### HW_SSL_X509ParseCommixFile @ 0x1a28
  00001a28  0dc0a0e1      mov      ip, sp                                    
  00001a2c  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  00001a30  04b04ce2      sub      fp, ip, #4                                
  00001a34  24d04de2      sub      sp, sp, #0x24                             
  00001a38  0260a0e1      mov      r6, r2                                    
  00001a3c  44300be5      str      r3, [fp, #-0x44]                          
  00001a40  0030a0e3      mov      r3, #0                                    
  00001a44  030050e1      cmp      r0, r3                                    
  00001a48  03005111      cmpne    r1, r3                                    
  00001a4c  30300be5      str      r3, [fp, #-0x30]                          
  00001a50  0170a0e1      mov      r7, r1                                    
  00001a54  0050a0e1      mov      r5, r0                                    
  00001a58  0100001a      bne      #0x1a64                                   
  00001a5c  060300e3      movw     r0, #0x306                                
  00001a60  080000ea      b        #0x1a88                                   
  00001a64  44201be5      ldr      r2, [fp, #-0x44]                          
  00001a68  000056e3      cmp      r6, #0                                    
  00001a6c  00005213      cmpne    r2, #0                                    
  00001a70  f9ffff0a      beq      #0x1a5c                                   
  00001a74  30104be2      sub      r1, fp, #0x30                             
  00001a78  70fdffeb      bl       #0x1040                                   
  00001a7c  000050e3      cmp      r0, #0                                    
  00001a80  0400000a      beq      #0x1a98                                   
  00001a84  090300e3      movw     r0, #0x309                                
  00001a88  0010e0e3      mvn      r1, #0                                    
  00001a8c  a1fdffeb      bl       #0x1118                                   
  00001a90  0000e0e3      mvn      r0, #0                                    
  00001a94  950000ea      b        #0x1cf0                                   
  00001a98  30001be5      ldr      r0, [fp, #-0x30]                          
  00001a9c  000050e3      cmp      r0, #0                                    
  00001aa0  f7ffff0a      beq      #0x1a84                                   
  00001aa4  010080e2      add      r0, r0, #1                                
  00001aa8  7cfdffeb      bl       #0x10a0                                   
  00001aac  004050e2      subs     r4, r0, #0                                
  00001ab0  c30fa003      moveq    r0, #0x30c                                
  00001ab4  f3ffff0a      beq      #0x1a88                                   
  00001ab8  38129fe5      ldr      r1, [pc, #0x238]                          
  00001abc  0500a0e1      mov      r0, r5                                    
  00001ac0  01108fe0      add      r1, pc, r1                                
  00001ac4  15fdffeb      bl       #0xf20                                    
  00001ac8  005050e2      subs     r5, r0, #0                                
  00001acc  0400a0e1      mov      r0, r4                                    
  00001ad0  1800000a      beq      #0x1b38                                   
  00001ad4  0530a0e1      mov      r3, r5                                    
  00001ad8  0110a0e3      mov      r1, #1                                    
  00001adc  30201be5      ldr      r2, [fp, #-0x30]                          
  00001ae0  3bfdffeb      bl       #0xfd4                                    
  00001ae4  30301be5      ldr      r3, [fp, #-0x30]                          
  00001ae8  030050e1      cmp      r0, r3                                    
  00001aec  0500a0e1      mov      r0, r5                                    
  00001af0  0100000a      beq      #0x1afc                                   
  00001af4  75fdffeb      bl       #0x10d0                                   
  00001af8  0d0000ea      b        #0x1b34                                   
  00001afc  f8519fe5      ldr      r5, [pc, #0x1f8]                          
  00001b00  72fdffeb      bl       #0x10d0                                   
  00001b04  0400a0e1      mov      r0, r4                                    
  00001b08  05508fe0      add      r5, pc, r5                                
  00001b0c  0510a0e1      mov      r1, r5                                    
  00001b10  74fdffeb      bl       #0x10e8                                   
  00001b14  009050e2      subs     sb, r0, #0                                
  00001b18  0500000a      beq      #0x1b34                                   
  00001b1c  dc819fe5      ldr      r8, [pc, #0x1dc]                          
  00001b20  08808fe0      add      r8, pc, r8                                
  00001b24  0810a0e1      mov      r1, r8                                    
  00001b28  6efdffeb      bl       #0x10e8                                   
  00001b2c  00a050e2      subs     sl, r0, #0                                
  00001b30  0200001a      bne      #0x1b40                                   
  00001b34  0400a0e1      mov      r0, r4                                    
  00001b38  28fdffeb      bl       #0xfe0                                    
  00001b3c  d3ffffea      b        #0x1a90                                   
  00001b40  0800a0e1      mov      r0, r8                                    
  00001b44  0a3069e0      rsb      r3, sb, sl                                
  00001b48  48300be5      str      r3, [fp, #-0x48]                          
  00001b4c  50fdffeb      bl       #0x1094                                   
  00001b50  48301be5      ldr      r3, [fp, #-0x48]                          
  00001b54  0510a0e1      mov      r1, r5                                    
  00001b58  003083e0      add      r3, r3, r0                                
  00001b5c  0a00a0e1      mov      r0, sl                                    
  00001b60  3c300be5      str      r3, [fp, #-0x3c]                          
  00001b64  5ffdffeb      bl       #0x10e8                                   
  00001b68  00a050e2      subs     sl, r0, #0                                
  00001b6c  0100001a      bne      #0x1b78                                   
  00001b70  0080a0e3      mov      r8, #0                                    
  00001b74  0a0000ea      b        #0x1ba4                                   
  00001b78  84519fe5      ldr      r5, [pc, #0x184]                          
  00001b7c  0a00a0e1      mov      r0, sl                                    
  00001b80  05508fe0      add      r5, pc, r5                                
  00001b84  0510a0e1      mov      r1, r5                                    
  00001b88  56fdffeb      bl       #0x10e8                                   
  00001b8c  000050e3      cmp      r0, #0                                    
  00001b90  f6ffff0a      beq      #0x1b70                                   
  00001b94  00806ae0      rsb      r8, sl, r0                                
  00001b98  0500a0e1      mov      r0, r5                                    
  00001b9c  3cfdffeb      bl       #0x1094                                   
  00001ba0  008088e0      add      r8, r8, r0                                
  00001ba4  5c119fe5      ldr      r1, [pc, #0x15c]                          
  00001ba8  0400a0e1      mov      r0, r4                                    
  00001bac  01108fe0      add      r1, pc, r1                                
  00001bb0  4cfdffeb      bl       #0x10e8                                   
  00001bb4  003050e2      subs     r3, r0, #0                                
  00001bb8  40300be5      str      r3, [fp, #-0x40]                          
  00001bbc  0100001a      bne      #0x1bc8                                   
  00001bc0  0030a0e3      mov      r3, #0                                    
  00001bc4  0c0000ea      b        #0x1bfc                                   
  00001bc8  3c519fe5      ldr      r5, [pc, #0x13c]                          
  00001bcc  05508fe0      add      r5, pc, r5                                
  00001bd0  0510a0e1      mov      r1, r5                                    
  00001bd4  43fdffeb      bl       #0x10e8                                   
  00001bd8  000050e3      cmp      r0, #0                                    
  00001bdc  f7ffff0a      beq      #0x1bc0                                   
  00001be0  40201be5      ldr      r2, [fp, #-0x40]                          
  00001be4  003062e0      rsb      r3, r2, r0                                
  00001be8  0500a0e1      mov      r0, r5                                    
  00001bec  48300be5      str      r3, [fp, #-0x48]                          
  00001bf0  27fdffeb      bl       #0x1094                                   
  00001bf4  48301be5      ldr      r3, [fp, #-0x48]                          
  00001bf8  003083e0      add      r3, r3, r0                                
  00001bfc  38300be5      str      r3, [fp, #-0x38]                          
  00001c00  3c301be5      ldr      r3, [fp, #-0x3c]                          
  00001c04  000053e3      cmp      r3, #0                                    
  00001c08  150000da      ble      #0x1c64                                   
  00001c0c  fc509fe5      ldr      r5, [pc, #0xfc]                           
  00001c10  0900a0e1      mov      r0, sb                                    
  00001c14  0310a0e1      mov      r1, r3                                    
  00001c18  05508fe0      add      r5, pc, r5                                
  00001c1c  0520a0e1      mov      r2, r5                                    
  00001c20  68feffeb      bl       #0x15c8                                   
  00001c24  0500a0e1      mov      r0, r5                                    
  00001c28  0afdffeb      bl       #0x1058                                   
  00001c2c  009050e2      subs     sb, r0, #0                                
  00001c30  0300001a      bne      #0x1c44                                   
  00001c34  0400a0e1      mov      r0, r4                                    
  00001c38  e8fcffeb      bl       #0xfe0                                    
  00001c3c  0500a0e1      mov      r0, r5                                    
  00001c40  160000ea      b        #0x1ca0                                   
  00001c44  fc2099e5      ldr      r2, [sb, #0xfc]                           
  00001c48  0500a0e1      mov      r0, r5                                    
  00001c4c  010052e3      cmp      r2, #1                                    
  00001c50  0710a001      moveq    r1, r7                                    
  00001c54  0610a011      movne    r1, r6                                    
  00001c58  c5fcffeb      bl       #0xf74                                    
  00001c5c  0900a0e1      mov      r0, sb                                    
  00001c60  e1fcffeb      bl       #0xfec                                    
  00001c64  000058e3      cmp      r8, #0                                    
  00001c68  160000da      ble      #0x1cc8                                   
  00001c6c  a0909fe5      ldr      sb, [pc, #0xa0]                           
  00001c70  0810a0e1      mov      r1, r8                                    
  00001c74  0a00a0e1      mov      r0, sl                                    
  00001c78  09908fe0      add      sb, pc, sb                                
  00001c7c  0920a0e1      mov      r2, sb                                    
  00001c80  50feffeb      bl       #0x15c8                                   
  00001c84  0900a0e1      mov      r0, sb                                    
  00001c88  f2fcffeb      bl       #0x1058                                   
  00001c8c  008050e2      subs     r8, r0, #0                                
  00001c90  0400001a      bne      #0x1ca8                                   
  00001c94  0400a0e1      mov      r0, r4                                    
  00001c98  d0fcffeb      bl       #0xfe0                                    
  00001c9c  0900a0e1      mov      r0, sb                                    
  00001ca0  c8fcffeb      bl       #0xfc8                                    
  00001ca4  79ffffea      b        #0x1a90                                   
  00001ca8  fc3098e5      ldr      r3, [r8, #0xfc]                           
  00001cac  0900a0e1      mov      r0, sb                                    
  00001cb0  010053e3      cmp      r3, #1                                    
  00001cb4  0710a001      moveq    r1, r7                                    
  00001cb8  0610a011      movne    r1, r6                                    
  00001cbc  acfcffeb      bl       #0xf74                                    
  00001cc0  0800a0e1      mov      r0, r8                                    
  00001cc4  c8fcffeb      bl       #0xfec                                    
  00001cc8  38301be5      ldr      r3, [fp, #-0x38]                          
  00001ccc  000053e3      cmp      r3, #0                                    
  00001cd0  030000da      ble      #0x1ce4                                   
  00001cd4  40001be5      ldr      r0, [fp, #-0x40]                          
  00001cd8  0310a0e1      mov      r1, r3                                    
  00001cdc  44201be5      ldr      r2, [fp, #-0x44]                          
  00001ce0  38feffeb      bl       #0x15c8                                   
  00001ce4  0400a0e1      mov      r0, r4                                    
  00001ce8  bcfcffeb      bl       #0xfe0                                    
  00001cec  0000a0e3      mov      r0, #0                                    
  00001cf0  28d04be2      sub      sp, fp, #0x28                             
  00001cf4  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  00001cf8  4b030000      andeq    r0, r0, fp, asr #6                        
  00001cfc  1e030000      andeq    r0, r0, lr, lsl r3                        
  00001d00  22030000      andeq    r0, r0, r2, lsr #6                        
  00001d04  c2020000      andeq    r0, r0, r2, asr #5                        
  00001d08  be020000      strheq   r0, [r0], -lr                             
  00001d0c  be020000      strheq   r0, [r0], -lr                             
  00001d10  f6010000      strdeq   r0, r1, [r0], -r6                         
  00001d14  96010000      muleq    r0, r6, r1                                
  00001d18  000050e3      cmp      r0, #0                                    
  00001d1c  0dc0a0e1      mov      ip, sp                                    
  00001d20  18d82de9      push     {r3, r4, fp, ip, lr, pc}                  
  00001d24  04b04ce2      sub      fp, ip, #4                                
  00001d28  0100001a      bne      #0x1d34                                   
  00001d2c  0040a0e3      mov      r4, #0                                    
  00001d30  070000ea      b        #0x1d54                                   
  00001d34  94fcffeb      bl       #0xf8c                                    
  00001d38  010050e3      cmp      r0, #1                                    
  00001d3c  020c5013      cmpne    r0, #0x200                                
  00001d40  0040a0e1      mov      r4, r0                                    
  00001d44  f8ffff1a      bne      #0x1d2c                                   
  00001d48  970300e3      movw     r0, #0x397                                
  00001d4c  0410a0e1      mov      r1, r4                                    
  00001d50  f0fcffeb      bl       #0x1118                                   
  00001d54  0400a0e1      mov      r0, r4                                    
  00001d58  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                  
  00001d5c  0210a0e1      mov      r1, r2                                    
  00001d60  c8fcffea      b        #0x1088                                   
  00001d64  000050e3      cmp      r0, #0                                    
  00001d68  00005213      cmpne    r2, #0                                    
  00001d6c  0dc0a0e1      mov      ip, sp                                    
  00001d70  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}              
  00001d74  04b04ce2      sub      fp, ip, #4                                
  00001d78  14d04de2      sub      sp, sp, #0x14                             
  00001d7c  0340a0e1      mov      r4, r3                                    
  00001d80  01c0a0e1      mov      ip, r1                                    
  00001d84  0230a0e1      mov      r3, r2                                    
  00001d88  00e0a0e1      mov      lr, r0                                    
  00001d8c  0700000a      beq      #0x1db0                                   
  00001d90  000051e3      cmp      r1, #0                                    
  00001d94  00005413      cmpne    r4, #0                                    
  00001d98  0050a013      movne    r5, #0                                    
  00001d9c  0150a003      moveq    r5, #1                                    
  00001da0  0200000a      beq      #0x1db0                                   
  00001da4  006094e5      ldr      r6, [r4]                                  
  00001da8  3f0056e3      cmp      r6, #0x3f                                 
  00001dac  0b0000ca      bgt      #0x1de0                                   
  00001db0  000054e3      cmp      r4, #0                                    
  00001db4  40009fe5      ldr      r0, [pc, #0x40]                           
  00001db8  10108de8      stm      sp, {r4, ip}                              
  00001dbc  0e20a0e1      mov      r2, lr                                    
  00001dc0  00109415      ldrne    r1, [r4]                                  
  00001dc4  0410a001      moveq    r1, r4                                    
  00001dc8  00008fe0      add      r0, pc, r0                                
  00001dcc  08108de5      str      r1, [sp, #8]                              
  00001dd0  2410a0e3      mov      r1, #0x24                                 
  00001dd4  6ffcffeb      bl       #0xf98                                    
  00001dd8  0100a0e3      mov      r0, #1                                    
  00001ddc  040000ea      b        #0x1df4                                   
  00001de0  0530a0e1      mov      r3, r5                                    
  00001de4  86fcffeb      bl       #0x1004                                   
  00001de8  0500a0e1      mov      r0, r5                                    
  00001dec  4030a0e3      mov      r3, #0x40                                 
  00001df0  003084e5      str      r3, [r4]                                  
  00001df4  18d04be2      sub      sp, fp, #0x18                             
  00001df8  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}              
  00001dfc  e0000000      andeq    r0, r0, r0, ror #1                        
  00001e00  68775f73      cmpvc    pc, #104, #14                             
  00001e04  736c5f61      cmpvs    pc, r3, ror ip                            