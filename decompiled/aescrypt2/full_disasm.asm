# aescrypt2  –  Full ARM32 Disassembly
# Size:      17,920 bytes
# .text:     0x00000f6c  size=6,876  (1719 instructions)
# Exports:   13
# PLT imps:  44


; ─── main @ 0x00000f6c ───
  00000f6c  0dc0a0e1      mov      ip, sp                                      
  00000f70  8020a0e3      mov      r2, #0x80                                   
  00000f74  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  00000f78  04b04ce2      sub      fp, ip, #4                                  
  00000f7c  51de4de2      sub      sp, sp, #0x510                              
  00000f80  0050a0e1      mov      r5, r0                                      
  00000f84  08d04de2      sub      sp, sp, #8                                  
  00000f88  510e4be2      sub      r0, fp, #0x510                              
  00000f8c  0160a0e1      mov      r6, r1                                      
  00000f90  0c0040e2      sub      r0, r0, #0xc                                
  00000f94  0010a0e3      mov      r1, #0                                      
  00000f98  0040e0e3      mvn      r4, #0                                      
  00000f9c  28450be5      str      r4, [fp, #-0x528]                           
  00000fa0  88ffffeb      bl       #0xdc8                                      
  00000fa4  490e4be2      sub      r0, fp, #0x490                              
  00000fa8  0010a0e3      mov      r1, #0                                      
  00000fac  8020a0e3      mov      r2, #0x80                                   
  00000fb0  0c0040e2      sub      r0, r0, #0xc                                
  00000fb4  83ffffeb      bl       #0xdc8                                      
  00000fb8  410e4be2      sub      r0, fp, #0x410                              
  00000fbc  0010a0e3      mov      r1, #0                                      
  00000fc0  022ca0e3      mov      r2, #0x200                                  
  00000fc4  0c0040e2      sub      r0, r0, #0xc                                
  00000fc8  7effffeb      bl       #0xdc8                                      
  00000fcc  870f4be2      sub      r0, fp, #0x21c                              
  00000fd0  0010a0e3      mov      r1, #0                                      
  00000fd4  022ca0e3      mov      r2, #0x200                                  
  00000fd8  7affffeb      bl       #0xdc8                                      
  00000fdc  0030a0e3      mov      r3, #0                                      
  00000fe0  24350be5      str      r3, [fp, #-0x524]                           
  00000fe4  0230c5e3      bic      r3, r5, #2                                  
  00000fe8  040053e3      cmp      r3, #4                                      
  00000fec  20450be5      str      r4, [fp, #-0x520]                           
  00000ff0  0500000a      beq      #0x100c                                     
  00000ff4  050053e3      cmp      r3, #5                                      
  00000ff8  0300000a      beq      #0x100c                                     
  00000ffc  08049fe5      ldr      r0, [pc, #0x408]                            
  00001000  00008fe0      add      r0, pc, r0                                  
  00001004  72ffffeb      bl       #0xdd4                                      
  00001008  fc0000ea      b        #0x1400                                     
  0000100c  513e4be2      sub      r3, fp, #0x510                              
  00001010  040096e5      ldr      r0, [r6, #4]                                
  00001014  0c3043e2      sub      r3, r3, #0xc                                
  00001018  0c1043e2      sub      r1, r3, #0xc                                
  0000101c  9cffffeb      bl       #0xe94                                      
  00001020  28351be5      ldr      r3, [fp, #-0x528]                           
  00001024  010053e3      cmp      r3, #1                                      
  00001028  0500009a      bls      #0x1044                                     
  0000102c  dc039fe5      ldr      r0, [pc, #0x3dc]                            
  00001030  f62300e3      movw     r2, #0x3f6                                  
  00001034  d8139fe5      ldr      r1, [pc, #0x3d8]                            
  00001038  00008fe0      add      r0, pc, r0                                  
  0000103c  01108fe0      add      r1, pc, r1                                  
  00001040  d00000ea      b        #0x1388                                     
  00001044  8010a0e3      mov      r1, #0x80                                   
  00001048  510e4be2      sub      r0, fp, #0x510                              
  0000104c  0130a0e1      mov      r3, r1                                      
  00001050  082096e5      ldr      r2, [r6, #8]                                
  00001054  0c0040e2      sub      r0, r0, #0xc                                
  00001058  45ffffeb      bl       #0xd74                                      
  0000105c  8010a0e3      mov      r1, #0x80                                   
  00001060  490e4be2      sub      r0, fp, #0x490                              
  00001064  0c2096e5      ldr      r2, [r6, #0xc]                              
  00001068  0c0040e2      sub      r0, r0, #0xc                                
  0000106c  0130a0e1      mov      r3, r1                                      
  00001070  3fffffeb      bl       #0xd74                                      
  00001074  070055e3      cmp      r5, #7                                      
  00001078  4c00001a      bne      #0x11b0                                     
  0000107c  180096e5      ldr      r0, [r6, #0x18]                             
  00001080  521e4be2      sub      r1, fp, #0x520                              
  00001084  82ffffeb      bl       #0xe94                                      
  00001088  28551be5      ldr      r5, [fp, #-0x528]                           
  0000108c  000055e3      cmp      r5, #0                                      
  00001090  0200000a      beq      #0x10a0                                     
  00001094  0050a0e3      mov      r5, #0                                      
  00001098  0040e0e3      mvn      r4, #0                                      
  0000109c  210000ea      b        #0x1128                                     
  000010a0  20351be5      ldr      r3, [fp, #-0x520]                           
  000010a4  010053e3      cmp      r3, #1                                      
  000010a8  f9ffff1a      bne      #0x1094                                     
  000010ac  64039fe5      ldr      r0, [pc, #0x364]                            
  000010b0  871f4be2      sub      r1, fp, #0x21c                              
  000010b4  ff2100e3      movw     r2, #0x1ff                                  
  000010b8  00008fe0      add      r0, pc, r0                                  
  000010bc  26ffffeb      bl       #0xd5c                                      
  000010c0  010070e3      cmn      r0, #1                                      
  000010c4  f2ffff0a      beq      #0x1094                                     
  000010c8  870f4be2      sub      r0, fp, #0x21c                              
  000010cc  48439fe5      ldr      r4, [pc, #0x348]                            
  000010d0  81ffffeb      bl       #0xedc                                      
  000010d4  04408fe0      add      r4, pc, r4                                  
  000010d8  0070a0e1      mov      r7, r0                                      
  000010dc  0400a0e1      mov      r0, r4                                      
  000010e0  7dffffeb      bl       #0xedc                                      
  000010e4  412e4be2      sub      r2, fp, #0x410                              
  000010e8  00408de5      str      r4, [sp]                                    
  000010ec  0710a0e1      mov      r1, r7                                      
  000010f0  0c2042e2      sub      r2, r2, #0xc                                
  000010f4  ff3100e3      movw     r3, #0x1ff                                  
  000010f8  04008de5      str      r0, [sp, #4]                                
  000010fc  870f4be2      sub      r0, fp, #0x21c                              
  00001100  81ffffeb      bl       #0xf0c                                      
  00001104  004050e2      subs     r4, r0, #0                                  
  00001108  0600001a      bne      #0x1128                                     
  0000110c  410e4be2      sub      r0, fp, #0x410                              
  00001110  0c0040e2      sub      r0, r0, #0xc                                
  00001114  70ffffeb      bl       #0xedc                                      
  00001118  0050a0e1      mov      r5, r0                                      
  0000111c  870f4be2      sub      r0, fp, #0x21c                              
  00001120  6dffffeb      bl       #0xedc                                      
  00001124  24050be5      str      r0, [fp, #-0x524]                           
  00001128  24351be5      ldr      r3, [fp, #-0x524]                           
  0000112c  000053e3      cmp      r3, #0                                      
  00001130  00005513      cmpne    r5, #0                                      
  00001134  6200001a      bne      #0x12c4                                     
  00001138  021ca0e3      mov      r1, #0x200                                  
  0000113c  0020a0e3      mov      r2, #0                                      
  00001140  0130a0e1      mov      r3, r1                                      
  00001144  870f4be2      sub      r0, fp, #0x21c                              
  00001148  30ffffeb      bl       #0xe10                                      
  0000114c  021ca0e3      mov      r1, #0x200                                  
  00001150  410e4be2      sub      r0, fp, #0x410                              
  00001154  0130a0e1      mov      r3, r1                                      
  00001158  0020a0e3      mov      r2, #0                                      
  0000115c  0c0040e2      sub      r0, r0, #0xc                                
  00001160  2affffeb      bl       #0xe10                                      
  00001164  410e4be2      sub      r0, fp, #0x410                              
  00001168  021ca0e3      mov      r1, #0x200                                  
  0000116c  102096e5      ldr      r2, [r6, #0x10]                             
  00001170  ff3100e3      movw     r3, #0x1ff                                  
  00001174  0c0040e2      sub      r0, r0, #0xc                                
  00001178  fdfeffeb      bl       #0xd74                                      
  0000117c  410e4be2      sub      r0, fp, #0x410                              
  00001180  0c0040e2      sub      r0, r0, #0xc                                
  00001184  54ffffeb      bl       #0xedc                                      
  00001188  021ca0e3      mov      r1, #0x200                                  
  0000118c  142096e5      ldr      r2, [r6, #0x14]                             
  00001190  ff3100e3      movw     r3, #0x1ff                                  
  00001194  0050a0e1      mov      r5, r0                                      
  00001198  870f4be2      sub      r0, fp, #0x21c                              
  0000119c  f4feffeb      bl       #0xd74                                      
  000011a0  870f4be2      sub      r0, fp, #0x21c                              
  000011a4  4cffffeb      bl       #0xedc                                      
  000011a8  24050be5      str      r0, [fp, #-0x524]                           
  000011ac  440000ea      b        #0x12c4                                     
  000011b0  050055e3      cmp      r5, #5                                      
  000011b4  2a00001a      bne      #0x1264                                     
  000011b8  410e4be2      sub      r0, fp, #0x410                              
  000011bc  021ca0e3      mov      r1, #0x200                                  
  000011c0  102096e5      ldr      r2, [r6, #0x10]                             
  000011c4  ff3100e3      movw     r3, #0x1ff                                  
  000011c8  0c0040e2      sub      r0, r0, #0xc                                
  000011cc  e8feffeb      bl       #0xd74                                      
  000011d0  410e4be2      sub      r0, fp, #0x410                              
  000011d4  0c0040e2      sub      r0, r0, #0xc                                
  000011d8  3fffffeb      bl       #0xedc                                      
  000011dc  0050a0e1      mov      r5, r0                                      
  000011e0  410e4be2      sub      r0, fp, #0x410                              
  000011e4  0c0040e2      sub      r0, r0, #0xc                                
  000011e8  3bffffeb      bl       #0xedc                                      
  000011ec  513e4be2      sub      r3, fp, #0x510                              
  000011f0  0c3043e2      sub      r3, r3, #0xc                                
  000011f4  081043e2      sub      r1, r3, #8                                  
  000011f8  dafeffeb      bl       #0xd68                                      
  000011fc  004050e2      subs     r4, r0, #0                                  
  00001200  2c040013      movwne   r0, #0x42c                                  
  00001204  1300001a      bne      #0x1258                                     
  00001208  410e4be2      sub      r0, fp, #0x410                              
  0000120c  0c429fe5      ldr      r4, [pc, #0x20c]                            
  00001210  0c0040e2      sub      r0, r0, #0xc                                
  00001214  30ffffeb      bl       #0xedc                                      
  00001218  04408fe0      add      r4, pc, r4                                  
  0000121c  24651be5      ldr      r6, [fp, #-0x524]                           
  00001220  0070a0e1      mov      r7, r0                                      
  00001224  0400a0e1      mov      r0, r4                                      
  00001228  2bffffeb      bl       #0xedc                                      
  0000122c  00408de5      str      r4, [sp]                                    
  00001230  0710a0e1      mov      r1, r7                                      
  00001234  872f4be2      sub      r2, fp, #0x21c                              
  00001238  0630a0e1      mov      r3, r6                                      
  0000123c  04008de5      str      r0, [sp, #4]                                
  00001240  410e4be2      sub      r0, fp, #0x410                              
  00001244  0c0040e2      sub      r0, r0, #0xc                                
  00001248  dbfeffeb      bl       #0xdbc                                      
  0000124c  004050e2      subs     r4, r0, #0                                  
  00001250  1b00000a      beq      #0x12c4                                     
  00001254  350400e3      movw     r0, #0x435                                  
  00001258  0410a0e1      mov      r1, r4                                      
  0000125c  090100eb      bl       #0x1688                                     
  00001260  660000ea      b        #0x1400                                     
  00001264  060055e3      cmp      r5, #6                                      
  00001268  0040e013      mvnne    r4, #0                                      
  0000126c  0050a013      movne    r5, #0                                      
  00001270  1300001a      bne      #0x12c4                                     
  00001274  410e4be2      sub      r0, fp, #0x410                              
  00001278  021ca0e3      mov      r1, #0x200                                  
  0000127c  102096e5      ldr      r2, [r6, #0x10]                             
  00001280  ff3100e3      movw     r3, #0x1ff                                  
  00001284  0c0040e2      sub      r0, r0, #0xc                                
  00001288  0040e0e3      mvn      r4, #0                                      
  0000128c  b8feffeb      bl       #0xd74                                      
  00001290  410e4be2      sub      r0, fp, #0x410                              
  00001294  0c0040e2      sub      r0, r0, #0xc                                
  00001298  0fffffeb      bl       #0xedc                                      
  0000129c  021ca0e3      mov      r1, #0x200                                  
  000012a0  142096e5      ldr      r2, [r6, #0x14]                             
  000012a4  ff3100e3      movw     r3, #0x1ff                                  
  000012a8  0050a0e1      mov      r5, r0                                      
  000012ac  870f4be2      sub      r0, fp, #0x21c                              
  000012b0  affeffeb      bl       #0xd74                                      
  000012b4  870f4be2      sub      r0, fp, #0x21c                              
  000012b8  07ffffeb      bl       #0xedc                                      
  000012bc  24050be5      str      r0, [fp, #-0x524]                           
  000012c0  ffffffea      b        #0x12c4                                     
  000012c4  28351be5      ldr      r3, [fp, #-0x528]                           
  000012c8  010053e3      cmp      r3, #1                                      
  000012cc  2000001a      bne      #0x1354                                     
  000012d0  410e4be2      sub      r0, fp, #0x410                              
  000012d4  0c0040e2      sub      r0, r0, #0xc                                
  000012d8  fffeffeb      bl       #0xedc                                      
  000012dc  000050e3      cmp      r0, #0                                      
  000012e0  1b00001a      bne      #0x1354                                     
  000012e4  870f4be2      sub      r0, fp, #0x21c                              
  000012e8  fbfeffeb      bl       #0xedc                                      
  000012ec  000050e3      cmp      r0, #0                                      
  000012f0  1700000a      beq      #0x1354                                     
  000012f4  870f4be2      sub      r0, fp, #0x21c                              
  000012f8  24419fe5      ldr      r4, [pc, #0x124]                            
  000012fc  f6feffeb      bl       #0xedc                                      
  00001300  04408fe0      add      r4, pc, r4                                  
  00001304  0060a0e1      mov      r6, r0                                      
  00001308  0400a0e1      mov      r0, r4                                      
  0000130c  f2feffeb      bl       #0xedc                                      
  00001310  412e4be2      sub      r2, fp, #0x410                              
  00001314  00408de5      str      r4, [sp]                                    
  00001318  0610a0e1      mov      r1, r6                                      
  0000131c  0c2042e2      sub      r2, r2, #0xc                                
  00001320  023ca0e3      mov      r3, #0x200                                  
  00001324  04008de5      str      r0, [sp, #4]                                
  00001328  870f4be2      sub      r0, fp, #0x21c                              
  0000132c  f6feffeb      bl       #0xf0c                                      
  00001330  004050e2      subs     r4, r0, #0                                  
  00001334  0600000a      beq      #0x1354                                     
  00001338  870f4be2      sub      r0, fp, #0x21c                              
  0000133c  e6feffeb      bl       #0xedc                                      
  00001340  0410a0e1      mov      r1, r4                                      
  00001344  0020a0e1      mov      r2, r0                                      
  00001348  4d0400e3      movw     r0, #0x44d                                  
  0000134c  ba0000eb      bl       #0x163c                                     
  00001350  2a0000ea      b        #0x1400                                     
  00001354  510e4be2      sub      r0, fp, #0x510                              
  00001358  491e4be2      sub      r1, fp, #0x490                              
  0000135c  0c0040e2      sub      r0, r0, #0xc                                
  00001360  0c1041e2      sub      r1, r1, #0xc                                
  00001364  8020a0e3      mov      r2, #0x80                                   
  00001368  f0feffeb      bl       #0xf30                                      
  0000136c  000050e3      cmp      r0, #0                                      
  00001370  0700001a      bne      #0x1394                                     
  00001374  ac009fe5      ldr      r0, [pc, #0xac]                             
  00001378  562400e3      movw     r2, #0x456                                  
  0000137c  a8109fe5      ldr      r1, [pc, #0xa8]                             
  00001380  00008fe0      add      r0, pc, r0                                  
  00001384  01108fe0      add      r1, pc, r1                                  
  00001388  91feffeb      bl       #0xdd4                                      
  0000138c  0000e0e3      mvn      r0, #0                                      
  00001390  1b0000ea      b        #0x1404                                     
  00001394  28351be5      ldr      r3, [fp, #-0x528]                           
  00001398  000053e3      cmp      r3, #0                                      
  0000139c  0c00001a      bne      #0x13d4                                     
  000013a0  873f4be2      sub      r3, fp, #0x21c                              
  000013a4  00308de5      str      r3, [sp]                                    
  000013a8  24351be5      ldr      r3, [fp, #-0x524]                           
  000013ac  510e4be2      sub      r0, fp, #0x510                              
  000013b0  491e4be2      sub      r1, fp, #0x490                              
  000013b4  412e4be2      sub      r2, fp, #0x410                              
  000013b8  0c1041e2      sub      r1, r1, #0xc                                
  000013bc  0c2042e2      sub      r2, r2, #0xc                                
  000013c0  04308de5      str      r3, [sp, #4]                                
  000013c4  0c0040e2      sub      r0, r0, #0xc                                
  000013c8  0530a0e1      mov      r3, r5                                      
  000013cc  b90100eb      bl       #0x1ab8                                     
  000013d0  090000ea      b        #0x13fc                                     
  000013d4  010053e3      cmp      r3, #1                                      
  000013d8  0800001a      bne      #0x1400                                     
  000013dc  510e4be2      sub      r0, fp, #0x510                              
  000013e0  491e4be2      sub      r1, fp, #0x490                              
  000013e4  412e4be2      sub      r2, fp, #0x410                              
  000013e8  0c0040e2      sub      r0, r0, #0xc                                
  000013ec  0c1041e2      sub      r1, r1, #0xc                                
  000013f0  0c2042e2      sub      r2, r2, #0xc                                
  000013f4  0530a0e1      mov      r3, r5                                      
  000013f8  f10300eb      bl       #0x23c4                                     
  000013fc  0040a0e1      mov      r4, r0                                      
  00001400  0400a0e1      mov      r0, r4                                      
  00001404  1cd04be2      sub      sp, fp, #0x1c                               
  00001408  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  0000140c  f6210000      strdeq   r2, r3, [r0], -r6                           
  00001410  41220000      andeq    r2, r0, r1, asr #4                          
  00001414  141e0000      andeq    r1, r0, r4, lsl lr                          
  00001418  e3210000      andeq    r2, r0, r3, ror #3                          
  0000141c  3b200000      andeq    r2, r0, fp, lsr r0                          
  00001420  f71e0000      strdeq   r1, r2, [r0], -r7                           
  00001424  0f1e0000      andeq    r1, r0, pc, lsl #28                         
  00001428  361f0000      andeq    r1, r0, r6, lsr pc                          
  0000142c  cc1a0000      andeq    r1, r0, ip, asr #21                         

; ─── _start @ 0x00001430 ───
  00001430  00b0a0e3      mov      fp, #0                                      
  00001434  00e0a0e3      mov      lr, #0                                      
  00001438  04109de4      pop      {r1}                                        
  0000143c  0d20a0e1      mov      r2, sp                                      
  00001440  04202de5      str      r2, [sp, #-4]!                              
  00001444  04002de5      str      r0, [sp, #-4]!                              
  00001448  28a09fe5      ldr      sl, [pc, #0x28]                             
  0000144c  24308fe2      add      r3, pc, #0x24                               
  00001450  03a08ae0      add      sl, sl, r3                                  
  00001454  20c09fe5      ldr      ip, [pc, #0x20]                             
  00001458  0c009ae7      ldr      r0, [sl, ip]                                
  0000145c  04002de5      str      r0, [sp, #-4]!                              
  00001460  18c09fe5      ldr      ip, [pc, #0x18]                             
  00001464  0c309ae7      ldr      r3, [sl, ip]                                
  00001468  14c09fe5      ldr      ip, [pc, #0x14]                             
  0000146c  0c009ae7      ldr      r0, [sl, ip]                                
  00001470  48feffea      b        #0xd98                                      
  00001474  44feffeb      bl       #0xd8c                                      
  00001478  88ab0000      andeq    sl, r0, r8, lsl #23                         
  0000147c  c4000000      andeq    r0, r0, r4, asr #1                          
  00001480  d4000000      ldrdeq   r0, r1, [r0], -r4                           
  00001484  bc000000      strheq   r0, [r0], -ip                               
  00001488  3c209fe5      ldr      r2, [pc, #0x3c]                             
  0000148c  3c009fe5      ldr      r0, [pc, #0x3c]                             
  00001490  02208fe0      add      r2, pc, r2                                  
  00001494  00008fe0      add      r0, pc, r0                                  
  00001498  032082e2      add      r2, r2, #3                                  
  0000149c  022060e0      rsb      r2, r0, r2                                  
  000014a0  08402de9      push     {r3, lr}                                    
  000014a4  060052e3      cmp      r2, #6                                      
  000014a8  24309fe5      ldr      r3, [pc, #0x24]                             
  000014ac  03308fe0      add      r3, pc, r3                                  
  000014b0  0880bd98      popls    {r3, pc}                                    
  000014b4  1c209fe5      ldr      r2, [pc, #0x1c]                             
  000014b8  023093e7      ldr      r3, [r3, r2]                                
  000014bc  000053e3      cmp      r3, #0                                      
  000014c0  0880bd08      popeq    {r3, pc}                                    
  000014c4  33ff2fe1      blx      r3                                          
  000014c8  0880bde8      pop      {r3, pc}                                    
  000014cc  54ac0000      andeq    sl, r0, r4, asr ip                          
  000014d0  50ac0000      andeq    sl, r0, r0, asr ip                          
  000014d4  4cab0000      andeq    sl, r0, ip, asr #22                         
  000014d8  d0000000      ldrdeq   r0, r1, [r0], -r0                           
  000014dc  08402de9      push     {r3, lr}                                    
  000014e0  40009fe5      ldr      r0, [pc, #0x40]                             
  000014e4  40309fe5      ldr      r3, [pc, #0x40]                             
  000014e8  00008fe0      add      r0, pc, r0                                  
  000014ec  3c209fe5      ldr      r2, [pc, #0x3c]                             
  000014f0  03308fe0      add      r3, pc, r3                                  
  000014f4  033060e0      rsb      r3, r0, r3                                  
  000014f8  02208fe0      add      r2, pc, r2                                  
  000014fc  4331a0e1      asr      r3, r3, #2                                  
  00001500  a33f83e0      add      r3, r3, r3, lsr #31                         
  00001504  c330b0e1      asrs     r3, r3, #1                                  
  00001508  0880bd08      popeq    {r3, pc}                                    
  0000150c  20109fe5      ldr      r1, [pc, #0x20]                             
  00001510  012092e7      ldr      r2, [r2, r1]                                
  00001514  000052e3      cmp      r2, #0                                      
  00001518  0880bd08      popeq    {r3, pc}                                    
  0000151c  0310a0e1      mov      r1, r3                                      
  00001520  32ff2fe1      blx      r2                                          
  00001524  0880bde8      pop      {r3, pc}                                    
  00001528  fcab0000      strdeq   sl, fp, [r0], -ip                           
  0000152c  f4ab0000      strdeq   sl, fp, [r0], -r4                           
  00001530  00ab0000      andeq    sl, r0, r0, lsl #22                         
  00001534  e0000000      andeq    r0, r0, r0, ror #1                          
  00001538  68309fe5      ldr      r3, [pc, #0x68]                             
  0000153c  10402de9      push     {r4, lr}                                    
  00001540  03308fe0      add      r3, pc, r3                                  
  00001544  60409fe5      ldr      r4, [pc, #0x60]                             
  00001548  0030d3e5      ldrb     r3, [r3]                                    
  0000154c  04408fe0      add      r4, pc, r4                                  
  00001550  000053e3      cmp      r3, #0                                      
  00001554  1080bd18      popne    {r4, pc}                                    
  00001558  50309fe5      ldr      r3, [pc, #0x50]                             
  0000155c  033094e7      ldr      r3, [r4, r3]                                
  00001560  000053e3      cmp      r3, #0                                      
  00001564  0200000a      beq      #0x1574                                     
  00001568  44309fe5      ldr      r3, [pc, #0x44]                             
  0000156c  03009fe7      ldr      r0, [pc, r3]                                
  00001570  50feffeb      bl       #0xeb8                                      
  00001574  c3ffffeb      bl       #0x1488                                     
  00001578  38309fe5      ldr      r3, [pc, #0x38]                             
  0000157c  033094e7      ldr      r3, [r4, r3]                                
  00001580  000053e3      cmp      r3, #0                                      
  00001584  0200000a      beq      #0x1594                                     
  00001588  2c009fe5      ldr      r0, [pc, #0x2c]                             
  0000158c  00008fe0      add      r0, pc, r0                                  
  00001590  06feffeb      bl       #0xdb0                                      
  00001594  24309fe5      ldr      r3, [pc, #0x24]                             
  00001598  0120a0e3      mov      r2, #1                                      
  0000159c  03308fe0      add      r3, pc, r3                                  
  000015a0  0020c3e5      strb     r2, [r3]                                    
  000015a4  1080bde8      pop      {r4, pc}                                    
  000015a8  a4ab0000      andeq    sl, r0, r4, lsr #23                         
  000015ac  acaa0000      andeq    sl, r0, ip, lsr #21                         
  000015b0  d8000000      ldrdeq   r0, r1, [r0], -r8                           
  000015b4  74ab0000      andeq    sl, r0, r4, ror fp                          
  000015b8  c8000000      andeq    r0, r0, r8, asr #1                          
  000015bc  6c1e0000      andeq    r1, r0, ip, ror #28                         
  000015c0  48ab0000      andeq    sl, r0, r8, asr #22                         
  000015c4  10402de9      push     {r4, lr}                                    
  000015c8  54409fe5      ldr      r4, [pc, #0x54]                             
  000015cc  54309fe5      ldr      r3, [pc, #0x54]                             
  000015d0  04408fe0      add      r4, pc, r4                                  
  000015d4  033094e7      ldr      r3, [r4, r3]                                
  000015d8  000053e3      cmp      r3, #0                                      
  000015dc  0400000a      beq      #0x15f4                                     
  000015e0  44009fe5      ldr      r0, [pc, #0x44]                             
  000015e4  44109fe5      ldr      r1, [pc, #0x44]                             
  000015e8  00008fe0      add      r0, pc, r0                                  
  000015ec  01108fe0      add      r1, pc, r1                                  
  000015f0  33feffeb      bl       #0xec4                                      
  000015f4  38009fe5      ldr      r0, [pc, #0x38]                             
  000015f8  00008fe0      add      r0, pc, r0                                  
  000015fc  003090e5      ldr      r3, [r0]                                    
  00001600  000053e3      cmp      r3, #0                                      
  00001604  0400000a      beq      #0x161c                                     
  00001608  28309fe5      ldr      r3, [pc, #0x28]                             
  0000160c  033094e7      ldr      r3, [r4, r3]                                
  00001610  000053e3      cmp      r3, #0                                      
  00001614  0000000a      beq      #0x161c                                     
  00001618  33ff2fe1      blx      r3                                          
  0000161c  1040bde8      pop      {r4, lr}                                    
  00001620  adffffea      b        #0x14dc                                     
  00001624  28aa0000      andeq    sl, r0, r8, lsr #20                         
  00001628  dc000000      ldrdeq   r0, r1, [r0], -ip                           
  0000162c  101e0000      andeq    r1, r0, r0, lsl lr                          
  00001630  fcaa0000      strdeq   sl, fp, [r0], -ip                           
  00001634  04a90000      andeq    sl, r0, r4, lsl #18                         
  00001638  cc000000      andeq    r0, r0, ip, asr #1                          
  0000163c  0dc0a0e1      mov      ip, sp                                      
  00001640  0230a0e1      mov      r3, r2                                      
  00001644  10d82de9      push     {r4, fp, ip, lr, pc}                        
  00001648  0040a0e1      mov      r4, r0                                      
  0000164c  14d04de2      sub      sp, sp, #0x14                               
  00001650  2c009fe5      ldr      r0, [pc, #0x2c]                             
  00001654  04b04ce2      sub      fp, ip, #4                                  
  00001658  01e0a0e1      mov      lr, r1                                      
  0000165c  00c0a0e3      mov      ip, #0                                      
  00001660  00008fe0      add      r0, pc, r0                                  
  00001664  00c08de5      str      ip, [sp]                                    
  00001668  04c08de5      str      ip, [sp, #4]                                
  0000166c  0410a0e1      mov      r1, r4                                      
  00001670  08c08de5      str      ip, [sp, #8]                                
  00001674  0e20a0e1      mov      r2, lr                                      
  00001678  defdffeb      bl       #0xdf8                                      
  0000167c  10d04be2      sub      sp, fp, #0x10                               
  00001680  10a89de8      ldm      sp, {r4, fp, sp, pc}                        
  00001684  f0170000      strdeq   r1, r2, [r0], -r0                           
  00001688  0dc0a0e1      mov      ip, sp                                      
  0000168c  0030a0e3      mov      r3, #0                                      
  00001690  00d82de9      push     {fp, ip, lr, pc}                            
  00001694  04b04ce2      sub      fp, ip, #4                                  
  00001698  10d04de2      sub      sp, sp, #0x10                               
  0000169c  00c0a0e1      mov      ip, r0                                      
  000016a0  20009fe5      ldr      r0, [pc, #0x20]                             
  000016a4  0120a0e1      mov      r2, r1                                      
  000016a8  00308de5      str      r3, [sp]                                    
  000016ac  04308de5      str      r3, [sp, #4]                                
  000016b0  00008fe0      add      r0, pc, r0                                  
  000016b4  08308de5      str      r3, [sp, #8]                                
  000016b8  0c10a0e1      mov      r1, ip                                      
  000016bc  cdfdffeb      bl       #0xdf8                                      
  000016c0  0cd04be2      sub      sp, fp, #0xc                                
  000016c4  00a89de8      ldm      sp, {fp, sp, pc}                            
  000016c8  a0170000      andeq    r1, r0, r0, lsr #15                         
  000016cc  50c09fe5      ldr      ip, [pc, #0x50]                             
  000016d0  0030a0e3      mov      r3, #0                                      
  000016d4  10402de9      push     {r4, lr}                                    
  000016d8  0cc08fe0      add      ip, pc, ip                                  
  000016dc  050000ea      b        #0x16f8                                     
  000016e0  0340d1e7      ldrb     r4, [r1, r3]                                
  000016e4  013083e2      add      r3, r3, #1                                  
  000016e8  004484e1      orr      r4, r4, r0, lsl #8                          
  000016ec  200ca0e1      lsr      r0, r0, #0x18                               
  000016f0  00019ce7      ldr      r0, [ip, r0, lsl #2]                        
  000016f4  000024e0      eor      r0, r4, r0                                  
  000016f8  020053e1      cmp      r3, r2                                      
  000016fc  f7ffff1a      bne      #0x16e0                                     
  00001700  20109fe5      ldr      r1, [pc, #0x20]                             
  00001704  0430a0e3      mov      r3, #4                                      
  00001708  01108fe0      add      r1, pc, r1                                  
  0000170c  202ca0e1      lsr      r2, r0, #0x18                               
  00001710  013053e2      subs     r3, r3, #1                                  
  00001714  022191e7      ldr      r2, [r1, r2, lsl #2]                        
  00001718  000422e0      eor      r0, r2, r0, lsl #8                          
  0000171c  faffff1a      bne      #0x170c                                     
  00001720  1080bde8      pop      {r4, pc}                                    
  00001724  78130000      andeq    r1, r0, r8, ror r3                          
  00001728  48130000      andeq    r1, r0, r8, asr #6                          
  0000172c  0dc0a0e1      mov      ip, sp                                      
  00001730  0010a0e3      mov      r1, #0                                      
  00001734  f0dd2de9      push     {r4, r5, r6, r7, r8, sl, fp, ip, lr, pc}    
  00001738  04b04ce2      sub      fp, ip, #4                                  
  0000173c  426e4be2      sub      r6, fp, #0x420                              
  00001740  01db4de2      sub      sp, sp, #0x400                              
  00001744  046046e2      sub      r6, r6, #4                                  
  00001748  08d04de2      sub      sp, sp, #8                                  
  0000174c  0040a0e1      mov      r4, r0                                      
  00001750  0600a0e1      mov      r0, r6                                      
  00001754  012ba0e3      mov      r2, #0x400                                  
  00001758  9afdffeb      bl       #0xdc8                                      
  0000175c  000054e3      cmp      r4, #0                                      
  00001760  0030e0e3      mvn      r3, #0                                      
  00001764  28340be5      str      r3, [fp, #-0x428]                           
  00001768  2d00000a      beq      #0x1824                                     
  0000176c  0400a0e1      mov      r0, r4                                      
  00001770  0010a0e3      mov      r1, #0                                      
  00001774  ff2100e3      movw     r2, #0x1ff                                  
  00001778  c2fdffeb      bl       #0xe88                                      
  0000177c  010070e3      cmn      r0, #1                                      
  00001780  0050a0e1      mov      r5, r0                                      
  00001784  2600000a      beq      #0x1824                                     
  00001788  0400a0e1      mov      r0, r4                                      
  0000178c  041046e2      sub      r1, r6, #4                                  
  00001790  b6fdffeb      bl       #0xe70                                      
  00001794  0500a0e1      mov      r0, r5                                      
  00001798  0610a0e1      mov      r1, r6                                      
  0000179c  012ba0e3      mov      r2, #0x400                                  
  000017a0  eefdffeb      bl       #0xf60                                      
  000017a4  000050e3      cmp      r0, #0                                      
  000017a8  0040a0c3      movgt    r4, #0                                      
  000017ac  0070a0c1      movgt    r7, r0                                      
  000017b0  04a0a0c1      movgt    sl, r4                                      
  000017b4  0e0000ca      bgt      #0x17f4                                     
  000017b8  0500a0e1      mov      r0, r5                                      
  000017bc  9ffdffeb      bl       #0xe40                                      
  000017c0  170000ea      b        #0x1824                                     
  000017c4  087067e0      rsb      r7, r7, r8                                  
  000017c8  28740be5      str      r7, [fp, #-0x428]                           
  000017cc  0500a0e1      mov      r0, r5                                      
  000017d0  0610a0e1      mov      r1, r6                                      
  000017d4  012ba0e3      mov      r2, #0x400                                  
  000017d8  e0fdffeb      bl       #0xf60                                      
  000017dc  000050e3      cmp      r0, #0                                      
  000017e0  020000ca      bgt      #0x17f0                                     
  000017e4  0500a0e1      mov      r0, r5                                      
  000017e8  94fdffeb      bl       #0xe40                                      
  000017ec  0d0000ea      b        #0x1828                                     
  000017f0  0070a0e1      mov      r7, r0                                      
  000017f4  28841be5      ldr      r8, [fp, #-0x428]                           
  000017f8  0400a0e1      mov      r0, r4                                      
  000017fc  0610a0e1      mov      r1, r6                                      
  00001800  080057e1      cmp      r7, r8                                      
  00001804  0720a031      movlo    r2, r7                                      
  00001808  0820a021      movhs    r2, r8                                      
  0000180c  aeffffeb      bl       #0x16cc                                     
  00001810  080057e1      cmp      r7, r8                                      
  00001814  28a40b85      strhi    sl, [fp, #-0x428]                           
  00001818  0040a0e1      mov      r4, r0                                      
  0000181c  eaffff8a      bhi      #0x17cc                                     
  00001820  e7ffffea      b        #0x17c4                                     
  00001824  0040a0e3      mov      r4, #0                                      
  00001828  0400a0e1      mov      r0, r4                                      
  0000182c  24d04be2      sub      sp, fp, #0x24                               
  00001830  f0ad9de8      ldm      sp, {r4, r5, r6, r7, r8, sl, fp, sp, pc}    
  00001834  0dc0a0e1      mov      ip, sp                                      
  00001838  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  0000183c  04b04ce2      sub      fp, ip, #4                                  
  00001840  0040a0e3      mov      r4, #0                                      
  00001844  87df4de2      sub      sp, sp, #0x21c                              
  00001848  0070a0e1      mov      r7, r0                                      
  0000184c  01a0a0e1      mov      sl, r1                                      
  00001850  0260a0e1      mov      r6, r2                                      
  00001854  0410a0e1      mov      r1, r4                                      
  00001858  832fa0e3      mov      r2, #0x20c                                  
  0000185c  8e0f4be2      sub      r0, fp, #0x238                              
  00001860  0390a0e1      mov      sb, r3                                      
  00001864  40420be5      str      r4, [fp, #-0x240]                           
  00001868  3c420be5      str      r4, [fp, #-0x23c]                           
  0000186c  55fdffeb      bl       #0xdc8                                      
  00001870  50119fe5      ldr      r1, [pc, #0x150]                            
  00001874  0900a0e1      mov      r0, sb                                      
  00001878  44420be5      str      r4, [fp, #-0x244]                           
  0000187c  01108fe0      add      r1, pc, r1                                  
  00001880  44819fe5      ldr      r8, [pc, #0x144]                            
  00001884  3dfdffeb      bl       #0xd80                                      
  00001888  08808fe0      add      r8, pc, r8                                  
  0000188c  005050e2      subs     r5, r0, #0                                  
  00001890  0700001a      bne      #0x18b4                                     
  00001894  34219fe5      ldr      r2, [pc, #0x134]                            
  00001898  34119fe5      ldr      r1, [pc, #0x134]                            
  0000189c  023098e7      ldr      r3, [r8, r2]                                
  000018a0  01108fe0      add      r1, pc, r1                                  
  000018a4  0920a0e1      mov      r2, sb                                      
  000018a8  000093e5      ldr      r0, [r3]                                    
  000018ac  7efdffeb      bl       #0xeac                                      
  000018b0  420000ea      b        #0x19c0                                     
  000018b4  1c119fe5      ldr      r1, [pc, #0x11c]                            
  000018b8  04009be5      ldr      r0, [fp, #4]                                
  000018bc  01108fe0      add      r1, pc, r1                                  
  000018c0  2efdffeb      bl       #0xd80                                      
  000018c4  004050e2      subs     r4, r0, #0                                  
  000018c8  0800001a      bne      #0x18f0                                     
  000018cc  fc209fe5      ldr      r2, [pc, #0xfc]                             
  000018d0  04119fe5      ldr      r1, [pc, #0x104]                            
  000018d4  023098e7      ldr      r3, [r8, r2]                                
  000018d8  01108fe0      add      r1, pc, r1                                  
  000018dc  04209be5      ldr      r2, [fp, #4]                                
  000018e0  000093e5      ldr      r0, [r3]                                    
  000018e4  70fdffeb      bl       #0xeac                                      
  000018e8  0500a0e1      mov      r0, r5                                      
  000018ec  320000ea      b        #0x19bc                                     
  000018f0  000056e3      cmp      r6, #0                                      
  000018f4  0b00001a      bne      #0x1928                                     
  000018f8  2c004be2      sub      r0, fp, #0x2c                               
  000018fc  0160a0e3      mov      r6, #1                                      
  00001900  0410a0e3      mov      r1, #4                                      
  00001904  0620a0e1      mov      r2, r6                                      
  00001908  146220e5      str      r6, [r0, #-0x214]!                          
  0000190c  0430a0e1      mov      r3, r4                                      
  00001910  3c720be5      str      r7, [fp, #-0x23c]                           
  00001914  22fdffeb      bl       #0xda4                                      
  00001918  8f0f4be2      sub      r0, fp, #0x23c                              
  0000191c  0410a0e3      mov      r1, #4                                      
  00001920  0620a0e1      mov      r2, r6                                      
  00001924  180000ea      b        #0x198c                                     
  00001928  0230a0e3      mov      r3, #2                                      
  0000192c  0410a0e3      mov      r1, #4                                      
  00001930  38320be5      str      r3, [fp, #-0x238]                           
  00001934  0120a0e3      mov      r2, #1                                      
  00001938  0430a0e1      mov      r3, r4                                      
  0000193c  8e0f4be2      sub      r0, fp, #0x238                              
  00001940  34720be5      str      r7, [fp, #-0x234]                           
  00001944  30620be5      str      r6, [fp, #-0x230]                           
  00001948  15fdffeb      bl       #0xda4                                      
  0000194c  0410a0e3      mov      r1, #4                                      
  00001950  0120a0e3      mov      r2, #1                                      
  00001954  0430a0e1      mov      r3, r4                                      
  00001958  8d0f4be2      sub      r0, fp, #0x234                              
  0000195c  10fdffeb      bl       #0xda4                                      
  00001960  0410a0e3      mov      r1, #4                                      
  00001964  230e4be2      sub      r0, fp, #0x230                              
  00001968  0120a0e3      mov      r2, #1                                      
  0000196c  0430a0e1      mov      r3, r4                                      
  00001970  0bfdffeb      bl       #0xda4                                      
  00001974  0a00a0e1      mov      r0, sl                                      
  00001978  0610a0e1      mov      r1, r6                                      
  0000197c  010000ea      b        #0x1988                                     
  00001980  910f4be2      sub      r0, fp, #0x244                              
  00001984  0410a0e3      mov      r1, #4                                      
  00001988  0120a0e3      mov      r2, #1                                      
  0000198c  0430a0e1      mov      r3, r4                                      
  00001990  03fdffeb      bl       #0xda4                                      
  00001994  910f4be2      sub      r0, fp, #0x244                              
  00001998  0410a0e3      mov      r1, #4                                      
  0000199c  0120a0e3      mov      r2, #1                                      
  000019a0  0530a0e1      mov      r3, r5                                      
  000019a4  22fdffeb      bl       #0xe34                                      
  000019a8  000050e3      cmp      r0, #0                                      
  000019ac  f3ffff1a      bne      #0x1980                                     
  000019b0  0500a0e1      mov      r0, r5                                      
  000019b4  5afdffeb      bl       #0xf24                                      
  000019b8  0400a0e1      mov      r0, r4                                      
  000019bc  58fdffeb      bl       #0xf24                                      
  000019c0  28d04be2      sub      sp, fp, #0x28                               
  000019c4  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  000019c8  e3150000      andeq    r1, r0, r3, ror #11                         
  000019cc  70a70000      andeq    sl, r0, r0, ror r7                          
  000019d0  c0000000      andeq    r0, r0, r0, asr #1                          
  000019d4  c2150000      andeq    r1, r0, r2, asr #11                         
  000019d8  bb150000      strheq   r1, [r0], -fp                               
  000019dc  a3150000      andeq    r1, r0, r3, lsr #11                         
  000019e0  0dc0a0e1      mov      ip, sp                                      
  000019e4  f0d82de9      push     {r4, r5, r6, r7, fp, ip, lr, pc}            
  000019e8  04b04ce2      sub      fp, ip, #4                                  
  000019ec  21de4de2      sub      sp, sp, #0x210                              
  000019f0  0050a0e1      mov      r5, r0                                      
  000019f4  0260a0e1      mov      r6, r2                                      
  000019f8  0140a0e1      mov      r4, r1                                      
  000019fc  870f4be2      sub      r0, fp, #0x21c                              
  00001a00  0010a0e3      mov      r1, #0                                      
  00001a04  022ca0e3      mov      r2, #0x200                                  
  00001a08  0370a0e1      mov      r7, r3                                      
  00001a0c  edfcffeb      bl       #0xdc8                                      
  00001a10  000055e3      cmp      r5, #0                                      
  00001a14  00005613      cmpne    r6, #0                                      
  00001a18  0100000a      beq      #0x1a24                                     
  00001a1c  020c54e3      cmp      r4, #0x200                                  
  00001a20  0b00002a      bhs      #0x1a54                                     
  00001a24  88009fe5      ldr      r0, [pc, #0x88]                             
  00001a28  0030a0e3      mov      r3, #0                                      
  00001a2c  00408de5      str      r4, [sp]                                    
  00001a30  711100e3      movw     r1, #0x171                                  
  00001a34  04308de5      str      r3, [sp, #4]                                
  00001a38  00008fe0      add      r0, pc, r0                                  
  00001a3c  08308de5      str      r3, [sp, #8]                                
  00001a40  0020e0e3      mvn      r2, #0                                      
  00001a44  0530a0e1      mov      r3, r5                                      
  00001a48  eafcffeb      bl       #0xdf8                                      
  00001a4c  0000e0e3      mvn      r0, #0                                      
  00001a50  150000ea      b        #0x1aac                                     
  00001a54  000057e3      cmp      r7, #0                                      
  00001a58  0500000a      beq      #0x1a74                                     
  00001a5c  870f4be2      sub      r0, fp, #0x21c                              
  00001a60  021ca0e3      mov      r1, #0x200                                  
  00001a64  0620a0e1      mov      r2, r6                                      
  00001a68  0730a0e1      mov      r3, r7                                      
  00001a6c  c0fcffeb      bl       #0xd74                                      
  00001a70  070000ea      b        #0x1a94                                     
  00001a74  871f4be2      sub      r1, fp, #0x21c                              
  00001a78  0400a0e3      mov      r0, #4                                      
  00001a7c  022ca0e3      mov      r2, #0x200                                  
  00001a80  2dfdffeb      bl       #0xf3c                                      
  00001a84  001050e2      subs     r1, r0, #0                                  
  00001a88  0100000a      beq      #0x1a94                                     
  00001a8c  7e0100e3      movw     r0, #0x17e                                  
  00001a90  fcfeffeb      bl       #0x1688                                     
  00001a94  0500a0e1      mov      r0, r5                                      
  00001a98  0410a0e1      mov      r1, r4                                      
  00001a9c  872f4be2      sub      r2, fp, #0x21c                              
  00001aa0  023ca0e3      mov      r3, #0x200                                  
  00001aa4  eefcffeb      bl       #0xe64                                      
  00001aa8  0000a0e3      mov      r0, #0                                      
  00001aac  1cd04be2      sub      sp, fp, #0x1c                               
  00001ab0  f0a89de8      ldm      sp, {r4, r5, r6, r7, fp, sp, pc}            
  00001ab4  18140000      andeq    r1, r0, r8, lsl r4                          
  00001ab8  0dc0a0e1      mov      ip, sp                                      
  00001abc  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  00001ac0  04b04ce2      sub      fp, ip, #4                                  
  00001ac4  8dde4de2      sub      sp, sp, #0x8d0                              
  00001ac8  8e7e4be2      sub      r7, fp, #0x8e0                              
  00001acc  04d04de2      sub      sp, sp, #4                                  
  00001ad0  0040a0e1      mov      r4, r0                                      
  00001ad4  0180a0e1      mov      r8, r1                                      
  00001ad8  0290a0e1      mov      sb, r2                                      
  00001adc  0010a0e3      mov      r1, #0                                      
  00001ae0  1020a0e3      mov      r2, #0x10                                   
  00001ae4  0700a0e1      mov      r0, r7                                      
  00001ae8  e8380be5      str      r3, [fp, #-0x8e8]                           
  00001aec  b5fcffeb      bl       #0xdc8                                      
  00001af0  0010a0e3      mov      r1, #0                                      
  00001af4  2020a0e3      mov      r2, #0x20                                   
  00001af8  8d0e4be2      sub      r0, fp, #0x8d0                              
  00001afc  0050a0e3      mov      r5, #0                                      
  00001b00  b0fcffeb      bl       #0xdc8                                      
  00001b04  420e4be2      sub      r0, fp, #0x420                              
  00001b08  0010a0e3      mov      r1, #0                                      
  00001b0c  012ba0e3      mov      r2, #0x400                                  
  00001b10  0c0040e2      sub      r0, r0, #0xc                                
  00001b14  abfcffeb      bl       #0xdc8                                      
  00001b18  1d0d4be2      sub      r0, fp, #0x740                              
  00001b1c  0010a0e3      mov      r1, #0                                      
  00001b20  462fa0e3      mov      r2, #0x118                                  
  00001b24  040040e2      sub      r0, r0, #4                                  
  00001b28  a6fcffeb      bl       #0xdc8                                      
  00001b2c  0010a0e3      mov      r1, #0                                      
  00001b30  ec20a0e3      mov      r2, #0xec                                   
  00001b34  830e4be2      sub      r0, fp, #0x830                              
  00001b38  a2fcffeb      bl       #0xdc8                                      
  00001b3c  0510a0e1      mov      r1, r5                                      
  00001b40  8020a0e3      mov      r2, #0x80                                   
  00001b44  8b0e4be2      sub      r0, fp, #0x8b0                              
  00001b48  e4580be5      str      r5, [fp, #-0x8e4]                           
  00001b4c  9dfcffeb      bl       #0xdc8                                      
  00001b50  620e4be2      sub      r0, fp, #0x620                              
  00001b54  0510a0e1      mov      r1, r5                                      
  00001b58  022ca0e3      mov      r2, #0x200                                  
  00001b5c  0c0040e2      sub      r0, r0, #0xc                                
  00001b60  98fcffeb      bl       #0xdc8                                      
  00001b64  8d3e4be2      sub      r3, fp, #0x8d0                              
  00001b68  0c3043e2      sub      r3, r3, #0xc                                
  00001b6c  0400a0e1      mov      r0, r4                                      
  00001b70  081043e2      sub      r1, r3, #8                                  
  00001b74  bdfcffeb      bl       #0xe70                                      
  00001b78  00a050e2      subs     sl, r0, #0                                  
  00001b7c  0a00000a      beq      #0x1bac                                     
  00001b80  defcffeb      bl       #0xf00                                      
  00001b84  e4281be5      ldr      r2, [fp, #-0x8e4]                           
  00001b88  08508de5      str      r5, [sp, #8]                                
  00001b8c  b51100e3      movw     r1, #0x1b5                                  
  00001b90  24008de8      stm      sp, {r2, r5}                                
  00001b94  0020e0e3      mvn      r2, #0                                      
  00001b98  0030a0e1      mov      r3, r0                                      
  00001b9c  30049fe5      ldr      r0, [pc, #0x430]                            
  00001ba0  00008fe0      add      r0, pc, r0                                  
  00001ba4  93fcffeb      bl       #0xdf8                                      
  00001ba8  130000ea      b        #0x1bfc                                     
  00001bac  24149fe5      ldr      r1, [pc, #0x424]                            
  00001bb0  0400a0e1      mov      r0, r4                                      
  00001bb4  01108fe0      add      r1, pc, r1                                  
  00001bb8  70fcffeb      bl       #0xd80                                      
  00001bbc  006050e2      subs     r6, r0, #0                                  
  00001bc0  0f00001a      bne      #0x1c04                                     
  00001bc4  cdfcffeb      bl       #0xf00                                      
  00001bc8  0c149fe5      ldr      r1, [pc, #0x40c]                            
  00001bcc  6f2fa0e3      mov      r2, #0x1bc                                  
  00001bd0  0430a0e1      mov      r3, r4                                      
  00001bd4  01108fe0      add      r1, pc, r1                                  
  00001bd8  00008de5      str      r0, [sp]                                    
  00001bdc  fc039fe5      ldr      r0, [pc, #0x3fc]                            
  00001be0  00008fe0      add      r0, pc, r0                                  
  00001be4  7afcffeb      bl       #0xdd4                                      
  00001be8  c4fcffeb      bl       #0xf00                                      
  00001bec  0010e0e3      mvn      r1, #0                                      
  00001bf0  0020a0e1      mov      r2, r0                                      
  00001bf4  bd0100e3      movw     r0, #0x1bd                                  
  00001bf8  8ffeffeb      bl       #0x163c                                     
  00001bfc  0000e0e3      mvn      r0, #0                                      
  00001c00  f10000ea      b        #0x1fcc                                     
  00001c04  d8139fe5      ldr      r1, [pc, #0x3d8]                            
  00001c08  0800a0e1      mov      r0, r8                                      
  00001c0c  01108fe0      add      r1, pc, r1                                  
  00001c10  5afcffeb      bl       #0xd80                                      
  00001c14  005050e2      subs     r5, r0, #0                                  
  00001c18  e4281b15      ldrne    r2, [fp, #-0x8e4]                           
  00001c1c  0f00001a      bne      #0x1c60                                     
  00001c20  b6fcffeb      bl       #0xf00                                      
  00001c24  bc139fe5      ldr      r1, [pc, #0x3bc]                            
  00001c28  712fa0e3      mov      r2, #0x1c4                                  
  00001c2c  0830a0e1      mov      r3, r8                                      
  00001c30  01108fe0      add      r1, pc, r1                                  
  00001c34  00008de5      str      r0, [sp]                                    
  00001c38  ac039fe5      ldr      r0, [pc, #0x3ac]                            
  00001c3c  00008fe0      add      r0, pc, r0                                  
  00001c40  63fcffeb      bl       #0xdd4                                      
  00001c44  adfcffeb      bl       #0xf00                                      
  00001c48  0010e0e3      mvn      r1, #0                                      
  00001c4c  0020a0e1      mov      r2, r0                                      
  00001c50  c50100e3      movw     r0, #0x1c5                                  
  00001c54  78feffeb      bl       #0x163c                                     
  00001c58  0600a0e1      mov      r0, r6                                      
  00001c5c  c30000ea      b        #0x1f70                                     
  00001c60  42ce4be2      sub      ip, fp, #0x420                              
  00001c64  8a31a0e1      lsl      r3, sl, #3                                  
  00001c68  0cc04ce2      sub      ip, ip, #0xc                                
  00001c6c  3233a0e1      lsr      r3, r2, r3                                  
  00001c70  0c30cae7      strb     r3, [sl, ip]                                
  00001c74  01a08ae2      add      sl, sl, #1                                  
  00001c78  08005ae3      cmp      sl, #8                                      
  00001c7c  f7ffff1a      bne      #0x1c60                                     
  00001c80  8010a0e3      mov      r1, #0x80                                   
  00001c84  0420a0e1      mov      r2, r4                                      
  00001c88  0130a0e1      mov      r3, r1                                      
  00001c8c  8b0e4be2      sub      r0, fp, #0x8b0                              
  00001c90  ecc80be5      str      ip, [fp, #-0x8ec]                           
  00001c94  36fcffeb      bl       #0xd74                                      
  00001c98  830e4be2      sub      r0, fp, #0x830                              
  00001c9c  0010a0e3      mov      r1, #0                                      
  00001ca0  5dfcffeb      bl       #0xe1c                                      
  00001ca4  ecc81be5      ldr      ip, [fp, #-0x8ec]                           
  00001ca8  0a20a0e1      mov      r2, sl                                      
  00001cac  830e4be2      sub      r0, fp, #0x830                              
  00001cb0  0c10a0e1      mov      r1, ip                                      
  00001cb4  a3fcffeb      bl       #0xf48                                      
  00001cb8  8010a0e3      mov      r1, #0x80                                   
  00001cbc  8b0e4be2      sub      r0, fp, #0x8b0                              
  00001cc0  a3fcffeb      bl       #0xf54                                      
  00001cc4  8b1e4be2      sub      r1, fp, #0x8b0                              
  00001cc8  0020a0e1      mov      r2, r0                                      
  00001ccc  830e4be2      sub      r0, fp, #0x830                              
  00001cd0  9cfcffeb      bl       #0xf48                                      
  00001cd4  830e4be2      sub      r0, fp, #0x830                              
  00001cd8  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001cdc  81fcffeb      bl       #0xee8                                      
  00001ce0  1010a0e3      mov      r1, #0x10                                   
  00001ce4  0130a0e1      mov      r3, r1                                      
  00001ce8  8d2e4be2      sub      r2, fp, #0x8d0                              
  00001cec  0700a0e1      mov      r0, r7                                      
  00001cf0  5bfcffeb      bl       #0xe64                                      
  00001cf4  d1385be5      ldrb     r3, [fp, #-0x8d1]                           
  00001cf8  e4281be5      ldr      r2, [fp, #-0x8e4]                           
  00001cfc  0700a0e1      mov      r0, r7                                      
  00001d00  0f30c3e3      bic      r3, r3, #0xf                                
  00001d04  0110a0e3      mov      r1, #1                                      
  00001d08  0f2002e2      and      r2, r2, #0xf                                
  00001d0c  033082e1      orr      r3, r2, r3                                  
  00001d10  1020a0e3      mov      r2, #0x10                                   
  00001d14  d1384be5      strb     r3, [fp, #-0x8d1]                           
  00001d18  0530a0e1      mov      r3, r5                                      
  00001d1c  20fcffeb      bl       #0xda4                                      
  00001d20  100050e3      cmp      r0, #0x10                                   
  00001d24  00a0a0e1      mov      sl, r0                                      
  00001d28  0600000a      beq      #0x1d48                                     
  00001d2c  bc029fe5      ldr      r0, [pc, #0x2bc]                            
  00001d30  eb2100e3      movw     r2, #0x1eb                                  
  00001d34  b8129fe5      ldr      r1, [pc, #0x2b8]                            
  00001d38  1030a0e3      mov      r3, #0x10                                   
  00001d3c  00008fe0      add      r0, pc, r0                                  
  00001d40  01108fe0      add      r1, pc, r1                                  
  00001d44  490000ea      b        #0x1e70                                     
  00001d48  2010a0e3      mov      r1, #0x20                                   
  00001d4c  0020a0e3      mov      r2, #0                                      
  00001d50  0130a0e1      mov      r3, r1                                      
  00001d54  8d0e4be2      sub      r0, fp, #0x8d0                              
  00001d58  2cfcffeb      bl       #0xe10                                      
  00001d5c  0a30a0e1      mov      r3, sl                                      
  00001d60  62ae4be2      sub      sl, fp, #0x620                              
  00001d64  2010a0e3      mov      r1, #0x20                                   
  00001d68  0ca04ae2      sub      sl, sl, #0xc                                
  00001d6c  0720a0e1      mov      r2, r7                                      
  00001d70  8d0e4be2      sub      r0, fp, #0x8d0                              
  00001d74  3afcffeb      bl       #0xe64                                      
  00001d78  0920a0e1      mov      r2, sb                                      
  00001d7c  021ca0e3      mov      r1, #0x200                                  
  00001d80  e8381be5      ldr      r3, [fp, #-0x8e8]                           
  00001d84  0a00a0e1      mov      r0, sl                                      
  00001d88  029aa0e3      mov      sb, #0x2000                                 
  00001d8c  13ffffeb      bl       #0x19e0                                     
  00001d90  0a00a0e1      mov      r0, sl                                      
  00001d94  021ca0e3      mov      r1, #0x200                                  
  00001d98  6dfcffeb      bl       #0xf54                                      
  00001d9c  e8080be5      str      r0, [fp, #-0x8e8]                           
  00001da0  830e4be2      sub      r0, fp, #0x830                              
  00001da4  0010a0e3      mov      r1, #0                                      
  00001da8  1bfcffeb      bl       #0xe1c                                      
  00001dac  830e4be2      sub      r0, fp, #0x830                              
  00001db0  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001db4  2020a0e3      mov      r2, #0x20                                   
  00001db8  62fcffeb      bl       #0xf48                                      
  00001dbc  830e4be2      sub      r0, fp, #0x830                              
  00001dc0  0a10a0e1      mov      r1, sl                                      
  00001dc4  e8281be5      ldr      r2, [fp, #-0x8e8]                           
  00001dc8  5efcffeb      bl       #0xf48                                      
  00001dcc  830e4be2      sub      r0, fp, #0x830                              
  00001dd0  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001dd4  43fcffeb      bl       #0xee8                                      
  00001dd8  019059e2      subs     sb, sb, #1                                  
  00001ddc  efffff1a      bne      #0x1da0                                     
  00001de0  021ca0e3      mov      r1, #0x200                                  
  00001de4  0a00a0e1      mov      r0, sl                                      
  00001de8  0130a0e1      mov      r3, r1                                      
  00001dec  0920a0e1      mov      r2, sb                                      
  00001df0  06fcffeb      bl       #0xe10                                      
  00001df4  1d0d4be2      sub      r0, fp, #0x740                              
  00001df8  040040e2      sub      r0, r0, #4                                  
  00001dfc  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001e00  012ca0e3      mov      r2, #0x100                                  
  00001e04  42ae4be2      sub      sl, fp, #0x420                              
  00001e08  fdfbffeb      bl       #0xe04                                      
  00001e0c  830e4be2      sub      r0, fp, #0x830                              
  00001e10  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001e14  2020a0e3      mov      r2, #0x20                                   
  00001e18  0930a0e1      mov      r3, sb                                      
  00001e1c  0ca04ae2      sub      sl, sl, #0xc                                
  00001e20  1efcffeb      bl       #0xea0                                      
  00001e24  e8980be5      str      sb, [fp, #-0x8e8]                           
  00001e28  390000ea      b        #0x1f14                                     
  00001e2c  e8381be5      ldr      r3, [fp, #-0x8e8]                           
  00001e30  0a00a0e1      mov      r0, sl                                      
  00001e34  0110a0e3      mov      r1, #1                                      
  00001e38  0c9063e0      rsb      sb, r3, ip                                  
  00001e3c  0630a0e1      mov      r3, r6                                      
  00001e40  100059e3      cmp      sb, #0x10                                   
  00001e44  1090a023      movhs    sb, #0x10                                   
  00001e48  0920a0e1      mov      r2, sb                                      
  00001e4c  f8fbffeb      bl       #0xe34                                      
  00001e50  090050e1      cmp      r0, sb                                      
  00001e54  0700000a      beq      #0x1e78                                     
  00001e58  98019fe5      ldr      r0, [pc, #0x198]                            
  00001e5c  122200e3      movw     r2, #0x212                                  
  00001e60  94119fe5      ldr      r1, [pc, #0x194]                            
  00001e64  0930a0e1      mov      r3, sb                                      
  00001e68  00008fe0      add      r0, pc, r0                                  
  00001e6c  01108fe0      add      r1, pc, r1                                  
  00001e70  d7fbffeb      bl       #0xdd4                                      
  00001e74  3a0000ea      b        #0x1f64                                     
  00001e78  0090a0e3      mov      sb, #0                                      
  00001e7c  0a30d9e7      ldrb     r3, [sb, sl]                                
  00001e80  0920d7e7      ldrb     r2, [r7, sb]                                
  00001e84  033022e0      eor      r3, r2, r3                                  
  00001e88  0a30c9e7      strb     r3, [sb, sl]                                
  00001e8c  019089e2      add      sb, sb, #1                                  
  00001e90  100059e3      cmp      sb, #0x10                                   
  00001e94  f8ffff1a      bne      #0x1e7c                                     
  00001e98  1d0d4be2      sub      r0, fp, #0x740                              
  00001e9c  0a30a0e1      mov      r3, sl                                      
  00001ea0  040040e2      sub      r0, r0, #4                                  
  00001ea4  0110a0e3      mov      r1, #1                                      
  00001ea8  0a20a0e1      mov      r2, sl                                      
  00001eac  10fcffeb      bl       #0xef4                                      
  00001eb0  830e4be2      sub      r0, fp, #0x830                              
  00001eb4  0a10a0e1      mov      r1, sl                                      
  00001eb8  0920a0e1      mov      r2, sb                                      
  00001ebc  e2fbffeb      bl       #0xe4c                                      
  00001ec0  0a00a0e1      mov      r0, sl                                      
  00001ec4  0110a0e3      mov      r1, #1                                      
  00001ec8  0920a0e1      mov      r2, sb                                      
  00001ecc  0530a0e1      mov      r3, r5                                      
  00001ed0  b3fbffeb      bl       #0xda4                                      
  00001ed4  100050e3      cmp      r0, #0x10                                   
  00001ed8  0500000a      beq      #0x1ef4                                     
  00001edc  1c019fe5      ldr      r0, [pc, #0x11c]                            
  00001ee0  222200e3      movw     r2, #0x222                                  
  00001ee4  18119fe5      ldr      r1, [pc, #0x118]                            
  00001ee8  00008fe0      add      r0, pc, r0                                  
  00001eec  01108fe0      add      r1, pc, r1                                  
  00001ef0  1a0000ea      b        #0x1f60                                     
  00001ef4  0930a0e1      mov      r3, sb                                      
  00001ef8  0700a0e1      mov      r0, r7                                      
  00001efc  0910a0e1      mov      r1, sb                                      
  00001f00  0a20a0e1      mov      r2, sl                                      
  00001f04  d6fbffeb      bl       #0xe64                                      
  00001f08  e8381be5      ldr      r3, [fp, #-0x8e8]                           
  00001f0c  103083e2      add      r3, r3, #0x10                               
  00001f10  e8380be5      str      r3, [fp, #-0x8e8]                           
  00001f14  e4c81be5      ldr      ip, [fp, #-0x8e4]                           
  00001f18  e8381be5      ldr      r3, [fp, #-0x8e8]                           
  00001f1c  0c0053e1      cmp      r3, ip                                      
  00001f20  c1ffff3a      blo      #0x1e2c                                     
  00001f24  830e4be2      sub      r0, fp, #0x830                              
  00001f28  8d1e4be2      sub      r1, fp, #0x8d0                              
  00001f2c  e7fbffeb      bl       #0xed0                                      
  00001f30  8d0e4be2      sub      r0, fp, #0x8d0                              
  00001f34  0110a0e3      mov      r1, #1                                      
  00001f38  2020a0e3      mov      r2, #0x20                                   
  00001f3c  0530a0e1      mov      r3, r5                                      
  00001f40  97fbffeb      bl       #0xda4                                      
  00001f44  200050e3      cmp      r0, #0x20                                   
  00001f48  0a00000a      beq      #0x1f78                                     
  00001f4c  b4009fe5      ldr      r0, [pc, #0xb4]                             
  00001f50  322200e3      movw     r2, #0x232                                  
  00001f54  b0109fe5      ldr      r1, [pc, #0xb0]                             
  00001f58  00008fe0      add      r0, pc, r0                                  
  00001f5c  01108fe0      add      r1, pc, r1                                  
  00001f60  9bfbffeb      bl       #0xdd4                                      
  00001f64  0600a0e1      mov      r0, r6                                      
  00001f68  edfbffeb      bl       #0xf24                                      
  00001f6c  0500a0e1      mov      r0, r5                                      
  00001f70  ebfbffeb      bl       #0xf24                                      
  00001f74  20ffffea      b        #0x1bfc                                     
  00001f78  0600a0e1      mov      r0, r6                                      
  00001f7c  e8fbffeb      bl       #0xf24                                      
  00001f80  0500a0e1      mov      r0, r5                                      
  00001f84  e6fbffeb      bl       #0xf24                                      
  00001f88  0400a0e1      mov      r0, r4                                      
  00001f8c  a5fbffeb      bl       #0xe28                                      
  00001f90  0410a0e1      mov      r1, r4                                      
  00001f94  0800a0e1      mov      r0, r8                                      
  00001f98  90fbffeb      bl       #0xde0                                      
  00001f9c  0400a0e1      mov      r0, r4                                      
  00001fa0  e1fdffeb      bl       #0x172c                                     
  00001fa4  06009be9      ldmib    fp, {r1, r2}                                
  00001fa8  0430a0e1      mov      r3, r4                                      
  00001fac  00808de5      str      r8, [sp]                                    
  00001fb0  1ffeffeb      bl       #0x1834                                     
  00001fb4  0400a0e1      mov      r0, r4                                      
  00001fb8  9afbffeb      bl       #0xe28                                      
  00001fbc  0800a0e1      mov      r0, r8                                      
  00001fc0  0410a0e1      mov      r1, r4                                      
  00001fc4  85fbffeb      bl       #0xde0                                      
  00001fc8  0000a0e3      mov      r0, #0                                      
  00001fcc  28d04be2      sub      sp, fp, #0x28                               
  00001fd0  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  00001fd4  b0120000      strheq   r1, [r0], -r0                               
  00001fd8  ab120000      andeq    r1, r0, fp, lsr #5                          
  00001fdc  7c120000      andeq    r1, r0, ip, ror r2                          
  00001fe0  b1120000      strheq   r1, [r0], -r1                               
  00001fe4  6b120000      andeq    r1, r0, fp, ror #4                          
  00001fe8  20120000      andeq    r1, r0, r0, lsr #4                          
  00001fec  55120000      andeq    r1, r0, r5, asr r2                          
  00001ff0  7e110000      andeq    r1, r0, lr, ror r1                          
  00001ff4  10110000      andeq    r1, r0, r0, lsl r1                          
  00001ff8  74100000      andeq    r1, r0, r4, ror r0                          
  00001ffc  e40f0000      andeq    r0, r0, r4, ror #31                         
  00002000  15100000      andeq    r1, r0, r5, lsl r0                          
  00002004  640f0000      andeq    r0, r0, r4, ror #30                         
  00002008  a50f0000      andeq    r0, r0, r5, lsr #31                         
  0000200c  f40e0000      strdeq   r0, r1, [r0], -r4                           
  00002010  0dc0a0e1      mov      ip, sp                                      
  00002014  f0d92de9      push     {r4, r5, r6, r7, r8, fp, ip, lr, pc}        
  00002018  0170a0e1      mov      r7, r1                                      
  0000201c  70129fe5      ldr      r1, [pc, #0x270]                            
  00002020  04b04ce2      sub      fp, ip, #4                                  
  00002024  1cd04de2      sub      sp, sp, #0x1c                               
  00002028  0050a0e1      mov      r5, r0                                      
  0000202c  01108fe0      add      r1, pc, r1                                  
  00002030  0280a0e1      mov      r8, r2                                      
  00002034  0360a0e1      mov      r6, r3                                      
  00002038  0030a0e3      mov      r3, #0                                      
  0000203c  2c300be5      str      r3, [fp, #-0x2c]                            
  00002040  28300be5      str      r3, [fp, #-0x28]                            
  00002044  31304be5      strb     r3, [fp, #-0x31]                            
  00002048  30300be5      str      r3, [fp, #-0x30]                            
  0000204c  4bfbffeb      bl       #0xd80                                      
  00002050  004050e2      subs     r4, r0, #0                                  
  00002054  0800001a      bne      #0x207c                                     
  00002058  a8fbffeb      bl       #0xf00                                      
  0000205c  34129fe5      ldr      r1, [pc, #0x234]                            
  00002060  662200e3      movw     r2, #0x266                                  
  00002064  0530a0e1      mov      r3, r5                                      
  00002068  01108fe0      add      r1, pc, r1                                  
  0000206c  00008de5      str      r0, [sp]                                    
  00002070  24029fe5      ldr      r0, [pc, #0x224]                            
  00002074  00008fe0      add      r0, pc, r0                                  
  00002078  800000ea      b        #0x2280                                     
  0000207c  0120a0e3      mov      r2, #1                                      
  00002080  2c004be2      sub      r0, fp, #0x2c                               
  00002084  0410a0e3      mov      r1, #4                                      
  00002088  0430a0e1      mov      r3, r4                                      
  0000208c  68fbffeb      bl       #0xe34                                      
  00002090  010050e3      cmp      r0, #1                                      
  00002094  0020a0e1      mov      r2, r0                                      
  00002098  0700000a      beq      #0x20bc                                     
  0000209c  97fbffeb      bl       #0xf00                                      
  000020a0  f8119fe5      ldr      r1, [pc, #0x1f8]                            
  000020a4  9b2fa0e3      mov      r2, #0x26c                                  
  000020a8  01108fe0      add      r1, pc, r1                                  
  000020ac  00008de5      str      r0, [sp]                                    
  000020b0  ec019fe5      ldr      r0, [pc, #0x1ec]                            
  000020b4  00008fe0      add      r0, pc, r0                                  
  000020b8  120000ea      b        #0x2108                                     
  000020bc  2c301be5      ldr      r3, [fp, #-0x2c]                            
  000020c0  013043e2      sub      r3, r3, #1                                  
  000020c4  010053e3      cmp      r3, #1                                      
  000020c8  4a00008a      bhi      #0x21f8                                     
  000020cc  2c304be2      sub      r3, fp, #0x2c                               
  000020d0  0410a0e3      mov      r1, #4                                      
  000020d4  040083e2      add      r0, r3, #4                                  
  000020d8  0430a0e1      mov      r3, r4                                      
  000020dc  54fbffeb      bl       #0xe34                                      
  000020e0  010050e3      cmp      r0, #1                                      
  000020e4  0020a0e1      mov      r2, r0                                      
  000020e8  0800000a      beq      #0x2110                                     
  000020ec  83fbffeb      bl       #0xf00                                      
  000020f0  b0119fe5      ldr      r1, [pc, #0x1b0]                            
  000020f4  7a2200e3      movw     r2, #0x27a                                  
  000020f8  01108fe0      add      r1, pc, r1                                  
  000020fc  00008de5      str      r0, [sp]                                    
  00002100  a4019fe5      ldr      r0, [pc, #0x1a4]                            
  00002104  00008fe0      add      r0, pc, r0                                  
  00002108  0530a0e1      mov      r3, r5                                      
  0000210c  380000ea      b        #0x21f4                                     
  00002110  2c301be5      ldr      r3, [fp, #-0x2c]                            
  00002114  020053e3      cmp      r3, #2                                      
  00002118  2700001a      bne      #0x21bc                                     
  0000211c  30004be2      sub      r0, fp, #0x30                               
  00002120  0410a0e3      mov      r1, #4                                      
  00002124  0430a0e1      mov      r3, r4                                      
  00002128  41fbffeb      bl       #0xe34                                      
  0000212c  010050e3      cmp      r0, #1                                      
  00002130  0020a0e1      mov      r2, r0                                      
  00002134  0700000a      beq      #0x2158                                     
  00002138  70fbffeb      bl       #0xf00                                      
  0000213c  6c119fe5      ldr      r1, [pc, #0x16c]                            
  00002140  a12fa0e3      mov      r2, #0x284                                  
  00002144  01108fe0      add      r1, pc, r1                                  
  00002148  00008de5      str      r0, [sp]                                    
  0000214c  60019fe5      ldr      r0, [pc, #0x160]                            
  00002150  00008fe0      add      r0, pc, r0                                  
  00002154  ebffffea      b        #0x2108                                     
  00002158  30101be5      ldr      r1, [fp, #-0x30]                            
  0000215c  020c51e3      cmp      r1, #0x200                                  
  00002160  0600003a      blo      #0x2180                                     
  00002164  00108de5      str      r1, [sp]                                    
  00002168  8a2200e3      movw     r2, #0x28a                                  
  0000216c  44019fe5      ldr      r0, [pc, #0x144]                            
  00002170  44119fe5      ldr      r1, [pc, #0x144]                            
  00002174  00008fe0      add      r0, pc, r0                                  
  00002178  01108fe0      add      r1, pc, r1                                  
  0000217c  e1ffffea      b        #0x2108                                     
  00002180  0800a0e1      mov      r0, r8                                      
  00002184  0430a0e1      mov      r3, r4                                      
  00002188  29fbffeb      bl       #0xe34                                      
  0000218c  010050e3      cmp      r0, #1                                      
  00002190  0700000a      beq      #0x21b4                                     
  00002194  59fbffeb      bl       #0xf00                                      
  00002198  20119fe5      ldr      r1, [pc, #0x120]                            
  0000219c  912200e3      movw     r2, #0x291                                  
  000021a0  01108fe0      add      r1, pc, r1                                  
  000021a4  00008de5      str      r0, [sp]                                    
  000021a8  14019fe5      ldr      r0, [pc, #0x114]                            
  000021ac  00008fe0      add      r0, pc, r0                                  
  000021b0  d4ffffea      b        #0x2108                                     
  000021b4  30301be5      ldr      r3, [fp, #-0x30]                            
  000021b8  003087e5      str      r3, [r7]                                    
  000021bc  04119fe5      ldr      r1, [pc, #0x104]                            
  000021c0  0600a0e1      mov      r0, r6                                      
  000021c4  01108fe0      add      r1, pc, r1                                  
  000021c8  ecfaffeb      bl       #0xd80                                      
  000021cc  005050e2      subs     r5, r0, #0                                  
  000021d0  1000001a      bne      #0x2218                                     
  000021d4  49fbffeb      bl       #0xf00                                      
  000021d8  ec109fe5      ldr      r1, [pc, #0xec]                             
  000021dc  a72fa0e3      mov      r2, #0x29c                                  
  000021e0  0630a0e1      mov      r3, r6                                      
  000021e4  01108fe0      add      r1, pc, r1                                  
  000021e8  00008de5      str      r0, [sp]                                    
  000021ec  dc009fe5      ldr      r0, [pc, #0xdc]                             
  000021f0  00008fe0      add      r0, pc, r0                                  
  000021f4  f6faffeb      bl       #0xdd4                                      
  000021f8  0400a0e1      mov      r0, r4                                      
  000021fc  48fbffeb      bl       #0xf24                                      
  00002200  1f0000ea      b        #0x2284                                     
  00002204  0110a0e3      mov      r1, #1                                      
  00002208  31004be2      sub      r0, fp, #0x31                               
  0000220c  0120a0e1      mov      r2, r1                                      
  00002210  0530a0e1      mov      r3, r5                                      
  00002214  e2faffeb      bl       #0xda4                                      
  00002218  0110a0e3      mov      r1, #1                                      
  0000221c  31004be2      sub      r0, fp, #0x31                               
  00002220  0120a0e1      mov      r2, r1                                      
  00002224  0430a0e1      mov      r3, r4                                      
  00002228  01fbffeb      bl       #0xe34                                      
  0000222c  007050e2      subs     r7, r0, #0                                  
  00002230  f3ffff1a      bne      #0x2204                                     
  00002234  0400a0e1      mov      r0, r4                                      
  00002238  39fbffeb      bl       #0xf24                                      
  0000223c  0500a0e1      mov      r0, r5                                      
  00002240  37fbffeb      bl       #0xf24                                      
  00002244  0600a0e1      mov      r0, r6                                      
  00002248  37fdffeb      bl       #0x172c                                     
  0000224c  0040a0e1      mov      r4, r0                                      
  00002250  0600a0e1      mov      r0, r6                                      
  00002254  f3faffeb      bl       #0xe28                                      
  00002258  28301be5      ldr      r3, [fp, #-0x28]                            
  0000225c  040053e1      cmp      r3, r4                                      
  00002260  0700a001      moveq    r0, r7                                      
  00002264  0800000a      beq      #0x228c                                     
  00002268  64009fe5      ldr      r0, [pc, #0x64]                             
  0000226c  af2200e3      movw     r2, #0x2af                                  
  00002270  60109fe5      ldr      r1, [pc, #0x60]                             
  00002274  00008fe0      add      r0, pc, r0                                  
  00002278  00408de5      str      r4, [sp]                                    
  0000227c  01108fe0      add      r1, pc, r1                                  
  00002280  d3faffeb      bl       #0xdd4                                      
  00002284  0000e0e3      mvn      r0, #0                                      
  00002288  ffffffea      b        #0x228c                                     
  0000228c  20d04be2      sub      sp, fp, #0x20                               
  00002290  f0a99de8      ldm      sp, {r4, r5, r6, r7, r8, fp, sp, pc}        
  00002294  330e0000      andeq    r0, r0, r3, lsr lr                          
  00002298  e80d0000      andeq    r0, r0, r8, ror #27                         
  0000229c  ab0e0000      andeq    r0, r0, fp, lsr #29                         
  000022a0  a80d0000      andeq    r0, r0, r8, lsr #27                         
  000022a4  960e0000      muleq    r0, r6, lr                                  
  000022a8  580d0000      andeq    r0, r0, r8, asr sp                          
  000022ac  7b0e0000      andeq    r0, r0, fp, ror lr                          
  000022b0  0c0d0000      andeq    r0, r0, ip, lsl #26                         
  000022b4  2f0e0000      andeq    r0, r0, pc, lsr #28                         
  000022b8  3f0e0000      andeq    r0, r0, pc, lsr lr                          
  000022bc  d80c0000      ldrdeq   r0, r1, [r0], -r8                           
  000022c0  b00c0000      strheq   r0, [r0], -r0                               
  000022c4  3a0e0000      andeq    r0, r0, sl, lsr lr                          
  000022c8  b30c0000      strheq   r0, [r0], -r3                               
  000022cc  6c0c0000      andeq    r0, r0, ip, ror #24                         
  000022d0  2f0d0000      andeq    r0, r0, pc, lsr #26                         
  000022d4  a60d0000      andeq    r0, r0, r6, lsr #27                         
  000022d8  d40b0000      ldrdeq   r0, r1, [r0], -r4                           
  000022dc  000051e3      cmp      r1, #0                                      
  000022e0  0dc0a0e1      mov      ip, sp                                      
  000022e4  70d82de9      push     {r4, r5, r6, fp, ip, lr, pc}                
  000022e8  04b04ce2      sub      fp, ip, #4                                  
  000022ec  14d04de2      sub      sp, sp, #0x14                               
  000022f0  04408112      addne    r4, r1, #4                                  
  000022f4  0140a001      moveq    r4, r1                                      
  000022f8  20104be2      sub      r1, fp, #0x20                               
  000022fc  0030a0e3      mov      r3, #0                                      
  00002300  0050a0e1      mov      r5, r0                                      
  00002304  0260a0e1      mov      r6, r2                                      
  00002308  20300be5      str      r3, [fp, #-0x20]                            
  0000230c  d7faffeb      bl       #0xe70                                      
  00002310  000050e3      cmp      r0, #0                                      
  00002314  0900000a      beq      #0x2340                                     
  00002318  f8faffeb      bl       #0xf00                                      
  0000231c  88109fe5      ldr      r1, [pc, #0x88]                             
  00002320  d32200e3      movw     r2, #0x2d3                                  
  00002324  0530a0e1      mov      r3, r5                                      
  00002328  01108fe0      add      r1, pc, r1                                  
  0000232c  00008de5      str      r0, [sp]                                    
  00002330  78009fe5      ldr      r0, [pc, #0x78]                             
  00002334  00008fe0      add      r0, pc, r0                                  
  00002338  a5faffeb      bl       #0xdd4                                      
  0000233c  090000ea      b        #0x2368                                     
  00002340  20301be5      ldr      r3, [fp, #-0x20]                            
  00002344  382084e2      add      r2, r4, #0x38                               
  00002348  020053e1      cmp      r3, r2                                      
  0000234c  0700002a      bhs      #0x2370                                     
  00002350  5c009fe5      ldr      r0, [pc, #0x5c]                             
  00002354  e22200e3      movw     r2, #0x2e2                                  
  00002358  58109fe5      ldr      r1, [pc, #0x58]                             
  0000235c  00008fe0      add      r0, pc, r0                                  
  00002360  01108fe0      add      r1, pc, r1                                  
  00002364  9afaffeb      bl       #0xdd4                                      
  00002368  0000e0e3      mvn      r0, #0                                      
  0000236c  0c0000ea      b        #0x23a4                                     
  00002370  034064e0      rsb      r4, r4, r3                                  
  00002374  083044e2      sub      r3, r4, #8                                  
  00002378  20300be5      str      r3, [fp, #-0x20]                            
  0000237c  0f0013e2      ands     r0, r3, #0xf                                
  00002380  0500000a      beq      #0x239c                                     
  00002384  30009fe5      ldr      r0, [pc, #0x30]                             
  00002388  ed2200e3      movw     r2, #0x2ed                                  
  0000238c  2c109fe5      ldr      r1, [pc, #0x2c]                             
  00002390  00008fe0      add      r0, pc, r0                                  
  00002394  01108fe0      add      r1, pc, r1                                  
  00002398  f1ffffea      b        #0x2364                                     
  0000239c  384044e2      sub      r4, r4, #0x38                               
  000023a0  004086e5      str      r4, [r6]                                    
  000023a4  18d04be2      sub      sp, fp, #0x18                               
  000023a8  70a89de8      ldm      sp, {r4, r5, r6, fp, sp, pc}                
  000023ac  280b0000      andeq    r0, r0, r8, lsr #22                         
  000023b0  180d0000      andeq    r0, r0, r8, lsl sp                          
  000023b4  1d0d0000      andeq    r0, r0, sp, lsl sp                          
  000023b8  f00a0000      strdeq   r0, r1, [r0], -r0                           
  000023bc  0d0d0000      andeq    r0, r0, sp, lsl #26                         
  000023c0  bc0a0000      strheq   r0, [r0], -ip                               
  000023c4  0dc0a0e1      mov      ip, sp                                      
  000023c8  f0df2de9      push     {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr, pc}
  000023cc  04b04ce2      sub      fp, ip, #4                                  
  000023d0  c6de4de2      sub      sp, sp, #0xc60                              
  000023d4  c77e4be2      sub      r7, fp, #0xc70                              
  000023d8  0cd04de2      sub      sp, sp, #0xc                                
  000023dc  0050a0e1      mov      r5, r0                                      
  000023e0  0180a0e1      mov      r8, r1                                      
  000023e4  0010a0e3      mov      r1, #0                                      
  000023e8  02a0a0e1      mov      sl, r2                                      
  000023ec  0700a0e1      mov      r0, r7                                      
  000023f0  1020a0e3      mov      r2, #0x10                                   
  000023f4  0360a0e1      mov      r6, r3                                      
  000023f8  72faffeb      bl       #0xdc8                                      
  000023fc  0010a0e3      mov      r1, #0                                      
  00002400  2020a0e3      mov      r2, #0x20                                   
  00002404  c50e4be2      sub      r0, fp, #0xc50                              
  00002408  0040a0e3      mov      r4, #0                                      
  0000240c  6dfaffeb      bl       #0xdc8                                      
  00002410  420e4be2      sub      r0, fp, #0x420                              
  00002414  0010a0e3      mov      r1, #0                                      
  00002418  012ba0e3      mov      r2, #0x400                                  
  0000241c  0c0040e2      sub      r0, r0, #0xc                                
  00002420  68faffeb      bl       #0xdc8                                      
  00002424  2d0d4be2      sub      r0, fp, #0xb40                              
  00002428  0010a0e3      mov      r1, #0                                      
  0000242c  462fa0e3      mov      r2, #0x118                                  
  00002430  040040e2      sub      r0, r0, #4                                  
  00002434  63faffeb      bl       #0xdc8                                      
  00002438  0010a0e3      mov      r1, #0                                      
  0000243c  ec20a0e3      mov      r2, #0xec                                   
  00002440  c30e4be2      sub      r0, fp, #0xc30                              
  00002444  5ffaffeb      bl       #0xdc8                                      
  00002448  0410a0e1      mov      r1, r4                                      
  0000244c  1020a0e3      mov      r2, #0x10                                   
  00002450  c60e4be2      sub      r0, fp, #0xc60                              
  00002454  784c0be5      str      r4, [fp, #-0xc78]                           
  00002458  5afaffeb      bl       #0xdc8                                      
  0000245c  a20e4be2      sub      r0, fp, #0xa20                              
  00002460  0410a0e1      mov      r1, r4                                      
  00002464  022ca0e3      mov      r2, #0x200                                  
  00002468  0c0040e2      sub      r0, r0, #0xc                                
  0000246c  55faffeb      bl       #0xdc8                                      
  00002470  820e4be2      sub      r0, fp, #0x820                              
  00002474  0410a0e1      mov      r1, r4                                      
  00002478  022ca0e3      mov      r2, #0x200                                  
  0000247c  0c0040e2      sub      r0, r0, #0xc                                
  00002480  744c0be5      str      r4, [fp, #-0xc74]                           
  00002484  4ffaffeb      bl       #0xdc8                                      
  00002488  620e4be2      sub      r0, fp, #0x620                              
  0000248c  0410a0e1      mov      r1, r4                                      
  00002490  022ca0e3      mov      r2, #0x200                                  
  00002494  0c0040e2      sub      r0, r0, #0xc                                
  00002498  4afaffeb      bl       #0xdc8                                      
  0000249c  c63e4be2      sub      r3, fp, #0xc60                              
  000024a0  0c3043e2      sub      r3, r3, #0xc                                
  000024a4  822e4be2      sub      r2, fp, #0x820                              
  000024a8  081043e2      sub      r1, r3, #8                                  
  000024ac  0500a0e1      mov      r0, r5                                      
  000024b0  0c2042e2      sub      r2, r2, #0xc                                
  000024b4  0830a0e1      mov      r3, r8                                      
  000024b8  d4feffeb      bl       #0x2010                                     
  000024bc  040050e1      cmp      r0, r4                                      
  000024c0  4701001a      bne      #0x29e4                                     
  000024c4  c63e4be2      sub      r3, fp, #0xc60                              
  000024c8  0500a0e1      mov      r0, r5                                      
  000024cc  0c3043e2      sub      r3, r3, #0xc                                
  000024d0  741c1be5      ldr      r1, [fp, #-0xc74]                           
  000024d4  0c2043e2      sub      r2, r3, #0xc                                
  000024d8  7fffffeb      bl       #0x22dc                                     
  000024dc  040050e1      cmp      r0, r4                                      
  000024e0  0500000a      beq      #0x24fc                                     
  000024e4  08059fe5      ldr      r0, [pc, #0x508]                            
  000024e8  332300e3      movw     r2, #0x333                                  
  000024ec  04159fe5      ldr      r1, [pc, #0x504]                            
  000024f0  00008fe0      add      r0, pc, r0                                  
  000024f4  01108fe0      add      r1, pc, r1                                  
  000024f8  0a0000ea      b        #0x2528                                     
  000024fc  f8149fe5      ldr      r1, [pc, #0x4f8]                            
  00002500  0500a0e1      mov      r0, r5                                      
  00002504  01108fe0      add      r1, pc, r1                                  
  00002508  1cfaffeb      bl       #0xd80                                      
  0000250c  004050e2      subs     r4, r0, #0                                  
  00002510  0700001a      bne      #0x2534                                     
  00002514  e4049fe5      ldr      r0, [pc, #0x4e4]                            
  00002518  3a2300e3      movw     r2, #0x33a                                  
  0000251c  e0149fe5      ldr      r1, [pc, #0x4e0]                            
  00002520  00008fe0      add      r0, pc, r0                                  
  00002524  01108fe0      add      r1, pc, r1                                  
  00002528  0530a0e1      mov      r3, r5                                      
  0000252c  28faffeb      bl       #0xdd4                                      
  00002530  2b0100ea      b        #0x29e4                                     
  00002534  74cc1be5      ldr      ip, [fp, #-0xc74]                           
  00002538  00005ce3      cmp      ip, #0                                      
  0000253c  4000000a      beq      #0x2644                                     
  00002540  820e4be2      sub      r0, fp, #0x820                              
  00002544  88cc0be5      str      ip, [fp, #-0xc88]                           
  00002548  0c0040e2      sub      r0, r0, #0xc                                
  0000254c  b4949fe5      ldr      sb, [pc, #0x4b4]                            
  00002550  61faffeb      bl       #0xedc                                      
  00002554  09908fe0      add      sb, pc, sb                                  
  00002558  0010a0e1      mov      r1, r0                                      
  0000255c  0900a0e1      mov      r0, sb                                      
  00002560  841c0be5      str      r1, [fp, #-0xc84]                           
  00002564  5cfaffeb      bl       #0xedc                                      
  00002568  622e4be2      sub      r2, fp, #0x620                              
  0000256c  00908de5      str      sb, [sp]                                    
  00002570  841c1be5      ldr      r1, [fp, #-0xc84]                           
  00002574  0c2042e2      sub      r2, r2, #0xc                                
  00002578  023ca0e3      mov      r3, #0x200                                  
  0000257c  04008de5      str      r0, [sp, #4]                                
  00002580  820e4be2      sub      r0, fp, #0x820                              
  00002584  0c0040e2      sub      r0, r0, #0xc                                
  00002588  5ffaffeb      bl       #0xf0c                                      
  0000258c  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  00002590  009050e2      subs     sb, r0, #0                                  
  00002594  0700000a      beq      #0x25b8                                     
  00002598  820e4be2      sub      r0, fp, #0x820                              
  0000259c  0c0040e2      sub      r0, r0, #0xc                                
  000025a0  4dfaffeb      bl       #0xedc                                      
  000025a4  0910a0e1      mov      r1, sb                                      
  000025a8  0020a0e1      mov      r2, r0                                      
  000025ac  d20fa0e3      mov      r0, #0x348                                  
  000025b0  21fcffeb      bl       #0x163c                                     
  000025b4  0b0100ea      b        #0x29e8                                     
  000025b8  000056e3      cmp      r6, #0                                      
  000025bc  0c00000a      beq      #0x25f4                                     
  000025c0  621e4be2      sub      r1, fp, #0x620                              
  000025c4  0a00a0e1      mov      r0, sl                                      
  000025c8  0c1041e2      sub      r1, r1, #0xc                                
  000025cc  88cc0be5      str      ip, [fp, #-0xc88]                           
  000025d0  20faffeb      bl       #0xe58                                      
  000025d4  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  000025d8  000050e3      cmp      r0, #0                                      
  000025dc  0400000a      beq      #0x25f4                                     
  000025e0  4f0300e3      movw     r0, #0x34f                                  
  000025e4  0010e0e3      mvn      r1, #0                                      
  000025e8  0620a0e1      mov      r2, r6                                      
  000025ec  12fcffeb      bl       #0x163c                                     
  000025f0  fb0000ea      b        #0x29e4                                     
  000025f4  021ca0e3      mov      r1, #0x200                                  
  000025f8  0020a0e3      mov      r2, #0                                      
  000025fc  0130a0e1      mov      r3, r1                                      
  00002600  0a00a0e1      mov      r0, sl                                      
  00002604  04908ce2      add      sb, ip, #4                                  
  00002608  00faffeb      bl       #0xe10                                      
  0000260c  620e4be2      sub      r0, fp, #0x620                              
  00002610  0c0040e2      sub      r0, r0, #0xc                                
  00002614  30faffeb      bl       #0xedc                                      
  00002618  622e4be2      sub      r2, fp, #0x620                              
  0000261c  021ca0e3      mov      r1, #0x200                                  
  00002620  0c2042e2      sub      r2, r2, #0xc                                
  00002624  0030a0e1      mov      r3, r0                                      
  00002628  0a00a0e1      mov      r0, sl                                      
  0000262c  d0f9ffeb      bl       #0xd74                                      
  00002630  620e4be2      sub      r0, fp, #0x620                              
  00002634  0c0040e2      sub      r0, r0, #0xc                                
  00002638  27faffeb      bl       #0xedc                                      
  0000263c  0060a0e1      mov      r6, r0                                      
  00002640  000000ea      b        #0x2648                                     
  00002644  0c90a0e1      mov      sb, ip                                      
  00002648  0400a0e1      mov      r0, r4                                      
  0000264c  081089e2      add      r1, sb, #8                                  
  00002650  0020a0e3      mov      r2, #0                                      
  00002654  2ffaffeb      bl       #0xf18                                      
  00002658  000050e3      cmp      r0, #0                                      
  0000265c  060000aa      bge      #0x267c                                     
  00002660  a4039fe5      ldr      r0, [pc, #0x3a4]                            
  00002664  5d2300e3      movw     r2, #0x35d                                  
  00002668  a0139fe5      ldr      r1, [pc, #0x3a0]                            
  0000266c  0530a0e1      mov      r3, r5                                      
  00002670  00008fe0      add      r0, pc, r0                                  
  00002674  01108fe0      add      r1, pc, r1                                  
  00002678  5b0000ea      b        #0x27ec                                     
  0000267c  420e4be2      sub      r0, fp, #0x420                              
  00002680  0110a0e3      mov      r1, #1                                      
  00002684  0c0040e2      sub      r0, r0, #0xc                                
  00002688  1020a0e3      mov      r2, #0x10                                   
  0000268c  0430a0e1      mov      r3, r4                                      
  00002690  e7f9ffeb      bl       #0xe34                                      
  00002694  100050e3      cmp      r0, #0x10                                   
  00002698  0090a0e1      mov      sb, r0                                      
  0000269c  0700000a      beq      #0x26c0                                     
  000026a0  6c039fe5      ldr      r0, [pc, #0x36c]                            
  000026a4  672300e3      movw     r2, #0x367                                  
  000026a8  68139fe5      ldr      r1, [pc, #0x368]                            
  000026ac  00008fe0      add      r0, pc, r0                                  
  000026b0  01108fe0      add      r1, pc, r1                                  
  000026b4  c6f9ffeb      bl       #0xdd4                                      
  000026b8  0400a0e1      mov      r0, r4                                      
  000026bc  ae0000ea      b        #0x297c                                     
  000026c0  422e4be2      sub      r2, fp, #0x420                              
  000026c4  0910a0e1      mov      r1, sb                                      
  000026c8  0930a0e1      mov      r3, sb                                      
  000026cc  0c2042e2      sub      r2, r2, #0xc                                
  000026d0  0700a0e1      mov      r0, r7                                      
  000026d4  e2f9ffeb      bl       #0xe64                                      
  000026d8  a2ce4be2      sub      ip, fp, #0xa20                              
  000026dc  0cc04ce2      sub      ip, ip, #0xc                                
  000026e0  613c5be5      ldrb     r3, [fp, #-0xc61]                           
  000026e4  0a20a0e1      mov      r2, sl                                      
  000026e8  021ca0e3      mov      r1, #0x200                                  
  000026ec  0f3003e2      and      r3, r3, #0xf                                
  000026f0  0c00a0e1      mov      r0, ip                                      
  000026f4  803c0be5      str      r3, [fp, #-0xc80]                           
  000026f8  0630a0e1      mov      r3, r6                                      
  000026fc  88cc0be5      str      ip, [fp, #-0xc88]                           
  00002700  b6fcffeb      bl       #0x19e0                                     
  00002704  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  00002708  021ca0e3      mov      r1, #0x200                                  
  0000270c  02aaa0e3      mov      sl, #0x2000                                 
  00002710  0c00a0e1      mov      r0, ip                                      
  00002714  0efaffeb      bl       #0xf54                                      
  00002718  0930a0e1      mov      r3, sb                                      
  0000271c  2010a0e3      mov      r1, #0x20                                   
  00002720  0720a0e1      mov      r2, r7                                      
  00002724  0060a0e1      mov      r6, r0                                      
  00002728  c50e4be2      sub      r0, fp, #0xc50                              
  0000272c  ccf9ffeb      bl       #0xe64                                      
  00002730  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  00002734  0c90a0e1      mov      sb, ip                                      
  00002738  c30e4be2      sub      r0, fp, #0xc30                              
  0000273c  0010a0e3      mov      r1, #0                                      
  00002740  b5f9ffeb      bl       #0xe1c                                      
  00002744  c30e4be2      sub      r0, fp, #0xc30                              
  00002748  c51e4be2      sub      r1, fp, #0xc50                              
  0000274c  2020a0e3      mov      r2, #0x20                                   
  00002750  fcf9ffeb      bl       #0xf48                                      
  00002754  c30e4be2      sub      r0, fp, #0xc30                              
  00002758  0910a0e1      mov      r1, sb                                      
  0000275c  0620a0e1      mov      r2, r6                                      
  00002760  f8f9ffeb      bl       #0xf48                                      
  00002764  c30e4be2      sub      r0, fp, #0xc30                              
  00002768  c51e4be2      sub      r1, fp, #0xc50                              
  0000276c  ddf9ffeb      bl       #0xee8                                      
  00002770  01a05ae2      subs     sl, sl, #1                                  
  00002774  efffff1a      bne      #0x2738                                     
  00002778  021ca0e3      mov      r1, #0x200                                  
  0000277c  0900a0e1      mov      r0, sb                                      
  00002780  0130a0e1      mov      r3, r1                                      
  00002784  0a20a0e1      mov      r2, sl                                      
  00002788  a0f9ffeb      bl       #0xe10                                      
  0000278c  2d0d4be2      sub      r0, fp, #0xb40                              
  00002790  040040e2      sub      r0, r0, #4                                  
  00002794  c51e4be2      sub      r1, fp, #0xc50                              
  00002798  012ca0e3      mov      r2, #0x100                                  
  0000279c  92f9ffeb      bl       #0xdec                                      
  000027a0  c30e4be2      sub      r0, fp, #0xc30                              
  000027a4  c51e4be2      sub      r1, fp, #0xc50                              
  000027a8  2020a0e3      mov      r2, #0x20                                   
  000027ac  0a30a0e1      mov      r3, sl                                      
  000027b0  baf9ffeb      bl       #0xea0                                      
  000027b4  60129fe5      ldr      r1, [pc, #0x260]                            
  000027b8  0800a0e1      mov      r0, r8                                      
  000027bc  01108fe0      add      r1, pc, r1                                  
  000027c0  6ef9ffeb      bl       #0xd80                                      
  000027c4  009050e2      subs     sb, r0, #0                                  
  000027c8  426e4b12      subne    r6, fp, #0x420                              
  000027cc  0c604612      subne    r6, r6, #0xc                                
  000027d0  5000001a      bne      #0x2918                                     
  000027d4  44029fe5      ldr      r0, [pc, #0x244]                            
  000027d8  862300e3      movw     r2, #0x386                                  
  000027dc  40129fe5      ldr      r1, [pc, #0x240]                            
  000027e0  0830a0e1      mov      r3, r8                                      
  000027e4  00008fe0      add      r0, pc, r0                                  
  000027e8  01108fe0      add      r1, pc, r1                                  
  000027ec  78f9ffeb      bl       #0xdd4                                      
  000027f0  b0ffffea      b        #0x26b8                                     
  000027f4  0600a0e1      mov      r0, r6                                      
  000027f8  0110a0e3      mov      r1, #1                                      
  000027fc  1020a0e3      mov      r2, #0x10                                   
  00002800  0430a0e1      mov      r3, r4                                      
  00002804  8af9ffeb      bl       #0xe34                                      
  00002808  100050e3      cmp      r0, #0x10                                   
  0000280c  00c0a0e1      mov      ip, r0                                      
  00002810  0600000a      beq      #0x2830                                     
  00002814  0c029fe5      ldr      r0, [pc, #0x20c]                            
  00002818  922300e3      movw     r2, #0x392                                  
  0000281c  08129fe5      ldr      r1, [pc, #0x208]                            
  00002820  00008fe0      add      r0, pc, r0                                  
  00002824  01108fe0      add      r1, pc, r1                                  
  00002828  69f9ffeb      bl       #0xdd4                                      
  0000282c  4f0000ea      b        #0x2970                                     
  00002830  0c30a0e1      mov      r3, ip                                      
  00002834  0c10a0e1      mov      r1, ip                                      
  00002838  0620a0e1      mov      r2, r6                                      
  0000283c  c60e4be2      sub      r0, fp, #0xc60                              
  00002840  88cc0be5      str      ip, [fp, #-0xc88]                           
  00002844  86f9ffeb      bl       #0xe64                                      
  00002848  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  0000284c  c30e4be2      sub      r0, fp, #0xc30                              
  00002850  0610a0e1      mov      r1, r6                                      
  00002854  0c20a0e1      mov      r2, ip                                      
  00002858  7bf9ffeb      bl       #0xe4c                                      
  0000285c  2d0d4be2      sub      r0, fp, #0xb40                              
  00002860  040040e2      sub      r0, r0, #4                                  
  00002864  0010a0e3      mov      r1, #0                                      
  00002868  0620a0e1      mov      r2, r6                                      
  0000286c  0630a0e1      mov      r3, r6                                      
  00002870  9ff9ffeb      bl       #0xef4                                      
  00002874  00c0a0e3      mov      ip, #0                                      
  00002878  0630dce7      ldrb     r3, [ip, r6]                                
  0000287c  0c20d7e7      ldrb     r2, [r7, ip]                                
  00002880  033022e0      eor      r3, r2, r3                                  
  00002884  0630cce7      strb     r3, [ip, r6]                                
  00002888  01c08ce2      add      ip, ip, #1                                  
  0000288c  10005ce3      cmp      ip, #0x10                                   
  00002890  f8ffff1a      bne      #0x2878                                     
  00002894  0c30a0e1      mov      r3, ip                                      
  00002898  0c10a0e1      mov      r1, ip                                      
  0000289c  0700a0e1      mov      r0, r7                                      
  000028a0  c62e4be2      sub      r2, fp, #0xc60                              
  000028a4  88cc0be5      str      ip, [fp, #-0xc88]                           
  000028a8  6df9ffeb      bl       #0xe64                                      
  000028ac  803c1be5      ldr      r3, [fp, #-0xc80]                           
  000028b0  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  000028b4  000053e3      cmp      r3, #0                                      
  000028b8  0400000a      beq      #0x28d0                                     
  000028bc  78cc1be5      ldr      ip, [fp, #-0xc78]                           
  000028c0  10c04ce2      sub      ip, ip, #0x10                               
  000028c4  0c005ae1      cmp      sl, ip                                      
  000028c8  1030a013      movne    r3, #0x10                                   
  000028cc  03c0a0e1      mov      ip, r3                                      
  000028d0  0c20a0e1      mov      r2, ip                                      
  000028d4  0600a0e1      mov      r0, r6                                      
  000028d8  0110a0e3      mov      r1, #1                                      
  000028dc  0930a0e1      mov      r3, sb                                      
  000028e0  88cc0be5      str      ip, [fp, #-0xc88]                           
  000028e4  2ef9ffeb      bl       #0xda4                                      
  000028e8  88cc1be5      ldr      ip, [fp, #-0xc88]                           
  000028ec  0c0050e1      cmp      r0, ip                                      
  000028f0  0600000a      beq      #0x2910                                     
  000028f4  34019fe5      ldr      r0, [pc, #0x134]                            
  000028f8  a92300e3      movw     r2, #0x3a9                                  
  000028fc  30119fe5      ldr      r1, [pc, #0x130]                            
  00002900  0c30a0e1      mov      r3, ip                                      
  00002904  00008fe0      add      r0, pc, r0                                  
  00002908  01108fe0      add      r1, pc, r1                                  
  0000290c  160000ea      b        #0x296c                                     
  00002910  10a08ae2      add      sl, sl, #0x10                               
  00002914  ffffffea      b        #0x2918                                     
  00002918  783c1be5      ldr      r3, [fp, #-0xc78]                           
  0000291c  03005ae1      cmp      sl, r3                                      
  00002920  b3ffff3a      blo      #0x27f4                                     
  00002924  c30e4be2      sub      r0, fp, #0xc30                              
  00002928  c51e4be2      sub      r1, fp, #0xc50                              
  0000292c  67f9ffeb      bl       #0xed0                                      
  00002930  420e4be2      sub      r0, fp, #0x420                              
  00002934  0c0040e2      sub      r0, r0, #0xc                                
  00002938  0110a0e3      mov      r1, #1                                      
  0000293c  2020a0e3      mov      r2, #0x20                                   
  00002940  0430a0e1      mov      r3, r4                                      
  00002944  3af9ffeb      bl       #0xe34                                      
  00002948  200050e3      cmp      r0, #0x20                                   
  0000294c  0060a0e1      mov      r6, r0                                      
  00002950  0b00000a      beq      #0x2984                                     
  00002954  dc009fe5      ldr      r0, [pc, #0xdc]                             
  00002958  b72300e3      movw     r2, #0x3b7                                  
  0000295c  d8109fe5      ldr      r1, [pc, #0xd8]                             
  00002960  2030a0e3      mov      r3, #0x20                                   
  00002964  00008fe0      add      r0, pc, r0                                  
  00002968  01108fe0      add      r1, pc, r1                                  
  0000296c  18f9ffeb      bl       #0xdd4                                      
  00002970  0400a0e1      mov      r0, r4                                      
  00002974  6af9ffeb      bl       #0xf24                                      
  00002978  0900a0e1      mov      r0, sb                                      
  0000297c  68f9ffeb      bl       #0xf24                                      
  00002980  170000ea      b        #0x29e4                                     
  00002984  0400a0e1      mov      r0, r4                                      
  00002988  65f9ffeb      bl       #0xf24                                      
  0000298c  0900a0e1      mov      r0, sb                                      
  00002990  63f9ffeb      bl       #0xf24                                      
  00002994  421e4be2      sub      r1, fp, #0x420                              
  00002998  c50e4be2      sub      r0, fp, #0xc50                              
  0000299c  0c1041e2      sub      r1, r1, #0xc                                
  000029a0  0620a0e1      mov      r2, r6                                      
  000029a4  34f9ffeb      bl       #0xe7c                                      
  000029a8  009050e2      subs     sb, r0, #0                                  
  000029ac  0600000a      beq      #0x29cc                                     
  000029b0  88009fe5      ldr      r0, [pc, #0x88]                             
  000029b4  c22300e3      movw     r2, #0x3c2                                  
  000029b8  84109fe5      ldr      r1, [pc, #0x84]                             
  000029bc  00008fe0      add      r0, pc, r0                                  
  000029c0  01108fe0      add      r1, pc, r1                                  
  000029c4  02f9ffeb      bl       #0xdd4                                      
  000029c8  050000ea      b        #0x29e4                                     
  000029cc  0500a0e1      mov      r0, r5                                      
  000029d0  14f9ffeb      bl       #0xe28                                      
  000029d4  0800a0e1      mov      r0, r8                                      
  000029d8  0510a0e1      mov      r1, r5                                      
  000029dc  fff8ffeb      bl       #0xde0                                      
  000029e0  000000ea      b        #0x29e8                                     
  000029e4  0090e0e3      mvn      sb, #0                                      
  000029e8  0900a0e1      mov      r0, sb                                      
  000029ec  28d04be2      sub      sp, fp, #0x28                               
  000029f0  f0af9de8      ldm      sp, {r4, r5, r6, r7, r8, sb, sl, fp, sp, pc}
  000029f4  d50b0000      ldrdeq   r0, r1, [r0], -r5                           
  000029f8  5c090000      andeq    r0, r0, ip, asr sb                          
  000029fc  5b090000      andeq    r0, r0, fp, asr sb                          
  00002a00  cb0b0000      andeq    r0, r0, fp, asr #23                         
  00002a04  2c090000      andeq    r0, r0, ip, lsr #18                         
  00002a08  bb0b0000      strheq   r0, [r0], -fp                               
  00002a0c  b00a0000      strheq   r0, [r0], -r0                               
  00002a10  dc070000      ldrdeq   r0, r1, [r0], -ip                           
  00002a14  950a0000      muleq    r0, r5, sl                                  
  00002a18  a0070000      andeq    r0, r0, r0, lsr #15                         
  00002a1c  bb060000      strheq   r0, [r0], -fp                               
  00002a20  8c090000      andeq    r0, r0, ip, lsl #19                         
  00002a24  68060000      andeq    r0, r0, r8, ror #12                         
  00002a28  6f090000      andeq    r0, r0, pc, ror #18                         
  00002a2c  2c060000      andeq    r0, r0, ip, lsr #12                         
  00002a30  b6050000      strheq   r0, [r0], -r6                               
  00002a34  48050000      andeq    r0, r0, r8, asr #10                         
  00002a38  78050000      andeq    r0, r0, r8, ror r5                          
  00002a3c  e8040000      andeq    r0, r0, r8, ror #9                          
  00002a40  ff070000      strdeq   r0, r1, [r0], -pc                           
  00002a44  90040000      muleq    r0, r0, r4                                  