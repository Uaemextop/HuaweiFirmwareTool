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