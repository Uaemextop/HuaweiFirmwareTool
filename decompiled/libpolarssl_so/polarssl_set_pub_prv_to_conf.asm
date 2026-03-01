
### polarssl_set_pub_prv_to_conf @ 0x3ee34
  0003ee34  f8402de9      push     {r3, r4, r5, r6, r7, lr}                  
  0003ee38  004050e2      subs     r4, r0, #0                                
  0003ee3c  0160a0e1      mov      r6, r1                                    
  0003ee40  0270a0e1      mov      r7, r2                                    
  0003ee44  0350a0e1      mov      r5, r3                                    
  0003ee48  2300000a      beq      #0x3eedc                                  
  0003ee4c  0100a0e3      mov      r0, #1                                    
  0003ee50  4e1fa0e3      mov      r1, #0x138                                
  0003ee54  f341ffeb      bl       #0xf628                                   
  0003ee58  000050e3      cmp      r0, #0                                    
  0003ee5c  0c0084e5      str      r0, [r4, #0xc]                            
  0003ee60  1a00000a      beq      #0x3eed0                                  
  0003ee64  0010a0e3      mov      r1, #0                                    
  0003ee68  4e2fa0e3      mov      r2, #0x138                                
  0003ee6c  c743ffeb      bl       #0xfd90                                   
  0003ee70  0100a0e3      mov      r0, #1                                    
  0003ee74  0810a0e3      mov      r1, #8                                    
  0003ee78  ea41ffeb      bl       #0xf628                                   
  0003ee7c  000050e3      cmp      r0, #0                                    
  0003ee80  100084e5      str      r0, [r4, #0x10]                           
  0003ee84  1100000a      beq      #0x3eed0                                  
  0003ee88  00c0a0e3      mov      ip, #0                                    
  0003ee8c  0710a0e1      mov      r1, r7                                    
  0003ee90  00c080e5      str      ip, [r0]                                  
  0003ee94  04c080e5      str      ip, [r0, #4]                              
  0003ee98  0c0094e5      ldr      r0, [r4, #0xc]                            
  0003ee9c  ba44ffeb      bl       #0x1018c                                  
  0003eea0  0610a0e1      mov      r1, r6                                    
  0003eea4  0520a0e1      mov      r2, r5                                    
  0003eea8  0070a0e1      mov      r7, r0                                    
  0003eeac  100094e5      ldr      r0, [r4, #0x10]                           
  0003eeb0  4845ffeb      bl       #0x103d8                                  
  0003eeb4  0c1094e5      ldr      r1, [r4, #0xc]                            
  0003eeb8  102094e5      ldr      r2, [r4, #0x10]                           
  0003eebc  075080e1      orr      r5, r0, r7                                
  0003eec0  000094e5      ldr      r0, [r4]                                  
  0003eec4  9541ffeb      bl       #0xf520                                   
  0003eec8  000085e1      orr      r0, r5, r0                                
  0003eecc  f880bde8      pop      {r3, r4, r5, r6, r7, pc}                  
  ; [RETURN]