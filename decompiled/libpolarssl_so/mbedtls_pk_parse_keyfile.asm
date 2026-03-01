
### mbedtls_pk_parse_keyfile @ 0x31ddc
  00031ddc  70402de9      push     {r4, r5, r6, lr}                          
  00031de0  10d04de2      sub      sp, sp, #0x10                             
  00031de4  0060a0e1      mov      r6, r0                                    
  00031de8  0250a0e1      mov      r5, r2                                    
  00031dec  0100a0e1      mov      r0, r1                                    
  00031df0  08208de2      add      r2, sp, #8                                
  00031df4  0c108de2      add      r1, sp, #0xc                              
  00031df8  4574ffeb      bl       #0xef14                                   
  00031dfc  004050e2      subs     r4, r0, #0                                
  00031e00  0f00001a      bne      #0x31e44                                  
  00031e04  000055e3      cmp      r5, #0                                    
  00031e08  1000000a      beq      #0x31e50                                  
  00031e0c  0500a0e1      mov      r0, r5                                    
  00031e10  e579ffeb      bl       #0x105ac                                  
  00031e14  0530a0e1      mov      r3, r5                                    
  00031e18  0c109de5      ldr      r1, [sp, #0xc]                            
  00031e1c  08209de5      ldr      r2, [sp, #8]                              
  00031e20  00008de5      str      r0, [sp]                                  
  00031e24  0600a0e1      mov      r0, r6                                    
  00031e28  5975ffeb      bl       #0xf394                                   
  00031e2c  0040a0e1      mov      r4, r0                                    
  00031e30  0c009de5      ldr      r0, [sp, #0xc]                            
  00031e34  08109de5      ldr      r1, [sp, #8]                              
  00031e38  9c76ffeb      bl       #0xf8b0                                   
  00031e3c  0c009de5      ldr      r0, [sp, #0xc]                            
  00031e40  517affeb      bl       #0x1078c                                  
  00031e44  0400a0e1      mov      r0, r4                                    
  00031e48  10d08de2      add      sp, sp, #0x10                             
  00031e4c  7080bde8      pop      {r4, r5, r6, pc}                          
  ; [RETURN]