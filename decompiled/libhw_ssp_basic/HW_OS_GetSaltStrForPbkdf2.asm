### HW_OS_GetSaltStrForPbkdf2 @ 0x2f0f4
  0002f0f4  0dc0a0e1      mov      ip, sp                                    
  0002f0f8  30d82de9      push     {r4, r5, fp, ip, lr, pc}                  
  0002f0fc  04b04ce2      sub      fp, ip, #4                                
  0002f100  0140a0e1      mov      r4, r1                                    
  0002f104  0050a0e1      mov      r5, r0                                    
  0002f108  42c8ffeb      bl       #0x21218                                  
  0002f10c  0510a0e1      mov      r1, r5                                    
  0002f110  0420a0e1      mov      r2, r4                                    
  0002f114  30689de8      ldm      sp, {r4, r5, fp, sp, lr}                  
  0002f118  55c0ffea      b        #0x1f274                                  
  0002f11c  2134a0e1      lsr      r3, r1, #8                                
  0002f120  0310c0e5      strb     r1, [r0, #3]                              
  0002f124  0230c0e5      strb     r3, [r0, #2]                              
  0002f128  2138a0e1      lsr      r3, r1, #0x10                             
  0002f12c  211ca0e1      lsr      r1, r1, #0x18                             
  0002f130  0130c0e5      strb     r3, [r0, #1]                              
  0002f134  0010c0e5      strb     r1, [r0]                                  
  0002f138  1eff2fe1      bx       lr                                        