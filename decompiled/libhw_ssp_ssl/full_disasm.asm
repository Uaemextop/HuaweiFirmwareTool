# libhw_ssp_ssl.so  –  Full ARM32 Disassembly
# Size:      13,188 bytes
# .text:     0x00001118  size=3,304  (35 instructions)
# Exports:   34
# PLT imps:  42

  00001118  0dc0a0e1      mov      ip, sp                                      
  0000111c  0030a0e3      mov      r3, #0                                      
  00001120  00d82de9      push     {fp, ip, lr, pc}                            
  00001124  04b04ce2      sub      fp, ip, #4                                  
  00001128  10d04de2      sub      sp, sp, #0x10                               
  0000112c  00c0a0e1      mov      ip, r0                                      
  00001130  20009fe5      ldr      r0, [pc, #0x20]                             
  00001134  0120a0e1      mov      r2, r1                                      
  00001138  00308de5      str      r3, [sp]                                    
  0000113c  04308de5      str      r3, [sp, #4]                                
  00001140  00008fe0      add      r0, pc, r0                                  
  00001144  08308de5      str      r3, [sp, #8]                                
  00001148  0c10a0e1      mov      r1, ip                                      
  0000114c  91ffffeb      bl       #0xf98                                      
  00001150  0cd04be2      sub      sp, fp, #0xc                                
  00001154  00a89de8      ldm      sp, {fp, sp, pc}                            
  00001158  b80c0000      strheq   r0, [r0], -r8                               

; ─── HW_SSL_EnableCAUpdate @ 0x0000115c ───
  0000115c  010050e3      cmp      r0, #1                                      
  00001160  0010a0e1      mov      r1, r0                                      
  00001164  0100009a      bls      #0x1170                                     
  00001168  3000a0e3      mov      r0, #0x30                                   
  0000116c  e9ffffea      b        #0x1118                                     
  00001170  7cffffea      b        #0xf68                                      

; ─── HW_SSL_GetCipher @ 0x00001174 ───
  00001174  0dc0a0e1      mov      ip, sp                                      
  00001178  18d82de9      push     {r3, r4, fp, ip, lr, pc}                    
  0000117c  004050e2      subs     r4, r0, #0                                  
  00001180  04b04ce2      sub      fp, ip, #4                                  
  00001184  0100000a      beq      #0x1190                                     
  00001188  18689de8      ldm      sp, {r3, r4, fp, sp, lr}                    
  0000118c  baffffea      b        #0x107c                                     
  00001190  4500a0e3      mov      r0, #0x45                                   
  00001194  08109fe5      ldr      r1, [pc, #8]                                
  00001198  deffffeb      bl       #0x1118                                     
  0000119c  0400a0e1      mov      r0, r4                                      
  000011a0  18a89de8      ldm      sp, {r3, r4, fp, sp, pc}                    