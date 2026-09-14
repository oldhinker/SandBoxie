ifndef _WIN64

.386
.model flat,stdcall

endif

.code 
Interrupt Proc  
		
		int 3
        ret
		
Interrupt ENDP


END
