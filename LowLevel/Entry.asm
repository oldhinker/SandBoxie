ifndef _WIN64

.386p
.model flat,stdcall

endif

.code 
start:	
ifdef _WIN64  ;64-bit

EXTERN 	EntryPointC : PROC
_Start:
		;int 3
		sub	rsp, 28h		
		mov	qword ptr [rsp+4*8], rcx
		mov	qword ptr [rsp+5*8], rdx
		mov	qword ptr [rsp+6*8], r8
		mov	qword ptr [rsp+7*8], r9

		call	$+5
_001:	pop     rcx	
		mov rbx,rcx									;rbx = rcx = _001:的代码地址
		add	rcx, offset DataInfo - _001				;rcx = DataInfo数据的绝对地址
		mov rdx,rbx                                
		add rdx, offset _DetourCode - _001          ;rdx = _DetourCode数据的绝对地址
		mov r8,rbx
		add r8, offset _SystemService - _001        ;r8 = _SystemService函数的绝对地址
        		
		call	EntrypointC
		
		mov	rcx, qword ptr [rsp+4*8]
		mov	rdx, qword ptr [rsp+5*8]
		mov	r8, qword ptr [rsp+6*8]
		mov	r9, qword ptr [rsp+7*8]
		add	rsp, 28h
		jmp	rax										;rax = jump to LdrInitializeThunk trampoline

else    ;32-bit
EXTERN 	EntryPointC@12 : PROC
_Start:		
		call	$+5   
_001:	pop	eax
		mov edx,eax
		add eax, offset _SystemService - _001 
		push eax
		mov eax,edx
		add eax, offset _RtlFindActivationContextSectionString - _001
		push eax
		mov eax, edx
		add	eax, offset DataInfo - _001
		push eax
		call	EntryPointC@12
		jmp	eax	

endif	
_SystemService:		
ifdef _WIN64	; 64-bit
ServiceProcedure Proc  
		db	48h, 0B8h	; rax -> DataInfo
		dq	?
	
		push rdi; target rsp 
		push rbx; target rip

		mov r11,[rax + 0e0h] ; DataInfo.RealNtDeviceIoControlFile
		add r11b,0fh

		mov rbx, r11 ; pass new rip in rbx
		mov r11, rsp ; restore stack in r11
		add	r11, 10h 

		mov rdi, r11 ; pass stack frame in rbp

		API_NUM_ARGS = 8
		sub	rsp, (API_NUM_ARGS + 1 + 2 + 10) * 8

		;
		; spill parameters in registers onto the stack
		;

		mov	qword ptr [r11+1*8], rcx
		mov	qword ptr [r11+2*8], rdx
		mov	qword ptr [r11+3*8], r8
		mov	qword ptr [r11+4*8], r9

		
		;
		; parms[1] = syscall_index
		; parms[2] = pointer to system service arguments on stack
		; parms[0] = API_INVOKE_SYSCALL (from SbieLowData)
		;

		lea	rcx, [rsp+13*8]			; rcx -> parms
		
		mov	qword ptr [rcx+1*8], r10	; syscall index
		mov	r10, rax			; r10 -> SbieLowData

		lea	r11, [r11+8]
		mov	qword ptr [rcx+2*8], r11	; stack address
		
		mov	eax, dword ptr [r10+3*8+4]	; API_INVOKE_SYSCALL
		mov	qword ptr [rcx+0*8], rax
		
		;
		; the 64-bit kernel function for NtDeviceIoControlFile
		; expects the 64-bit IoStatusBlock argument to contain a
		; 32-bit pointer to a 32-bit IoStatusBlock structure.
		; we can allocate the 32-bit structure on the stack
		; because the stack is 32-bits in a 32-bit program
		;
		
		lea	rax, [rsp+12*8]		; rax -> IoStatusBlock32
		lea	rdx, [rsp+10*8]		; rdx -> MyIoStatusBlock64
		mov	qword ptr [rdx], rax
		
		;
		; invoke SbieLow.NtDeviceIoControlFile(
		;		data->api_device_handle,
		;		NULL, NULL, NULL,
		;		&MyIoStatusBlock,
		;		API_SBIEDRV_CTLCODE,
		;		parms,
		;		API_NUM_ARGS * sizeof(ULONG64),
		;		NULL, 0);
		;
		
		mov	qword ptr [rsp+4*8], rdx	; MyIoStatusBlock64

		mov	eax, [r10+3*8+0]		; API_SBIEDRV_CTLCODE
		mov	qword ptr [rsp+5*8], rax
		
		mov	qword ptr [rsp+6*8], rcx	; parms
		
		mov	eax, (API_NUM_ARGS * 8)
		mov	qword ptr [rsp+7*8], rax
		
		mov	rcx, qword ptr [r10+2*8]	; file handle

		xor	rdx, rdx
		mov	r8, rdx
		mov	r9, rdx
		
		mov	qword ptr [rsp+8*8], rdx
		mov	qword ptr [rsp+9*8], rdx

		lea	r10, [r10+80h] ; r10 -> SbieLow.NtDeviceIoControlFile_code

		call	r10
		add	rsp, (API_NUM_ARGS + 1 + 2 + 10) * 8

		pop rbx
		pop rdi
        ret
		
ServiceProcedure ENDP

else 		; 32-bit

		mov	edx, 0		; edx -> SbieLowData
		push	eax		; save syscall index and param count
		push	ebp
		mov	ebp, esp
		
		;
		; make room for several qwords on the stack:
		;     IO_STATUS_BLOCK MyIoStatusBlock;
		;     __declspec(align(8)) ULONG64 parms[API_NUM_ARGS];
		; align stack on 8-bytes for call to NtDeviceIoControlFile
		;
		; keep API_NUM_ARGS in sync with core/drv/api_defs.h

		API_NUM_ARGS = 8
		
		sub	esp, (API_NUM_ARGS + 1) * 8 + 7
		and	esp, 0FFFFFFF8h
		
		;
		; parms[1] = syscall_index
		; parms[2] = pointer to system service arguments on stack
		; parms[0] = API_INVOKE_SYSCALL (from SbieLowData)
		;

		and	eax, 1FFFh	; keep just service index number
		mov	dword ptr [esp+2*8], eax

		lea	eax, [ebp+4*3]	; eax -> orig arg 1 on stack
		mov	dword ptr [esp+3*8], eax
		
		mov	eax, [edx+3*8+4] ; eax = SbieLow.api_invoke_syscall
		mov	dword ptr [esp+1*8], eax

		;
		; invoke SbieLow.NtDeviceIoControlFile(
		;		data->api_device_handle,
		;		NULL, NULL, NULL,
		;		&MyIoStatusBlock,
		;		API_SBIEDRV_CTLCODE,
		;		parms,
		;		API_NUM_ARGS * sizeof(ULONG64),
		;		NULL, 0);
		;
		
		mov	ecx, esp	; ecx = address of IoStatusBlock
		lea	eax, [esp+1*8]	; eax = address of parms
		
		push	0
		push	0
		push	(API_NUM_ARGS * 8)
		push	eax		; push address of parms
		push	[edx+3*8+0]	; push API_SBIEDRV_CTLCODE
		push	ecx		; push address of IoStatusBlock
		push	0
		push	0
		push	0
		push	[edx+2*8]	; push SbieLow.api_device_handle

		lea	eax, [edx+80h] ; eax -> SbieLow.NtDeviceIoControlFile_code
		call	eax
		
		;
		; restore stack and return to caller.  we can't do "ret n"
		; because n is not a known constant, so we manually pop the
		; arguments off the stack and jump to the return address
		;
		
		mov	esp, ebp
		pop	ebp
		
		pop	ecx		; restore original eax
		shr	ecx, 24		; keep just param count
		add	ecx, 4
		add	esp, ecx	; pop arguments for service call
		neg	ecx
		mov	ecx, [esp+ecx]
		jmp	ecx		; return to caller

endif 		; 32-bit or 64-bit

InjectData		struct		
DataInfo				dq	?				; 0x00
RtlFindActCtx			dq	?				; 0x08
InjectData		ends

ifdef _WIN64
EXTERN 		DetourProcedure : PROC
dq 0h       ;InjectData
_DetourCode:
		mov	rax, qword ptr [$-8]		; rax -> inject data area	
		push	rsi		; save rsi, and align stack
		sub	rsp, 8*8	; set up local stack
		;int 3
		mov	qword ptr [rsp+4*8], rcx
		mov	qword ptr [rsp+5*8], rdx
		mov	qword ptr [rsp+6*8], r8
		mov	qword ptr [rsp+7*8], r9
		mov  	rsi, rax  	

		mov	rcx, rsi
		xor	rdx, rdx
		xor	r8, r8
		xor	r9, r9
		call DetourProcedure

		mov	rcx, qword ptr [rsp+4*8]
		mov	rdx, qword ptr [rsp+5*8]
		mov	r8, qword ptr [rsp+6*8]
		mov	r9, qword ptr [rsp+7*8]
		
		add	rsp, 8*8
		mov	rax, qword ptr [rsi].InjectData.RtlFindActCtx
		pop	rsi
		jmp	rax
else 	

_DetourCode:
endif 		; 32-bit or 64-bit

DataInfo LABEL	QWORD

		dq	48 dup (0)	

.code	xxxx
		dq	 _Start
		dq   DataInfo
		dq	_DetourCode
END
