/* change.asm */
global change_16
global change_32
global bit

section .data
	buf : db 0,0,0,0

section .text
change_16 :
	push rbp
	mov rbp,rsp
	push rbx
	
	mov rax,0
	mov ax,di		;edi 高8位	al
	mov bx,si		;esi 低8位	bl
	mov ah,al
	mov al,bl
	
	pop rbx
	pop rbp

	ret 

change_32 :
	push rbp
	mov rbp,rsp

	mov eax,0
	mov eax,edi
	mov [buf+3],al
	mov eax,esi
	mov [buf+2],al
	mov eax,edx
	mov [buf+1],al
	mov eax,ecx
	mov [buf],al

	mov eax,[buf]

	pop rbp
	ret

bit : 
	push rbp
	mov rbp,rsp

	push rbx
	push rcx

	mov rax,0
	mov rcx,0
	mov ecx,esi

	mov ax,di
	mov ah,0
	dec cl
	shr al,cl
	and ax,1

	pop rcx
	pop rbx
	pop rbp

	ret
