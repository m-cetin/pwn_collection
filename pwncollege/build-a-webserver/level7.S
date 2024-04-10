# This code is a simple HTTP server that listens for one connection, reads the HTTP request, 
# serves the requested file, and then exits. It uses syscalls directly, which are low-level system calls to the Linux kernel. 
# The code is written in x86-64 assembly language and is intended to be run on a Linux system. 
# Each syscall has a number associated with it, which is placed in the rax register before calling the syscall instruction. 
# The arguments for the syscalls are placed in the rdi, rsi, rdx, r10, r8, and r9 registers, in that order. 

.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Open a socket using the socket syscall (number 41)
    # rdi = domain (AF_INET = 2), rsi = type (SOCK_STREAM = 1), rdx = protocol (IPPROTO_IP = 0)
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 41
    syscall
    # Store the returned socket file descriptor in rbx for later use
    mov rbx, rax

    # Bind the socket to an address using the bind syscall (number 49)
    # rdi = socket file descriptor, rsi = pointer to sockaddr structure, rdx = size of sockaddr structure
    mov rdi, rbx
    lea rsi, sa_family_t
    mov rdx, 16
    mov rax, 49
    syscall

    # Listen for incoming connections on the socket using the listen syscall (number 50)
    # rdi = socket file descriptor, rsi = backlog (number of connections allowed on the incoming queue)
    mov rdi, rbx
    mov rsi, 0
    mov rax, 50
    syscall

    # Accept a connection using the accept syscall (number 43)
    # rdi = socket file descriptor, rsi = pointer to sockaddr structure for the client address (null if not needed), rdx = size of client address structure
    mov rdi, rbx
    mov rsi, 0
    mov rdx, 0
    mov rax, 43
    syscall
    # Save the returned file descriptor for the new connection in r12
    mov r12, rax

    # Read data from the connection using the read syscall (number 0)
    # rdi = file descriptor of the connection, rsi = buffer to read into, rdx = number of bytes to read
    mov rdi, r12
    lea rsi, read_buffer
    mov rdx, [read_packet_length]
    mov rax, 0
    syscall

    # Parse the HTTP request to figure out the requested file
    # We assume the request is in the format "GET /filename HTTP/1.1"
    # We use a helper function get_nth_substr to find the second space character, which is followed by the filename
    lea rdi, read_buffer
    mov rsi, 1
    lea rdx, space
    call get_nth_substr
    mov r13, rax
    lea rdi, read_buffer
    mov rsi, 2
    call get_nth_substr
    mov r14, rax
    sub r14, 1
    # r13 = start (exclusive), r14 = end (inclusive) of the filename in the request
    mov rdi, r13
    mov rsi, r14
    lea rdx, file_name_buffer
    call write_to_buf
    # The filename is now stored in file_name_buffer

    # Open the requested file using the open syscall (number 2)
    # rdi = pointer to the filename, rsi = flags (O_RDONLY = 0), rdx = mode (not needed when opening for reading)
    lea rdi, file_name_buffer
    mov rsi, 0
    mov rdx, 0
    mov rax, 2
    syscall
    # Save the returned file descriptor in r13
    mov r13, rax

    # Read the contents of the file into a buffer using the read syscall
    # rdi = file descriptor, rsi = buffer to read into, rdx = number of bytes to read
    mov rdi, r13
    lea rsi, file_read_buffer
    mov rdx, 1024
    mov rax, 0
    syscall

    # Close the file using the close syscall (number 3)
    # rdi = file descriptor
    mov rdi, r13
    mov rax, 3
    syscall

    # Write the HTTP response status line to the connection
    # We use the write syscall (number 1) to send data over the connection
    # rdi = file descriptor, rsi = buffer containing the status line, rdx = number of bytes to write
    mov rdi, r12
    lea rsi, write_static
    mov rdx, 19
    mov rax, 1
    syscall

    # Write the contents of the file to the connection
    # First, we calculate the length of the file data using a helper function get_len
    lea rdi, file_read_buffer
    call get_len
    mov rdx, rax
    sub rdx, 1
    # Then we use the write syscall to send the file data
    mov rdi, r12
    lea rsi, file_read_buffer
    mov rax, 1
    syscall

    # Close the connection using the close syscall
    mov rdi, r12
    mov rax, 3
    syscall

    # Exit the program using the exit syscall (number 60)
    # rdi = exit status
    mov rdi, 0
    mov rax, 60
    syscall

    # helper functions from: https://gist.githubusercontent.com/Elijah-Bodden/88416ba6671bae09a467b10ab208499c/raw/4fe2bade838122d5e50bd1a93d71933891fa45be/Web%2520server.S
    # Get the length of a null-terminated string (including the first null byte)
    # Args:
    # rdi - buffer we're checking the length of
    # rax - length
    get_len:
        mov rax, 0
        get_len_loop:
            # See if rdi + rax-th byte is null
            mov r10, rdi
            add r10, rax
            mov r10, [r10]
            add rax, 1
            cmp r10, 0x00
            jne get_len_loop
        ret

    # Copy the bytes spanning rdi to rsi to the buffer rdx
    # rdx MUST BE LONGER THAN rsi - rdi BYTES, rdi MUST BE LESS THAN rsi
    # Args:
    # rdi - start (exclusive) of the string we're copying
    # rsi - end (inclusive) of the string we're copying
    # rdx - buffer we're copying to
    # rax - unchanged
    write_to_buf:
        write_to_buf_loop:
            add rdi, 1
            mov r9, [rdi]
            mov [rdx], r9
            add rdx, 1
            cmp rdi, rsi
            jne write_to_buf_loop
        mov byte ptr [rdx], 0x00
        ret

    # Get address of the (last byte of) the nth occurence of substring in string (occurences must be non-overlapping)
    # ONLY GUARANTEED TO WORK ON NULL-TERMINATED STRINGS
    # Args:
    # rdi - target string address
    # rsi - n
    # rdx - substring

    # rax - address of nth character
    get_nth_substr:
        # Set rcx (ocurrence counter)
        mov rcx, 0
        # Set r10 (to traverse substring)
        mov r10, rdx
        check_character_loop:
            # r9b = character at position
            mov r9b, [rdi]
            # If string's terminated, obviously the substring doesn't occur enough times
            cmp r9b, 0x00
            je not_enough_occurrences
            # Step through substring iff r9b = current byte
            cmp r9b, byte ptr [r10]
            jne character_not_equal
                add r10, 1
                # If we've reached the end of the substring, increment counter and reset r10
                cmp byte ptr [r10], 0x00
                jne after_comparison
                    mov r10, rdx
                    add rcx, 1
                    jmp after_comparison
            character_not_equal:
                # Reset r10 without adding to count
                mov r10, rdx
            after_comparison:
            # Return address if we've got the nth ocurrence
            cmp rcx, rsi
            je match
            # Otherwise increment and continue
            add rdi, 1
            jmp check_character_loop
        match:
        mov rax, rdi
        ret
        not_enough_occurrences:
        mov rax, -1
        ret

.section .data
    # sockaddr_in struct
    sa_family_t: .word 2
    bind_port: .word 0x5000   # 0x5000 is port 80
    bind_address: .double 0x00000000
    pad: .byte 0,0,0,0,0,0,0,0
    # Buffers for reading data and storing filenames
    read_buffer: .space 1024
    file_name_buffer: .space 1024
    file_read_buffer: .space 1024
    read_packet_length: .quad 0x0000000000000400
    # Static HTTP response status line
    write_static: .string "HTTP/1.0 200 OK\r\n\r\n"
    # Strings used for parsing the HTTP request
    space: .string " "
    double_cr_lf: .string "\r\n\r\n"
