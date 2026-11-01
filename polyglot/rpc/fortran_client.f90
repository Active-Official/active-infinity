! Thin Active RPC client over native ARP1 on TCP (Fortran 2018).
!
! Run against `active-rpc/examples/thin_peer.rs`:
!
!   ACTIVE_RPC_ADDR=127.0.0.1:54321 \
!   ACTIVE_RPC_CAP=<32 hex chars> \
!   ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
!   ./rpc-client-fortran
!
! Fortran has no socket module, so the connect/send/recv calls go through
! `native/rpc_socket.c` (a byte carrier, nothing more). The envelope itself is
! encoded here, field by field, in little-endian order: that is what the lane
! proves.
!
! Build: cc -c polyglot/rpc/native/rpc_socket.c -o rpc_socket.o
!        gfortran -O2 polyglot/rpc/fortran_client.f90 rpc_socket.o -o rpc-client-fortran

program rpc_client
    use, intrinsic :: iso_c_binding
    implicit none

    integer, parameter :: max_frame = 1048576

    interface
        function arp1_connect(host, port) bind(c, name="arp1_connect") result(handle)
            import :: c_char, c_int64_t
            character(kind=c_char), intent(in) :: host(*)
            integer(c_int64_t), value :: port
            integer(c_int64_t) :: handle
        end function arp1_connect

        function arp1_send(handle, buffer, length) bind(c, name="arp1_send") result(status)
            import :: c_int64_t, c_int8_t
            integer(c_int64_t), value :: handle
            integer(c_int8_t), intent(in) :: buffer(*)
            integer(c_int64_t), value :: length
            integer(c_int64_t) :: status
        end function arp1_send

        function arp1_recv(handle, buffer, capacity) bind(c, name="arp1_recv") result(length)
            import :: c_int64_t, c_int8_t
            integer(c_int64_t), value :: handle
            integer(c_int8_t), intent(out) :: buffer(*)
            integer(c_int64_t), value :: capacity
            integer(c_int64_t) :: length
        end function arp1_recv

        subroutine arp1_close(handle) bind(c, name="arp1_close")
            import :: c_int64_t
            integer(c_int64_t), value :: handle
        end subroutine arp1_close

        function arp1_hex16(text, out) bind(c, name="arp1_hex16") result(status)
            import :: c_char, c_int64_t, c_int8_t
            character(kind=c_char), intent(in) :: text(*)
            integer(c_int8_t), intent(out) :: out(*)
            integer(c_int64_t) :: status
        end function arp1_hex16
    end interface

    integer(c_int8_t) :: frame(0:max_frame-1)
    integer(c_int8_t) :: response(0:max_frame-1)
    integer(c_int8_t) :: cap(0:15)
    integer(c_int8_t), allocatable :: payload(:)
    character(len=:), allocatable :: address
    character(len=:), allocatable :: payload_path
    integer :: position

    address = env_or_die("ACTIVE_RPC_ADDR")
    payload_path = env_or_die("ACTIVE_RPC_PAYLOAD")
    call read_payload(payload_path, payload)
    if (hex_capability(env_or_die("ACTIVE_RPC_CAP"), cap) /= 0) then
        error stop "ACTIVE_RPC_CAP must be 32 hex characters"
    end if

    call expect_echo(address, 42_c_int64_t, payload, cap, .true.)
    call expect_refusal(address, 43_c_int64_t, "refuse", payload, cap, .true., "rpc/method-not-granted")
    call expect_refusal(address, 44_c_int64_t, "echo", payload, cap, .false., "rpc/unknown-capability")
    print '(a)', "Fortran thin RPC PASS (echo, refusal, missing capability)"

contains

    ! The Fortran runtime reads the environment itself: the C helper could not,
    ! because a GnuCOBOL/gfortran executable and a statically linked C object
    ! can disagree about which CRT owns the environment block.
    function env_or_die(name) result(value)
        character(len=*), intent(in) :: name
        character(len=:), allocatable :: value
        character(len=4096) :: buffer
        integer :: length
        integer :: status
        call get_environment_variable(name, buffer, length, status)
        if (status /= 0 .or. length <= 0) then
            print '(a)', "missing environment variable " // trim(name)
            error stop
        end if
        value = buffer(1:length)
    end function env_or_die

    subroutine read_payload(path, bytes)
        character(len=*), intent(in) :: path
        integer(c_int8_t), allocatable, intent(out) :: bytes(:)
        integer :: unit
        integer :: file_size
        open (newunit=unit, file=trim(path), access='stream', form='unformatted', &
              status='old', action='read')
        inquire (unit=unit, size=file_size)
        allocate (bytes(0:file_size-1))
        read (unit) bytes
        close (unit)
    end subroutine read_payload

    integer function hex_capability(text, out) result(status)
        character(len=*), intent(in) :: text
        integer(c_int8_t), intent(out) :: out(0:15)
        if (len_trim(text) /= 32) then
            status = -1
            return
        end if
        status = int(arp1_hex16(trim(text) // c_null_char, out))
    end function hex_capability

    subroutine put_u8(buffer, at, value)
        integer(c_int8_t), intent(inout) :: buffer(0:)
        integer, intent(inout) :: at
        integer(c_int8_t), intent(in) :: value
        buffer(at) = value
        at = at + 1
    end subroutine put_u8

    subroutine put_u16(buffer, at, value)
        integer(c_int8_t), intent(inout) :: buffer(0:)
        integer, intent(inout) :: at
        integer(c_int16_t), intent(in) :: value
        buffer(at:at+1) = transfer(value, buffer(at:at+1))
        at = at + 2
    end subroutine put_u16

    subroutine put_u32(buffer, at, value)
        integer(c_int8_t), intent(inout) :: buffer(0:)
        integer, intent(inout) :: at
        integer(c_int32_t), intent(in) :: value
        buffer(at:at+3) = transfer(value, buffer(at:at+3))
        at = at + 4
    end subroutine put_u32

    subroutine put_u64(buffer, at, value)
        integer(c_int8_t), intent(inout) :: buffer(0:)
        integer, intent(inout) :: at
        integer(c_int64_t), intent(in) :: value
        buffer(at:at+7) = transfer(value, buffer(at:at+7))
        at = at + 8
    end subroutine put_u64

    subroutine put_text(buffer, at, text)
        integer(c_int8_t), intent(inout) :: buffer(0:)
        integer, intent(inout) :: at
        character(len=*), intent(in) :: text
        integer(c_int8_t) :: encoded(len(text))
        integer :: index
        encoded = transfer(text, encoded)
        do index = 1, len(text)
            buffer(at + index - 1) = encoded(index)
        end do
        at = at + len(text)
    end subroutine put_text

    integer(c_int32_t) function get_u32(buffer, at) result(value)
        integer(c_int8_t), intent(in) :: buffer(0:)
        integer, intent(in) :: at
        value = transfer(buffer(at:at+3), value)
    end function get_u32

    integer(c_int64_t) function get_u64(buffer, at) result(value)
        integer(c_int8_t), intent(in) :: buffer(0:)
        integer, intent(in) :: at
        value = transfer(buffer(at:at+7), value)
    end function get_u64

    logical function matches(buffer, at, text) result(equal)
        integer(c_int8_t), intent(in) :: buffer(0:)
        integer, intent(in) :: at
        character(len=*), intent(in) :: text
        integer(c_int8_t) :: expected(len(text))
        equal = .false.
        if (at < 0 .or. at + len(text) > size(buffer)) return
        expected = transfer(text, expected)
        equal = all(buffer(at:at+len(text)-1) == expected)
    end function matches

    recursive integer function skip_value(buffer, at, depth) result(next)
        integer(c_int8_t), intent(in) :: buffer(0:)
        integer, intent(in) :: at
        integer, intent(in) :: depth
        integer(c_int8_t) :: tag
        integer :: index
        integer :: count
        integer :: key_length
        if (depth > 64) error stop "value nesting exceeds the ceiling"
        tag = buffer(at)
        next = at + 1
        select case (tag)
        case (0_c_int8_t, 7_c_int8_t)
            return
        case (1_c_int8_t)
            next = next + 1
        case (2_c_int8_t, 3_c_int8_t)
            next = next + 8
        case (4_c_int8_t, 8_c_int8_t, 9_c_int8_t)
            next = next + 4 + int(get_u32(buffer, next))
        case (5_c_int8_t)
            count = int(get_u32(buffer, next))
            next = next + 4
            do index = 1, count
                next = skip_value(buffer, next, depth + 1)
            end do
        case (6_c_int8_t)
            count = int(get_u32(buffer, next))
            next = next + 4
            do index = 1, count
                key_length = int(get_u32(buffer, next))
                next = skip_value(buffer, next + 4 + key_length, depth + 1)
            end do
        case default
            error stop "unknown value tag"
        end select
    end function skip_value

    integer function skip_args(buffer, at, count) result(next)
        integer(c_int8_t), intent(in) :: buffer(0:)
        integer, intent(in) :: at
        integer, intent(in) :: count
        integer :: index
        integer(c_int8_t) :: tag
        next = at
        do index = 1, count
            tag = buffer(next)
            next = next + 1
            select case (tag)
            case (0_c_int8_t)
                next = skip_value(buffer, next, 0)
            case (1_c_int8_t)
                next = next + 8
            case (2_c_int8_t)
                next = next + 16
            case default
                error stop "unknown argument tag"
            end select
        end do
    end function skip_args

    subroutine encode_request(request_id, method, payload, cap, with_cap, length)
        integer(c_int64_t), intent(in) :: request_id
        character(len=*), intent(in) :: method
        integer(c_int8_t), intent(in) :: payload(0:)
        integer(c_int8_t), intent(in) :: cap(0:15)
        logical, intent(in) :: with_cap
        integer, intent(out) :: length
        integer :: at
        at = 0
        call put_text(frame, at, "ARP1")
        call put_u8(frame, at, 1_c_int8_t)          ! version
        call put_u8(frame, at, 1_c_int8_t)          ! kind: request
        call put_u16(frame, at, 0_c_int16_t)        ! flags
        call put_u64(frame, at, request_id)
        call put_u32(frame, at, int(len(method), c_int32_t))
        call put_text(frame, at, method)
        call put_u32(frame, at, 0_c_int32_t)        ! no positional arguments
        call put_u32(frame, at, int(size(payload), c_int32_t))
        frame(at:at+size(payload)-1) = payload
        at = at + size(payload)
        if (.not. with_cap) then
            call put_u32(frame, at, 0_c_int32_t)
        else
            call put_u32(frame, at, 1_c_int32_t)
            frame(at:at+15) = cap
            at = at + 16
            call put_u32(frame, at, 1_c_int32_t)    ! one method
            call put_u32(frame, at, 4_c_int32_t)
            call put_text(frame, at, "echo")
            call put_u64(frame, at, 10000_c_int64_t)
            call put_u64(frame, at, 67108864_c_int64_t)
            call put_u64(frame, at, 5000_c_int64_t)
            call put_u64(frame, at, 100000_c_int64_t)
            call put_u64(frame, at, 256_c_int64_t)
            call put_u64(frame, at, 100000_c_int64_t)
            call put_u64(frame, at, 10000000_c_int64_t)
            call put_u8(frame, at, 0_c_int8_t)      ! read_only
            call put_u8(frame, at, 0_c_int8_t)      ! redact
            call put_u8(frame, at, 0_c_int8_t)      ! no path scope
        end if
        length = at
    end subroutine encode_request

    subroutine round_trip(address, request_id, method, payload, cap, with_cap, body, body_length)
        character(len=*), intent(in) :: address
        integer(c_int64_t), intent(in) :: request_id
        character(len=*), intent(in) :: method
        integer(c_int8_t), intent(in) :: payload(0:)
        integer(c_int8_t), intent(in) :: cap(0:15)
        logical, intent(in) :: with_cap
        integer(c_int8_t), intent(out) :: body(0:)
        integer, intent(out) :: body_length
        integer(c_int8_t) :: prefix(0:3)
        integer :: colon
        integer :: length
        character(len=:), allocatable :: host
        integer(c_int64_t) :: handle
        integer(c_int64_t) :: port
        integer(c_int64_t) :: received

        call encode_request(request_id, method, payload, cap, with_cap, length)
        prefix(0:3) = transfer(int(length, c_int32_t), prefix(0:3))

        colon = index(address, ":", back=.true.)
        if (colon <= 1) error stop "ACTIVE_RPC_ADDR must be host:port"
        host = address(1:colon-1)
        read (address(colon+1:), *) port
        handle = arp1_connect(trim(host) // c_null_char, port)
        if (handle < 0) error stop "connect failed"
        if (arp1_send(handle, prefix, 4_c_int64_t) /= 0) error stop "send failed"
        if (arp1_send(handle, frame, int(length, c_int64_t)) /= 0) error stop "send failed"
        received = arp1_recv(handle, body, int(size(body), c_int64_t))
        call arp1_close(handle)
        if (received < 0) error stop "recv failed"
        body_length = int(received)
    end subroutine round_trip

    subroutine expect_echo(address, request_id, payload, cap, with_cap)
        character(len=*), intent(in) :: address
        integer(c_int64_t), intent(in) :: request_id
        integer(c_int8_t), intent(in) :: payload(0:)
        integer(c_int8_t), intent(in) :: cap(0:15)
        logical, intent(in) :: with_cap
        integer :: length
        integer :: at
        integer :: count
        integer :: payload_length

        call round_trip(address, request_id, "echo", payload, cap, with_cap, response, length)
        if (response(5) /= 2_c_int8_t) error stop "echo was not a response"
        if (get_u64(response, 8) /= request_id) error stop "echo echoed a different request id"
        at = 20 + int(get_u32(response, 16))
        count = int(get_u32(response, at))
        at = skip_args(response, at + 4, count)
        payload_length = int(get_u32(response, at))
        at = at + 4
        if (at + payload_length > length) error stop "truncated response payload"
        if (.not. all(response(at:at+payload_length-1) == payload)) &
            error stop "the AINF payload was not echoed"
    end subroutine expect_echo

    subroutine expect_refusal(address, request_id, method, payload, cap, with_cap, code)
        character(len=*), intent(in) :: address
        integer(c_int64_t), intent(in) :: request_id
        character(len=*), intent(in) :: method
        integer(c_int8_t), intent(in) :: payload(0:)
        integer(c_int8_t), intent(in) :: cap(0:15)
        logical, intent(in) :: with_cap
        character(len=*), intent(in) :: code
        integer :: length

        call round_trip(address, request_id, method, payload, cap, with_cap, response, length)
        if (response(5) /= 3_c_int8_t) error stop "the call was not refused"
        if (.not. matches(response, 20, code)) error stop "wrong refusal code"
    end subroutine expect_refusal

end program rpc_client
