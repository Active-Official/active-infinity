! Conformance test for the Fortran binding.
!
!   gfortran -I polyglot/fortran polyglot/fortran/active_infinity.f90 \
!            polyglot/fortran/conformance.f90 \
!            ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib \
!            -o conformance-fortran
!   ./conformance-fortran
!
! Validates every valid vector, reproduces its manifest content hash, re-encodes
! canonically, compiles Active text, and checks that the redaction canary never
! leaves the projection.
program conformance
  use, intrinsic :: iso_c_binding
  use active_infinity
  implicit none

  interface
    function c_strlen(text) bind(C, name="strlen") result(length)
      import :: c_ptr, c_size_t
      type(c_ptr), value :: text
      integer(c_size_t) :: length
    end function
  end interface

  integer :: checked
  character(len=:), allocatable :: manifest
  character(len=:), allocatable :: path
  character(len=:), allocatable :: name
  character(len=64) :: expected
  character(len=64) :: expected_code
  integer :: position, kind_at, path_at, name_at, hash_at, quote_at, code_at
  integer :: invalid_checked, invalid_skipped, invalid_total
  integer(c_int8_t), allocatable, target :: image(:)
  integer(c_int32_t) :: status

  call read_text("conformance/manifest.json", manifest)
  checked = 0
  position = 1
  do
    call find_after(manifest, '"kind": "valid"', position, kind_at)
    if (kind_at == 0) exit
    call find_after(manifest, '"name": "', kind_at, name_at)
    if (name_at == 0) exit
    name_at = name_at + len('"name": "')
    quote_at = index(manifest(name_at:), '"') + name_at - 1
    name = manifest(name_at:quote_at - 1)

    call find_after(manifest, '"path": "', quote_at, path_at)
    if (path_at == 0) exit
    path_at = path_at + len('"path": "')
    quote_at = index(manifest(path_at:), '"') + path_at - 1
    path = manifest(path_at:quote_at - 1)

    call find_after(manifest, '"content_hash": "', quote_at, hash_at)
    if (hash_at == 0) exit
    hash_at = hash_at + len('"content_hash": "')
    expected = manifest(hash_at:hash_at + 63)
    position = hash_at + 64

    call read_bytes(path, image)
    if (trim(name) == "non_canonical") then
      ! NF-INF02-01: validate and content_hash prove the canonical form
      ! (INF-02), so a non-canonical image is refused; reencode repairs it.
      call expect_validate_refusal(image)
      call expect_hash_refusal(image)
      ! INF-POLY-03: the binding surfaces validate_canonical; it must
      ! refuse the non-canonical image with the same code.
      call expect_canonical_refusal(image)
    else
      status = ai_validate(c_loc(image), int(size(image), c_size_t))
      if (status /= ai_ok) call fail("validate " // path)
      status = ai_validate_canonical(c_loc(image), int(size(image), c_size_t))
      if (status /= ai_ok) call fail("validate_canonical " // path)
      if (hash_hex(image) /= expected) call fail("content hash " // path)
    end if
    call check_reencode(image, trim(name))
    checked = checked + 1
  end do
  ! INF-POLY-03: pin the exact count -- the manifest lists 5 valid
  ! vectors. A slack `< 4` let a dropped vector pass silently.
  if (checked /= 5) call fail("the manifest must list exactly five valid cases")

  ! INF-POLY-02: every invalid vector except the two limits-dependent
  ! ones (limit, too_deep) must be refused by validate_canonical with
  ! exactly the manifest's expected_code. The FFI exposes no limits
  ! parameter, so those two need narrowed limits (max_nodes:1,
  ! max_depth:8) and are covered by the CLI's `conformance run` and the
  ! Rust suite instead. invalid_stream vectors are CLI-only: no stream
  ! decode exists in the FFI. The scan finds `"kind": "invalid"` with
  ! the closing quote, so `"kind": "invalid_stream"` never matches.
  invalid_checked = 0
  invalid_skipped = 0
  invalid_total = 0
  position = 1
  do
    call find_after(manifest, '"kind": "invalid"', position, kind_at)
    if (kind_at == 0) exit
    call find_after(manifest, '"name": "', kind_at, name_at)
    if (name_at == 0) exit
    name_at = name_at + len('"name": "')
    quote_at = index(manifest(name_at:), '"') + name_at - 1
    name = manifest(name_at:quote_at - 1)

    call find_after(manifest, '"path": "', quote_at, path_at)
    if (path_at == 0) exit
    path_at = path_at + len('"path": "')
    quote_at = index(manifest(path_at:), '"') + path_at - 1
    path = manifest(path_at:quote_at - 1)

    call find_after(manifest, '"expected_code": "', quote_at, code_at)
    if (code_at == 0) exit
    code_at = code_at + len('"expected_code": "')
    quote_at = index(manifest(code_at:), '"') + code_at - 1
    expected_code = manifest(code_at:quote_at - 1)
    position = quote_at + 1

    invalid_total = invalid_total + 1
    if (trim(name) == "limit" .or. trim(name) == "too_deep") then
      invalid_skipped = invalid_skipped + 1
      cycle
    end if
    call read_bytes(path, image)
    call expect_invalid_refusal(image, trim(expected_code))
    invalid_checked = invalid_checked + 1
  end do
  if (invalid_checked + invalid_skipped /= invalid_total) &
    call fail("the manifest invalid vectors were not exercised")
  if (invalid_skipped /= 2) call fail("the limits-dependent skips changed")

  call check_from_active()
  call check_redaction()
  call check_malformed()

  write (*, '(a,i0,a,i0,a)') "Fortran conformance PASS (", checked, " vectors, ABI ", &
    int(ai_abi_version()), ")"
contains

  subroutine find_after(text, pattern, start, at)
    character(len=*), intent(in) :: text, pattern
    integer, intent(in) :: start
    integer, intent(out) :: at
    at = index(text(start:), pattern)
    if (at > 0) at = at + start - 1
  end subroutine

  subroutine read_text(file, text)
    character(len=*), intent(in) :: file
    character(len=:), allocatable, intent(out) :: text
    integer :: unit, size_bytes
    inquire (file=file, size=size_bytes)
    allocate (character(len=size_bytes) :: text)
    open (newunit=unit, file=file, access='stream', form='unformatted', status='old')
    read (unit) text
    close (unit)
  end subroutine

  subroutine read_bytes(file, data)
    character(len=*), intent(in) :: file
    integer(c_int8_t), allocatable, target, intent(out) :: data(:)
    integer :: unit, size_bytes
    inquire (file=file, size=size_bytes)
    allocate (data(size_bytes))
    open (newunit=unit, file=file, access='stream', form='unformatted', status='old')
    read (unit) data
    close (unit)
  end subroutine

  function hash_hex(data) result(text)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    character(len=64) :: text
    integer(c_int8_t), target :: digest(32)
    character(len=16), parameter :: digits = '0123456789abcdef'
    integer :: index, value, high, low, status
    status = ai_content_hash(c_loc(data), int(size(data), c_size_t), c_loc(digest))
    if (status /= ai_ok) call fail("content_hash")
    do index = 1, 32
      value = iand(int(digest(index)), 255)
      high = value / 16
      low = mod(value, 16)
      text(2 * index - 1:2 * index) = digits(high + 1:high + 1) // digits(low + 1:low + 1)
    end do
  end function

  subroutine check_reencode(data, name)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    character(len=*), intent(in) :: name
    integer(c_int8_t), allocatable, target :: out(:)
    integer(c_size_t) :: capacity
    integer(c_int32_t) :: status
    logical :: same
    capacity = 0
    status = ai_reencode(c_loc(data), int(size(data), c_size_t), c_null_ptr, capacity)
    if (status /= ai_too_small) call fail("reencode size query " // name)
    allocate (out(capacity))
    status = ai_reencode(c_loc(data), int(size(data), c_size_t), c_loc(out), capacity)
    if (status /= ai_ok) call fail("reencode " // name)
    same = int(capacity) == size(data) .and. all(out(1:int(capacity)) == data)
    if (name == "non_canonical") then
      if (same) call fail("non-canonical image re-encoded unchanged")
      status = ai_validate(c_loc(out), capacity)
      if (status /= ai_ok) call fail("repaired bytes do not validate " // name)
    else if (.not. same) then
      call fail("re-encode changed canonical bytes: " // name)
    end if
  end subroutine

  subroutine expect_validate_refusal(data)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    integer(c_int32_t) :: status
    character(len=:), allocatable :: code
    status = ai_validate(c_loc(data), int(size(data), c_size_t))
    if (status /= ai_invalid) call fail("non-canonical image was validated")
    call last_error_text(code)
    if (code /= "infinity/not-canonical") call fail("wrong code for validate: " // code)
  end subroutine

  subroutine expect_canonical_refusal(data)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    integer(c_int32_t) :: status
    character(len=:), allocatable :: code
    status = ai_validate_canonical(c_loc(data), int(size(data), c_size_t))
    if (status /= ai_invalid) call fail("non-canonical image passed validate_canonical")
    call last_error_text(code)
    if (code /= "infinity/not-canonical") call fail("wrong code for validate_canonical: " // code)
  end subroutine

  ! INF-POLY-02: an invalid vector must be refused by validate_canonical
  ! with exactly the manifest's expected_code.
  subroutine expect_invalid_refusal(data, expected)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    character(len=*), intent(in) :: expected
    integer(c_int32_t) :: status
    character(len=:), allocatable :: code
    status = ai_validate_canonical(c_loc(data), int(size(data), c_size_t))
    if (status /= ai_invalid) call fail("invalid image was accepted: " // expected)
    call last_error_text(code)
    if (code /= expected) call fail("wrong code for validate_canonical: " // code)
  end subroutine

  subroutine expect_hash_refusal(data)
    integer(c_int8_t), allocatable, target, intent(in) :: data(:)
    integer(c_int8_t), target :: digest(32)
    integer(c_int32_t) :: status
    character(len=:), allocatable :: code
    status = ai_content_hash(c_loc(data), int(size(data), c_size_t), c_loc(digest))
    if (status /= ai_invalid) call fail("non-canonical image was hashed")
    call last_error_text(code)
    if (code /= "infinity/not-canonical") call fail("wrong code for content_hash: " // code)
  end subroutine

  subroutine check_from_active()
    character(len=*), parameter :: source = 'port = 8080' // char(10) // 'name = "fortran"' // char(10)
    character(len=*), parameter :: name_text = 'fortran.active'
    character(kind=c_char), target :: module_name(16)
    integer(c_int8_t), target :: source_bytes(len(source))
    integer(c_int8_t), allocatable, target :: first(:), second(:)
    integer(c_size_t) :: capacity
    integer(c_int32_t) :: status
    integer :: index

    do index = 1, len(source)
      source_bytes(index) = int(iachar(source(index:index)), c_int8_t)
    end do
    module_name = c_null_char
    do index = 1, len(name_text)
      module_name(index) = name_text(index:index)
    end do

    capacity = 0
    status = ai_from_active(c_loc(source_bytes), int(size(source_bytes), c_size_t), &
                            c_loc(module_name), c_null_ptr, capacity)
    if (status /= ai_too_small) call fail("from_active size query")
    allocate (first(capacity))
    status = ai_from_active(c_loc(source_bytes), int(size(source_bytes), c_size_t), &
                            c_loc(module_name), c_loc(first), capacity)
    if (status /= ai_ok) call fail("from_active")
    status = ai_validate(c_loc(first), capacity)
    if (status /= ai_ok) call fail("from_active result does not validate")

    capacity = 0
    status = ai_from_active(c_loc(source_bytes), int(size(source_bytes), c_size_t), &
                            c_loc(module_name), c_null_ptr, capacity)
    allocate (second(capacity))
    status = ai_from_active(c_loc(source_bytes), int(size(source_bytes), c_size_t), &
                            c_loc(module_name), c_loc(second), capacity)
    if (status /= ai_ok) call fail("from_active retry")
    if (.not. all(first == second)) call fail("from_active is not deterministic")
  end subroutine

  subroutine check_redaction()
    integer(c_int8_t), allocatable, target :: image(:)
    integer(c_int8_t), allocatable, target :: out(:)
    integer(c_size_t) :: capacity
    integer(c_int32_t) :: status
    character(len=:), allocatable :: json
    integer :: position

    call read_bytes("tests/vectors/valid/full.ainf", image)
    capacity = 0
    status = ai_redacted_json(c_loc(image), int(size(image), c_size_t), c_null_ptr, capacity)
    if (status /= ai_too_small) call fail("redacted_json size query")
    allocate (out(capacity))
    status = ai_redacted_json(c_loc(image), int(size(image), c_size_t), c_loc(out), capacity)
    if (status /= ai_ok) call fail("redacted_json")
    allocate (character(len=int(capacity)) :: json)
    do position = 1, int(capacity)
      json(position:position) = achar(iand(int(out(position)), 255))
    end do
    if (index(json, "CANARY_SECRET_") > 0) call fail("the redacted projection leaked the canary")
    if (json(1:1) /= "{") call fail("the redacted projection is not JSON")
  end subroutine

  subroutine check_malformed()
    integer(c_int8_t), target :: bad(3)
    integer(c_int32_t) :: status
    character(len=:), allocatable :: code
    bad = int([-1, -1, -1], c_int8_t)
    status = ai_validate(c_loc(bad), 3_c_size_t)
    if (status == ai_ok) call fail("malformed input was accepted")
    call last_error_text(code)
    if (code(1:9) /= "infinity/") call fail("an error code must start with infinity/: " // code)
  end subroutine

  subroutine last_error_text(text)
    character(len=:), allocatable, intent(out) :: text
    type(c_ptr) :: pointer
    character(kind=c_char), pointer :: bytes(:)
    integer(c_size_t) :: length
    integer :: index
    pointer = ai_last_error()
    if (.not. c_associated(pointer)) then
      text = "infinity/unavailable"
      return
    end if
    length = c_strlen(pointer)
    call c_f_pointer(pointer, bytes, [length])
    allocate (character(len=int(length)) :: text)
    do index = 1, int(length)
      text(index:index) = bytes(index)
    end do
  end subroutine

  subroutine fail(message)
    character(len=*), intent(in) :: message
    write (*, '(a)') "Fortran conformance FAIL: " // message
    stop 1
  end subroutine
end program conformance
