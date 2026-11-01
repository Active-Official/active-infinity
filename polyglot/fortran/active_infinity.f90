! Active Infinity binding for Fortran (ISO C interoperability).
!
! The library is the Rust reference through the frozen C ABI, so bytes cannot
! drift between languages. Point ACTIVE_INFINITY_LIB at the shared library.
module active_infinity
  use, intrinsic :: iso_c_binding
  implicit none
  private

  public :: ai_abi_version, ai_validate, ai_validate_canonical, ai_content_hash
  public :: ai_reencode, ai_redacted_json, ai_from_active, ai_last_error
  public :: ai_ok, ai_invalid, ai_too_small, ai_panic

  integer(c_int32_t), parameter :: ai_ok = 0_c_int32_t
  integer(c_int32_t), parameter :: ai_invalid = -1_c_int32_t
  integer(c_int32_t), parameter :: ai_too_small = -2_c_int32_t
  integer(c_int32_t), parameter :: ai_panic = -3_c_int32_t

  interface
    function ai_abi_version() bind(C, name="active_infinity_abi_version") result(value)
      import :: c_int32_t
      integer(c_int32_t) :: value
    end function

    function ai_last_error() bind(C, name="active_infinity_last_error") result(pointer)
      import :: c_ptr
      type(c_ptr) :: pointer
    end function

    function ai_validate(ptr, len) bind(C, name="active_infinity_validate") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      integer(c_int32_t) :: status
    end function

    function ai_validate_canonical(ptr, len) bind(C, name="active_infinity_validate_canonical") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      integer(c_int32_t) :: status
    end function

    function ai_content_hash(ptr, len, out) bind(C, name="active_infinity_content_hash") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      type(c_ptr), value :: out
      integer(c_int32_t) :: status
    end function

    function ai_reencode(ptr, len, out, out_len) bind(C, name="active_infinity_reencode") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      type(c_ptr), value :: out
      integer(c_size_t) :: out_len
      integer(c_int32_t) :: status
    end function

    function ai_redacted_json(ptr, len, out, out_len) bind(C, name="active_infinity_redacted_json") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      type(c_ptr), value :: out
      integer(c_size_t) :: out_len
      integer(c_int32_t) :: status
    end function

    function ai_from_active(source, source_len, name, out, out_len) bind(C, name="active_infinity_from_active") result(status)
      import :: c_int32_t, c_size_t, c_ptr
      type(c_ptr), value :: source
      integer(c_size_t), value :: source_len
      type(c_ptr), value :: name
      type(c_ptr), value :: out
      integer(c_size_t) :: out_len
      integer(c_int32_t) :: status
    end function
  end interface
end module active_infinity
