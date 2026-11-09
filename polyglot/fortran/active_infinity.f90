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
  public :: ai_limits, ai_limits_default, ai_validate_with_limits
  public :: ai_decode_with_limits, ai_set_limit
  ! INF-FFI-02: caller-supplied budget. The limits type mirrors the C
  ! `active_infinity_limits` struct field for field; bind(C) gives it the
  ! same layout (21 int32 ceilings, then the two int64 ceilings, then
  ! max_depth as int32).
  type, bind(C) :: ai_limits
    integer(c_int32_t) :: max_nodes
    integer(c_int32_t) :: max_edges
    integer(c_int32_t) :: max_children
    integer(c_int32_t) :: max_fields
    integer(c_int32_t) :: max_parts
    integer(c_int32_t) :: max_strings
    integer(c_int32_t) :: max_string_bytes
    integer(c_int32_t) :: max_blobs
    integer(c_int32_t) :: max_blob_bytes
    integer(c_int32_t) :: max_annotations
    integer(c_int32_t) :: max_units
    integer(c_int32_t) :: max_types
    integer(c_int32_t) :: max_aux
    integer(c_int32_t) :: max_numbers
    integer(c_int32_t) :: max_secrets
    integer(c_int32_t) :: max_secret_bytes
    integer(c_int32_t) :: max_extensions
    integer(c_int32_t) :: max_prov_bytes
    integer(c_int32_t) :: max_prov_entries
    integer(c_int32_t) :: max_hashes
    integer(c_int32_t) :: max_bindings
    integer(c_int64_t) :: max_total_bytes
    integer(c_int64_t) :: max_decoded_bytes
    integer(c_int32_t) :: max_depth
  end type ai_limits


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

    ! INF-FFI-02: caller-supplied budget. The limits are filled with the
    ! library defaults, then the caller overrides the ceiling it wants to
    ! tighten; a null limits pointer means the defaults.
    function ai_limits_default(limits) bind(C, name="active_infinity_limits_default") result(status)
      import :: c_int32_t, ai_limits
      type(ai_limits) :: limits
      integer(c_int32_t) :: status
    end function

    function ai_validate_with_limits(ptr, len, limits) bind(C, name="active_infinity_validate_with_limits") result(status)
      import :: c_int32_t, c_size_t, c_ptr, ai_limits
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      type(ai_limits), intent(in) :: limits
      integer(c_int32_t) :: status
    end function

    function ai_decode_with_limits(ptr, len, limits, out, out_len) bind(C, name="active_infinity_decode_with_limits") result(status)
      import :: c_int32_t, c_size_t, c_ptr, ai_limits
      type(c_ptr), value :: ptr
      integer(c_size_t), value :: len
      type(ai_limits), intent(in) :: limits
      type(c_ptr), value :: out
      integer(c_size_t) :: out_len
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

contains

  ! INF-FFI-02: set one ceiling by its C field name (e.g. "max_nodes").
  ! Returns 0 on success, -1 on an unknown field (fail closed: the caller
  ! refuses to run). A function, not a subroutine, because the module
  ! cannot call the test program's fail().
  function ai_set_limit(limits, field, value) result(status)
    type(ai_limits), intent(inout) :: limits
    character(len=*), intent(in) :: field
    integer(c_int64_t), intent(in) :: value
    integer(c_int32_t) :: status
    select case (trim(field))
    case ("max_nodes")
      limits%max_nodes = int(value, c_int32_t)
    case ("max_edges")
      limits%max_edges = int(value, c_int32_t)
    case ("max_children")
      limits%max_children = int(value, c_int32_t)
    case ("max_fields")
      limits%max_fields = int(value, c_int32_t)
    case ("max_parts")
      limits%max_parts = int(value, c_int32_t)
    case ("max_strings")
      limits%max_strings = int(value, c_int32_t)
    case ("max_string_bytes")
      limits%max_string_bytes = int(value, c_int32_t)
    case ("max_blobs")
      limits%max_blobs = int(value, c_int32_t)
    case ("max_blob_bytes")
      limits%max_blob_bytes = int(value, c_int32_t)
    case ("max_annotations")
      limits%max_annotations = int(value, c_int32_t)
    case ("max_units")
      limits%max_units = int(value, c_int32_t)
    case ("max_types")
      limits%max_types = int(value, c_int32_t)
    case ("max_aux")
      limits%max_aux = int(value, c_int32_t)
    case ("max_numbers")
      limits%max_numbers = int(value, c_int32_t)
    case ("max_secrets")
      limits%max_secrets = int(value, c_int32_t)
    case ("max_secret_bytes")
      limits%max_secret_bytes = int(value, c_int32_t)
    case ("max_extensions")
      limits%max_extensions = int(value, c_int32_t)
    case ("max_prov_bytes")
      limits%max_prov_bytes = int(value, c_int32_t)
    case ("max_prov_entries")
      limits%max_prov_entries = int(value, c_int32_t)
    case ("max_hashes")
      limits%max_hashes = int(value, c_int32_t)
    case ("max_bindings")
      limits%max_bindings = int(value, c_int32_t)
    case ("max_total_bytes")
      limits%max_total_bytes = int(value, c_int64_t)
    case ("max_decoded_bytes")
      limits%max_decoded_bytes = int(value, c_int64_t)
    case ("max_depth")
      limits%max_depth = int(value, c_int32_t)
    case default
      status = -1_c_int32_t
      return
    end select
    status = 0_c_int32_t
  end function ai_set_limit

end module active_infinity
