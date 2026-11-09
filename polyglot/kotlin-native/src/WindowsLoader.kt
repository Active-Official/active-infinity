@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

import kotlinx.cinterop.*
import platform.posix.getenv
import platform.windows.*

/**
 * Windows native-library loader for the Kotlin/Native conformance runner
 * (mingw_x64 target): `LoadLibraryW` / `GetProcAddress`.
 *
 * XPL-INF-06: Windows has no `dlopen`, so the POSIX loader cannot even
 * compile for this target, and the old hardcoded default
 * `libactive_infinity_ffi.so` names no `.dll`. The default here is the
 * cdylib the FFI crate builds on Windows (`active_infinity_ffi.dll`);
 * ACTIVE_INFINITY_LIB still overrides it. build.sh compiles this file
 * instead of PosixLoader.kt on Windows hosts.
 */
internal fun defaultLibraryName(): String = "active_infinity_ffi.dll"

internal fun openNativeLibrary(): COpaquePointer {
    // `getenv` lives in platform.posix even on the mingw target (it is not
    // in platform.windows). `LoadLibraryW` takes a Kotlin String directly:
    // the bindings convert it to UTF-16 (LPCWSTR).
    val configured = getenv("ACTIVE_INFINITY_LIB")?.toKString()
    val name = if (configured.isNullOrEmpty()) defaultLibraryName() else configured
    return LoadLibraryW(name)?.reinterpret()
        ?: error("cannot load $name (Win32 error ${GetLastError()})")
}

internal fun <T : CFunction<*>> loadSymbol(handle: COpaquePointer, name: String): CPointer<T> {
    val pointer = GetProcAddress(handle.reinterpret<HINSTANCE__>(), name)
        ?: error("missing symbol $name")
    return pointer.reinterpret()
}
