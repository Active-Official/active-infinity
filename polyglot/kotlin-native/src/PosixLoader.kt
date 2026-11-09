@file:OptIn(
    kotlinx.cinterop.ExperimentalForeignApi::class,
    kotlin.experimental.ExperimentalNativeApi::class,
)

import kotlinx.cinterop.*
import platform.posix.*
import kotlin.native.OsFamily
import kotlin.native.Platform

/**
 * POSIX native-library loader for the Kotlin/Native conformance runner
 * (Linux and macOS): `dlopen` / `dlsym`.
 *
 * XPL-INF-06: the default library name is per-OS. It used to be a
 * hardcoded `libactive_infinity_ffi.so`, which names no `.dylib`, so the
 * runner could not load the reference library on macOS without
 * ACTIVE_INFINITY_LIB. Windows is not POSIX: it has no `dlopen`, so the
 * mingw target compiles WindowsLoader.kt instead (see build.sh).
 */
internal fun defaultLibraryName(): String = when (Platform.osFamily) {
    OsFamily.MACOSX, OsFamily.IOS, OsFamily.TVOS, OsFamily.WATCHOS ->
        "libactive_infinity_ffi.dylib"
    else -> "libactive_infinity_ffi.so"
}

internal fun openNativeLibrary(): COpaquePointer {
    val configured = getenv("ACTIVE_INFINITY_LIB")?.toKString()
    val name = if (configured.isNullOrEmpty()) defaultLibraryName() else configured
    return dlopen(name, RTLD_NOW)
        ?: error("cannot load $name: ${dlerror()?.toKString()}")
}

internal fun <T : CFunction<*>> loadSymbol(handle: COpaquePointer, name: String): CPointer<T> {
    val pointer = dlsym(handle, name) ?: error("missing symbol $name")
    return pointer.reinterpret()
}
