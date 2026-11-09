*> Conformance test for the GnuCOBOL binding.
*>
*>   cobc -x -free -o conformance-cobol polyglot/cobol/conformance.cob \
*>        polyglot/cobol/libactive_infinity_cobol.dll.a \
*>        ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib
*>
*> The binding calls the frozen C ABI directly. `native/active_infinity_cobol.c`
*> only supplies byte-oriented helpers (file read, hex, manifest scan) that
*> COBOL has no library for.
identification division.
program-id. conformance.

data division.
working-storage section.
*> C strings: the NUL terminator is part of the field.
01 ws-manifest-path.
   05 filler pic x(25) value "conformance/manifest.json".
   05 filler pic x value x"00".
01 ws-full-path.
   05 filler pic x(29) value "tests/vectors/valid/full.ainf".
   05 filler pic x value x"00".
01 ws-manifest pic x(65536).
01 ws-manifest-length usage binary-double unsigned.
01 ws-manifest-cap usage binary-double unsigned value 65536.
01 ws-total usage binary-double unsigned.
01 ws-index usage binary-double unsigned.
01 ws-checked usage binary-double unsigned value 0.
01 ws-case-path pic x(256).
01 ws-case-name pic x(64).
01 ws-expected pic x(65).
01 ws-cap-path usage binary-double unsigned value 256.
01 ws-cap-name usage binary-double unsigned value 64.
01 ws-cap-hash usage binary-double unsigned value 65.
01 ws-invalid-total usage binary-double unsigned.
01 ws-invalid-index usage binary-double unsigned.
01 ws-invalid-checked usage binary-double unsigned value 0.
01 ws-invalid-skipped usage binary-double unsigned value 0.
01 ws-expected-code pic x(64).
01 ws-cap-code usage binary-double unsigned value 64.
01 ws-code-length usage binary-double unsigned.
01 ws-image pic x(1048576).
01 ws-image-length usage binary-double unsigned.
01 ws-image-cap usage binary-double unsigned value 1048576.
01 ws-out pic x(2097152).
01 ws-out-cap usage binary-double unsigned.
01 ws-dummy pic x(1).
01 ws-status usage binary-long.
01 ws-abi usage binary-long.
01 ws-digest pic x(32).
01 ws-digest-hex pic x(64).
01 ws-scan-count usage binary-long.
01 ws-count-text pic z(9).
01 ws-abi-text pic z(9).
01 ws-reason pic x(120).
01 ws-error pic x(256).
01 ws-error-cap usage binary-double unsigned value 256.

01 ws-source.
   05 filler pic x(12) value "port = 8080".
   05 filler pic x value x"0A".
   05 filler pic x(14) value 'name = "cobol"'.
   05 filler pic x value x"0A".
01 ws-source-length usage binary-double unsigned value 28.

01 ws-name-bytes.
   05 filler pic x(12) value "cobol.active".
   05 filler pic x value x"00".

procedure division.
main-paragraph.
    call static "ai_cobol_read_file" using
        by reference ws-manifest-path
        by reference ws-manifest
        by value ws-manifest-cap
        returning ws-manifest-length
    if ws-manifest-length = 0
        move "cannot read the conformance manifest" to ws-reason
        perform fail-now
    end-if

    call static "ai_cobol_case_count" using
        by reference ws-manifest
        by value ws-manifest-length
        returning ws-total
    if ws-total not = 5
        move "the manifest must list exactly five valid cases" to ws-reason
        perform fail-now
    end-if

    move 0 to ws-index
    perform until ws-index >= ws-total
        call static "ai_cobol_case" using
            by reference ws-manifest
            by value ws-manifest-length
            by value ws-index
            by reference ws-case-path
            by value ws-cap-path
            by reference ws-case-name
            by value ws-cap-name
            by reference ws-expected
            by value ws-cap-hash
            returning ws-status
        if ws-status not = 1
            move "the manifest case scan failed" to ws-reason
            perform fail-now
        end-if
        perform check-case
        add 1 to ws-index
        add 1 to ws-checked
    end-perform

    *> INF-POLY-02: every invalid vector except the two limits-dependent
    *> ones (limit, too_deep) must be refused by validate_canonical with
    *> exactly the manifest's expected_code. The FFI exposes no limits
    *> parameter, so those two need narrowed limits (max_nodes:1,
    *> max_depth:8) and are covered by the CLI's `conformance run` and the
    *> Rust suite instead. invalid_stream vectors are CLI-only: no stream
    *> decode exists in the FFI.
    call static "ai_cobol_invalid_count" using
        by reference ws-manifest
        by value ws-manifest-length
        returning ws-invalid-total
    if ws-invalid-total not = 35
        move "the manifest must list exactly 35 invalid cases" to ws-reason
        perform fail-now
    end-if
    move 0 to ws-invalid-index
    move 0 to ws-invalid-checked
    move 0 to ws-invalid-skipped
    perform until ws-invalid-index >= ws-invalid-total
        call static "ai_cobol_invalid_case" using
            by reference ws-manifest
            by value ws-manifest-length
            by value ws-invalid-index
            by reference ws-case-path
            by value ws-cap-path
            by reference ws-case-name
            by value ws-cap-name
            by reference ws-expected-code
            by value ws-cap-code
            returning ws-status
        if ws-status not = 1
            move "the manifest invalid case scan failed" to ws-reason
            perform fail-now
        end-if
        if ws-case-name(1:5) = "limit" or ws-case-name(1:8) = "too_deep"
            add 1 to ws-invalid-skipped
        else
            perform check-invalid-case
            add 1 to ws-invalid-checked
        end-if
        add 1 to ws-invalid-index
    end-perform
    if ws-invalid-checked + ws-invalid-skipped not = ws-invalid-total
        move "the manifest invalid vectors were not exercised" to ws-reason
        perform fail-now
    end-if
    if ws-invalid-skipped not = 2
        move "the limits-dependent skips changed" to ws-reason
        perform fail-now
    end-if

    perform check-from-active
    perform check-redaction
    perform check-malformed

    call static "active_infinity_abi_version" returning ws-abi
    move ws-checked to ws-count-text
    move ws-abi to ws-abi-text
    display "COBOL conformance PASS (" function trim(ws-count-text)
            " vectors, ABI " function trim(ws-abi-text) ")"
    stop run returning 0.

check-case.
    call static "ai_cobol_read_file" using
        by reference ws-case-path
        by reference ws-image
        by value ws-image-cap
        returning ws-image-length
    if ws-image-length = 0
        move "cannot read a vector" to ws-reason
        perform fail-now
    end-if

    if ws-case-name(1:13) = "non_canonical"
        perform check-non-canonical-refusals
    else
        call static "active_infinity_validate" using
            by reference ws-image
            by value ws-image-length
            returning ws-status
        if ws-status not = 0
            move "validate refused a valid vector" to ws-reason
            perform fail-now
        end-if

        *> INF-POLY-03: the binding surfaces validate_canonical.
        call static "active_infinity_validate_canonical" using
            by reference ws-image
            by value ws-image-length
            returning ws-status
        if ws-status not = 0
            move "validate_canonical refused a valid vector" to ws-reason
            perform fail-now
        end-if

        call static "active_infinity_content_hash" using
            by reference ws-image
            by value ws-image-length
            by reference ws-digest
            returning ws-status
        if ws-status not = 0
            move "content_hash failed" to ws-reason
            perform fail-now
        end-if
        call static "ai_cobol_hex32" using
            by reference ws-digest
            by reference ws-digest-hex
        if ws-digest-hex not = ws-expected(1:64)
            move "content hash mismatch" to ws-reason
            perform fail-now
        end-if
    end-if

    move 0 to ws-out-cap
    call static "active_infinity_reencode" using
        by reference ws-image
        by value ws-image-length
        by reference ws-dummy
        by reference ws-out-cap
        returning ws-status
    if ws-status not = -2
        move "reencode did not report the required size" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_reencode" using
        by reference ws-image
        by value ws-image-length
        by reference ws-out
        by reference ws-out-cap
        returning ws-status
    if ws-status not = 0
        move "reencode failed" to ws-reason
        perform fail-now
    end-if

    if ws-case-name(1:13) = "non_canonical"
        if ws-out(1:ws-out-cap) = ws-image(1:ws-image-length)
            move "non-canonical image re-encoded unchanged" to ws-reason
            perform fail-now
        end-if
        call static "active_infinity_validate" using
            by reference ws-out
            by value ws-out-cap
            returning ws-status
        if ws-status not = 0
            move "repaired bytes do not validate" to ws-reason
            perform fail-now
        end-if
    else
        if ws-out-cap not = ws-image-length
            move "re-encode changed the canonical length" to ws-reason
            perform fail-now
        end-if
        if ws-out(1:ws-out-cap) not = ws-image(1:ws-image-length)
            move "re-encode changed canonical bytes" to ws-reason
            perform fail-now
        end-if
    end-if.

check-non-canonical-refusals.
    *> NF-INF02-01: validate and content_hash prove the canonical form
    *> (INF-02), so a non-canonical image is refused; reencode repairs it.
    call static "active_infinity_validate" using
        by reference ws-image
        by value ws-image-length
        returning ws-status
    if ws-status = 0
        move "non-canonical image was validated" to ws-reason
        perform fail-now
    end-if
    call static "ai_cobol_last_error" using
        by reference ws-error
        by value ws-error-cap
    if ws-error(1:22) not = "infinity/not-canonical"
        move "validate refused with the wrong code" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_content_hash" using
        by reference ws-image
        by value ws-image-length
        by reference ws-digest
        returning ws-status
    if ws-status = 0
        move "non-canonical image was hashed" to ws-reason
        perform fail-now
    end-if
    call static "ai_cobol_last_error" using
        by reference ws-error
        by value ws-error-cap
    if ws-error(1:22) not = "infinity/not-canonical"
        move "content_hash refused with the wrong code" to ws-reason
        perform fail-now
    end-if
    *> INF-POLY-03: the binding surfaces validate_canonical.
    call static "active_infinity_validate_canonical" using
        by reference ws-image
        by value ws-image-length
        returning ws-status
    if ws-status = 0
        move "non-canonical image passed validate_canonical" to ws-reason
        perform fail-now
    end-if
    call static "ai_cobol_last_error" using
        by reference ws-error
        by value ws-error-cap
    if ws-error(1:22) not = "infinity/not-canonical"
        move "validate_canonical refused with the wrong code" to ws-reason
        perform fail-now
    end-if.

check-invalid-case.
    call static "ai_cobol_read_file" using
        by reference ws-case-path
        by reference ws-image
        by value ws-image-cap
        returning ws-image-length
    if ws-image-length = 0
        move "cannot read an invalid vector" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_validate_canonical" using
        by reference ws-image
        by value ws-image-length
        returning ws-status
    if ws-status = 0
        move "invalid image was accepted" to ws-reason
        perform fail-now
    end-if
    call static "ai_cobol_last_error" using
        by reference ws-error
        by value ws-error-cap
    compute ws-code-length =
        function length(function trim(ws-expected-code))
    if ws-error(1:ws-code-length) not =
            ws-expected-code(1:ws-code-length)
        move "wrong code for the invalid vector" to ws-reason
        perform fail-now
    end-if.

check-from-active.
    move 0 to ws-out-cap
    call static "active_infinity_from_active" using
        by reference ws-source
        by value ws-source-length
        by reference ws-name-bytes
        by reference ws-dummy
        by reference ws-out-cap
        returning ws-status
    if ws-status not = -2
        move "from_active did not report the required size" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_from_active" using
        by reference ws-source
        by value ws-source-length
        by reference ws-name-bytes
        by reference ws-out
        by reference ws-out-cap
        returning ws-status
    if ws-status not = 0
        move "from_active failed" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_validate" using
        by reference ws-out
        by value ws-out-cap
        returning ws-status
    if ws-status not = 0
        move "the from_active result does not validate" to ws-reason
        perform fail-now
    end-if.

check-redaction.
    call static "ai_cobol_read_file" using
        by reference ws-full-path
        by reference ws-image
        by value ws-image-cap
        returning ws-image-length
    move 0 to ws-out-cap
    call static "active_infinity_redacted_json" using
        by reference ws-image
        by value ws-image-length
        by reference ws-dummy
        by reference ws-out-cap
        returning ws-status
    if ws-status not = -2
        move "redacted_json did not report the required size" to ws-reason
        perform fail-now
    end-if
    call static "active_infinity_redacted_json" using
        by reference ws-image
        by value ws-image-length
        by reference ws-out
        by reference ws-out-cap
        returning ws-status
    if ws-status not = 0
        move "redacted_json failed" to ws-reason
        perform fail-now
    end-if
    if ws-out(1:1) not = "{"
        move "the redacted projection is not JSON" to ws-reason
        perform fail-now
    end-if
    move 0 to ws-scan-count
    inspect ws-out tallying ws-scan-count for all "CANARY_SECRET_"
    if ws-scan-count > 0
        move "the redacted projection leaked the canary" to ws-reason
        perform fail-now
    end-if.

check-malformed.
    move x"FFFFFF" to ws-image(1:3)
    move 3 to ws-image-length
    call static "active_infinity_validate" using
        by reference ws-image
        by value ws-image-length
        returning ws-status
    if ws-status = 0
        move "malformed input was accepted" to ws-reason
        perform fail-now
    end-if
    call static "ai_cobol_last_error" using
        by reference ws-error
        by value ws-error-cap
    if ws-error(1:9) not = "infinity/"
        move "an error code must start with infinity/" to ws-reason
        perform fail-now
    end-if.

fail-now.
    display "COBOL conformance FAIL: " ws-reason
    stop run returning 1.
