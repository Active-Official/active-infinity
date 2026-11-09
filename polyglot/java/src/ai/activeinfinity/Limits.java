package ai.activeinfinity;

/**
 * A caller-supplied budget (INF-FFI-02): one ceiling per field, in the same
 * order as the C {@code active_infinity_limits} struct. Build one with
 * {@link #defaults()}, set a ceiling with {@link #setField(String, long)},
 * pass it to {@link ActiveInfinity#validateWithLimits(byte[], Limits)} or
 * {@link ActiveInfinity#decodeWithLimits(byte[], Limits)}. The 24 ceilings
 * are carried as longs (the two uint64 ceilings need 64 bits); the JNI
 * converts them to the C struct.
 */
public final class Limits {
    // Field order = C struct order.
    private static final String[] FIELDS = {
        "max_nodes", "max_edges", "max_children", "max_fields", "max_parts",
        "max_strings", "max_string_bytes", "max_blobs", "max_blob_bytes",
        "max_annotations", "max_units", "max_types", "max_aux", "max_numbers",
        "max_secrets", "max_secret_bytes", "max_extensions", "max_prov_bytes",
        "max_prov_entries", "max_hashes", "max_bindings", "max_total_bytes",
        "max_decoded_bytes", "max_depth",
    };

    private final long[] values = new long[24];

    private Limits(long[] values) {
        System.arraycopy(values, 0, this.values, 0, values.length);
    }

    public static Limits defaults() {
        long[] values = new long[24];
        int status = Native.limitsDefault(values);
        if (status != 0) {
            throw new ActiveInfinity.Error(Native.lastError(), status);
        }
        return new Limits(values);
    }

    public void setField(String name, long value) {
        for (int index = 0; index < FIELDS.length; index++) {
            if (FIELDS[index].equals(name)) {
                values[index] = value;
                return;
            }
        }
        throw new IllegalArgumentException("unknown limits field " + name);
    }

    long[] toArray() {
        return values.clone();
    }
}
