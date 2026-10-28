//! Unit discriminants for `Quantity` values.
//!
//! Units are a *closed* set of stable numeric discriminants plus a named
//! escape hatch, so the wire format never depends on the spelling table of
//! any particular `active-core` release. Ids in the range `0..=66` are the
//! built-in physical units and are permanent: a reader that meets an id it
//! does not implement must reject the buffer (`infinity/unknown-unit`)
//! rather than guess. Custom units travel as `Named` and are matched by
//! exact UTF-8 name.
//!
//! The numeric ids are part of the wire contract (`docs/spec/layout.md`
//! §5.2). They mirror the order of `active_core::types::Unit`, which is
//! intentional: the interop layer maps one-to-one, but the layout spec — not
//! that enum — is authoritative.

use std::fmt;

/// Discriminant reserved for a named (custom) unit.
pub const UNIT_NAMED: u32 = 0xFFFF;
/// Highest built-in discriminant implemented by this format version.
pub const UNIT_MAX_BUILTIN: u32 = 66;

/// A unit attached to a quantity.
// The discriminants and their numeric ids are specified in
// `docs/spec/layout.md` §5.2; variant names are the unit identifiers.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitTag {
    // Time (canonical: nanoseconds)
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
    // Information (binary)
    Bytes,
    Kibibytes,
    Mebibytes,
    Gibibytes,
    Tebibytes,
    Pebibytes,
    Exbibytes,
    // Information (decimal)
    Kilobytes,
    Megabytes,
    Gigabytes,
    Terabytes,
    // Rates
    PerSecond,
    PerMinute,
    PerHour,
    RequestsPerSecond,
    RequestsPerMinute,
    RequestsPerHour,
    // Ratios and frequencies
    Percent,
    Hertz,
    Kilohertz,
    Megahertz,
    Gigahertz,
    Terahertz,
    // Bits and bit rates
    Bits,
    Kilobits,
    Megabits,
    Gigabits,
    BitsPerSecond,
    KilobitsPerSecond,
    MegabitsPerSecond,
    GigabitsPerSecond,
    MegabytesPerSecond,
    // AI-age units
    Tokens,
    KiloTokens,
    MegaTokens,
    TokensPerSecond,
    Flops,
    TeraFlops,
    PetaFlops,
    // Domain SI
    Pascal,
    Bar,
    Psi,
    Volts,
    Amperes,
    Watts,
    Joules,
    KilowattHours,
    Newtons,
    Degrees,
    Radians,
    Rpm,
    Meters,
    Kilometers,
    Kilograms,
    Grams,
    Kelvin,
    Celsius,
    Fahrenheit,
    Decibel,
    /// A unit outside the built-in table, identified by its exact name.
    Named(String),
}

impl UnitTag {
    /// Stable wire discriminant. `Named` is not a discriminant on its own;
    /// callers must also carry the name in the unit table entry.
    pub fn discriminant(&self) -> u32 {
        match self {
            UnitTag::Nanoseconds => 0,
            UnitTag::Microseconds => 1,
            UnitTag::Milliseconds => 2,
            UnitTag::Seconds => 3,
            UnitTag::Minutes => 4,
            UnitTag::Hours => 5,
            UnitTag::Days => 6,
            UnitTag::Weeks => 7,
            UnitTag::Bytes => 8,
            UnitTag::Kibibytes => 9,
            UnitTag::Mebibytes => 10,
            UnitTag::Gibibytes => 11,
            UnitTag::Tebibytes => 12,
            UnitTag::Pebibytes => 13,
            UnitTag::Exbibytes => 14,
            UnitTag::Kilobytes => 15,
            UnitTag::Megabytes => 16,
            UnitTag::Gigabytes => 17,
            UnitTag::Terabytes => 18,
            UnitTag::PerSecond => 19,
            UnitTag::PerMinute => 20,
            UnitTag::PerHour => 21,
            UnitTag::RequestsPerSecond => 22,
            UnitTag::RequestsPerMinute => 23,
            UnitTag::RequestsPerHour => 24,
            UnitTag::Percent => 25,
            UnitTag::Hertz => 26,
            UnitTag::Kilohertz => 27,
            UnitTag::Megahertz => 28,
            UnitTag::Gigahertz => 29,
            UnitTag::Terahertz => 30,
            UnitTag::Bits => 31,
            UnitTag::Kilobits => 32,
            UnitTag::Megabits => 33,
            UnitTag::Gigabits => 34,
            UnitTag::BitsPerSecond => 35,
            UnitTag::KilobitsPerSecond => 36,
            UnitTag::MegabitsPerSecond => 37,
            UnitTag::GigabitsPerSecond => 38,
            UnitTag::MegabytesPerSecond => 39,
            UnitTag::Tokens => 40,
            UnitTag::KiloTokens => 41,
            UnitTag::MegaTokens => 42,
            UnitTag::TokensPerSecond => 43,
            UnitTag::Flops => 44,
            UnitTag::TeraFlops => 45,
            UnitTag::PetaFlops => 46,
            UnitTag::Pascal => 47,
            UnitTag::Bar => 48,
            UnitTag::Psi => 49,
            UnitTag::Volts => 50,
            UnitTag::Amperes => 51,
            UnitTag::Watts => 52,
            UnitTag::Joules => 53,
            UnitTag::KilowattHours => 54,
            UnitTag::Newtons => 55,
            UnitTag::Degrees => 56,
            UnitTag::Radians => 57,
            UnitTag::Rpm => 58,
            UnitTag::Meters => 59,
            UnitTag::Kilometers => 60,
            UnitTag::Kilograms => 61,
            UnitTag::Grams => 62,
            UnitTag::Kelvin => 63,
            UnitTag::Celsius => 64,
            UnitTag::Fahrenheit => 65,
            UnitTag::Decibel => 66,
            UnitTag::Named(_) => UNIT_NAMED,
        }
    }

    /// Built-in unit for a discriminant, or `None` when out of range.
    pub fn from_discriminant(disc: u32) -> Option<UnitTag> {
        let unit = match disc {
            0 => UnitTag::Nanoseconds,
            1 => UnitTag::Microseconds,
            2 => UnitTag::Milliseconds,
            3 => UnitTag::Seconds,
            4 => UnitTag::Minutes,
            5 => UnitTag::Hours,
            6 => UnitTag::Days,
            7 => UnitTag::Weeks,
            8 => UnitTag::Bytes,
            9 => UnitTag::Kibibytes,
            10 => UnitTag::Mebibytes,
            11 => UnitTag::Gibibytes,
            12 => UnitTag::Tebibytes,
            13 => UnitTag::Pebibytes,
            14 => UnitTag::Exbibytes,
            15 => UnitTag::Kilobytes,
            16 => UnitTag::Megabytes,
            17 => UnitTag::Gigabytes,
            18 => UnitTag::Terabytes,
            19 => UnitTag::PerSecond,
            20 => UnitTag::PerMinute,
            21 => UnitTag::PerHour,
            22 => UnitTag::RequestsPerSecond,
            23 => UnitTag::RequestsPerMinute,
            24 => UnitTag::RequestsPerHour,
            25 => UnitTag::Percent,
            26 => UnitTag::Hertz,
            27 => UnitTag::Kilohertz,
            28 => UnitTag::Megahertz,
            29 => UnitTag::Gigahertz,
            30 => UnitTag::Terahertz,
            31 => UnitTag::Bits,
            32 => UnitTag::Kilobits,
            33 => UnitTag::Megabits,
            34 => UnitTag::Gigabits,
            35 => UnitTag::BitsPerSecond,
            36 => UnitTag::KilobitsPerSecond,
            37 => UnitTag::MegabitsPerSecond,
            38 => UnitTag::GigabitsPerSecond,
            39 => UnitTag::MegabytesPerSecond,
            40 => UnitTag::Tokens,
            41 => UnitTag::KiloTokens,
            42 => UnitTag::MegaTokens,
            43 => UnitTag::TokensPerSecond,
            44 => UnitTag::Flops,
            45 => UnitTag::TeraFlops,
            46 => UnitTag::PetaFlops,
            47 => UnitTag::Pascal,
            48 => UnitTag::Bar,
            49 => UnitTag::Psi,
            50 => UnitTag::Volts,
            51 => UnitTag::Amperes,
            52 => UnitTag::Watts,
            53 => UnitTag::Joules,
            54 => UnitTag::KilowattHours,
            55 => UnitTag::Newtons,
            56 => UnitTag::Degrees,
            57 => UnitTag::Radians,
            58 => UnitTag::Rpm,
            59 => UnitTag::Meters,
            60 => UnitTag::Kilometers,
            61 => UnitTag::Kilograms,
            62 => UnitTag::Grams,
            63 => UnitTag::Kelvin,
            64 => UnitTag::Celsius,
            65 => UnitTag::Fahrenheit,
            66 => UnitTag::Decibel,
            _ => return None,
        };
        Some(unit)
    }

    /// Stable textual name, independent of source spelling.
    pub fn name(&self) -> &str {
        match self {
            UnitTag::Nanoseconds => "nanoseconds",
            UnitTag::Microseconds => "microseconds",
            UnitTag::Milliseconds => "milliseconds",
            UnitTag::Seconds => "seconds",
            UnitTag::Minutes => "minutes",
            UnitTag::Hours => "hours",
            UnitTag::Days => "days",
            UnitTag::Weeks => "weeks",
            UnitTag::Bytes => "bytes",
            UnitTag::Kibibytes => "kibibytes",
            UnitTag::Mebibytes => "mebibytes",
            UnitTag::Gibibytes => "gibibytes",
            UnitTag::Tebibytes => "tebibytes",
            UnitTag::Pebibytes => "pebibytes",
            UnitTag::Exbibytes => "exbibytes",
            UnitTag::Kilobytes => "kilobytes",
            UnitTag::Megabytes => "megabytes",
            UnitTag::Gigabytes => "gigabytes",
            UnitTag::Terabytes => "terabytes",
            UnitTag::PerSecond => "per-second",
            UnitTag::PerMinute => "per-minute",
            UnitTag::PerHour => "per-hour",
            UnitTag::RequestsPerSecond => "requests-per-second",
            UnitTag::RequestsPerMinute => "requests-per-minute",
            UnitTag::RequestsPerHour => "requests-per-hour",
            UnitTag::Percent => "percent",
            UnitTag::Hertz => "hertz",
            UnitTag::Kilohertz => "kilohertz",
            UnitTag::Megahertz => "megahertz",
            UnitTag::Gigahertz => "gigahertz",
            UnitTag::Terahertz => "terahertz",
            UnitTag::Bits => "bits",
            UnitTag::Kilobits => "kilobits",
            UnitTag::Megabits => "megabits",
            UnitTag::Gigabits => "gigabits",
            UnitTag::BitsPerSecond => "bits-per-second",
            UnitTag::KilobitsPerSecond => "kilobits-per-second",
            UnitTag::MegabitsPerSecond => "megabits-per-second",
            UnitTag::GigabitsPerSecond => "gigabits-per-second",
            UnitTag::MegabytesPerSecond => "megabytes-per-second",
            UnitTag::Tokens => "tokens",
            UnitTag::KiloTokens => "kilo-tokens",
            UnitTag::MegaTokens => "mega-tokens",
            UnitTag::TokensPerSecond => "tokens-per-second",
            UnitTag::Flops => "flops",
            UnitTag::TeraFlops => "teraflops",
            UnitTag::PetaFlops => "petaflops",
            UnitTag::Pascal => "pascal",
            UnitTag::Bar => "bar",
            UnitTag::Psi => "psi",
            UnitTag::Volts => "volts",
            UnitTag::Amperes => "amperes",
            UnitTag::Watts => "watts",
            UnitTag::Joules => "joules",
            UnitTag::KilowattHours => "kilowatt-hours",
            UnitTag::Newtons => "newtons",
            UnitTag::Degrees => "degrees",
            UnitTag::Radians => "radians",
            UnitTag::Rpm => "rpm",
            UnitTag::Meters => "meters",
            UnitTag::Kilometers => "kilometers",
            UnitTag::Kilograms => "kilograms",
            UnitTag::Grams => "grams",
            UnitTag::Kelvin => "kelvin",
            UnitTag::Celsius => "celsius",
            UnitTag::Fahrenheit => "fahrenheit",
            UnitTag::Decibel => "decibel",
            UnitTag::Named(name) => name,
        }
    }

    /// Absolute temperatures and decibels admit equality and ordering but
    /// never arithmetic (`active-core` spec Ch. 4 §4.1). Preserved so the
    /// binary form cannot be used to smuggle an illegal operation past the
    /// evaluator.
    pub fn is_non_arithmetic(&self) -> bool {
        matches!(
            self,
            UnitTag::Kelvin | UnitTag::Celsius | UnitTag::Fahrenheit | UnitTag::Decibel
        )
    }

    /// True for the closed built-in table and false for `Named`.
    pub fn is_builtin(&self) -> bool {
        !matches!(self, UnitTag::Named(_))
    }
}

impl fmt::Display for UnitTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // A named unit is free text and can hold a secret copy. The raw
            // name stays available through `name()` for a deliberate transfer.
            UnitTag::Named(name) => write!(f, "named-unit(<{} bytes>)", name.len()),
            other => f.write_str(other.name()),
        }
    }
}

impl fmt::Debug for UnitTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A named unit is caller text and can carry a secret copy. Debug prints
        // its size; built-in discriminants are a closed, safe set.
        match self {
            UnitTag::Named(name) => write!(f, "Named(<{} bytes>)", name.len()),
            other => f.write_str(other.name()),
        }
    }
}

#[cfg(feature = "active-core")]
mod interop {
    use super::UnitTag;
    use active_core::Unit;

    impl From<&Unit> for UnitTag {
        fn from(unit: &Unit) -> Self {
            match unit {
                Unit::Nanoseconds => UnitTag::Nanoseconds,
                Unit::Microseconds => UnitTag::Microseconds,
                Unit::Milliseconds => UnitTag::Milliseconds,
                Unit::Seconds => UnitTag::Seconds,
                Unit::Minutes => UnitTag::Minutes,
                Unit::Hours => UnitTag::Hours,
                Unit::Days => UnitTag::Days,
                Unit::Weeks => UnitTag::Weeks,
                Unit::Bytes => UnitTag::Bytes,
                Unit::Kibibytes => UnitTag::Kibibytes,
                Unit::Mebibytes => UnitTag::Mebibytes,
                Unit::Gibibytes => UnitTag::Gibibytes,
                Unit::Tebibytes => UnitTag::Tebibytes,
                Unit::Pebibytes => UnitTag::Pebibytes,
                Unit::Exbibytes => UnitTag::Exbibytes,
                Unit::Kilobytes => UnitTag::Kilobytes,
                Unit::Megabytes => UnitTag::Megabytes,
                Unit::Gigabytes => UnitTag::Gigabytes,
                Unit::Terabytes => UnitTag::Terabytes,
                Unit::PerSecond => UnitTag::PerSecond,
                Unit::PerMinute => UnitTag::PerMinute,
                Unit::PerHour => UnitTag::PerHour,
                Unit::RequestsPerSecond => UnitTag::RequestsPerSecond,
                Unit::RequestsPerMinute => UnitTag::RequestsPerMinute,
                Unit::RequestsPerHour => UnitTag::RequestsPerHour,
                Unit::Percent => UnitTag::Percent,
                Unit::Hertz => UnitTag::Hertz,
                Unit::Kilohertz => UnitTag::Kilohertz,
                Unit::Megahertz => UnitTag::Megahertz,
                Unit::Gigahertz => UnitTag::Gigahertz,
                Unit::Terahertz => UnitTag::Terahertz,
                Unit::Bits => UnitTag::Bits,
                Unit::Kilobits => UnitTag::Kilobits,
                Unit::Megabits => UnitTag::Megabits,
                Unit::Gigabits => UnitTag::Gigabits,
                Unit::BitsPerSecond => UnitTag::BitsPerSecond,
                Unit::KilobitsPerSecond => UnitTag::KilobitsPerSecond,
                Unit::MegabitsPerSecond => UnitTag::MegabitsPerSecond,
                Unit::GigabitsPerSecond => UnitTag::GigabitsPerSecond,
                Unit::MegabytesPerSecond => UnitTag::MegabytesPerSecond,
                Unit::Tokens => UnitTag::Tokens,
                Unit::KiloTokens => UnitTag::KiloTokens,
                Unit::MegaTokens => UnitTag::MegaTokens,
                Unit::TokensPerSecond => UnitTag::TokensPerSecond,
                Unit::Flops => UnitTag::Flops,
                Unit::TeraFlops => UnitTag::TeraFlops,
                Unit::PetaFlops => UnitTag::PetaFlops,
                Unit::Pascal => UnitTag::Pascal,
                Unit::Bar => UnitTag::Bar,
                Unit::Psi => UnitTag::Psi,
                Unit::Volts => UnitTag::Volts,
                Unit::Amperes => UnitTag::Amperes,
                Unit::Watts => UnitTag::Watts,
                Unit::Joules => UnitTag::Joules,
                Unit::KilowattHours => UnitTag::KilowattHours,
                Unit::Newtons => UnitTag::Newtons,
                Unit::Degrees => UnitTag::Degrees,
                Unit::Radians => UnitTag::Radians,
                Unit::Rpm => UnitTag::Rpm,
                Unit::Meters => UnitTag::Meters,
                Unit::Kilometers => UnitTag::Kilometers,
                Unit::Kilograms => UnitTag::Kilograms,
                Unit::Grams => UnitTag::Grams,
                Unit::Kelvin => UnitTag::Kelvin,
                Unit::Celsius => UnitTag::Celsius,
                Unit::Fahrenheit => UnitTag::Fahrenheit,
                Unit::Decibel => UnitTag::Decibel,
                Unit::Custom(name) => UnitTag::Named(name.clone()),
            }
        }
    }

    impl From<&UnitTag> for Unit {
        fn from(tag: &UnitTag) -> Self {
            match tag {
                UnitTag::Nanoseconds => Unit::Nanoseconds,
                UnitTag::Microseconds => Unit::Microseconds,
                UnitTag::Milliseconds => Unit::Milliseconds,
                UnitTag::Seconds => Unit::Seconds,
                UnitTag::Minutes => Unit::Minutes,
                UnitTag::Hours => Unit::Hours,
                UnitTag::Days => Unit::Days,
                UnitTag::Weeks => Unit::Weeks,
                UnitTag::Bytes => Unit::Bytes,
                UnitTag::Kibibytes => Unit::Kibibytes,
                UnitTag::Mebibytes => Unit::Mebibytes,
                UnitTag::Gibibytes => Unit::Gibibytes,
                UnitTag::Tebibytes => Unit::Tebibytes,
                UnitTag::Pebibytes => Unit::Pebibytes,
                UnitTag::Exbibytes => Unit::Exbibytes,
                UnitTag::Kilobytes => Unit::Kilobytes,
                UnitTag::Megabytes => Unit::Megabytes,
                UnitTag::Gigabytes => Unit::Gigabytes,
                UnitTag::Terabytes => Unit::Terabytes,
                UnitTag::PerSecond => Unit::PerSecond,
                UnitTag::PerMinute => Unit::PerMinute,
                UnitTag::PerHour => Unit::PerHour,
                UnitTag::RequestsPerSecond => Unit::RequestsPerSecond,
                UnitTag::RequestsPerMinute => Unit::RequestsPerMinute,
                UnitTag::RequestsPerHour => Unit::RequestsPerHour,
                UnitTag::Percent => Unit::Percent,
                UnitTag::Hertz => Unit::Hertz,
                UnitTag::Kilohertz => Unit::Kilohertz,
                UnitTag::Megahertz => Unit::Megahertz,
                UnitTag::Gigahertz => Unit::Gigahertz,
                UnitTag::Terahertz => Unit::Terahertz,
                UnitTag::Bits => Unit::Bits,
                UnitTag::Kilobits => Unit::Kilobits,
                UnitTag::Megabits => Unit::Megabits,
                UnitTag::Gigabits => Unit::Gigabits,
                UnitTag::BitsPerSecond => Unit::BitsPerSecond,
                UnitTag::KilobitsPerSecond => Unit::KilobitsPerSecond,
                UnitTag::MegabitsPerSecond => Unit::MegabitsPerSecond,
                UnitTag::GigabitsPerSecond => Unit::GigabitsPerSecond,
                UnitTag::MegabytesPerSecond => Unit::MegabytesPerSecond,
                UnitTag::Tokens => Unit::Tokens,
                UnitTag::KiloTokens => Unit::KiloTokens,
                UnitTag::MegaTokens => Unit::MegaTokens,
                UnitTag::TokensPerSecond => Unit::TokensPerSecond,
                UnitTag::Flops => Unit::Flops,
                UnitTag::TeraFlops => Unit::TeraFlops,
                UnitTag::PetaFlops => Unit::PetaFlops,
                UnitTag::Pascal => Unit::Pascal,
                UnitTag::Bar => Unit::Bar,
                UnitTag::Psi => Unit::Psi,
                UnitTag::Volts => Unit::Volts,
                UnitTag::Amperes => Unit::Amperes,
                UnitTag::Watts => Unit::Watts,
                UnitTag::Joules => Unit::Joules,
                UnitTag::KilowattHours => Unit::KilowattHours,
                UnitTag::Newtons => Unit::Newtons,
                UnitTag::Degrees => Unit::Degrees,
                UnitTag::Radians => Unit::Radians,
                UnitTag::Rpm => Unit::Rpm,
                UnitTag::Meters => Unit::Meters,
                UnitTag::Kilometers => Unit::Kilometers,
                UnitTag::Kilograms => Unit::Kilograms,
                UnitTag::Grams => Unit::Grams,
                UnitTag::Kelvin => Unit::Kelvin,
                UnitTag::Celsius => Unit::Celsius,
                UnitTag::Fahrenheit => Unit::Fahrenheit,
                UnitTag::Decibel => Unit::Decibel,
                UnitTag::Named(name) => Unit::Custom(name.clone()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_are_bijective() {
        for disc in 0..=UNIT_MAX_BUILTIN {
            let unit = UnitTag::from_discriminant(disc).expect("builtin in range");
            assert_eq!(unit.discriminant(), disc, "round trip for {disc}");
            assert!(unit.is_builtin());
        }
        assert!(UnitTag::from_discriminant(UNIT_MAX_BUILTIN + 1).is_none());
        assert!(UnitTag::from_discriminant(UNIT_NAMED).is_none());
    }

    #[test]
    fn named_units_keep_their_name() {
        let unit = UnitTag::Named("widgets".to_string());
        assert_eq!(unit.discriminant(), UNIT_NAMED);
        assert_eq!(unit.name(), "widgets");
        assert!(!unit.is_builtin());
    }

    #[test]
    fn non_arithmetic_units_match_active_core() {
        for unit in [
            UnitTag::Kelvin,
            UnitTag::Celsius,
            UnitTag::Fahrenheit,
            UnitTag::Decibel,
        ] {
            assert!(unit.is_non_arithmetic(), "{unit} must be non-arithmetic");
        }
        assert!(!UnitTag::Meters.is_non_arithmetic());
    }
}
