//! sre's opcodes, position codes, categories and flags (re/_constants.py,
//! CPython 3.11-3.14), numbered as CPython numbers them.

pub const MAXREPEAT: u32 = u32::MAX; // _sre.MAXREPEAT (CODESIZE 4)
pub const MAXGROUPS: usize = 1_073_741_823; // _sre.MAXGROUPS (64-bit builds)
pub const MAXCODE: u64 = u32::MAX as u64;

// opcodes
pub const FAILURE: u32 = 0;
pub const SUCCESS: u32 = 1;
pub const ANY: u32 = 2;
pub const ANY_ALL: u32 = 3;
pub const ASSERT: u32 = 4;
pub const ASSERT_NOT: u32 = 5;
pub const AT: u32 = 6;
pub const BRANCH: u32 = 7;
pub const CATEGORY: u32 = 8;
pub const CHARSET: u32 = 9;
pub const BIGCHARSET: u32 = 10;
pub const GROUPREF: u32 = 11;
pub const GROUPREF_EXISTS: u32 = 12;
pub const IN: u32 = 13;
pub const INFO: u32 = 14;
pub const JUMP: u32 = 15;
pub const LITERAL: u32 = 16;
pub const MARK: u32 = 17;
pub const MAX_UNTIL: u32 = 18;
pub const MIN_UNTIL: u32 = 19;
pub const NOT_LITERAL: u32 = 20;
pub const NEGATE: u32 = 21;
pub const RANGE: u32 = 22;
pub const REPEAT: u32 = 23;
pub const REPEAT_ONE: u32 = 24;
pub const SUBPATTERN: u32 = 25;
pub const MIN_REPEAT_ONE: u32 = 26;
pub const ATOMIC_GROUP: u32 = 27;
pub const POSSESSIVE_REPEAT: u32 = 28;
pub const POSSESSIVE_REPEAT_ONE: u32 = 29;
pub const GROUPREF_IGNORE: u32 = 30;
pub const IN_IGNORE: u32 = 31;
pub const LITERAL_IGNORE: u32 = 32;
pub const NOT_LITERAL_IGNORE: u32 = 33;
pub const GROUPREF_LOC_IGNORE: u32 = 34;
pub const IN_LOC_IGNORE: u32 = 35;
pub const LITERAL_LOC_IGNORE: u32 = 36;
pub const NOT_LITERAL_LOC_IGNORE: u32 = 37;
pub const GROUPREF_UNI_IGNORE: u32 = 38;
pub const IN_UNI_IGNORE: u32 = 39;
pub const LITERAL_UNI_IGNORE: u32 = 40;
pub const NOT_LITERAL_UNI_IGNORE: u32 = 41;
pub const RANGE_UNI_IGNORE: u32 = 42;

// positions
pub const AT_BEGINNING: u32 = 0;
pub const AT_BEGINNING_LINE: u32 = 1;
pub const AT_BEGINNING_STRING: u32 = 2;
pub const AT_BOUNDARY: u32 = 3;
pub const AT_NON_BOUNDARY: u32 = 4;
pub const AT_END: u32 = 5;
pub const AT_END_LINE: u32 = 6;
pub const AT_END_STRING: u32 = 7;
pub const AT_LOC_BOUNDARY: u32 = 8;
pub const AT_LOC_NON_BOUNDARY: u32 = 9;
pub const AT_UNI_BOUNDARY: u32 = 10;
pub const AT_UNI_NON_BOUNDARY: u32 = 11;

// categories
pub const CATEGORY_DIGIT: u32 = 0;
pub const CATEGORY_NOT_DIGIT: u32 = 1;
pub const CATEGORY_SPACE: u32 = 2;
pub const CATEGORY_NOT_SPACE: u32 = 3;
pub const CATEGORY_WORD: u32 = 4;
pub const CATEGORY_NOT_WORD: u32 = 5;
pub const CATEGORY_LINEBREAK: u32 = 6;
pub const CATEGORY_NOT_LINEBREAK: u32 = 7;
pub const CATEGORY_LOC_WORD: u32 = 8;
pub const CATEGORY_LOC_NOT_WORD: u32 = 9;
pub const CATEGORY_UNI_DIGIT: u32 = 10;
pub const CATEGORY_UNI_NOT_DIGIT: u32 = 11;
pub const CATEGORY_UNI_SPACE: u32 = 12;
pub const CATEGORY_UNI_NOT_SPACE: u32 = 13;
pub const CATEGORY_UNI_WORD: u32 = 14;
pub const CATEGORY_UNI_NOT_WORD: u32 = 15;
pub const CATEGORY_UNI_LINEBREAK: u32 = 16;
pub const CATEGORY_UNI_NOT_LINEBREAK: u32 = 17;

// flags
pub const FLAG_IGNORECASE: u32 = 2;
pub const FLAG_LOCALE: u32 = 4;
pub const FLAG_MULTILINE: u32 = 8;
pub const FLAG_DOTALL: u32 = 16;
pub const FLAG_UNICODE: u32 = 32;
pub const FLAG_VERBOSE: u32 = 64;
pub const FLAG_DEBUG: u32 = 128;
pub const FLAG_ASCII: u32 = 256;
pub const TYPE_FLAGS: u32 = FLAG_ASCII | FLAG_LOCALE | FLAG_UNICODE;
pub const GLOBAL_FLAGS: u32 = FLAG_DEBUG;

// INFO block flags
pub const INFO_PREFIX: u32 = 1;
pub const INFO_LITERAL: u32 = 2;
pub const INFO_CHARSET: u32 = 4;

pub fn at_multiline(av: u32) -> u32 {
    match av {
        AT_BEGINNING => AT_BEGINNING_LINE,
        AT_END => AT_END_LINE,
        x => x,
    }
}

pub fn at_unicode(av: u32) -> u32 {
    match av {
        AT_BOUNDARY => AT_UNI_BOUNDARY,
        AT_NON_BOUNDARY => AT_UNI_NON_BOUNDARY,
        x => x,
    }
}

pub fn at_locale(av: u32) -> u32 {
    match av {
        AT_BOUNDARY => AT_LOC_BOUNDARY,
        AT_NON_BOUNDARY => AT_LOC_NON_BOUNDARY,
        x => x,
    }
}

pub fn ch_unicode(av: u32) -> u32 {
    match av {
        CATEGORY_DIGIT => CATEGORY_UNI_DIGIT,
        CATEGORY_NOT_DIGIT => CATEGORY_UNI_NOT_DIGIT,
        CATEGORY_SPACE => CATEGORY_UNI_SPACE,
        CATEGORY_NOT_SPACE => CATEGORY_UNI_NOT_SPACE,
        CATEGORY_WORD => CATEGORY_UNI_WORD,
        CATEGORY_NOT_WORD => CATEGORY_UNI_NOT_WORD,
        CATEGORY_LINEBREAK => CATEGORY_UNI_LINEBREAK,
        CATEGORY_NOT_LINEBREAK => CATEGORY_UNI_NOT_LINEBREAK,
        x => x,
    }
}

pub fn ch_locale(av: u32) -> u32 {
    match av {
        CATEGORY_WORD => CATEGORY_LOC_WORD,
        CATEGORY_NOT_WORD => CATEGORY_LOC_NOT_WORD,
        x => x,
    }
}
