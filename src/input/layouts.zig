//! XKB layout for the remote session. Like a Windows host, the server types with the
//! client's layout (TS_UD_CS_CORE.keyboardLayout) and keeps the session's XKB model and
//! options; an unknown KLID keeps the session's configuration.

const std = @import("std");

pub const Xkb = struct { layout: []const u8, variant: []const u8 = "" };

pub const Entry = struct { klid: u32, xkb: Xkb };

/// Windows keyboard layout IDs (KLID) → xkeyboard-config layout(variant).
pub const table = [_]Entry{
    .{ .klid = 0x00000401, .xkb = .{ .layout = "ara" } },
    .{ .klid = 0x00000402, .xkb = .{ .layout = "bg" } },
    .{ .klid = 0x00000404, .xkb = .{ .layout = "us" } }, // Chinese (Traditional): US keys + IME
    .{ .klid = 0x00000405, .xkb = .{ .layout = "cz" } },
    .{ .klid = 0x00000406, .xkb = .{ .layout = "dk" } },
    .{ .klid = 0x00000407, .xkb = .{ .layout = "de" } },
    .{ .klid = 0x00000408, .xkb = .{ .layout = "gr" } },
    .{ .klid = 0x00000409, .xkb = .{ .layout = "us" } },
    .{ .klid = 0x0000040A, .xkb = .{ .layout = "es" } },
    .{ .klid = 0x0000040B, .xkb = .{ .layout = "fi" } },
    .{ .klid = 0x0000040C, .xkb = .{ .layout = "fr" } },
    .{ .klid = 0x0000040D, .xkb = .{ .layout = "il" } },
    .{ .klid = 0x0000040E, .xkb = .{ .layout = "hu" } },
    .{ .klid = 0x0000040F, .xkb = .{ .layout = "is" } },
    .{ .klid = 0x00000410, .xkb = .{ .layout = "it" } },
    .{ .klid = 0x00000411, .xkb = .{ .layout = "jp" } },
    .{ .klid = 0x00000412, .xkb = .{ .layout = "kr" } },
    .{ .klid = 0x00000413, .xkb = .{ .layout = "nl" } },
    .{ .klid = 0x00000414, .xkb = .{ .layout = "no" } },
    .{ .klid = 0x00000415, .xkb = .{ .layout = "pl" } }, // Polish (Programmers)
    .{ .klid = 0x00000416, .xkb = .{ .layout = "br" } },
    .{ .klid = 0x00000418, .xkb = .{ .layout = "ro", .variant = "winkeys" } }, // Romanian (Legacy): QWERTZ
    .{ .klid = 0x00000419, .xkb = .{ .layout = "ru" } },
    .{ .klid = 0x0000041A, .xkb = .{ .layout = "hr" } },
    .{ .klid = 0x0000041B, .xkb = .{ .layout = "sk" } },
    .{ .klid = 0x0000041D, .xkb = .{ .layout = "se" } },
    .{ .klid = 0x0000041E, .xkb = .{ .layout = "th" } },
    .{ .klid = 0x0000041F, .xkb = .{ .layout = "tr" } },
    .{ .klid = 0x00000422, .xkb = .{ .layout = "ua" } },
    .{ .klid = 0x00000424, .xkb = .{ .layout = "si" } },
    .{ .klid = 0x00000425, .xkb = .{ .layout = "ee" } },
    .{ .klid = 0x00000426, .xkb = .{ .layout = "lv" } },
    .{ .klid = 0x00000427, .xkb = .{ .layout = "lt", .variant = "ibm" } }, // Lithuanian IBM (LST 1205-92)
    .{ .klid = 0x0000042F, .xkb = .{ .layout = "mk" } },
    .{ .klid = 0x00000452, .xkb = .{ .layout = "gb", .variant = "extd" } },
    .{ .klid = 0x00000804, .xkb = .{ .layout = "us" } }, // Chinese (Simplified): US keys + IME
    .{ .klid = 0x00000807, .xkb = .{ .layout = "ch" } },
    .{ .klid = 0x00000809, .xkb = .{ .layout = "gb" } },
    .{ .klid = 0x0000080A, .xkb = .{ .layout = "latam" } },
    .{ .klid = 0x0000080C, .xkb = .{ .layout = "be" } },
    .{ .klid = 0x00000813, .xkb = .{ .layout = "be" } },
    .{ .klid = 0x00000816, .xkb = .{ .layout = "pt" } },
    .{ .klid = 0x0000081A, .xkb = .{ .layout = "rs", .variant = "latin" } },
    .{ .klid = 0x00000C0C, .xkb = .{ .layout = "ca", .variant = "fr-legacy" } },
    .{ .klid = 0x00001009, .xkb = .{ .layout = "ca" } },
    .{ .klid = 0x0000100C, .xkb = .{ .layout = "ch", .variant = "fr" } },
    .{ .klid = 0x00001809, .xkb = .{ .layout = "ie" } },
    .{ .klid = 0x00010405, .xkb = .{ .layout = "cz", .variant = "qwerty" } },
    .{ .klid = 0x00010409, .xkb = .{ .layout = "us", .variant = "dvorak" } },
    .{ .klid = 0x0001040C, .xkb = .{ .layout = "fr", .variant = "afnor" } }, // French (Standard, AZERTY)
    .{ .klid = 0x0001040A, .xkb = .{ .layout = "es" } },
    .{ .klid = 0x00010415, .xkb = .{ .layout = "pl", .variant = "qwertz" } }, // Polish (214)
    .{ .klid = 0x00010416, .xkb = .{ .layout = "br" } }, // ABNT2
    .{ .klid = 0x00010418, .xkb = .{ .layout = "ro", .variant = "std" } }, // Romanian (Standard)
    .{ .klid = 0x00010419, .xkb = .{ .layout = "ru", .variant = "typewriter" } },
    .{ .klid = 0x0001041B, .xkb = .{ .layout = "sk", .variant = "qwerty" } },
    .{ .klid = 0x0001041F, .xkb = .{ .layout = "tr", .variant = "f" } },
    .{ .klid = 0x00010427, .xkb = .{ .layout = "lt" } }, // Lithuanian
    .{ .klid = 0x00011009, .xkb = .{ .layout = "ca", .variant = "multix" } },
    .{ .klid = 0x00020409, .xkb = .{ .layout = "us", .variant = "intl" } },
    .{ .klid = 0x00020418, .xkb = .{ .layout = "ro" } }, // Romanian (Programmers)
    .{ .klid = 0x00020427, .xkb = .{ .layout = "lt", .variant = "std" } }, // Lithuanian Standard (LST 1582:2000)
    .{ .klid = 0x00030409, .xkb = .{ .layout = "us", .variant = "dvorak-l" } },
    .{ .klid = 0x00040409, .xkb = .{ .layout = "us", .variant = "dvorak-r" } },
};

/// Language IDs whose default keyboard layout has another ID; languages that are
/// themselves table KLIDs are left out.
const lang_defaults = [_]struct { lang: u16, klid: u32 }{
    .{ .lang = 0x0436, .klid = 0x00000409 }, // AFRIKAANS
    .{ .lang = 0x0801, .klid = 0x00000409 }, // ARABIC_IRAQ
    .{ .lang = 0x0C01, .klid = 0x00000409 }, // ARABIC_EGYPT
    .{ .lang = 0x1001, .klid = 0x0000040C }, // ARABIC_LIBYA
    .{ .lang = 0x1401, .klid = 0x0000040C }, // ARABIC_ALGERIA
    .{ .lang = 0x1801, .klid = 0x0000040C }, // ARABIC_MOROCCO
    .{ .lang = 0x1C01, .klid = 0x0000040C }, // ARABIC_TUNISIA
    .{ .lang = 0x2001, .klid = 0x00000409 }, // ARABIC_OMAN
    .{ .lang = 0x2401, .klid = 0x00000409 }, // ARABIC_YEMEN
    .{ .lang = 0x2801, .klid = 0x00000409 }, // ARABIC_SYRIA
    .{ .lang = 0x2C01, .klid = 0x00000409 }, // ARABIC_JORDAN
    .{ .lang = 0x3001, .klid = 0x00000409 }, // ARABIC_LEBANON
    .{ .lang = 0x3401, .klid = 0x00000409 }, // ARABIC_KUWAIT
    .{ .lang = 0x3801, .klid = 0x00000409 }, // ARABIC_UAE
    .{ .lang = 0x3C01, .klid = 0x00000409 }, // ARABIC_BAHRAIN
    .{ .lang = 0x4001, .klid = 0x00000409 }, // ARABIC_QATAR
    .{ .lang = 0x042D, .klid = 0x0000040A }, // BASQUE
    .{ .lang = 0x0403, .klid = 0x0000040A }, // CATALAN
    .{ .lang = 0x0C04, .klid = 0x00000409 }, // CHINESE_HONG_KONG
    .{ .lang = 0x1004, .klid = 0x00000409 }, // CHINESE_SINGAPORE
    .{ .lang = 0x1404, .klid = 0x00000409 }, // CHINESE_MACAU
    .{ .lang = 0x101A, .klid = 0x0000041A }, // CROATIAN_BOSNIA_HERZEGOVINA
    .{ .lang = 0x0465, .klid = 0x00000409 }, // DIVEHI
    .{ .lang = 0x0C09, .klid = 0x00000409 }, // ENGLISH_AUSTRALIAN
    .{ .lang = 0x1409, .klid = 0x00000409 }, // ENGLISH_NEW_ZEALAND
    .{ .lang = 0x1C09, .klid = 0x00000409 }, // ENGLISH_SOUTH_AFRICA
    .{ .lang = 0x2009, .klid = 0x00000409 }, // ENGLISH_JAMAICA
    .{ .lang = 0x2409, .klid = 0x00000409 }, // ENGLISH_CARIBBEAN
    .{ .lang = 0x2809, .klid = 0x00000409 }, // ENGLISH_BELIZE
    .{ .lang = 0x2C09, .klid = 0x00000409 }, // ENGLISH_TRINIDAD
    .{ .lang = 0x3009, .klid = 0x00000409 }, // ENGLISH_ZIMBABWE
    .{ .lang = 0x3409, .klid = 0x00000409 }, // ENGLISH_PHILIPPINES
    .{ .lang = 0x0438, .klid = 0x00000406 }, // FAEROESE
    .{ .lang = 0x0429, .klid = 0x00000409 }, // FARSI
    .{ .lang = 0x140C, .klid = 0x0000040C }, // FRENCH_LUXEMBOURG
    .{ .lang = 0x180C, .klid = 0x0000040C }, // FRENCH_MONACO
    .{ .lang = 0x0456, .klid = 0x0000040A }, // GALICIAN
    .{ .lang = 0x0C07, .klid = 0x00000407 }, // GERMAN_AUSTRIAN
    .{ .lang = 0x1007, .klid = 0x00000407 }, // GERMAN_LUXEMBOURG
    .{ .lang = 0x1407, .klid = 0x00000407 }, // GERMAN_LIECHTENSTEIN
    .{ .lang = 0x0447, .klid = 0x00000409 }, // GUJARATI
    .{ .lang = 0x0439, .klid = 0x00000409 }, // HINDI
    .{ .lang = 0x0421, .klid = 0x00000409 }, // INDONESIAN
    .{ .lang = 0x0810, .klid = 0x00000410 }, // ITALIAN_SWISS
    .{ .lang = 0x044B, .klid = 0x00000409 }, // KANNADA
    .{ .lang = 0x0457, .klid = 0x00000409 }, // KONKANI
    .{ .lang = 0x043E, .klid = 0x00000409 }, // MALAY_MALAYSIA
    .{ .lang = 0x083E, .klid = 0x00000409 }, // MALAY_BRUNEI_DARUSSALAM
    .{ .lang = 0x044C, .klid = 0x00000409 }, // MALAYALAM
    .{ .lang = 0x043A, .klid = 0x00000409 }, // MALTESE
    .{ .lang = 0x0481, .klid = 0x00000409 }, // MAORI
    .{ .lang = 0x044E, .klid = 0x00000409 }, // MARATHI
    .{ .lang = 0x0814, .klid = 0x00000414 }, // NORWEGIAN_NYNORSK
    .{ .lang = 0x0446, .klid = 0x00000409 }, // PUNJABI
    .{ .lang = 0x046B, .klid = 0x00000409 }, // QUECHUA_BOLIVIA
    .{ .lang = 0x086B, .klid = 0x00000409 }, // QUECHUA_ECUADOR
    .{ .lang = 0x0C6B, .klid = 0x00000409 }, // QUECHUA_PERU
    .{ .lang = 0x243B, .klid = 0x0001083B }, // SAMI_INARI
    .{ .lang = 0x103B, .klid = 0x0000043B }, // SAMI_LULE_NORWAY
    .{ .lang = 0x143B, .klid = 0x0000083B }, // SAMI_LULE_SWEDEN
    .{ .lang = 0x0C3B, .klid = 0x0001083B }, // SAMI_NORTHERN_FINLAND
    .{ .lang = 0x203B, .klid = 0x0001083B }, // SAMI_SKOLT
    .{ .lang = 0x183B, .klid = 0x0000043B }, // SAMI_SOUTHERN_NORWAY
    .{ .lang = 0x1C3B, .klid = 0x0000083B }, // SAMI_SOUTHERN_SWEDEN
    .{ .lang = 0x044F, .klid = 0x00000409 }, // SANSKRIT
    .{ .lang = 0x181A, .klid = 0x0000081A }, // SERBIAN_LATIN_BOSNIA_HERZEGOVINA
    .{ .lang = 0x1C1A, .klid = 0x00000C1A }, // SERBIAN_CYRILLIC_BOSNIA_HERZEGOVINA
    .{ .lang = 0x0C0A, .klid = 0x0000040A }, // SPANISH_MODERN_SORT
    .{ .lang = 0x100A, .klid = 0x0000080A }, // SPANISH_GUATEMALA
    .{ .lang = 0x140A, .klid = 0x0000080A }, // SPANISH_COSTA_RICA
    .{ .lang = 0x180A, .klid = 0x0000080A }, // SPANISH_PANAMA
    .{ .lang = 0x1C0A, .klid = 0x0000080A }, // SPANISH_DOMINICAN_REPUBLIC
    .{ .lang = 0x200A, .klid = 0x0000080A }, // SPANISH_VENEZUELA
    .{ .lang = 0x240A, .klid = 0x0000080A }, // SPANISH_COLOMBIA
    .{ .lang = 0x280A, .klid = 0x0000080A }, // SPANISH_PERU
    .{ .lang = 0x2C0A, .klid = 0x0000080A }, // SPANISH_ARGENTINA
    .{ .lang = 0x300A, .klid = 0x0000080A }, // SPANISH_ECUADOR
    .{ .lang = 0x340A, .klid = 0x0000080A }, // SPANISH_CHILE
    .{ .lang = 0x380A, .klid = 0x0000080A }, // SPANISH_URUGUAY
    .{ .lang = 0x3C0A, .klid = 0x0000080A }, // SPANISH_PARAGUAY
    .{ .lang = 0x400A, .klid = 0x0000080A }, // SPANISH_BOLIVIA
    .{ .lang = 0x440A, .klid = 0x0000080A }, // SPANISH_EL_SALVADOR
    .{ .lang = 0x480A, .klid = 0x0000080A }, // SPANISH_HONDURAS
    .{ .lang = 0x4C0A, .klid = 0x0000080A }, // SPANISH_NICARAGUA
    .{ .lang = 0x500A, .klid = 0x0000080A }, // SPANISH_PUERTO_RICO
    .{ .lang = 0x0441, .klid = 0x00000409 }, // SWAHILI
    .{ .lang = 0x081D, .klid = 0x0000041D }, // SWEDISH_FINLAND
    .{ .lang = 0x045A, .klid = 0x00000409 }, // SYRIAC
    .{ .lang = 0x0449, .klid = 0x00000409 }, // TAMIL
    .{ .lang = 0x044A, .klid = 0x00000409 }, // TELUGU
    .{ .lang = 0x0432, .klid = 0x00000409 }, // TSWANA
    .{ .lang = 0x0420, .klid = 0x00000401 }, // URDU
    .{ .lang = 0x0443, .klid = 0x00000409 }, // UZBEK_LATIN
    .{ .lang = 0x042A, .klid = 0x00000409 }, // VIETNAMESE
    .{ .lang = 0x0434, .klid = 0x00000409 }, // XHOSA
};

/// HKL high word 0xF000 | Layout Id -> KLID.
const layout_ids = [_]struct { id: u16, klid: u32 }{
    .{ .id = 0x0028, .klid = 0x00010401 }, .{ .id = 0x0004, .klid = 0x00010402 },
    .{ .id = 0x0005, .klid = 0x00010405 }, .{ .id = 0x0012, .klid = 0x00010407 },
    .{ .id = 0x0016, .klid = 0x00010408 }, .{ .id = 0x0002, .klid = 0x00010409 },
    .{ .id = 0x0086, .klid = 0x0001040A }, .{ .id = 0x0006, .klid = 0x0001040E },
    .{ .id = 0x0003, .klid = 0x00010410 }, .{ .id = 0x0007, .klid = 0x00010415 },
    .{ .id = 0x001D, .klid = 0x00010416 }, .{ .id = 0x0008, .klid = 0x00010419 },
    .{ .id = 0x0013, .klid = 0x0001041B }, .{ .id = 0x0021, .klid = 0x0001041E },
    .{ .id = 0x0014, .klid = 0x0001041F }, .{ .id = 0x0015, .klid = 0x00010426 },
    .{ .id = 0x0027, .klid = 0x00010427 }, .{ .id = 0x0025, .klid = 0x0001042B },
    .{ .id = 0x000C, .klid = 0x00010439 }, .{ .id = 0x002B, .klid = 0x0001043A },
    .{ .id = 0x002C, .klid = 0x0001043B }, .{ .id = 0x002A, .klid = 0x00010445 },
    .{ .id = 0x000E, .klid = 0x0001045A }, .{ .id = 0x000D, .klid = 0x00010465 },
    .{ .id = 0x001E, .klid = 0x0001080C }, .{ .id = 0x002D, .klid = 0x0001083B },
    .{ .id = 0x0020, .klid = 0x00011009 }, .{ .id = 0x0026, .klid = 0x00011809 },
    .{ .id = 0x0029, .klid = 0x00020401 }, .{ .id = 0x000A, .klid = 0x00020405 },
    .{ .id = 0x0018, .klid = 0x00020408 }, .{ .id = 0x0001, .klid = 0x00020409 },
    .{ .id = 0x0022, .klid = 0x0002041E }, .{ .id = 0x002E, .klid = 0x0002083B },
    .{ .id = 0x0017, .klid = 0x00030408 }, .{ .id = 0x001A, .klid = 0x00030409 },
    .{ .id = 0x0023, .klid = 0x0003041E }, .{ .id = 0x0011, .klid = 0x00040408 },
    .{ .id = 0x001B, .klid = 0x00040409 }, .{ .id = 0x001C, .klid = 0x19360409 },
    .{ .id = 0x0019, .klid = 0x00050408 }, .{ .id = 0x000B, .klid = 0x00050409 },
    .{ .id = 0x001F, .klid = 0x00060408 }, .{ .id = 0x00C0, .klid = 0xA000040C },
    .{ .id = 0x00C0, .klid = 0xB0000407 },
};

/// Exact KLID match, else what the HKL high word names (MS-RDPBCGR 2.2.1.3.2): 0xF000 |
/// Layout Id, an IME (0xExxx) or a language ID; last the low word's default layout.
pub fn fromKlid(klid: u32) ?Xkb {
    for (table) |e| if (e.klid == klid) return e.xkb;
    const hi: u16 = @intCast(klid >> 16);
    const lang: u16 = @truncate(klid);
    switch (hi >> 12) {
        0xF => if (fromLayoutId(hi & 0x0FFF, lang)) |x| return x,
        0xE => {},
        // Variant KLIDs (0x0001xxxx) have no sublanguage bits (10..15).
        else => if (hi >> 10 != 0) {
            if (fromLanguage(hi)) |x| return x;
        },
    }
    return fromLanguage(lang);
}

fn fromLanguage(lang: u16) ?Xkb {
    if (lang == 0) return null;
    for (table) |e| if (e.klid == lang) return e.xkb;
    for (lang_defaults) |d| if (d.lang == lang) return exactOrLanguage(d.klid);
    return null;
}

/// Of two layouts with the same Layout Id, the one for the HKL's language.
fn fromLayoutId(id: u16, lang: u16) ?Xkb {
    var found: ?u32 = null;
    for (layout_ids) |l| {
        if (l.id != id) continue;
        if (found == null or l.klid & 0xFFFF == lang) found = l.klid;
    }
    return exactOrLanguage(found orelse return null);
}

fn exactOrLanguage(klid: u32) ?Xkb {
    for (table) |e| if (e.klid == klid) return e.xkb;
    const lang = klid & 0xFFFF;
    for (table) |e| if (e.klid == lang) return e.xkb;
    return null;
}

/// Hyprland input:kb_*; layout and variant may be comma-separated lists.
pub const Session = struct {
    rules: []const u8 = "",
    model: []const u8 = "",
    layout: []const u8 = "",
    variant: []const u8 = "",
    options: []const u8 = "",
};

pub const Choice = struct {
    rules: []const u8,
    model: []const u8,
    layout: []const u8,
    variant: []const u8,
    options: []const u8,
    from_client: bool,
};

pub fn choose(klid: u32, session: Session) Choice {
    const base: Choice = .{
        .rules = session.rules,
        .model = session.model,
        .layout = session.layout,
        .variant = session.variant,
        .options = session.options,
        .from_client = false,
    };
    const x = fromKlid(klid) orelse return base;
    var variant = x.variant;
    if (variant.len == 0) {
        // Same layout as one the session uses: keep the session's variant.
        var ls = std.mem.splitScalar(u8, session.layout, ',');
        var vs = std.mem.splitScalar(u8, session.variant, ',');
        while (ls.next()) |l| {
            const v = vs.next() orelse "";
            if (std.mem.eql(u8, std.mem.trim(u8, l, " "), x.layout)) {
                variant = std.mem.trim(u8, v, " ");
                break;
            }
        }
    }
    return .{
        .rules = session.rules,
        .model = session.model,
        .layout = x.layout,
        .variant = variant,
        // Group-switching options are harmless with a single layout.
        .options = session.options,
        .from_client = true,
    };
}

test "klid lookup" {
    try std.testing.expectEqualStrings("fr", fromKlid(0x0000040C).?.layout);
    try std.testing.expectEqualStrings("intl", fromKlid(0x00020409).?.variant);
    // HKL: 0xF000 | Layout Id 0002 is US-Dvorak, whatever the language.
    try std.testing.expectEqualStrings("dvorak", fromKlid(0xF0020407).?.variant);
    // HKL with the layout's language ID in the high word.
    try std.testing.expectEqualStrings("es", fromKlid(0x040A0C0A).?.layout);
    try std.testing.expect(fromKlid(0x00000000) == null);
}

test "client layout wins, session options and variant are kept" {
    const session: Session = .{ .layout = "fr,us", .variant = "oss,", .options = "ctrl:nocaps", .model = "pc105" };
    const fr = choose(0x0000040C, session);
    try std.testing.expectEqualStrings("fr", fr.layout);
    try std.testing.expectEqualStrings("oss", fr.variant);
    try std.testing.expectEqualStrings("ctrl:nocaps", fr.options);
    try std.testing.expect(fr.from_client);

    const us = choose(0x00000409, session);
    try std.testing.expectEqualStrings("us", us.layout);
    try std.testing.expectEqualStrings("", us.variant);

    const dvorak = choose(0x00010409, session);
    try std.testing.expectEqualStrings("dvorak", dvorak.variant);

    const unknown = choose(0x00000999, session);
    try std.testing.expectEqualStrings("fr,us", unknown.layout);
    try std.testing.expect(!unknown.from_client);
}

test "every table entry compiles with the system XKB data" {
    const kb = @import("keyboard.zig");
    for (table) |e| {
        var l: [32:0]u8 = @splat(0);
        var v: [32:0]u8 = @splat(0);
        @memcpy(l[0..e.xkb.layout.len], e.xkb.layout);
        @memcpy(v[0..e.xkb.variant.len], e.xkb.variant);
        var km = kb.Keymap.fromNames(.{
            .layout = l[0..e.xkb.layout.len :0],
            .variant = v[0..e.xkb.variant.len :0],
        }) catch |err| {
            std.debug.print("klid 0x{x:0>8} {s}({s}): {t}\n", .{ e.klid, e.xkb.layout, e.xkb.variant, err });
            return err;
        };
        km.deinit();
    }
}
