//! Embedded clean-room Diceware word list and external EFF word list file loader.

use crate::error::{Result, RustPassError};
use std::path::Path;

/// Built-in 512-word curated high-distinctiveness English passphrase vocabulary (9 bits/word
/// offline fallback; external `eff_large.wordlist` with 7,776 words = 12.925 bits/word is loaded
/// automatically when `--wordlist` or system wordlists are available).
pub const EMBEDDED_WORDLIST: &[&str] = &[
    "abacus", "abbey", "ablaze", "aboard", "abrupt", "absent", "absorb", "accent", "accept",
    "access", "accord", "acorn", "acoustic", "acquire", "acrobat", "action", "active", "actual",
    "adapt", "admiral", "admire", "admit", "adobe", "adopt", "adrift", "advance", "advice",
    "aerial", "affair", "affirm", "afford", "afield", "afloat", "agenda", "agile", "airbag",
    "airlock", "airport", "airship", "alarm", "album", "alchemy", "alcove", "alert", "algae",
    "alibi", "align", "alkali", "allergy", "almanac", "almond", "alpine", "altitude", "alumni",
    "amaze", "amber", "ambush", "amend", "amidst", "amnesty", "amount", "amulet", "analog",
    "anchor", "ancient", "android", "anemone", "angora", "animal", "ankle", "annex", "annual",
    "anode", "answer", "antenna", "anthem", "antler", "anvil", "apache", "apex", "apology",
    "apparel", "appeal", "apple", "apply", "apricot", "apron", "aquatic", "arcade", "archer",
    "archive", "arctic", "ardent", "arena", "argon", "argyle", "armada", "armory", "aroma",
    "around", "arrow", "artery", "artful", "artist", "ascend", "ascent", "ashamed", "ashore",
    "asleep", "aspect", "aspen", "asphalt", "aspire", "assault", "asset", "assign", "assist",
    "assume", "assure", "astound", "astral", "athlete", "atlas", "atom", "atrium", "attach",
    "attain", "attempt", "attend", "attic", "attire", "august", "aurora", "author", "autumn",
    "avatar", "avenge", "avenue", "aviator", "avocado", "awake", "award", "awhile", "awning",
    "axiom", "azimuth", "azure", "baboon", "backer", "backup", "bacon", "badge", "badger",
    "baffle", "bagel", "bagpipe", "bakery", "balance", "balcony", "ballad", "ballet", "balloon",
    "ballot", "bamboo", "banana", "bandit", "banjo", "banner", "banquet", "banyan", "baobab",
    "barber", "barcode", "bargain", "barge", "barley", "baron", "barrel", "barrier", "basalt",
    "basket", "bassoon", "bastion", "battery", "beacon", "beaker", "beanie", "beaver", "beckon",
    "bedrock", "beehive", "beetle", "begonia", "behold", "belfry", "belief", "bellow", "velvet",
    "beneath", "benefit", "beret", "berry", "beside", "bestow", "betray", "beyond", "bicycle",
    "bighorn", "billet", "binary", "binder", "biology", "biopsy", "biplane", "birch", "biscuit",
    "bishop", "bison", "bistro", "bitter", "bizarre", "bladder", "blanket", "blazer", "bleach",
    "blend", "blimp", "blinker", "bliss", "blizzard", "blossom", "blouse", "bobcat", "bobsled",
    "bodice", "boiler", "bolster", "bonfire", "bonnet", "bonsai", "bonus", "booklet", "booster",
    "border", "borough", "botany", "bottle", "boulder", "bounce", "bounty", "bouquet", "bourbon",
    "bowline", "boxcar", "bracket", "braid", "bramble", "branch", "bravery", "brazier", "breach",
    "breeze", "brewery", "briar", "bridge", "bridle", "brigade", "bright", "brim", "brisket",
    "bristle", "bronze", "brooch", "brook", "broom", "browser", "bruise", "brunch", "brush",
    "bubble", "bucket", "buckle", "budget", "buffalo", "buffer", "buffet", "buggy", "bugle",
    "builder", "bulb", "bullion", "bulwark", "bumble", "bumper", "bundle", "bunker", "burlap",
    "burner", "burnish", "burrow", "bushel", "butler", "butter", "button", "buzzard", "cabana",
    "cabbage", "cabin", "cabinet", "cable", "cacao", "cache", "cactus", "caddie", "cadence",
    "cadet", "cairn", "calcite", "calcium", "caliber", "calico", "callus", "calmly", "calorie",
    "calypso", "camel", "cameo", "camera", "camper", "campus", "canal", "canary", "cancel",
    "candid", "candle", "canine", "canister", "cannon", "canopy", "canteen", "canter", "canvas",
    "canyon", "capable", "capitol", "caprice", "capsule", "captain", "caption", "captive",
    "capture", "carafe", "caramel", "carat", "caravan", "carbon", "cardigan", "career", "cargo",
    "caribou", "carol", "carpet", "carrot", "cartel", "carton", "carve", "cascade", "cashew",
    "cashier", "casing", "castle", "casual", "catalog", "catchy", "catfish", "cathode", "catnip",
    "cattle", "caucus", "cauldron", "caution", "cavalry", "cavern", "caviar", "cedar", "ceiling",
    "celery", "cellar", "cement", "censer", "census", "center", "ceramic", "cereal", "cerise",
    "certain", "chalet", "chalice", "chalk", "chamber", "chamois", "chance", "change", "channel",
    "chant", "chapel", "chapter", "charcoal", "charge", "chariot", "charity", "charter", "chassis",
    "chateau", "cheddar", "cheetah", "chemist", "cherry", "cherub", "chess", "chestnut", "chevron",
    "chicken", "chicory", "chimney", "chisel", "chlorine", "choice", "chorale", "chorus", "chrome",
    "chuckle", "cinder", "cinema", "cipher", "circle", "circuit", "circus", "cistern", "citadel",
    "citizen", "citron", "citrus", "civic", "claim", "clamor", "clarion", "clarity", "classic",
    "clatter", "clause", "clavicle", "cleanse", "clear", "cleaver", "cleft", "climate", "climax",
    "clinic", "clipper", "cloak", "clock", "cloister", "closet", "clover", "cluster", "clutch",
    "coaster", "cobalt", "cobbler", "cobra", "cocoon", "codex", "coffee", "cogent", "cognac",
    "cohort", "colander", "collage", "collar", "collect", "college", "collide", "collie", "colony",
    "column", "combat", "combine", "comedy", "comet", "comfort", "command", "comment", "commit",
    "common", "commune", "compact", "company", "compare", "compass", "compile", "complex",
    "compose", "compost", "compute", "comrade", "concave", "conceal", "concept", "concert",
    "concise", "concord",
];

/// Parses an external word list file (supports EFF tab/space-separated `11111\tword` lines as well
/// as plain one-word-per-line files).
pub fn load_wordlist_file(path: &Path) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)?;
    let words = parse_wordlist_str(&raw);
    if words.len() < 32 {
        return Err(RustPassError::InvalidArgument(format!(
            "Wordlist '{}' must contain at least 32 distinct words (got {})",
            path.display(),
            words.len()
        )));
    }
    Ok(words)
}

/// Parses raw wordlist text into deduplicated words.
#[must_use]
pub fn parse_wordlist_str(raw: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // EFF Diceware format: "11111\tabacus" or "11111 abacus"
        let token = match trimmed.split_once(['\t', ' ']) {
            Some((prefix, rest)) if prefix.chars().all(|c| c.is_ascii_digit()) => rest.trim(),
            _ => trimmed,
        };
        // Deduplicate: index-based entropy math assumes distinct words.
        if !token.is_empty() && seen.insert(token) {
            words.push(token.to_string());
        }
    }
    words
}

/// The official EFF large wordlist (7 776 words, dice-indexed), embedded so strong
/// Diceware passphrases (12.9 bits/word) work out of the box with no host install.
pub const EFF_LARGE_WORDLIST_RAW: &str = include_str!("eff_large.wordlist");

/// Resolves the best available Diceware word list:
/// 1. Explicit `custom_path` if supplied,
/// 2. Standard host EFF Large Wordlist (`C:\Program Files\KeePassXC\share\wordlists\eff_large.wordlist`
///    or `/usr/share/keepassxc/wordlists/eff_large.wordlist`) if readable,
/// 3. Embedded official EFF large wordlist (7 776 words),
/// 4. Built-in compact `EMBEDDED_WORDLIST`.
pub fn resolve_wordlist(custom_path: Option<&Path>) -> Result<Vec<String>> {
    if let Some(p) = custom_path {
        return load_wordlist_file(p);
    }

    let system_candidates = [
        r"C:\Program Files\KeePassXC\share\wordlists\eff_large.wordlist",
        "/usr/share/keepassxc/wordlists/eff_large.wordlist",
        "/usr/local/share/keepassxc/wordlists/eff_large.wordlist",
    ];
    for candidate in system_candidates {
        let p = Path::new(candidate);
        if p.is_file()
            && let Ok(list) = load_wordlist_file(p)
        {
            return Ok(list);
        }
    }

    // Embedded official EFF large list: no host install needed.
    let eff = parse_wordlist_str(EFF_LARGE_WORDLIST_RAW);
    if eff.len() >= 32 {
        return Ok(eff);
    }

    Ok(EMBEDDED_WORDLIST.iter().map(|&w| w.to_string()).collect())
}
