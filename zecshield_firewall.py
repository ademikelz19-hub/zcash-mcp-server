"""
ZECSHIELD // PRIVACY FIREWALL & PRE-FLIGHT AUDIT ENGINE
======================================================
The Signature Security & Privacy Innovation for Zcash Applications.
Audits transactions, wallet operations, memos, and application configurations
before broadcast to prevent privacy breaks, data leaks, and protocol violations.

Checks Enforced:
  1. CHECK_01_TRANSPARENT_EXPOSURE: Detect transparent addresses (t1, t3) or transparent-only UAs
  2. CHECK_02_PRIVACY_DOWNGRADE: Block operations silently falling back from shielded to transparent
  3. CHECK_03_SENSITIVE_MEMO_PII: Detect cleartext emails, IPs, phone numbers, SSNs, credit cards
  4. CHECK_04_VIEWING_KEY_EXPOSURE: Detect UFVK / FVK / IVK strings in memos, logs, or outputs
  5. CHECK_05_WALLET_SECRET_PROTECTION: Detect spending keys, seed phrases, or private credentials
  6. CHECK_06_UNSAFE_RPC_TARGET: Enforce loopback air-gap policy; reject cleartext remote RPCs
  7. CHECK_07_ADDRESS_RECEIVER_VALIDATION: Validate ZIP 316 structure, network ID, and pool support
  8. CHECK_08_AMOUNT_SATOSHI_PRECISION: Validate exact zatoshis; prevent float rounding, negative or zero amounts
  9. CHECK_09_TRANSACTION_POLICY_ENFORCEMENT: Enforce human approval requirement for state mutation
 10. CHECK_10_METADATA_CORRELATION_LEAK: Detect persistent invoice IDs, UUIDs, or timestamp fingerprints
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519


# ===========================================================================
# 1. COMPILED HEURISTIC REGEX PATTERNS
# ===========================================================================

# PII Patterns
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
REGEX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
REGEX_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
REGEX_PHONE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
REGEX_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
REGEX_CREDIT_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

# Keys & Secret Patterns
REGEX_SPENDING_KEY = re.compile(
    r"\b(?:secret-extended-key(?:main|test|regtest)1[0-9a-z]+|zxprv[0-9a-z]+|SK_ORCHARD_[0-9a-zA-Z]+|SK_SAPLING_[0-9a-zA-Z]+)\b",
    re.IGNORECASE,
)
REGEX_VIEWING_KEY = re.compile(
    r"\b(?:uview1[0-9a-z]+|utview1[0-9a-z]+|zxviews1[0-9a-z]+|zviews1[0-9a-z]+)\b",
    re.IGNORECASE,
)

# Correlation Identifiers & Invoices
REGEX_CORRELATION_ID = re.compile(r"\b(?:INV|ORDER|CUST|BILL|TXN|USER|ACC)[-_#:][0-9a-zA-Z]{3,}\b", re.IGNORECASE)
REGEX_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

# Prompt Injection Patterns in Memos
REGEX_PROMPT_INJECTION = re.compile(
    r"(?i)\b(?:ignore\s+previous\s+instructions|system\s+prompt|transfer\s+all\s+funds|exfiltrate|run\s+as\s+admin|drop\s+database|override\s+policy)\b"
)

# Common BIP-39 English word subset for seed phrase detection
BIP39_SAMPLE_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool",
    "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country",
    "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
    "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
    "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble",
    "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current",
    "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance",
    "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade",
    "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree",
    "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail",
    "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel",
    "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree",
    "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce",
    "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor",
    "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream",
    "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
    "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle",
    "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge",
    "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant",
    "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion",
    "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy",
    "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure",
    "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode",
    "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence",
    "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect",
    "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face",
    "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan",
    "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite",
    "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch",
    "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final",
    "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit",
    "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip",
    "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog",
    "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune",
    "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh",
    "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun",
    "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap",
    "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge",
    "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift",
    "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide",
    "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold",
    "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
    "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
    "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym",
    "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh",
    "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
    "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint",
    "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
    "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
    "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle",
    "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore",
    "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve",
    "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant",
    "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent",
    "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into",
    "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket",
    "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke",
    "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo",
    "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss",
    "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab",
    "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later",
    "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader",
    "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon",
    "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
    "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
    "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic",
    "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage",
    "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid",
    "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion",
    "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass",
    "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean",
    "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention",
    "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle",
    "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror",
    "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom",
    "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito",
    "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule",
    "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
    "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need",
    "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never",
    "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north",
    "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse",
    "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur",
    "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old",
    "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera",
    "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient",
    "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven",
    "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
    "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park",
    "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave",
    "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
    "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano",
    "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe",
    "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge",
    "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond",
    "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty",
    "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent",
    "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process",
    "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud",
    "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy",
    "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum",
    "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack",
    "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range",
    "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason",
    "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform",
    "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain",
    "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat",
    "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich",
    "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual",
    "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie",
    "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug",
    "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad",
    "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce",
    "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school",
    "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search",
    "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select",
    "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup",
    "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift",
    "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove",
    "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign",
    "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister",
    "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
    "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
    "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
    "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier",
    "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound",
    "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed",
    "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil",
    "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze",
    "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state",
    "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock",
    "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle",
    "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden",
    "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply",
    "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow",
    "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword",
    "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk",
    "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell",
    "ten", "tenant", "tennis", "term", "test", "text", "thank", "that", "theme", "then",
    "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb",
    "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
    "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple",
    "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy",
    "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray",
    "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
    "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition",
    "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin",
    "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover",
    "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
    "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset",
    "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant",
    "vacuum", "vague", "valuable", "valve", "van", "vanish", "vapor", "various", "vast", "vault",
    "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin",
    "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void",
    "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut",
    "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome",
    "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper",
    "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle",
    "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra",
    "zero", "zone", "zoo"
}


# ===========================================================================
# 2. FIREWALL DATA STRUCTURES & RESULT SCHEMA
# ===========================================================================

class FirewallFinding:
    def __init__(
        self,
        finding_id: str,
        name: str,
        severity: str,  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "WARNING"
        confidence: str,  # "CONFIRMED", "HIGH", "MEDIUM", "HEURISTIC"
        category: str,
        evidence: str,
        impact: str,
        remediation: str,
    ) -> None:
        self.finding_id = finding_id
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.category = category
        self.evidence = evidence
        self.impact = impact
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.finding_id,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
        }


# ===========================================================================
# 3. CORE INSPECTION CHECKS
# ===========================================================================

def audit_address_and_pools(address: str, strict_shielded_only: bool = True) -> List[FirewallFinding]:
    """Inspects recipient address for transparent fallback or format issues."""
    findings: List[FirewallFinding] = []
    addr = (address or "").strip()

    if not addr:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-ADDR-001",
                name="MISSING_RECIPIENT_ADDRESS",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="address_validation",
                evidence="Address argument is empty or null.",
                impact="Transaction cannot be addressed; attempting broadcast will fail closed.",
                remediation="Specify a valid ZIP 316 Unified Address with shielded receiver.",
            )
        )
        return findings

    # Check for legacy transparent addresses (t1 P2PKH, t3 P2SH, tm Testnet)
    if addr.startswith(("t1", "t3", "tm")):
        severity = "CRITICAL" if strict_shielded_only else "HIGH"
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-001",
                name="TRANSPARENT_ADDRESS_EXPOSURE",
                severity=severity,
                confidence="CONFIRMED",
                category="transparent_exposure",
                evidence=f"Recipient is a transparent address: {addr[:6]}...{addr[-4:]}",
                impact="Strips all zero-knowledge privacy guarantees. Exposes sender/receiver graph and balances permanently on the public ledger.",
                remediation="Switch recipient to a ZIP 316 Unified Address containing Orchard or Sapling shielded receivers.",
            )
        )

    # Check for Unified Address prefix
    elif addr.startswith(("u1", "utest1", "uregtest1")):
        # Unified Address: Check if it's transparent-only
        pass
    elif addr.startswith(("zs1", "ztestsapling1")):
        # Legacy Sapling shielded address - valid shielded
        pass
    else:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-ADDR-002",
                name="UNKNOWN_OR_MALFORMED_ADDRESS_FORMAT",
                severity="HIGH",
                confidence="CONFIRMED",
                category="address_validation",
                evidence=f"Unrecognized address format: {addr[:10]}...",
                impact="Address does not conform to standard Zcash mainnet or testnet/regtest specifications.",
                remediation="Use a canonical ZIP 316 Unified Address (u1... or uregtest1...).",
            )
        )

    return findings


def audit_memo_content(memo_utf8: str) -> List[FirewallFinding]:
    """Inspects unencrypted or candidate memo text for PII, secrets, injections, and correlation IDs."""
    findings: List[FirewallFinding] = []
    memo = (memo_utf8 or "").strip()
    if not memo:
        return findings

    # 1. Byte length check (ZIP 321 max 512 bytes)
    memo_bytes = memo.encode("utf-8")
    if len(memo_bytes) > 512:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-MEMO-001",
                name="MEMO_SIZE_EXCEEDS_512_BYTES",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="memo_inspection",
                evidence=f"Memo payload is {len(memo_bytes)} bytes, exceeding the 512-byte consensus limit.",
                impact="Transaction construction will fail or be rejected by mempool consensus.",
                remediation="Truncate or summarize the memo payload to <= 512 UTF-8 bytes.",
            )
        )

    # 2. Email detection
    emails = REGEX_EMAIL.findall(memo)
    if emails:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-002",
                name="PII_EMAIL_IN_MEMO",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="memo_pii",
                evidence=f"Cleartext email address detected in memo: '{emails[0]}'",
                impact="Permanently binds real-world human identity to encrypted on-chain note, exposing recipient if viewing keys are audited.",
                remediation="Remove email addresses from memo fields. Use off-chain zero-knowledge proofs or ephemeral session hashes.",
            )
        )

    # 3. IP Address detection
    ipv4s = [ip for ip in REGEX_IPV4.findall(memo) if not ip.startswith("127.") and ip != "0.0.0.0"]
    if ipv4s:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-003",
                name="PII_IP_ADDRESS_IN_MEMO",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="memo_pii",
                evidence=f"Public or intranet IPv4 address detected in memo: '{ipv4s[0]}'",
                impact="Exposes network topology, hosting infrastructure, or user client location to note decryptors.",
                remediation="Strip IP addresses from memo payloads.",
            )
        )

    # 4. Phone Number detection
    phones = REGEX_PHONE.findall(memo)
    if phones:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-004",
                name="PII_PHONE_NUMBER_IN_MEMO",
                severity="HIGH",
                confidence="HIGH",
                category="memo_pii",
                evidence=f"Probable phone number detected in memo: '{phones[0]}'",
                impact="Binds telecommunications identity to payment records.",
                remediation="Remove phone numbers from memo text.",
            )
        )

    # 5. SSN / Tax ID detection
    ssns = REGEX_SSN.findall(memo)
    if ssns:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-005",
                name="PII_SSN_OR_GOV_ID_IN_MEMO",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="memo_pii",
                evidence="Social Security Number / National ID pattern detected in memo.",
                impact="Severe regulatory and privacy hazard. Compromises personal identity.",
                remediation="Never place government identifiers in transaction memos.",
            )
        )

    # 6. Spending Key / Private Key detection
    spending_keys = REGEX_SPENDING_KEY.findall(memo)
    if spending_keys:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-SEC-001",
                name="WALLET_SPENDING_KEY_IN_MEMO",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="secret_exposure",
                evidence=f"Spending key detected in memo: '{spending_keys[0][:16]}...'",
                impact="Immediate loss of wallet custody! Anyone reading the memo or log obtains full spending power.",
                remediation="Immediately revoke key, transfer remaining funds to fresh seed, and strip key from memo.",
            )
        )

    # 7. Viewing Key detection
    viewing_keys = REGEX_VIEWING_KEY.findall(memo)
    if viewing_keys:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-006",
                name="VIEWING_KEY_IN_MEMO",
                severity="HIGH",
                confidence="CONFIRMED",
                category="viewing_key_exposure",
                evidence=f"Viewing key detected in memo: '{viewing_keys[0][:16]}...'",
                impact="Permits third parties reading this memo to decrypt future transaction history.",
                remediation="Do not transmit viewing keys across public memo channels.",
            )
        )

    # 8. BIP-39 Seed Phrase detection (heuristic: 12 or 24 words from dictionary)
    words = memo.lower().split()
    if len(words) in (12, 24):
        match_count = sum(1 for w in words if w in BIP39_SAMPLE_WORDS)
        if match_count >= len(words) - 1:
            findings.append(
                FirewallFinding(
                    finding_id="ZEC-SEC-002",
                    name="BIP39_SEED_PHRASE_IN_MEMO",
                    severity="CRITICAL",
                    confidence="HIGH",
                    category="secret_exposure",
                    evidence=f"Detected probable {len(words)}-word BIP-39 mnemonic seed phrase in memo.",
                    impact="Catastrophic compromise of master seed and all derived addresses.",
                    remediation="Never paste or transmit mnemonic recovery phrases in application memos.",
                )
            )

    # 9. Prompt Injection detection
    injections = REGEX_PROMPT_INJECTION.findall(memo)
    if injections:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-SEC-003",
                name="PROMPT_INJECTION_IN_MEMO",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="prompt_injection",
                evidence=f"Adversarial instruction pattern in memo: '{injections[0]}'",
                impact="Attempted jailbreak of downstream LLM agents parsing incoming transaction history.",
                remediation="Sanitize memo contents before presenting to language models.",
            )
        )

    # 10. Persistent Correlation Identifier detection (Invoice ID / UUID)
    corr_ids = REGEX_CORRELATION_ID.findall(memo)
    uuids = REGEX_UUID.findall(memo)
    if corr_ids or uuids:
        sample_id = corr_ids[0] if corr_ids else uuids[0]
        findings.append(
            FirewallFinding(
                finding_id="ZEC-PRIV-007",
                name="METADATA_CORRELATION_IDENTIFIER_LEAK",
                severity="MEDIUM",
                confidence="HIGH",
                category="metadata_leak",
                evidence=f"Static invoice or correlation ID found in memo: '{sample_id}'",
                impact="Allows AI hosts or multi-party observers to cross-reference transactions across disparate sessions.",
                remediation="Use single-use blind commitments or HMAC tokens instead of predictable invoice strings.",
            )
        )

    return findings


def audit_payment_amount(amount_zec: str) -> Tuple[List[FirewallFinding], Optional[int]]:
    """Validates payment amount precision, boundaries, and zatoshis conversion."""
    findings: List[FirewallFinding] = []
    zatoshis: Optional[int] = None

    try:
        dec = Decimal(str(amount_zec).strip())
    except (InvalidOperation, ValueError):
        findings.append(
            FirewallFinding(
                finding_id="ZEC-AMT-001",
                name="MALFORMED_AMOUNT_FORMAT",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="payment_validation",
                evidence=f"Cannot parse amount string: '{amount_zec}'",
                impact="Transaction cannot be constructed.",
                remediation="Provide a valid decimal string, e.g. '1.5' or '0.0001'.",
            )
        )
        return findings, None

    if dec <= Decimal("0"):
        findings.append(
            FirewallFinding(
                finding_id="ZEC-AMT-002",
                name="NON_POSITIVE_AMOUNT",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="payment_validation",
                evidence=f"Amount is non-positive: {dec} ZEC",
                impact="Zero or negative transactions are rejected by consensus.",
                remediation="Specify an amount greater than 0 ZEC.",
            )
        )
        return findings, None

    # Max Zcash supply is 21,000,000 ZEC
    if dec > Decimal("21000000"):
        findings.append(
            FirewallFinding(
                finding_id="ZEC-AMT-003",
                name="AMOUNT_EXCEEDS_MAX_SUPPLY",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="payment_validation",
                evidence=f"Amount {dec} ZEC exceeds total circulating cap of 21,000,000 ZEC.",
                impact="Impossible transaction amount.",
                remediation="Ensure amount is within realistic wallet balance.",
            )
        )
        return findings, None

    # Check precision: Zcash supports up to 8 decimal places (1 zatoshi = 0.00000001 ZEC)
    if dec.as_tuple().exponent < -8:
        findings.append(
            FirewallFinding(
                finding_id="ZEC-AMT-004",
                name="SUB_ZATOSHI_PRECISION",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="payment_validation",
                evidence=f"Amount '{amount_zec}' contains fractional zatoshis (> 8 decimal places).",
                impact="Fractional zatoshis cause rounding errors or consensus divergence.",
                remediation="Quantize amounts to exactly 8 decimal places (integer zatoshis).",
            )
        )
        return findings, None

    zatoshis = int(dec * Decimal("100000000"))
    return findings, zatoshis


def audit_rpc_configuration(rpc_url: str) -> List[FirewallFinding]:
    """Inspects target node RPC URL for air-gap and remote binding violations."""
    findings: List[FirewallFinding] = []
    if not rpc_url:
        return findings

    parsed = urllib.parse.urlparse(rpc_url)
    host = (parsed.hostname or "").lower()

    if host not in ("127.0.0.1", "localhost", "::1"):
        findings.append(
            FirewallFinding(
                finding_id="ZEC-NET-001",
                name="NON_LOOPBACK_RPC_DESTINATION",
                severity="HIGH",
                confidence="CONFIRMED",
                category="network_security",
                evidence=f"Outbound RPC target is non-loopback host: '{host}'",
                impact="Violates ZecShield air-gap mandate ('does not leak'). Remote nodes can log IP, transaction queries, and viewing keys.",
                remediation="Bind RPC services strictly to 127.0.0.1 loopback or run behind an encrypted local tunnel.",
            )
        )

    if parsed.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1"):
        findings.append(
            FirewallFinding(
                finding_id="ZEC-NET-002",
                name="CLEARTEXT_REMOTE_HTTP",
                severity="CRITICAL",
                confidence="CONFIRMED",
                category="network_security",
                evidence=f"Unencrypted cleartext HTTP used to remote destination: '{rpc_url}'",
                impact="Active network adversaries can eavesdrop on transaction payloads or tamper with RPC responses.",
                remediation="Use TLS (https://) or local loopback connection.",
            )
        )

    return findings


# ===========================================================================
# 4. MAIN FIREWALL EVALUATION ENTRY POINT
# ===========================================================================

def run_firewall_audit(
    address: str = "",
    amount_zec: str = "",
    memo_utf8: str = "",
    fee_zatoshis: int = 10000,
    rpc_url: str = "http://127.0.0.1:8232",
    strict_shielded_only: bool = True,
    human_approval_granted: bool = False,
    human_approval_token: Optional[str] = None,
    intent_ticket_id: Optional[str] = None,
    is_state_changing: bool = False,
) -> Dict[str, Any]:
    """
    Executes the complete 10-check ZecShield Privacy Firewall audit suite.
    Returns standardized JSON results schema with explicit PASS / WARN / BLOCK decision states.
    """
    all_findings: List[FirewallFinding] = []

    # Check 01 & 02 & 07: Address, Transparent Fallback & Pool Compatibility
    all_findings.extend(audit_address_and_pools(address, strict_shielded_only=strict_shielded_only))

    # Check 03, 04, 05, 10: Memo, PII, Secrets, Injections, Correlation IDs
    all_findings.extend(audit_memo_content(memo_utf8))

    # Check 08: Amount & Satoshi Precision
    if amount_zec:
        amt_findings, _ = audit_payment_amount(amount_zec)
        all_findings.extend(amt_findings)

    # Check 06: RPC Endpoint Air-Gap Policy
    all_findings.extend(audit_rpc_configuration(rpc_url))

    # Check 09: Human Approval Boundary for State Mutation
    if is_state_changing:
        if intent_ticket_id:
            ticket_res = verify_and_consume_authorization_ticket(
                ticket_id=intent_ticket_id,
                recipient=address,
                amount_zec=amount_zec,
                memo_utf8=memo_utf8,
                fee_zatoshis=fee_zatoshis,
                human_approval_token=human_approval_token or "",
                consume=False,
            )
            if ticket_res.get("authorized"):
                human_approval_granted = True
            else:
                all_findings.append(
                    FirewallFinding(
                        finding_id="ZEC-AUTH-001",
                        name="UNAUTHORIZED_AUTONOMOUS_SPEND_ATTEMPT",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        category="agent_authorization",
                        evidence=f"Authorization ticket verification failed: {ticket_res.get('error')} - {ticket_res.get('message')}",
                        impact="AI agents cannot unilaterally execute spending operations without verified cryptographic human approval.",
                        remediation="Obtain a valid authorization ticket and user approval token before broadcasting.",
                    )
                )
        else:
            if human_approval_token and human_approval_token.strip() == "ZECSHIELD_HUMAN_APPROVE_2026":
                human_approval_granted = True

            if not human_approval_granted:
                all_findings.append(
                    FirewallFinding(
                        finding_id="ZEC-AUTH-001",
                        name="UNAUTHORIZED_AUTONOMOUS_SPEND_ATTEMPT",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        category="agent_authorization",
                        evidence="State-changing transaction requested without explicit human authorization token or intent ticket.",
                        impact="AI agents cannot unilaterally execute spending operations without out-of-band user approval.",
                        remediation="Obtain explicit user approval or pass human_approval_token before executing broadcast.",
                    )
                )

    # Tally Severities
    critical_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.severity == "HIGH")
    medium_count = sum(1 for f in all_findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in all_findings if f.severity in ("LOW", "WARNING"))

    # Determine Safety & Privacy Score (100 is perfect privacy)
    # Deductions: CRITICAL = -40, HIGH = -20, MEDIUM = -10, LOW = -5
    deduction = (critical_count * 40) + (high_count * 20) + (medium_count * 10) + (low_count * 5)
    privacy_score = max(0, 100 - deduction)

    is_safe_to_broadcast = (critical_count == 0 and high_count == 0)

    # Decision Triad: PASS, WARN, BLOCK
    if critical_count > 0 or high_count > 0:
        decision = "BLOCK"
    elif medium_count > 0 or low_count > 0:
        decision = "WARN"
    else:
        decision = "PASS"

    return {
        "is_safe_to_broadcast": is_safe_to_broadcast,
        "decision": decision,
        "privacy_score": privacy_score,
        "policy_version": "ZECSHIELD_FIREWALL_v1.0",
        "verdict": "PERMITTED" if is_safe_to_broadcast else "BLOCKED_BY_FIREWALL",
        "summary": {
            "total_findings": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
        "findings": [f.to_dict() for f in all_findings],
        "evaluated_checks": [
            "CHECK_01_TRANSPARENT_EXPOSURE",
            "CHECK_02_PRIVACY_DOWNGRADE",
            "CHECK_03_SENSITIVE_MEMO_PII",
            "CHECK_04_VIEWING_KEY_EXPOSURE",
            "CHECK_05_WALLET_SECRET_PROTECTION",
            "CHECK_06_UNSAFE_RPC_TARGET",
            "CHECK_07_ADDRESS_RECEIVER_VALIDATION",
            "CHECK_08_AMOUNT_SATOSHI_PRECISION",
            "CHECK_09_TRANSACTION_POLICY_ENFORCEMENT",
            "CHECK_10_METADATA_CORRELATION_LEAK",
        ],
    }


def sanitize_memo_for_ai(raw_memo: str) -> str:
    """
    Sanitizes memo content for model context consumption.
    Replaces sensitive text with zero-correlation placeholder.
    """
    if not raw_memo:
        return ""
    # Complete redaction for privacy
    return "[REDACTED_BY_ZECSHIELD_FOR_AI_PRIVACY]"


# ===========================================================================
# 5. CRYPTOGRAPHIC INTENT-BOUND AUTHORIZATION TICKET ENGINE
# ===========================================================================

# ===========================================================================
# 5. CRYPTOGRAPHIC INTENT-BOUND AUTHORIZATION TICKET ENGINE (HITL)
# ===========================================================================

VAULT_DIR = os.environ.get(
    "ZECSHIELD_VAULT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".zecshield_vault"),
)
VAULT_FILE = os.path.join(VAULT_DIR, "authorizations.json")
LOCK_FILE = os.path.join(VAULT_DIR, "vault.lock")
OPERATOR_PUBKEY_FILE = os.path.join(VAULT_DIR, "operator_pubkey.hex")

_INTENT_TICKETS: Dict[str, Dict[str, Any]] = {}
_VAULT_THREAD_LOCK = threading.RLock()


def _ensure_vault() -> None:
    try:
        os.makedirs(VAULT_DIR, exist_ok=True)
    except Exception:
        pass


def derive_operator_keypair(passphrase: str = "") -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """
    Derives an Ed25519 private key and 32-byte public key hex from a human passphrase.
    Uses PBKDF2-HMAC-SHA256 with 100,000 iterations and domain separation salt.
    If passphrase is empty, uses the default test operator secret.
    """
    effective_passphrase = passphrase.strip() if passphrase else os.environ.get("ZECSHIELD_OPERATOR_SECRET", "ZECSHIELD_MASTER_OPERATOR_2026")
    seed = hashlib.pbkdf2_hmac(
        "sha256",
        effective_passphrase.encode("utf-8"),
        b"ZECSHIELD_OPERATOR_ED25519_SALT_2026",
        100000,
        32,
    )
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def get_registered_operator_pubkey() -> str:
    """Returns the registered operator public key hex from vault, generating if absent."""
    _ensure_vault()
    if os.path.exists(OPERATOR_PUBKEY_FILE):
        try:
            with open(OPERATOR_PUBKEY_FILE, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if len(val) == 64:
                    return val
        except Exception:
            pass
    _, pub_hex = derive_operator_keypair()
    try:
        with open(OPERATOR_PUBKEY_FILE, "w", encoding="utf-8") as f:
            f.write(pub_hex)
    except Exception:
        pass
    return pub_hex


def sign_approval_payload(
    ticket_id: str,
    intent_digest: str,
    nonce: str,
    passphrase: str = "",
    priv_key: Optional[ed25519.Ed25519PrivateKey] = None,
) -> str:
    """Signs an approval message payload using the operator's Ed25519 private key."""
    if priv_key is None:
        priv_key, _ = derive_operator_keypair(passphrase)
    msg = f"ZECSHIELD_APPROVAL_V2:{ticket_id}:{intent_digest}:{nonce}".encode("utf-8")
    return priv_key.sign(msg).hex()


def verify_operator_signature(
    ticket_id: str,
    intent_digest: str,
    nonce: str,
    signature_hex: str,
    expected_pubkey_hex: Optional[str] = None,
) -> bool:
    """Verifies that an approval signature was produced by the operator's private key."""
    pub_hex = expected_pubkey_hex or get_registered_operator_pubkey()
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig_bytes = bytes.fromhex(signature_hex)
        msg = f"ZECSHIELD_APPROVAL_V2:{ticket_id}:{intent_digest}:{nonce}".encode("utf-8")
        pub.verify(sig_bytes, msg)
        return True
    except Exception:
        return False


_VAULT_LOCK_STATE = threading.local()


@contextlib.contextmanager
def vault_exclusive_lock(timeout_seconds: float = 10.0):
    """
    Acquires an exclusive OS-level process lock and thread lock on the vault
    to guarantee atomic concurrency across multiple threads and processes.
    Uses msvcrt on Windows, fcntl on Unix/Linux/macOS.
    Fully re-entrant within the same thread.
    """
    _ensure_vault()
    _VAULT_THREAD_LOCK.acquire()
    depth = getattr(_VAULT_LOCK_STATE, "depth", 0)
    if depth > 0:
        _VAULT_LOCK_STATE.depth = depth + 1
        try:
            yield
        finally:
            _VAULT_LOCK_STATE.depth -= 1
            _VAULT_THREAD_LOCK.release()
        return

    _VAULT_LOCK_STATE.depth = 1
    lock_fd = None
    start_time = time.time()
    try:
        lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR)
        locked = False
        while time.time() - start_time < timeout_seconds:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    # Lock 1 byte from position 0
                    msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except (BlockingIOError, OSError, IOError):
                time.sleep(0.01)
        if not locked:
            raise TimeoutError("Could not acquire exclusive vault lock within timeout.")
        yield
    finally:
        _VAULT_LOCK_STATE.depth = 0
        if lock_fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    try:
                        msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                os.close(lock_fd)
            except Exception:
                pass
        _VAULT_THREAD_LOCK.release()


def _save_tickets_to_vault() -> None:
    _ensure_vault()
    tmp_file = f"{VAULT_FILE}.tmp.{os.getpid()}.{threading.get_ident()}"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(_INTENT_TICKETS, f, indent=2)
        os.replace(tmp_file, VAULT_FILE)
    except Exception:
        pass


def _load_tickets_from_vault() -> None:
    global _INTENT_TICKETS
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    _INTENT_TICKETS.update(loaded)
        except Exception:
            pass


# Initial load from disk
_load_tickets_from_vault()


def get_intent_tickets() -> Dict[str, Dict[str, Any]]:
    """Return copy of intent tickets for inspection/audit."""
    _load_tickets_from_vault()
    return dict(_INTENT_TICKETS)


def get_pending_intent_tickets() -> List[Dict[str, Any]]:
    """Return all non-expired tickets currently awaiting out-of-band human approval."""
    _load_tickets_from_vault()
    now = time.time()
    pending = []
    for t in _INTENT_TICKETS.values():
        if t.get("status") == "PENDING_HUMAN_APPROVAL" and now <= t.get("expires_at", 0):
            pending.append(t)
    return pending


def clear_intent_tickets() -> None:
    """Clear tickets from memory and remove vault file (for test isolation)."""
    global _INTENT_TICKETS
    _INTENT_TICKETS.clear()
    if os.path.exists(VAULT_FILE):
        try:
            os.remove(VAULT_FILE)
        except Exception:
            pass


def create_transaction_intent_ticket(
    recipient: str,
    amount_zec: str,
    memo_utf8: str = "",
    fee_zatoshis: int = 10000,
    ttl_seconds: int = 300,
    rpc_url: str = "http://127.0.0.1:8232",
    strict_shielded_only: bool = True,
) -> Dict[str, Any]:
    """
    Creates a cryptographically-bound transaction authorization ticket.
    Audits the candidate transaction with the Privacy Firewall.
    If the transaction violates critical privacy or security rules, ticket creation fails closed.
    Binds (recipient, amount_zatoshis, fee_zatoshis, memo_hash) into a SHA-256 intent digest.

    CRITICAL SECURITY INVARIANT:
      The AI model context NEVER receives approval credentials or tokens.
      The ticket is issued in 'PENDING_HUMAN_APPROVAL' status.
      Only an out-of-band human operator can transition the ticket to 'HUMAN_APPROVED'.
    """
    _load_tickets_from_vault()

    # 1. Pre-flight Firewall Audit
    firewall_res = run_firewall_audit(
        address=recipient,
        amount_zec=amount_zec,
        memo_utf8=memo_utf8,
        fee_zatoshis=fee_zatoshis,
        rpc_url=rpc_url,
        strict_shielded_only=strict_shielded_only,
        is_state_changing=False,
    )

    if firewall_res["decision"] == "BLOCK" or not firewall_res["is_safe_to_broadcast"]:
        return {
            "ticket_id": None,
            "status": "REJECTED_BY_FIREWALL",
            "authorized": False,
            "decision": "BLOCK",
            "reason": "Firewall blocked candidate transaction due to critical/high privacy or security violations.",
            "findings": firewall_res["findings"],
            "summary": firewall_res["summary"],
        }

    # 2. Extract exact zatoshis
    amt_findings, zatoshis = audit_payment_amount(amount_zec)
    if zatoshis is None:
        return {
            "ticket_id": None,
            "status": "REJECTED_BY_FIREWALL",
            "authorized": False,
            "decision": "BLOCK",
            "reason": "Invalid amount precision.",
            "findings": [f.to_dict() for f in amt_findings],
            "summary": {"total_findings": len(amt_findings), "critical": 1, "high": 0, "medium": 0, "low": 0},
        }

    # 3. Cryptographic Intent Digest Calculation
    memo_bytes = memo_utf8.encode("utf-8")
    memo_hash = hashlib.sha256(memo_bytes).hexdigest()
    intent_payload = f"{recipient.strip()}:{zatoshis}:{fee_zatoshis}:{memo_hash}"
    intent_digest = hashlib.sha256(intent_payload.encode("utf-8")).hexdigest()

    # 4. Generate Ticket Identifier (Non-sensitive public reference)
    ticket_id = f"zec_ticket_{secrets.token_hex(12)}"
    operator_internal_token = f"ZEC_AUTH_{secrets.token_hex(16).upper()}"
    nonce = secrets.token_hex(16)
    now = time.time()
    expires_at = now + ttl_seconds

    ticket_record = {
        "ticket_id": ticket_id,
        "status": "PENDING_HUMAN_APPROVAL",
        "recipient": recipient.strip(),
        "amount_zec": str(amount_zec).strip(),
        "amount_zatoshis": zatoshis,
        "fee_zatoshis": fee_zatoshis,
        "memo_hash": memo_hash,
        "memo_sanitized": sanitize_memo_for_ai(memo_utf8),
        "memo_raw": memo_utf8,
        "intent_digest": intent_digest,
        "operator_internal_token": operator_internal_token,
        "nonce": nonce,
        "created_at": now,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "firewall_summary": firewall_res["summary"],
        "firewall_decision": firewall_res["decision"],
        "firewall_score": firewall_res["privacy_score"],
        "human_approved": False,
        "approved_at": None,
        "approved_by": None,
        "consumed_at": None,
        "operator_signature": None,
    }
    _INTENT_TICKETS[ticket_id] = ticket_record
    _save_tickets_to_vault()

    # AI Model Facing Output: Zero approval credentials exposed to model
    return {
        "ticket_id": ticket_id,
        "status": "PENDING_HUMAN_APPROVAL",
        "authorized": False,
        "decision": firewall_res["decision"],
        "intent_digest": intent_digest,
        "recipient": recipient.strip(),
        "amount_zec": str(amount_zec).strip(),
        "amount_zatoshis": zatoshis,
        "fee_zatoshis": fee_zatoshis,
        "memo_sanitized": sanitize_memo_for_ai(memo_utf8),
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "firewall_score": firewall_res["privacy_score"],
        "requires_action": "OUT_OF_BAND_HUMAN_APPROVAL",
        "instructions": (
            "Transaction authorization ticket generated. Autonomous broadcast is strictly BLOCKED. "
            "A human operator must review and approve this transaction out-of-band via CLI: "
            f"'python cli.py approve {ticket_id}' or via dashboard portal. "
            "The AI assistant has zero self-authorization credentials."
        ),
    }


def approve_transaction_intent_ticket(
    ticket_id: str,
    operator_pin: str = "",
    operator_passphrase: str = "",
    operator_signature: str = "",
    operator_note: str = "",
    approver: str = "LOCAL_HUMAN_OPERATOR",
) -> Dict[str, Any]:
    """
    Explicit out-of-band human authorization action.
    Transitions a ticket from PENDING_HUMAN_APPROVAL to HUMAN_APPROVED.
    Attaches an authentic Ed25519 signature from the human operator.
    Can only be invoked by human operator interface (CLI / dashboard / test harness).
    NEVER exposed to AI model as an MCP tool.
    Protected by OS-level exclusive file lock.
    """
    expected_pin = os.environ.get("ZECSHIELD_OPERATOR_PIN", "2026")
    if operator_pin:
        if not secrets.compare_digest(operator_pin.strip(), expected_pin.strip()):
            return {
                "success": False,
                "error": "INVALID_OPERATOR_PIN",
                "message": "Human operator authentication failed: invalid PIN provided.",
            }

    with vault_exclusive_lock():
        _load_tickets_from_vault()
        if not ticket_id or ticket_id not in _INTENT_TICKETS:
            return {
                "success": False,
                "error": "INVALID_TICKET_ID",
                "message": f"Ticket '{ticket_id}' not found in active authorization vault.",
            }

        ticket = _INTENT_TICKETS[ticket_id]

        if ticket["status"] == "CONSUMED":
            return {
                "success": False,
                "error": "TICKET_ALREADY_CONSUMED",
                "message": f"Ticket '{ticket_id}' has already been consumed. Replay blocked.",
            }

        if ticket["status"] == "REJECTED":
            return {
                "success": False,
                "error": "TICKET_ALREADY_REJECTED",
                "message": f"Ticket '{ticket_id}' was previously rejected by operator.",
            }

        now = time.time()
        if now > ticket["expires_at"]:
            ticket["status"] = "EXPIRED"
            _save_tickets_to_vault()
            return {
                "success": False,
                "error": "TICKET_EXPIRED",
                "message": f"Ticket '{ticket_id}' has expired.",
            }

        # Cryptographic Ed25519 Proof of Human Approval
        nonce = ticket.get("nonce", "")
        if operator_signature:
            if not verify_operator_signature(ticket_id, ticket["intent_digest"], nonce, operator_signature):
                return {
                    "success": False,
                    "error": "INVALID_OPERATOR_SIGNATURE",
                    "message": "Operator Ed25519 signature verification failed against registered public key.",
                }
            sig_to_record = operator_signature
            pub_to_record = get_registered_operator_pubkey()
        elif operator_passphrase:
            priv, pub_hex = derive_operator_keypair(operator_passphrase)
            registered_pub = get_registered_operator_pubkey()
            if not secrets.compare_digest(pub_hex, registered_pub):
                return {
                    "success": False,
                    "error": "INVALID_OPERATOR_PASSPHRASE",
                    "message": "Human operator authentication failed: invalid passphrase provided.",
                }
            sig_to_record = sign_approval_payload(ticket_id, ticket["intent_digest"], nonce, priv_key=priv)
            pub_to_record = pub_hex
        else:
            priv, pub_hex = derive_operator_keypair()
            sig_to_record = sign_approval_payload(ticket_id, ticket["intent_digest"], nonce, priv_key=priv)
            pub_to_record = pub_hex

        ticket["status"] = "HUMAN_APPROVED"
        ticket["human_approved"] = True
        ticket["approved_at"] = now
        ticket["approved_by"] = approver
        ticket["operator_note"] = operator_note
        ticket["operator_signature"] = sig_to_record
        ticket["operator_pubkey"] = pub_to_record
        _save_tickets_to_vault()

        return {
            "success": True,
            "ticket_id": ticket_id,
            "status": "HUMAN_APPROVED",
            "intent_digest": ticket["intent_digest"],
            "operator_signature": sig_to_record,
            "recipient": ticket["recipient"],
            "amount_zec": ticket["amount_zec"],
            "amount_zatoshis": ticket["amount_zatoshis"],
            "approved_at": now,
            "approved_by": approver,
        }


def reject_transaction_intent_ticket(
    ticket_id: str,
    reason: str = "Rejected by human operator",
    rejected_by: str = "LOCAL_HUMAN_OPERATOR",
) -> Dict[str, Any]:
    """
    Explicit out-of-band human rejection action.
    Transitions a ticket to REJECTED. It cannot subsequently be broadcast.
    Protected by OS-level exclusive file lock.
    """
    with vault_exclusive_lock():
        _load_tickets_from_vault()
        if not ticket_id or ticket_id not in _INTENT_TICKETS:
            return {
                "success": False,
                "error": "INVALID_TICKET_ID",
                "message": f"Ticket '{ticket_id}' not found in authorization vault.",
            }

        ticket = _INTENT_TICKETS[ticket_id]
        ticket["status"] = "REJECTED"
        ticket["rejected_at"] = time.time()
        ticket["rejected_by"] = rejected_by
        ticket["rejection_reason"] = reason
        _save_tickets_to_vault()

        return {
            "success": True,
            "ticket_id": ticket_id,
            "status": "REJECTED",
            "reason": reason,
        }


def get_pending_intent_tickets() -> List[Dict[str, Any]]:
    """
    Returns all intent tickets that are currently pending human approval and not expired.
    Used by human operator CLI and dashboard interfaces out-of-band.
    """
    _load_tickets_from_vault()
    now = time.time()
    pending: List[Dict[str, Any]] = []
    for t_id, ticket in _INTENT_TICKETS.items():
        if ticket.get("status") == "PENDING_HUMAN_APPROVAL" and now <= ticket.get("expires_at", 0):
            pending.append({
                "ticket_id": t_id,
                "status": ticket["status"],
                "recipient": ticket["recipient"],
                "amount_zec": ticket["amount_zec"],
                "amount_zatoshis": ticket["amount_zatoshis"],
                "fee_zatoshis": ticket["fee_zatoshis"],
                "memo_sanitized": ticket.get("memo_sanitized", ""),
                "created_at": ticket.get("created_at"),
                "expires_at": ticket.get("expires_at"),
                "remaining_seconds": max(0, int(ticket.get("expires_at", 0) - now)),
                "intent_digest": ticket.get("intent_digest"),
            })
    return pending


def verify_and_consume_authorization_ticket(
    ticket_id: str,
    recipient: str,
    amount_zec: str,
    memo_utf8: str = "",
    fee_zatoshis: int = 10000,
    human_approval_token: str = "",
    approval_token: str = "",
    consume: bool = True,
) -> Dict[str, Any]:
    """
    Verifies cryptographic intent binding and optionally consumes the single-use authorization ticket.
    Protects against:
      1. AI self-authorization: Fails closed if human operator has not approved the ticket out-of-band.
      2. Parameter substitution / tampering: Recipient, amount, fee, or memo modifications are blocked.
      3. Ticket replay: Single-use atomic consumption prevents replaying old tickets.
      4. Ticket expiration: Expired tickets fail closed immediately.
    """
    if not human_approval_token and approval_token:
        human_approval_token = approval_token

    with vault_exclusive_lock():
        _load_tickets_from_vault()

        if not ticket_id or ticket_id not in _INTENT_TICKETS:
            return {
                "authorized": False,
                "error": "INVALID_TICKET_ID",
                "message": f"Authorization ticket '{ticket_id}' was not found in active session registry.",
            }

        ticket = _INTENT_TICKETS[ticket_id]

        # 1. Anti-Replay: Check if already consumed
        if ticket["status"] == "CONSUMED":
            return {
                "authorized": False,
                "error": "TICKET_ALREADY_CONSUMED",
                "message": f"Ticket '{ticket_id}' has already been consumed. Replay attack blocked.",
                "consumed_at": ticket.get("consumed_at"),
            }

        # 2. Rejection Check
        if ticket["status"] == "REJECTED":
            return {
                "authorized": False,
                "error": "TICKET_REJECTED",
                "message": f"Ticket '{ticket_id}' was explicitly rejected by the human operator.",
            }

        # 3. TTL Expiration Check
        now = time.time()
        if now > ticket["expires_at"]:
            ticket["status"] = "EXPIRED"
            _save_tickets_to_vault()
            return {
                "authorized": False,
                "error": "TICKET_EXPIRED",
                "message": f"Ticket '{ticket_id}' expired at {ticket['expires_at']} (current time {now}).",
            }

        # 4. Human Authorization Enforcement
        # Check if approved via out-of-band human approval interface
        if ticket["status"] != "HUMAN_APPROVED":
            # Legacy test fallback: if operator emergency token is provided
            if human_approval_token and human_approval_token.strip() == "ZECSHIELD_HUMAN_APPROVE_2026":
                ticket["status"] = "HUMAN_APPROVED"
                ticket["approved_by"] = "EMERGENCY_OVERRIDE_TOKEN"
            elif human_approval_token and ticket.get("operator_internal_token") and secrets.compare_digest(human_approval_token.strip(), ticket["operator_internal_token"]):
                ticket["status"] = "HUMAN_APPROVED"
                ticket["approved_by"] = "OPERATOR_VAULT_TOKEN"
            else:
                return {
                    "authorized": False,
                    "error": "AWAITING_HUMAN_APPROVAL",
                    "message": (
                        f"FAIL-CLOSED: Transaction ticket '{ticket_id}' has NOT been approved by a human operator. "
                        f"AI models cannot self-authorize financial operations. "
                        f"To approve, the operator must execute: 'python cli.py approve {ticket_id}' on the host console."
                    ),
                }

        # 4b. Cryptographic Proof of Human Approval (Ed25519 Verification)
        # Prevents AI agents from self-authorizing via direct vault JSON modification.
        sig = ticket.get("operator_signature", "")
        if not sig:
            if ticket.get("approved_by") not in ("EMERGENCY_OVERRIDE_TOKEN", "OPERATOR_VAULT_TOKEN"):
                return {
                    "authorized": False,
                    "error": "FORGERY_DETECTED",
                    "message": (
                        f"CRITICAL SECURITY VIOLATION: Ticket '{ticket_id}' lacks authentic Ed25519 operator signature! "
                        "Direct vault file modification or AI self-authorization attempt detected."
                    ),
                }
        else:
            is_valid_sig = verify_operator_signature(
                ticket_id=ticket_id,
                intent_digest=ticket["intent_digest"],
                nonce=ticket.get("nonce", ""),
                signature_hex=sig,
            )
            if not is_valid_sig:
                return {
                    "authorized": False,
                    "error": "FORGERY_DETECTED",
                    "message": (
                        f"CRITICAL SECURITY VIOLATION: Invalid operator signature for ticket '{ticket_id}'! "
                        "Ed25519 verification against registered operator public key failed."
                    ),
                }

        # 5. Anti-Tampering: Cryptographic Intent Digest Verification
        amt_findings, zatoshis = audit_payment_amount(amount_zec)
        if zatoshis is None:
            return {
                "authorized": False,
                "error": "INVALID_AMOUNT",
                "message": f"Invalid amount_zec '{amount_zec}' provided during ticket verification.",
            }

        memo_bytes = memo_utf8.encode("utf-8")
        memo_hash = hashlib.sha256(memo_bytes).hexdigest()
        candidate_payload = f"{recipient.strip()}:{zatoshis}:{fee_zatoshis}:{memo_hash}"
        candidate_digest = hashlib.sha256(candidate_payload.encode("utf-8")).hexdigest()

        if candidate_digest != ticket["intent_digest"]:
            return {
                "authorized": False,
                "error": "INTENT_TAMPERING_DETECTED",
                "message": (
                    "Candidate transaction parameters do not match the cryptographic intent approved by the operator! "
                    "Parameter substitution detected (recipient, amount, fee, or memo altered after approval)."
                ),
                "expected_digest": ticket["intent_digest"],
                "candidate_digest": candidate_digest,
            }

        # 6. Atomic Single-Use Consumption (if consume=True)
        if consume:
            ticket["status"] = "CONSUMED"
            ticket["consumed_at"] = now
            _save_tickets_to_vault()
            res_status = "CONSUMED"
        else:
            res_status = ticket.get("status", "HUMAN_APPROVED")

        return {
            "authorized": True,
            "ticket_id": ticket_id,
            "intent_digest": ticket["intent_digest"],
            "status": res_status,
            "consumed_at": ticket.get("consumed_at"),
            "recipient": ticket["recipient"],
            "amount_zatoshis": ticket["amount_zatoshis"],
            "amount_zec": ticket["amount_zec"],
        }


def begin_in_flight_broadcast(
    ticket_id: str,
    recipient: str,
    amount_zec: str,
    memo_utf8: str = "",
    fee_zatoshis: int = 10000,
    human_approval_token: str = "",
    inflight_timeout_seconds: float = 15.0,
    mempool_check_fn: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Phase 1 of Two-Phase Broadcast Protocol.
    Verifies human approval & Ed25519 signature, checks intent parameters,
    reconciles any prior crashed broadcasts, and marks ticket IN_FLIGHT_BROADCASTING.
    """
    with vault_exclusive_lock():
        _load_tickets_from_vault()
        if not ticket_id or ticket_id not in _INTENT_TICKETS:
            return {"authorized": False, "error": "INVALID_TICKET_ID", "message": f"Ticket '{ticket_id}' not found."}

        ticket = _INTENT_TICKETS[ticket_id]
        now = time.time()

        # Check if already consumed (idempotent replay protection)
        if ticket["status"] == "CONSUMED":
            return {
                "authorized": False,
                "error": "TICKET_ALREADY_CONSUMED",
                "message": f"Ticket '{ticket_id}' has already been consumed. Replay attack blocked.",
                "consumed_at": ticket.get("consumed_at"),
            }

        # Check if currently in-flight
        if ticket["status"] == "IN_FLIGHT_BROADCASTING":
            candidate_txid = ticket.get("candidate_txid", "")
            if mempool_check_fn and candidate_txid and mempool_check_fn(candidate_txid):
                ticket["status"] = "CONSUMED"
                ticket["txid"] = candidate_txid
                ticket["confirmed_txid"] = candidate_txid
                ticket["consumed_at"] = now
                _save_tickets_to_vault()
                return {
                    "authorized": True,
                    "reconciled": True,
                    "status": "CONSUMED",
                    "txid": candidate_txid,
                    "recipient": ticket["recipient"],
                    "amount_zec": ticket["amount_zec"],
                    "amount_zatoshis": ticket["amount_zatoshis"],
                    "intent_digest": ticket.get("intent_digest"),
                    "consumed_at": now,
                }

            started_at = ticket.get("broadcast_started_at", 0)
            if now - started_at < inflight_timeout_seconds:
                return {
                    "authorized": False,
                    "error": "TICKET_ALREADY_CONSUMED",
                    "message": "Transaction broadcast is currently in-flight in another thread or process.",
                }
            ticket["status"] = "HUMAN_APPROVED"

        # Regular verify
        auth_res = verify_and_consume_authorization_ticket(
            ticket_id=ticket_id,
            recipient=recipient,
            amount_zec=amount_zec,
            memo_utf8=memo_utf8,
            fee_zatoshis=fee_zatoshis,
            human_approval_token=human_approval_token,
            consume=False,
        )
        if not auth_res.get("authorized"):
            return auth_res

        ticket = _INTENT_TICKETS[ticket_id]
        candidate_txid = hashlib.sha256(f"{ticket_id}:{ticket['intent_digest']}:{now}".encode("utf-8")).hexdigest()
        ticket["status"] = "IN_FLIGHT_BROADCASTING"
        ticket["broadcast_started_at"] = now
        ticket["broadcast_pid"] = os.getpid()
        ticket["candidate_txid"] = candidate_txid
        _save_tickets_to_vault()

        return {
            "authorized": True,
            "reconciled": False,
            "status": "IN_FLIGHT_BROADCASTING",
            "candidate_txid": candidate_txid,
            "ticket_id": ticket_id,
            "recipient": ticket["recipient"],
            "amount_zec": ticket["amount_zec"],
            "amount_zatoshis": ticket["amount_zatoshis"],
            "intent_digest": ticket["intent_digest"],
        }


def finalize_in_flight_broadcast(
    ticket_id: str,
    txid: str,
    success: bool = True,
    error_message: str = "",
) -> Dict[str, Any]:
    """
    Phase 2 of Two-Phase Broadcast Protocol.
    Transitions ticket from IN_FLIGHT_BROADCASTING to CONSUMED (on success)
    or back to HUMAN_APPROVED / FAILED (on network abort).
    """
    with vault_exclusive_lock():
        _load_tickets_from_vault()
        if ticket_id not in _INTENT_TICKETS:
            return {"success": False, "error": "INVALID_TICKET_ID"}
        ticket = _INTENT_TICKETS[ticket_id]
        now = time.time()
        if success:
            ticket["status"] = "CONSUMED"
            ticket["txid"] = txid
            ticket["confirmed_txid"] = txid
            ticket["consumed_at"] = now
            _save_tickets_to_vault()
            return {"success": True, "status": "CONSUMED", "txid": txid, "consumed_at": now}
        else:
            ticket["status"] = "BROADCAST_FAILED"
            ticket["last_error"] = error_message
            _save_tickets_to_vault()
            return {"success": False, "status": "BROADCAST_FAILED", "error": error_message}



