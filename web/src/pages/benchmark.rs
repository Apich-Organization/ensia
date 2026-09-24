use leptos::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkRow {
    pub algo: &'static str,
    pub category: &'static str,
    pub base_size: usize,
    pub max_size: usize,
    pub size_ratio: f64,
    pub base_bbs: usize,
    pub max_bbs: usize,
    pub bb_ratio: f64,
    pub base_edges: usize,
    pub max_edges: usize,
    pub edges_ratio: f64,
    pub base_cyc: usize,
    pub max_cyc: usize,
    pub cyc_ratio: f64,
    pub base_z3_s: f64,
    pub max_z3_s: f64,
    pub z3_ratio: f64,
    pub base_timeout: bool,
    pub max_timeout: bool,
}

// Full 79-target empirical data compiled into static binary
const BENCHMARK_DATA: &[BenchmarkRow] = &[
    BenchmarkRow {
        algo: "aes128_ecb",
        category: "Block Cipher",
        base_size: 38568,
        max_size: 1939104,
        size_ratio: 50.28,
        base_bbs: 18,
        max_bbs: 470,
        bb_ratio: 26.11,
        base_edges: 194,
        max_edges: 5908,
        edges_ratio: 30.45,
        base_cyc: 8,
        max_cyc: 80,
        cyc_ratio: 10.0,
        base_z3_s: 0.0432,
        max_z3_s: 0.8178,
        z3_ratio: 18.93,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes192_ecb",
        category: "Block Cipher",
        base_size: 34440,
        max_size: 1771032,
        size_ratio: 51.42,
        base_bbs: 13,
        max_bbs: 259,
        bb_ratio: 19.92,
        base_edges: 185,
        max_edges: 5311,
        edges_ratio: 28.71,
        base_cyc: 4,
        max_cyc: 46,
        cyc_ratio: 11.5,
        base_z3_s: 0.0226,
        max_z3_s: 1.5559,
        z3_ratio: 68.85,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes256_ecb",
        category: "Block Cipher",
        base_size: 34440,
        max_size: 1459768,
        size_ratio: 42.39,
        base_bbs: 13,
        max_bbs: 540,
        bb_ratio: 41.54,
        base_edges: 185,
        max_edges: 4704,
        edges_ratio: 25.43,
        base_cyc: 4,
        max_cyc: 46,
        cyc_ratio: 11.5,
        base_z3_s: 0.0224,
        max_z3_s: 1.3591,
        z3_ratio: 60.67,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_cbc",
        category: "Block Cipher",
        base_size: 41616,
        max_size: 2447488,
        size_ratio: 58.81,
        base_bbs: 17,
        max_bbs: 929,
        bb_ratio: 54.65,
        base_edges: 232,
        max_edges: 7387,
        edges_ratio: 31.84,
        base_cyc: 7,
        max_cyc: 93,
        cyc_ratio: 13.29,
        base_z3_s: 0.0695,
        max_z3_s: 0.5194,
        z3_ratio: 7.47,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ccm",
        category: "Block Cipher",
        base_size: 45120,
        max_size: 3185928,
        size_ratio: 70.61,
        base_bbs: 16,
        max_bbs: 808,
        bb_ratio: 50.5,
        base_edges: 360,
        max_edges: 10196,
        edges_ratio: 28.32,
        base_cyc: 7,
        max_cyc: 69,
        cyc_ratio: 9.86,
        base_z3_s: 0.0458,
        max_z3_s: 0.9997,
        z3_ratio: 21.83,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_cfb",
        category: "Block Cipher",
        base_size: 41904,
        max_size: 2611368,
        size_ratio: 62.32,
        base_bbs: 17,
        max_bbs: 597,
        bb_ratio: 35.12,
        base_edges: 244,
        max_edges: 7904,
        edges_ratio: 32.39,
        base_cyc: 7,
        max_cyc: 90,
        cyc_ratio: 12.86,
        base_z3_s: 0.0472,
        max_z3_s: 0.6919,
        z3_ratio: 14.66,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "aes_ctr",
        category: "Block Cipher",
        base_size: 41816,
        max_size: 2635928,
        size_ratio: 63.04,
        base_bbs: 17,
        max_bbs: 461,
        bb_ratio: 27.12,
        base_edges: 223,
        max_edges: 7881,
        edges_ratio: 35.34,
        base_cyc: 8,
        max_cyc: 77,
        cyc_ratio: 9.62,
        base_z3_s: 0.0469,
        max_z3_s: 1.7251,
        z3_ratio: 36.78,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "aes_ecb_mode",
        category: "Block Cipher",
        base_size: 41048,
        max_size: 2086912,
        size_ratio: 50.84,
        base_bbs: 17,
        max_bbs: 459,
        bb_ratio: 27.0,
        base_edges: 210,
        max_edges: 6510,
        edges_ratio: 31.0,
        base_cyc: 7,
        max_cyc: 75,
        cyc_ratio: 10.71,
        base_z3_s: 0.0882,
        max_z3_s: 3.0367,
        z3_ratio: 34.43,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "aes_gcm",
        category: "Block Cipher",
        base_size: 47416,
        max_size: 3915248,
        size_ratio: 82.57,
        base_bbs: 20,
        max_bbs: 1369,
        bb_ratio: 68.45,
        base_edges: 404,
        max_edges: 12183,
        edges_ratio: 30.16,
        base_cyc: 10,
        max_cyc: 123,
        cyc_ratio: 12.3,
        base_z3_s: 0.0712,
        max_z3_s: 1.2962,
        z3_ratio: 18.21,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ofb",
        category: "Block Cipher",
        base_size: 41576,
        max_size: 2533576,
        size_ratio: 60.94,
        base_bbs: 17,
        max_bbs: 803,
        bb_ratio: 47.24,
        base_edges: 221,
        max_edges: 7620,
        edges_ratio: 34.48,
        base_cyc: 7,
        max_cyc: 103,
        cyc_ratio: 14.71,
        base_z3_s: 0.0785,
        max_z3_s: 1.1181,
        z3_ratio: 14.24,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "aes_siv",
        category: "Block Cipher",
        base_size: 56200,
        max_size: 3108800,
        size_ratio: 55.32,
        base_bbs: 12,
        max_bbs: 1097,
        bb_ratio: 91.42,
        base_edges: 405,
        max_edges: 10579,
        edges_ratio: 26.12,
        base_cyc: 4,
        max_cyc: 57,
        cyc_ratio: 14.25,
        base_z3_s: 0.0284,
        max_z3_s: 3.7565,
        z3_ratio: 132.27,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_xts",
        category: "Block Cipher",
        base_size: 49312,
        max_size: 2431704,
        size_ratio: 49.31,
        base_bbs: 26,
        max_bbs: 1066,
        bb_ratio: 41.0,
        base_edges: 311,
        max_edges: 8007,
        edges_ratio: 25.75,
        base_cyc: 15,
        max_cyc: 166,
        cyc_ratio: 11.07,
        base_z3_s: 0.116,
        max_z3_s: 0.8178,
        z3_ratio: 7.05,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ascon_aead128",
        category: "Lightweight / AEAD",
        base_size: 33960,
        max_size: 1352696,
        size_ratio: 39.83,
        base_bbs: 12,
        max_bbs: 728,
        bb_ratio: 60.67,
        base_edges: 370,
        max_edges: 4530,
        edges_ratio: 12.24,
        base_cyc: 4,
        max_cyc: 50,
        cyc_ratio: 12.5,
        base_z3_s: 0.0296,
        max_z3_s: 0.9175,
        z3_ratio: 31.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "ascon_hash256",
        category: "Lightweight / AEAD",
        base_size: 27368,
        max_size: 1037104,
        size_ratio: 37.89,
        base_bbs: 6,
        max_bbs: 208,
        bb_ratio: 34.67,
        base_edges: 142,
        max_edges: 3465,
        edges_ratio: 24.4,
        base_cyc: 1,
        max_cyc: 14,
        cyc_ratio: 14.0,
        base_z3_s: 0.0,
        max_z3_s: 0.584,
        z3_ratio: 5840.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ascon_xof128",
        category: "Lightweight / AEAD",
        base_size: 27640,
        max_size: 1082312,
        size_ratio: 39.16,
        base_bbs: 6,
        max_bbs: 133,
        bb_ratio: 22.17,
        base_edges: 164,
        max_edges: 3900,
        edges_ratio: 23.78,
        base_cyc: 1,
        max_cyc: 16,
        cyc_ratio: 16.0,
        base_z3_s: 0.0,
        max_z3_s: 1.5608,
        z3_ratio: 15608.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "bcrypt",
        category: "KDF / Password",
        base_size: 37840,
        max_size: 2615552,
        size_ratio: 69.12,
        base_bbs: 3,
        max_bbs: 69,
        bb_ratio: 23.0,
        base_edges: 298,
        max_edges: 8408,
        edges_ratio: 28.21,
        base_cyc: 1,
        max_cyc: 13,
        cyc_ratio: 13.0,
        base_z3_s: 0.0,
        max_z3_s: 0.3412,
        z3_ratio: 3412.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2b256",
        category: "Hash / Digest",
        base_size: 32456,
        max_size: 1271264,
        size_ratio: 39.17,
        base_bbs: 7,
        max_bbs: 137,
        bb_ratio: 19.57,
        base_edges: 171,
        max_edges: 4533,
        edges_ratio: 26.51,
        base_cyc: 3,
        max_cyc: 24,
        cyc_ratio: 8.0,
        base_z3_s: 0.0181,
        max_z3_s: 1.1736,
        z3_ratio: 64.84,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2b512",
        category: "Hash / Digest",
        base_size: 32488,
        max_size: 1324528,
        size_ratio: 40.77,
        base_bbs: 7,
        max_bbs: 350,
        bb_ratio: 50.0,
        base_edges: 175,
        max_edges: 4822,
        edges_ratio: 27.55,
        base_cyc: 3,
        max_cyc: 45,
        cyc_ratio: 15.0,
        base_z3_s: 0.0183,
        max_z3_s: 2.1766,
        z3_ratio: 118.94,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "blake2s128",
        category: "Hash / Digest",
        base_size: 32400,
        max_size: 1557784,
        size_ratio: 48.08,
        base_bbs: 7,
        max_bbs: 173,
        bb_ratio: 24.71,
        base_edges: 171,
        max_edges: 5231,
        edges_ratio: 30.59,
        base_cyc: 3,
        max_cyc: 30,
        cyc_ratio: 10.0,
        base_z3_s: 0.0177,
        max_z3_s: 0.8521,
        z3_ratio: 48.14,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2s256",
        category: "Hash / Digest",
        base_size: 32408,
        max_size: 1144056,
        size_ratio: 35.3,
        base_bbs: 7,
        max_bbs: 173,
        bb_ratio: 24.71,
        base_edges: 171,
        max_edges: 4252,
        edges_ratio: 24.87,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.0354,
        max_z3_s: 0.0706,
        z3_ratio: 1.99,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blowfish_ecb",
        category: "Block Cipher",
        base_size: 32736,
        max_size: 1078120,
        size_ratio: 32.93,
        base_bbs: 13,
        max_bbs: 277,
        bb_ratio: 21.31,
        base_edges: 208,
        max_edges: 3928,
        edges_ratio: 18.88,
        base_cyc: 4,
        max_cyc: 48,
        cyc_ratio: 12.0,
        base_z3_s: 0.0637,
        max_z3_s: 0.4714,
        z3_ratio: 7.4,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "camellia_ecb",
        category: "Block Cipher",
        base_size: 28608,
        max_size: 1111112,
        size_ratio: 38.84,
        base_bbs: 13,
        max_bbs: 395,
        bb_ratio: 30.38,
        base_edges: 188,
        max_edges: 3878,
        edges_ratio: 20.63,
        base_cyc: 4,
        max_cyc: 43,
        cyc_ratio: 10.75,
        base_z3_s: 0.0338,
        max_z3_s: 2.7231,
        z3_ratio: 80.57,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "cast128_ecb",
        category: "Block Cipher",
        base_size: 41920,
        max_size: 1377296,
        size_ratio: 32.86,
        base_bbs: 13,
        max_bbs: 435,
        bb_ratio: 33.46,
        base_edges: 146,
        max_edges: 4119,
        edges_ratio: 28.21,
        base_cyc: 4,
        max_cyc: 57,
        cyc_ratio: 14.25,
        base_z3_s: 0.031,
        max_z3_s: 0.8673,
        z3_ratio: 27.98,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "cast256_ecb",
        category: "Block Cipher",
        base_size: 46320,
        max_size: 992184,
        size_ratio: 21.42,
        base_bbs: 13,
        max_bbs: 251,
        bb_ratio: 19.31,
        base_edges: 176,
        max_edges: 3214,
        edges_ratio: 18.26,
        base_cyc: 4,
        max_cyc: 45,
        cyc_ratio: 11.25,
        base_z3_s: 0.0425,
        max_z3_s: 0.0588,
        z3_ratio: 1.38,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "chacha20_poly1305",
        category: "Stream Cipher",
        base_size: 40056,
        max_size: 3771232,
        size_ratio: 94.15,
        base_bbs: 12,
        max_bbs: 536,
        bb_ratio: 44.67,
        base_edges: 354,
        max_edges: 11699,
        edges_ratio: 33.05,
        base_cyc: 4,
        max_cyc: 42,
        cyc_ratio: 10.5,
        base_z3_s: 0.0469,
        max_z3_s: 4.8111,
        z3_ratio: 102.58,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "chacha20_stream",
        category: "Stream Cipher",
        base_size: 27680,
        max_size: 1679840,
        size_ratio: 60.69,
        base_bbs: 13,
        max_bbs: 598,
        bb_ratio: 46.0,
        base_edges: 207,
        max_edges: 5439,
        edges_ratio: 26.28,
        base_cyc: 5,
        max_cyc: 49,
        cyc_ratio: 9.8,
        base_z3_s: 0.0316,
        max_z3_s: 1.5256,
        z3_ratio: 48.28,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "cmac_aes",
        category: "Block Cipher",
        base_size: 49296,
        max_size: 2505352,
        size_ratio: 50.82,
        base_bbs: 13,
        max_bbs: 410,
        bb_ratio: 31.54,
        base_edges: 294,
        max_edges: 8204,
        edges_ratio: 27.9,
        base_cyc: 4,
        max_cyc: 54,
        cyc_ratio: 13.5,
        base_z3_s: 0.0319,
        max_z3_s: 0.6602,
        z3_ratio: 20.7,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "cshake128",
        category: "Hash / Digest",
        base_size: 39424,
        max_size: 2165320,
        size_ratio: 54.92,
        base_bbs: 7,
        max_bbs: 327,
        bb_ratio: 46.71,
        base_edges: 312,
        max_edges: 7939,
        edges_ratio: 25.45,
        base_cyc: 3,
        max_cyc: 38,
        cyc_ratio: 12.67,
        base_z3_s: 0.0273,
        max_z3_s: 1.0895,
        z3_ratio: 39.91,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "des3_ecb",
        category: "Block Cipher",
        base_size: 39216,
        max_size: 1509088,
        size_ratio: 38.48,
        base_bbs: 13,
        max_bbs: 437,
        bb_ratio: 33.62,
        base_edges: 184,
        max_edges: 4886,
        edges_ratio: 26.55,
        base_cyc: 4,
        max_cyc: 53,
        cyc_ratio: 13.25,
        base_z3_s: 0.0414,
        max_z3_s: 2.4159,
        z3_ratio: 58.36,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "des_ecb",
        category: "Block Cipher",
        base_size: 31856,
        max_size: 2086288,
        size_ratio: 65.49,
        base_bbs: 13,
        max_bbs: 305,
        bb_ratio: 23.46,
        base_edges: 141,
        max_edges: 5912,
        edges_ratio: 41.93,
        base_cyc: 4,
        max_cyc: 54,
        cyc_ratio: 13.5,
        base_z3_s: 0.0287,
        max_z3_s: 1.5612,
        z3_ratio: 54.4,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "dh2048",
        category: "Asymmetric / PKC",
        base_size: 66880,
        max_size: 7719336,
        size_ratio: 115.42,
        base_bbs: 5,
        max_bbs: 289,
        bb_ratio: 57.8,
        base_edges: 1253,
        max_edges: 29583,
        edges_ratio: 23.61,
        base_cyc: 1,
        max_cyc: 16,
        cyc_ratio: 16.0,
        base_z3_s: 0.0,
        max_z3_s: 0.5725,
        z3_ratio: 5725.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "dsa2048",
        category: "Asymmetric / PKC",
        base_size: 80928,
        max_size: 9958496,
        size_ratio: 123.05,
        base_bbs: 7,
        max_bbs: 278,
        bb_ratio: 39.71,
        base_edges: 1496,
        max_edges: 37043,
        edges_ratio: 24.76,
        base_cyc: 3,
        max_cyc: 41,
        cyc_ratio: 13.67,
        base_z3_s: 0.0235,
        max_z3_s: 1.9954,
        z3_ratio: 84.91,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "ecdh_p256",
        category: "Asymmetric / PKC",
        base_size: 144192,
        max_size: 16252248,
        size_ratio: 112.71,
        base_bbs: 21,
        max_bbs: 633,
        bb_ratio: 30.14,
        base_edges: 2397,
        max_edges: 53349,
        edges_ratio: 22.26,
        base_cyc: 10,
        max_cyc: 109,
        cyc_ratio: 10.9,
        base_z3_s: 0.0708,
        max_z3_s: 1.8243,
        z3_ratio: 25.77,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "ecdsa_p256",
        category: "Asymmetric / PKC",
        base_size: 158672,
        max_size: 16995728,
        size_ratio: 107.11,
        base_bbs: 18,
        max_bbs: 461,
        bb_ratio: 25.61,
        base_edges: 2571,
        max_edges: 56907,
        edges_ratio: 22.13,
        base_cyc: 4,
        max_cyc: 73,
        cyc_ratio: 18.25,
        base_z3_s: 0.0837,
        max_z3_s: 0.7591,
        z3_ratio: 9.07,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "ed25519",
        category: "Asymmetric / PKC",
        base_size: 245008,
        max_size: 27363032,
        size_ratio: 111.68,
        base_bbs: 11,
        max_bbs: 301,
        bb_ratio: 27.36,
        base_edges: 3883,
        max_edges: 89064,
        edges_ratio: 22.94,
        base_cyc: 4,
        max_cyc: 34,
        cyc_ratio: 8.5,
        base_z3_s: 0.0286,
        max_z3_s: 0.1236,
        z3_ratio: 4.32,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "gmac_aes",
        category: "Block Cipher",
        base_size: 63992,
        max_size: 3969856,
        size_ratio: 62.04,
        base_bbs: 16,
        max_bbs: 590,
        bb_ratio: 36.88,
        base_edges: 560,
        max_edges: 13621,
        edges_ratio: 24.32,
        base_cyc: 5,
        max_cyc: 50,
        cyc_ratio: 10.0,
        base_z3_s: 0.0614,
        max_z3_s: 2.0631,
        z3_ratio: 33.6,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "hkdf_sha256",
        category: "Hash / Digest",
        base_size: 47936,
        max_size: 2993096,
        size_ratio: 62.44,
        base_bbs: 7,
        max_bbs: 824,
        bb_ratio: 117.71,
        base_edges: 299,
        max_edges: 9555,
        edges_ratio: 31.96,
        base_cyc: 3,
        max_cyc: 26,
        cyc_ratio: 8.67,
        base_z3_s: 0.0216,
        max_z3_s: 0.9805,
        z3_ratio: 45.39,
        base_timeout: true,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "hmac_sha256",
        category: "Hash / Digest",
        base_size: 40504,
        max_size: 1284232,
        size_ratio: 31.71,
        base_bbs: 9,
        max_bbs: 202,
        bb_ratio: 22.44,
        base_edges: 240,
        max_edges: 4870,
        edges_ratio: 20.29,
        base_cyc: 3,
        max_cyc: 35,
        cyc_ratio: 11.67,
        base_z3_s: 0.0286,
        max_z3_s: 0.4065,
        z3_ratio: 14.21,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "idea_ecb",
        category: "Block Cipher",
        base_size: 27784,
        max_size: 1085856,
        size_ratio: 39.08,
        base_bbs: 13,
        max_bbs: 331,
        bb_ratio: 25.46,
        base_edges: 201,
        max_edges: 3877,
        edges_ratio: 19.29,
        base_cyc: 4,
        max_cyc: 61,
        cyc_ratio: 15.25,
        base_z3_s: 0.0369,
        max_z3_s: 0.0767,
        z3_ratio: 2.08,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "kmac128",
        category: "MAC / Authenticator",
        base_size: 53304,
        max_size: 3236592,
        size_ratio: 60.72,
        base_bbs: 7,
        max_bbs: 491,
        bb_ratio: 70.14,
        base_edges: 435,
        max_edges: 11837,
        edges_ratio: 27.21,
        base_cyc: 3,
        max_cyc: 32,
        cyc_ratio: 10.67,
        base_z3_s: 0.0436,
        max_z3_s: 0.4754,
        z3_ratio: 10.9,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "mars_ecb",
        category: "Block Cipher",
        base_size: 36520,
        max_size: 1672192,
        size_ratio: 45.79,
        base_bbs: 13,
        max_bbs: 298,
        bb_ratio: 22.92,
        base_edges: 176,
        max_edges: 5038,
        edges_ratio: 28.62,
        base_cyc: 4,
        max_cyc: 49,
        cyc_ratio: 12.25,
        base_z3_s: 0.0293,
        max_z3_s: 0.387,
        z3_ratio: 13.21,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "md5",
        category: "Hash / Digest",
        base_size: 31496,
        max_size: 1139656,
        size_ratio: 36.18,
        base_bbs: 12,
        max_bbs: 537,
        bb_ratio: 44.75,
        base_edges: 148,
        max_edges: 3808,
        edges_ratio: 25.73,
        base_cyc: 5,
        max_cyc: 63,
        cyc_ratio: 12.6,
        base_z3_s: 0.0446,
        max_z3_s: 1.0703,
        z3_ratio: 24.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "mldsa44",
        category: "Asymmetric / PKC",
        base_size: 20792,
        max_size: 285880,
        size_ratio: 13.75,
        base_bbs: 2,
        max_bbs: 79,
        bb_ratio: 39.5,
        base_edges: 54,
        max_edges: 834,
        edges_ratio: 15.44,
        base_cyc: 1,
        max_cyc: 13,
        cyc_ratio: 13.0,
        base_z3_s: 0.0,
        max_z3_s: 0.5251,
        z3_ratio: 5251.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "mlkem512",
        category: "Post-Quantum (PQC)",
        base_size: 20792,
        max_size: 142488,
        size_ratio: 6.85,
        base_bbs: 2,
        max_bbs: 47,
        bb_ratio: 23.5,
        base_edges: 54,
        max_edges: 514,
        edges_ratio: 9.52,
        base_cyc: 1,
        max_cyc: 10,
        cyc_ratio: 10.0,
        base_z3_s: 0.0,
        max_z3_s: 0.5651,
        z3_ratio: 5651.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "mlkem768",
        category: "Post-Quantum (PQC)",
        base_size: 20792,
        max_size: 89288,
        size_ratio: 4.29,
        base_bbs: 2,
        max_bbs: 88,
        bb_ratio: 44.0,
        base_edges: 54,
        max_edges: 421,
        edges_ratio: 7.8,
        base_cyc: 1,
        max_cyc: 16,
        cyc_ratio: 16.0,
        base_z3_s: 0.0,
        max_z3_s: 1.0764,
        z3_ratio: 10764.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "pbkdf2_sha256",
        category: "Hash / Digest",
        base_size: 48232,
        max_size: 1858312,
        size_ratio: 38.53,
        base_bbs: 7,
        max_bbs: 261,
        bb_ratio: 37.29,
        base_edges: 336,
        max_edges: 6974,
        edges_ratio: 20.76,
        base_cyc: 3,
        max_cyc: 41,
        cyc_ratio: 13.67,
        base_z3_s: 0.022,
        max_z3_s: 5.0312,
        z3_ratio: 228.69,
        base_timeout: true,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "poly1305",
        category: "MAC / Authenticator",
        base_size: 26440,
        max_size: 1782336,
        size_ratio: 67.41,
        base_bbs: 6,
        max_bbs: 133,
        bb_ratio: 22.17,
        base_edges: 130,
        max_edges: 4897,
        edges_ratio: 37.67,
        base_cyc: 1,
        max_cyc: 19,
        cyc_ratio: 19.0,
        base_z3_s: 0.0,
        max_z3_s: 2.5826,
        z3_ratio: 25826.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "present_ecb",
        category: "Block Cipher",
        base_size: 31192,
        max_size: 1721520,
        size_ratio: 55.19,
        base_bbs: 13,
        max_bbs: 422,
        bb_ratio: 32.46,
        base_edges: 123,
        max_edges: 4892,
        edges_ratio: 39.77,
        base_cyc: 4,
        max_cyc: 55,
        cyc_ratio: 13.75,
        base_z3_s: 0.0313,
        max_z3_s: 0.9496,
        z3_ratio: 30.34,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "rc2_ecb",
        category: "Block Cipher",
        base_size: 27128,
        max_size: 1167720,
        size_ratio: 43.04,
        base_bbs: 13,
        max_bbs: 267,
        bb_ratio: 20.54,
        base_edges: 172,
        max_edges: 3911,
        edges_ratio: 22.74,
        base_cyc: 4,
        max_cyc: 48,
        cyc_ratio: 12.0,
        base_z3_s: 0.0299,
        max_z3_s: 0.6157,
        z3_ratio: 20.59,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "rc4_stream",
        category: "Stream Cipher",
        base_size: 24664,
        max_size: 532408,
        size_ratio: 21.59,
        base_bbs: 13,
        max_bbs: 556,
        bb_ratio: 42.77,
        base_edges: 104,
        max_edges: 1906,
        edges_ratio: 18.33,
        base_cyc: 5,
        max_cyc: 56,
        cyc_ratio: 11.2,
        base_z3_s: 0.033,
        max_z3_s: 1.5892,
        z3_ratio: 48.16,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "rc6_ecb",
        category: "Block Cipher",
        base_size: 26712,
        max_size: 962880,
        size_ratio: 36.05,
        base_bbs: 13,
        max_bbs: 428,
        bb_ratio: 32.92,
        base_edges: 145,
        max_edges: 3294,
        edges_ratio: 22.72,
        base_cyc: 4,
        max_cyc: 54,
        cyc_ratio: 13.5,
        base_z3_s: 0.0615,
        max_z3_s: 0.6529,
        z3_ratio: 10.62,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "ripemd128",
        category: "Hash / Digest",
        base_size: 31736,
        max_size: 1823520,
        size_ratio: 57.46,
        base_bbs: 7,
        max_bbs: 129,
        bb_ratio: 18.43,
        base_edges: 140,
        max_edges: 5262,
        edges_ratio: 37.59,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.0202,
        max_z3_s: 0.2203,
        z3_ratio: 10.91,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ripemd160",
        category: "Hash / Digest",
        base_size: 33728,
        max_size: 2245312,
        size_ratio: 66.57,
        base_bbs: 7,
        max_bbs: 151,
        bb_ratio: 21.57,
        base_edges: 146,
        max_edges: 6160,
        edges_ratio: 42.19,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.0207,
        max_z3_s: 1.843,
        z3_ratio: 89.03,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "rsa2048",
        category: "Asymmetric / PKC",
        base_size: 109600,
        max_size: 15255568,
        size_ratio: 139.19,
        base_bbs: 7,
        max_bbs: 347,
        bb_ratio: 49.57,
        base_edges: 2156,
        max_edges: 55196,
        edges_ratio: 25.6,
        base_cyc: 3,
        max_cyc: 36,
        cyc_ratio: 12.0,
        base_z3_s: 0.0219,
        max_z3_s: 1.8917,
        z3_ratio: 86.38,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "salsa20_stream",
        category: "Stream Cipher",
        base_size: 26584,
        max_size: 696192,
        size_ratio: 26.19,
        base_bbs: 4,
        max_bbs: 104,
        bb_ratio: 26.0,
        base_edges: 90,
        max_edges: 2214,
        edges_ratio: 24.6,
        base_cyc: 1,
        max_cyc: 15,
        cyc_ratio: 15.0,
        base_z3_s: 0.0,
        max_z3_s: 0.6441,
        z3_ratio: 6441.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "scrypt",
        category: "KDF / Password",
        base_size: 57272,
        max_size: 3387720,
        size_ratio: 59.15,
        base_bbs: 7,
        max_bbs: 257,
        bb_ratio: 36.71,
        base_edges: 470,
        max_edges: 11844,
        edges_ratio: 25.2,
        base_cyc: 3,
        max_cyc: 35,
        cyc_ratio: 11.67,
        base_z3_s: 0.03,
        max_z3_s: 1.2788,
        z3_ratio: 42.63,
        base_timeout: true,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "seed_ecb",
        category: "Block Cipher",
        base_size: 31104,
        max_size: 709112,
        size_ratio: 22.8,
        base_bbs: 13,
        max_bbs: 284,
        bb_ratio: 21.85,
        base_edges: 144,
        max_edges: 2618,
        edges_ratio: 18.18,
        base_cyc: 4,
        max_cyc: 51,
        cyc_ratio: 12.75,
        base_z3_s: 0.0338,
        max_z3_s: 1.8695,
        z3_ratio: 55.31,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "serpent_ecb",
        category: "Block Cipher",
        base_size: 34840,
        max_size: 2314664,
        size_ratio: 66.44,
        base_bbs: 13,
        max_bbs: 516,
        bb_ratio: 39.69,
        base_edges: 174,
        max_edges: 6428,
        edges_ratio: 36.94,
        base_cyc: 4,
        max_cyc: 57,
        cyc_ratio: 14.25,
        base_z3_s: 0.0326,
        max_z3_s: 1.9437,
        z3_ratio: 59.62,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "sha1",
        category: "Hash / Digest",
        base_size: 26840,
        max_size: 1655864,
        size_ratio: 61.69,
        base_bbs: 12,
        max_bbs: 350,
        bb_ratio: 29.17,
        base_edges: 163,
        max_edges: 5358,
        edges_ratio: 32.87,
        base_cyc: 5,
        max_cyc: 55,
        cyc_ratio: 11.0,
        base_z3_s: 0.0344,
        max_z3_s: 0.456,
        z3_ratio: 13.26,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha224",
        category: "Hash / Digest",
        base_size: 29880,
        max_size: 1111416,
        size_ratio: 37.2,
        base_bbs: 7,
        max_bbs: 149,
        bb_ratio: 21.29,
        base_edges: 166,
        max_edges: 3967,
        edges_ratio: 23.9,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.0277,
        max_z3_s: 1.0159,
        z3_ratio: 36.68,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha256",
        category: "Hash / Digest",
        base_size: 27152,
        max_size: 1147808,
        size_ratio: 42.27,
        base_bbs: 12,
        max_bbs: 290,
        bb_ratio: 24.17,
        base_edges: 150,
        max_edges: 3890,
        edges_ratio: 25.93,
        base_cyc: 5,
        max_cyc: 54,
        cyc_ratio: 10.8,
        base_z3_s: 0.0319,
        max_z3_s: 1.7824,
        z3_ratio: 55.87,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha256_crypt",
        category: "Hash / Digest",
        base_size: 51024,
        max_size: 4120536,
        size_ratio: 80.76,
        base_bbs: 7,
        max_bbs: 207,
        bb_ratio: 29.57,
        base_edges: 386,
        max_edges: 12617,
        edges_ratio: 32.69,
        base_cyc: 2,
        max_cyc: 35,
        cyc_ratio: 17.5,
        base_z3_s: 0.0231,
        max_z3_s: 1.7387,
        z3_ratio: 75.27,
        base_timeout: true,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "sha384",
        category: "Hash / Digest",
        base_size: 30064,
        max_size: 1988432,
        size_ratio: 66.14,
        base_bbs: 7,
        max_bbs: 175,
        bb_ratio: 25.0,
        base_edges: 172,
        max_edges: 6065,
        edges_ratio: 35.26,
        base_cyc: 3,
        max_cyc: 32,
        cyc_ratio: 10.67,
        base_z3_s: 0.0199,
        max_z3_s: 2.6424,
        z3_ratio: 132.78,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "sha3_256",
        category: "Hash / Digest",
        base_size: 34096,
        max_size: 1299848,
        size_ratio: 38.12,
        base_bbs: 7,
        max_bbs: 135,
        bb_ratio: 19.29,
        base_edges: 205,
        max_edges: 4760,
        edges_ratio: 23.22,
        base_cyc: 3,
        max_cyc: 24,
        cyc_ratio: 8.0,
        base_z3_s: 0.0467,
        max_z3_s: 0.6187,
        z3_ratio: 13.25,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha3_512",
        category: "Hash / Digest",
        base_size: 34128,
        max_size: 1656344,
        size_ratio: 48.53,
        base_bbs: 7,
        max_bbs: 214,
        bb_ratio: 30.57,
        base_edges: 209,
        max_edges: 5674,
        edges_ratio: 27.15,
        base_cyc: 3,
        max_cyc: 30,
        cyc_ratio: 10.0,
        base_z3_s: 0.0191,
        max_z3_s: 1.245,
        z3_ratio: 65.18,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha512",
        category: "Hash / Digest",
        base_size: 26824,
        max_size: 1594336,
        size_ratio: 59.44,
        base_bbs: 7,
        max_bbs: 197,
        bb_ratio: 28.14,
        base_edges: 142,
        max_edges: 4805,
        edges_ratio: 33.84,
        base_cyc: 3,
        max_cyc: 37,
        cyc_ratio: 12.33,
        base_z3_s: 0.0232,
        max_z3_s: 0.1041,
        z3_ratio: 4.49,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "shake128",
        category: "Hash / Digest",
        base_size: 35312,
        max_size: 1808312,
        size_ratio: 51.21,
        base_bbs: 7,
        max_bbs: 171,
        bb_ratio: 24.43,
        base_edges: 223,
        max_edges: 6267,
        edges_ratio: 28.1,
        base_cyc: 3,
        max_cyc: 29,
        cyc_ratio: 9.67,
        base_z3_s: 0.0196,
        max_z3_s: 2.1441,
        z3_ratio: 109.39,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "shake256",
        category: "Hash / Digest",
        base_size: 35312,
        max_size: 1669016,
        size_ratio: 47.26,
        base_bbs: 7,
        max_bbs: 146,
        bb_ratio: 20.86,
        base_edges: 223,
        max_edges: 5962,
        edges_ratio: 26.74,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.021,
        max_z3_s: 1.7574,
        z3_ratio: 83.69,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "sm2",
        category: "Asymmetric / PKC",
        base_size: 157072,
        max_size: 15719856,
        size_ratio: 100.08,
        base_bbs: 10,
        max_bbs: 345,
        bb_ratio: 34.5,
        base_edges: 2512,
        max_edges: 52608,
        edges_ratio: 20.94,
        base_cyc: 4,
        max_cyc: 58,
        cyc_ratio: 14.5,
        base_z3_s: 0.0511,
        max_z3_s: 1.2041,
        z3_ratio: 23.56,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "sm3",
        category: "Hash / Digest",
        base_size: 26760,
        max_size: 1356592,
        size_ratio: 50.69,
        base_bbs: 7,
        max_bbs: 150,
        bb_ratio: 21.43,
        base_edges: 143,
        max_edges: 4322,
        edges_ratio: 30.22,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.0251,
        max_z3_s: 1.3971,
        z3_ratio: 55.66,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sm4_ecb",
        category: "Block Cipher",
        base_size: 27472,
        max_size: 938848,
        size_ratio: 34.17,
        base_bbs: 13,
        max_bbs: 354,
        bb_ratio: 27.23,
        base_edges: 144,
        max_edges: 3014,
        edges_ratio: 20.93,
        base_cyc: 4,
        max_cyc: 60,
        cyc_ratio: 15.0,
        base_z3_s: 0.0437,
        max_z3_s: 1.6678,
        z3_ratio: 38.16,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "tea_ecb",
        category: "Block Cipher",
        base_size: 25808,
        max_size: 483352,
        size_ratio: 18.73,
        base_bbs: 13,
        max_bbs: 475,
        bb_ratio: 36.54,
        base_edges: 120,
        max_edges: 1937,
        edges_ratio: 16.14,
        base_cyc: 4,
        max_cyc: 58,
        cyc_ratio: 14.5,
        base_z3_s: 0.0518,
        max_z3_s: 0.4494,
        z3_ratio: 8.68,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "tiger",
        category: "Hash / Digest",
        base_size: 39072,
        max_size: 1246464,
        size_ratio: 31.9,
        base_bbs: 7,
        max_bbs: 195,
        bb_ratio: 27.86,
        base_edges: 139,
        max_edges: 3820,
        edges_ratio: 27.48,
        base_cyc: 3,
        max_cyc: 37,
        cyc_ratio: 12.33,
        base_z3_s: 0.0212,
        max_z3_s: 0.5411,
        z3_ratio: 25.52,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "twofish_ecb",
        category: "Block Cipher",
        base_size: 29224,
        max_size: 1680496,
        size_ratio: 57.5,
        base_bbs: 13,
        max_bbs: 295,
        bb_ratio: 22.69,
        base_edges: 206,
        max_edges: 5275,
        edges_ratio: 25.61,
        base_cyc: 4,
        max_cyc: 51,
        cyc_ratio: 12.75,
        base_z3_s: 0.0433,
        max_z3_s: 1.7145,
        z3_ratio: 39.6,
        base_timeout: true,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "whirlpool",
        category: "Hash / Digest",
        base_size: 35016,
        max_size: 1312040,
        size_ratio: 37.47,
        base_bbs: 7,
        max_bbs: 194,
        bb_ratio: 27.71,
        base_edges: 157,
        max_edges: 4190,
        edges_ratio: 26.69,
        base_cyc: 3,
        max_cyc: 30,
        cyc_ratio: 10.0,
        base_z3_s: 0.0201,
        max_z3_s: 1.0898,
        z3_ratio: 54.22,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "x25519",
        category: "Asymmetric / PKC",
        base_size: 43904,
        max_size: 4799288,
        size_ratio: 109.31,
        base_bbs: 7,
        max_bbs: 299,
        bb_ratio: 42.71,
        base_edges: 408,
        max_edges: 13060,
        edges_ratio: 32.01,
        base_cyc: 3,
        max_cyc: 38,
        cyc_ratio: 12.67,
        base_z3_s: 0.0195,
        max_z3_s: 0.8962,
        z3_ratio: 45.96,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "xcbc_mac",
        category: "MAC / Authenticator",
        base_size: 48976,
        max_size: 1899376,
        size_ratio: 38.78,
        base_bbs: 13,
        max_bbs: 453,
        bb_ratio: 34.85,
        base_edges: 288,
        max_edges: 6741,
        edges_ratio: 23.41,
        base_cyc: 4,
        max_cyc: 47,
        cyc_ratio: 11.75,
        base_z3_s: 0.0286,
        max_z3_s: 1.3581,
        z3_ratio: 47.49,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "xtea_ecb",
        category: "Block Cipher",
        base_size: 25808,
        max_size: 856176,
        size_ratio: 33.17,
        base_bbs: 13,
        max_bbs: 260,
        bb_ratio: 20.0,
        base_edges: 120,
        max_edges: 2838,
        edges_ratio: 23.65,
        base_cyc: 4,
        max_cyc: 45,
        cyc_ratio: 11.25,
        base_z3_s: 0.0276,
        max_z3_s: 1.2672,
        z3_ratio: 45.91,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "zuc_stream",
        category: "Stream Cipher",
        base_size: 31592,
        max_size: 1528392,
        size_ratio: 48.38,
        base_bbs: 13,
        max_bbs: 400,
        bb_ratio: 30.77,
        base_edges: 138,
        max_edges: 4751,
        edges_ratio: 34.43,
        base_cyc: 5,
        max_cyc: 49,
        cyc_ratio: 9.8,
        base_z3_s: 0.0309,
        max_z3_s: 0.4758,
        z3_ratio: 15.4,
        base_timeout: false,
        max_timeout: true,
    },
];

#[derive(Clone, Debug, PartialEq)]
pub struct PassVerificationRow {
    pub id: &'static str,
    pub name: &'static str,
    pub workload: &'static str,
    pub ir_insts: usize,
    pub ir_ratio: f64,
    pub barriers: usize,
    pub volatile_stores: usize,
    pub asm_lines: usize,
    pub canary_probes: usize,
    pub status: &'static str,
    pub evidence: &'static str,
}

pub const PASS_VERIFICATION_DATA: &[PassVerificationRow] = &[
    PassVerificationRow {
        id: "BASELINE",
        name: "Unobfuscated Baseline",
        workload: "target_crypto.c",
        ir_insts: 218,
        ir_ratio: 1.0,
        barriers: 0,
        volatile_stores: 0,
        asm_lines: 373,
        canary_probes: 0,
        status: "SUCCESS",
        evidence: "Pristine baseline IR (12 BBs, 0 fences)",
    },
    PassVerificationRow {
        id: "SUBOBF",
        name: "Instruction Substitution",
        workload: "target_crypto.c",
        ir_insts: 661,
        ir_ratio: 3.03,
        barriers: 92,
        volatile_stores: 50,
        asm_lines: 977,
        canary_probes: 18,
        status: "SUCCESS",
        evidence: "480 synthetic arithmetic markers, 92 barriers",
    },
    PassVerificationRow {
        id: "MBAOBF",
        name: "Mixed Boolean-Arithmetic",
        workload: "target_crypto.c",
        ir_insts: 1354,
        ir_ratio: 6.21,
        barriers: 105,
        volatile_stores: 57,
        asm_lines: 2155,
        canary_probes: 24,
        status: "SUCCESS",
        evidence: "MBA polynomial noise & context globals, 105 barriers",
    },
    PassVerificationRow {
        id: "SPLITOBF",
        name: "Basic Block Splitting",
        workload: "target_control_flow.c",
        ir_insts: 953,
        ir_ratio: 4.37,
        barriers: 121,
        volatile_stores: 61,
        asm_lines: 2013,
        canary_probes: 25,
        status: "SUCCESS",
        evidence: "BB fragmentation, 121 barriers, 61 volatile stores",
    },
    PassVerificationRow {
        id: "BCFOBF",
        name: "Bogus Control Flow",
        workload: "target_control_flow.c",
        ir_insts: 1450,
        ir_ratio: 6.65,
        barriers: 122,
        volatile_stores: 62,
        asm_lines: 2692,
        canary_probes: 25,
        status: "SUCCESS",
        evidence: "Hardware CPUID/RDTSC dynamic opaque predicates",
    },
    PassVerificationRow {
        id: "CSMOBF",
        name: "Chaos State Machine",
        workload: "target_control_flow.c",
        ir_insts: 744,
        ir_ratio: 3.41,
        barriers: 0,
        volatile_stores: 0,
        asm_lines: 885,
        canary_probes: 0,
        status: "SUCCESS",
        evidence: "Q32 logistic map chaotic attractor dispatch",
    },
    PassVerificationRow {
        id: "CFFOBF",
        name: "Control Flow Flattening",
        workload: "target_control_flow.c",
        ir_insts: 744,
        ir_ratio: 3.41,
        barriers: 0,
        volatile_stores: 0,
        asm_lines: 885,
        canary_probes: 0,
        status: "SUCCESS",
        evidence: "Zero-SPOF branchless switch state dispatch",
    },
    PassVerificationRow {
        id: "VOBF",
        name: "Vector Obfuscation",
        workload: "target_crypto.c",
        ir_insts: 845,
        ir_ratio: 3.88,
        barriers: 55,
        volatile_stores: 0,
        asm_lines: 1600,
        canary_probes: 11,
        status: "SUCCESS",
        evidence: "512-bit SIMD vector lane lifting (<4 x i32>, <8 x float>)",
    },
    PassVerificationRow {
        id: "STRCRY",
        name: "String Encryption + AntiDump",
        workload: "target_data_strings.c",
        ir_insts: 12217,
        ir_ratio: 56.04,
        barriers: 466,
        volatile_stores: 233,
        asm_lines: 15397,
        canary_probes: 94,
        status: "SUCCESS (EXIT_1)",
        evidence: "Dual-layer Vernam+GF(2^8) & exit buffer zeroization",
    },
    PassVerificationRow {
        id: "CONSTENC",
        name: "Constant Encryption (Feistel)",
        workload: "target_crypto.c",
        ir_insts: 1759,
        ir_ratio: 8.07,
        barriers: 167,
        volatile_stores: 84,
        asm_lines: 3001,
        canary_probes: 34,
        status: "SUCCESS",
        evidence: "4-round Feistel network + .init_array dynamic S-Box",
    },
    PassVerificationRow {
        id: "INDIBRAN",
        name: "Indirect Branching",
        workload: "target_control_flow.c",
        ir_insts: 4767,
        ir_ratio: 21.87,
        barriers: 710,
        volatile_stores: 355,
        asm_lines: 7026,
        canary_probes: 142,
        status: "SUCCESS",
        evidence: "Knuth multiplicative indirect jump tables",
    },
    PassVerificationRow {
        id: "FUNCWRA",
        name: "Function Wrapper",
        workload: "target_crypto.c",
        ir_insts: 321,
        ir_ratio: 1.47,
        barriers: 27,
        volatile_stores: 14,
        asm_lines: 744,
        canary_probes: 6,
        status: "SUCCESS",
        evidence: "Polymorphic proxy wrappers & frame depth mutation",
    },
    PassVerificationRow {
        id: "FCO",
        name: "Function Call Obfuscation",
        workload: "target_crypto.c",
        ir_insts: 119,
        ir_ratio: 0.55,
        barriers: 0,
        volatile_stores: 0,
        asm_lines: 295,
        canary_probes: 0,
        status: "SUCCESS",
        evidence: "Dynamic dlopen/dlsym runtime dispatch indirection",
    },
    PassVerificationRow {
        id: "ADB",
        name: "Anti-Debugging",
        workload: "target_crypto.c",
        ir_insts: 1923,
        ir_ratio: 8.82,
        barriers: 129,
        volatile_stores: 65,
        asm_lines: 2061,
        canary_probes: 26,
        status: "SUCCESS",
        evidence: "ptrace + rdtsc timing + DR0-DR7 + TF traps + silent token",
    },
    PassVerificationRow {
        id: "ANTIHOOK",
        name: "Anti-Hooking",
        workload: "target_crypto.c",
        ir_insts: 2238,
        ir_ratio: 10.27,
        barriers: 124,
        volatile_stores: 62,
        asm_lines: 2664,
        canary_probes: 25,
        status: "SUCCESS",
        evidence: "Prologue 5-byte/14-byte integrity + direct syscall exit",
    },
    PassVerificationRow {
        id: "ACDOBF",
        name: "Anti-Class-Dump (Hardened)",
        workload: "target_objc.m",
        ir_insts: 258,
        ir_ratio: 5.86,
        barriers: 14,
        volatile_stores: 8,
        asm_lines: 541,
        canary_probes: 4,
        status: "VERIFIED",
        evidence: "Stack XOR decrypt + Frida/Substrate hook trap + 14 barriers",
    },
    PassVerificationRow {
        id: "PRESET_LOW",
        name: "Preset Low",
        workload: "target_crackme.c",
        ir_insts: 436773,
        ir_ratio: 2003.5,
        barriers: 49734,
        volatile_stores: 24867,
        asm_lines: 494438,
        canary_probes: 9948,
        status: "SUCCESS",
        evidence: "Sub+MBA+Split+BCF+Str+Const multi-pass cascade",
    },
    PassVerificationRow {
        id: "PRESET_MID",
        name: "Preset Mid (Production)",
        workload: "target_crackme.c",
        ir_insts: 327843,
        ir_ratio: 1503.8,
        barriers: 45149,
        volatile_stores: 22575,
        asm_lines: 448087,
        canary_probes: 9030,
        status: "SUCCESS",
        evidence: "Standard enterprise hardened profile",
    },
    PassVerificationRow {
        id: "PRESET_HIGH",
        name: "Preset High (Max Control)",
        workload: "target_crackme.c",
        ir_insts: 127528,
        ir_ratio: 585.0,
        barriers: 12958,
        volatile_stores: 6479,
        asm_lines: 177714,
        canary_probes: 2592,
        status: "SUCCESS",
        evidence: "CSM attractor loops + Feistel network + AntiAnalysis",
    },
    PassVerificationRow {
        id: "PRESET_MAX",
        name: "Preset Max (Extreme Cascade)",
        workload: "target_crackme.c",
        ir_insts: 450542,
        ir_ratio: 2066.7,
        barriers: 69270,
        volatile_stores: 34635,
        asm_lines: 835824,
        canary_probes: 13854,
        status: "SUCCESS",
        evidence: "Full extreme cascading pipeline: 835k ASM lines",
    },
];

#[derive(Clone, Debug, PartialEq)]
pub struct SmtCrackmeRow {
    pub id: &'static str,
    pub name: &'static str,
    pub std_status: &'static str,
    pub std_time: f64,
    pub std_states: usize,
    pub aware_status: &'static str,
    pub aware_time: f64,
    pub aware_states: usize,
    pub defense_mechanism: &'static str,
}

pub const SMT_CRACKME_DATA: &[SmtCrackmeRow] = &[
    SmtCrackmeRow {
        id: "BASELINE",
        name: "Unobfuscated Baseline",
        std_status: "SOLVED",
        std_time: 0.88,
        std_states: 19,
        aware_status: "SOLVED",
        aware_time: 0.88,
        aware_states: 19,
        defense_mechanism: "Zero defense; straight path exploration (19 states)",
    },
    SmtCrackmeRow {
        id: "SUBOBF",
        name: "Instruction Substitution",
        std_status: "SOLVED",
        std_time: 0.73,
        std_states: 22,
        aware_status: "SOLVED",
        aware_time: 0.73,
        aware_states: 22,
        defense_mechanism: "Bitwise arithmetic dilation; solved directly",
    },
    SmtCrackmeRow {
        id: "VOBF",
        name: "Vector Obfuscation",
        std_status: "SOLVED",
        std_time: 0.47,
        std_states: 20,
        aware_status: "SOLVED",
        aware_time: 0.47,
        aware_states: 20,
        defense_mechanism: "SIMD lane lifting; solver evaluates vector AST",
    },
    SmtCrackmeRow {
        id: "BCFOBF",
        name: "Bogus Control Flow",
        std_status: "SOLVED",
        std_time: 0.63,
        std_states: 33,
        aware_status: "SOLVED",
        aware_time: 0.63,
        aware_states: 33,
        defense_mechanism: "Hardware CPUID/RDTSC dynamic predicates",
    },
    SmtCrackmeRow {
        id: "CFFOBF",
        name: "Control Flow Flattening",
        std_status: "SOLVED",
        std_time: 1.05,
        std_states: 92,
        aware_status: "SOLVED",
        aware_time: 1.05,
        aware_states: 92,
        defense_mechanism: "Zero-SPOF branchless switch state machine (4.8x states)",
    },
    SmtCrackmeRow {
        id: "MBAOBF",
        name: "Mixed Boolean-Arithmetic",
        std_status: "SOLVED",
        std_time: 1.80,
        std_states: 23,
        aware_status: "SOLVED",
        aware_time: 1.80,
        aware_states: 23,
        defense_mechanism: "Polynomial identity expansion; AST complexity spike",
    },
    SmtCrackmeRow {
        id: "CSMOBF",
        name: "Chaos State Machine",
        std_status: "SOLVED",
        std_time: 2.24,
        std_states: 92,
        aware_status: "SOLVED",
        aware_time: 2.24,
        aware_states: 92,
        defense_mechanism: "Q32 logistic map chaotic attractor trajectories",
    },
    SmtCrackmeRow {
        id: "CONSTENC",
        name: "Constant Encryption",
        std_status: "EXHAUSTED",
        std_time: 0.39,
        std_states: 16,
        aware_status: "SOLVED",
        aware_time: 0.62,
        aware_states: 19,
        defense_mechanism: "Constructor-Bypass Trap: .init_array S-Box uninitialized",
    },
    SmtCrackmeRow {
        id: "PRESET_LOW",
        name: "Preset Low",
        std_status: "EXHAUSTED",
        std_time: 0.45,
        std_states: 18,
        aware_status: "SOLVED",
        aware_time: 4.29,
        aware_states: 136,
        defense_mechanism: "Constructor trap + 4.87x solver latency expansion",
    },
    SmtCrackmeRow {
        id: "PRESET_MID",
        name: "Preset Mid",
        std_status: "EXHAUSTED",
        std_time: 0.52,
        std_states: 21,
        aware_status: "SOLVED",
        aware_time: 4.62,
        aware_states: 142,
        defense_mechanism: "Interlocked cascade + 5.25x solver latency expansion",
    },
    SmtCrackmeRow {
        id: "PRESET_HIGH",
        name: "Preset High",
        std_status: "EXHAUSTED",
        std_time: 0.58,
        std_states: 24,
        aware_status: "SOLVED",
        aware_time: 4.48,
        aware_states: 150,
        defense_mechanism: "Chaotic state loops + Feistel network entanglement",
    },
    SmtCrackmeRow {
        id: "PRESET_MAX",
        name: "Preset Max",
        std_status: "EXHAUSTED",
        std_time: 0.65,
        std_states: 28,
        aware_status: "TIMEOUT",
        aware_time: 60.0,
        aware_states: 850,
        defense_mechanism: "State-Space Explosion: 850+ states, fs:[0x28] canary & CSM trap",
    },
];

#[derive(Clone, Debug, PartialEq)]
pub struct BarrierResilienceRow {
    pub id: &'static str,
    pub name: &'static str,
    pub workload: &'static str,
    pub orig_insts: usize,
    pub respect_insts: usize,
    pub respect_pct: f64,
    pub stripped_insts: usize,
    pub stripped_pct: f64,
    pub gap_pct: f64,
    pub barriers_count: usize,
    pub notes: &'static str,
}

pub const BARRIER_RESILIENCE_DATA: &[BarrierResilienceRow] = &[
    BarrierResilienceRow {
        id: "MBAOBF",
        name: "Mixed Boolean-Arithmetic",
        workload: "target_crypto.c",
        orig_insts: 1442,
        respect_insts: 1212,
        respect_pct: 84.0,
        stripped_insts: 473,
        stripped_pct: 32.8,
        gap_pct: 51.2,
        barriers_count: 65,
        notes: "Polynomial context identities protected by inline barriers",
    },
    BarrierResilienceRow {
        id: "VOBF",
        name: "Vector Obfuscation",
        workload: "target_crypto.c",
        orig_insts: 832,
        respect_insts: 632,
        respect_pct: 76.0,
        stripped_insts: 225,
        stripped_pct: 27.0,
        gap_pct: 49.0,
        barriers_count: 29,
        notes: "SIMD lane lifting prevents scalar dead-code elimination",
    },
    BarrierResilienceRow {
        id: "BCFOBF",
        name: "Bogus Control Flow",
        workload: "target_control_flow.c",
        orig_insts: 1800,
        respect_insts: 1238,
        respect_pct: 68.8,
        stripped_insts: 413,
        stripped_pct: 22.9,
        gap_pct: 45.9,
        barriers_count: 72,
        notes: "Hardware CPUID/RDTSC opaque predicates bound by memory fences",
    },
    BarrierResilienceRow {
        id: "SUBOBF",
        name: "Instruction Substitution",
        workload: "target_crypto.c",
        orig_insts: 561,
        respect_insts: 500,
        respect_pct: 89.1,
        stripped_insts: 273,
        stripped_pct: 48.7,
        gap_pct: 40.4,
        barriers_count: 34,
        notes: "Synthetic markers bound by volatile stores",
    },
    BarrierResilienceRow {
        id: "CONSTENC",
        name: "Constant Encryption",
        workload: "target_crypto.c",
        orig_insts: 1771,
        respect_insts: 1362,
        respect_pct: 76.9,
        stripped_insts: 851,
        stripped_pct: 48.1,
        gap_pct: 28.8,
        barriers_count: 94,
        notes: "Feistel network rounds + token entanglement protected",
    },
    BarrierResilienceRow {
        id: "SPLITOBF",
        name: "Basic Block Splitting",
        workload: "target_control_flow.c",
        orig_insts: 926,
        respect_insts: 485,
        respect_pct: 52.4,
        stripped_insts: 266,
        stripped_pct: 28.7,
        gap_pct: 23.7,
        barriers_count: 49,
        notes: "Basic block split chaining with opaque sinks",
    },
    BarrierResilienceRow {
        id: "ACDOBF",
        name: "Anti-Class-Dump (ObjC)",
        workload: "target_objc.m",
        orig_insts: 260,
        respect_insts: 122,
        respect_pct: 46.9,
        stripped_insts: 78,
        stripped_pct: 30.0,
        gap_pct: 16.9,
        barriers_count: 14,
        notes: "Dynamic stack XOR + Frida/Substrate hook traps + 14 barriers",
    },
    BarrierResilienceRow {
        id: "CFFOBF",
        name: "Control Flow Flattening",
        workload: "target_control_flow.c",
        orig_insts: 837,
        respect_insts: 243,
        respect_pct: 29.0,
        stripped_insts: 243,
        stripped_pct: 29.0,
        gap_pct: 0.0,
        barriers_count: 0,
        notes: "Zero-SPOF branchless switch state dispatch: 100% switches kept",
    },
    BarrierResilienceRow {
        id: "CSMOBF",
        name: "Chaos State Machine",
        workload: "target_control_flow.c",
        orig_insts: 837,
        respect_insts: 243,
        respect_pct: 29.0,
        stripped_insts: 243,
        stripped_pct: 29.0,
        gap_pct: 0.0,
        barriers_count: 0,
        notes: "Chaotic attractor state transitions immune to compiler folding",
    },
    BarrierResilienceRow {
        id: "PRESET_LOW",
        name: "Preset Low",
        workload: "target_crackme.c",
        orig_insts: 160639,
        respect_insts: 84047,
        respect_pct: 52.3,
        stripped_insts: 160639,
        stripped_pct: 100.0,
        gap_pct: 0.0,
        barriers_count: 8377,
        notes: "Composite defense: SSA def-use cycles prevent dead code elimination",
    },
    BarrierResilienceRow {
        id: "PRESET_MID",
        name: "Preset Mid",
        workload: "target_crackme.c",
        orig_insts: 125280,
        respect_insts: 76525,
        respect_pct: 61.1,
        stripped_insts: 125280,
        stripped_pct: 100.0,
        gap_pct: 0.0,
        barriers_count: 7678,
        notes: "Interlocked data-flow chains survive compiler passes intact",
    },
    BarrierResilienceRow {
        id: "PRESET_HIGH",
        name: "Preset High",
        workload: "target_crackme.c",
        orig_insts: 154959,
        respect_insts: 91556,
        respect_pct: 59.1,
        stripped_insts: 154959,
        stripped_pct: 100.0,
        gap_pct: 0.0,
        barriers_count: 9572,
        notes: "Chaotic attractor state feeds into Feistel constants",
    },
    BarrierResilienceRow {
        id: "PRESET_MAX",
        name: "Preset Max",
        workload: "target_crackme.c",
        orig_insts: 450542,
        respect_insts: 340150,
        respect_pct: 75.5,
        stripped_insts: 450542,
        stripped_pct: 100.0,
        gap_pct: 0.0,
        barriers_count: 69270,
        notes: "Full extreme cascading pipeline: 835k ASM lines retained",
    },
];

#[component]
pub fn BenchmarkPage() -> impl IntoView {
    let filter_cat = RwSignal::new("All".to_string());
    let search_query = RwSignal::new("".to_string());

    let categories = [
        "All",
        "Block Cipher",
        "Stream Cipher",
        "Hash / Digest",
        "MAC / Authenticator",
        "Asymmetric / PKC",
        "Post-Quantum (PQC)",
        "KDF / Password",
        "Lightweight / AEAD",
    ];

    let filtered_rows = move || {
        let cat = filter_cat.get();
        let q = search_query.get().trim().to_lowercase();

        BENCHMARK_DATA
            .iter()
            .filter(|r| {
                let matches_cat = cat == "All" || r.category == cat;
                let matches_search = q.is_empty()
                    || r.algo.to_lowercase().contains(&q)
                    || r.category.to_lowercase().contains(&q);
                matches_cat && matches_search
            })
            .cloned()
            .collect::<Vec<_>>()
    };

    view! {
        // ── Header ──────────────────────────────────────────────────────────
        <section class="hero" style="padding-bottom: 2rem;">
            <p class="hero-eyebrow">"Rigorous Security & Obfuscation Metrics"</p>
            <h1 class="hero-title">"Empirical Benchmark"</h1>
            <p class="hero-sub">
                "Comprehensive quantitative evaluation across 79 standardized cryptographic targets
                 (NIST, ISO/IEC, GB/T, IETF), 16 orthogonal compiler transformation passes,
                 and 4 enterprise cascading presets under automated reverse-engineering attack using
                 Angr 9.3 symbolic execution, Z3 4.12 SMT constraint solver, and aggressive LLVM 22/23 opt -O3 de-lifting."
            </p>
        </section>

        // ── Visualizations Gallery ───────────────────────────────────────────
        <section class="section page-wrap">
            <div class="mb-lg">
                <span class="section-chip">"Visualized Distributions & Resilience"</span>
                <h2>"Quantitative Distribution Charts"</h2>
                <p class="mt-sm text-muted">
                    "High-resolution vector distribution charts illustrating code footprint expansion,
                     CFG state-transition explosion, cyclomatic complexity dispersion, adversarial compiler stripping resilience, and SMT solver trapping."
                </p>
            </div>

            <div class="grid-2 mb-xl">
                // Chart 1: Size Expansion
                <div class="glass card-pad">
                    <h3 class="mb-sm">"1. Binary Code Size Expansion Multiplier"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Min, mean, and maximum binary expansion across the 8 cryptographic domains under the Max profile."
                    </p>
                    <img src="benchmark/size_expansion.svg" alt="Binary Size Expansion Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>

                // Chart 2: CFG Multipliers
                <div class="glass card-pad">
                    <h3 class="mb-sm">"2. CFG Basic Block & State-Transition Expansion"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Dual-metric comparative analysis of Basic Block multipliers (BB) vs. Global CFG transition edges."
                    </p>
                    <img src="benchmark/cfg_expansion.svg" alt="CFG Expansion Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>
            </div>

            <div class="grid-2 mb-xl">
                // Chart 3: Cyclomatic Complexity
                <div class="glass card-pad">
                    <h3 class="mb-sm">"3. Cyclomatic Complexity V(G) Dispersion"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Scatter comparison of baseline complexity (4–15) versus obfuscated complexity (30–110)."
                    </p>
                    <img src="benchmark/cyclomatic_complexity.svg" alt="Cyclomatic Complexity Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>

                // Chart 4: Symbolic Traversal: Solver Trapping Rate
                <div class="glass card-pad">
                    <h3 class="mb-sm">"4. Symbolic Traversal: Solver Trapping Rate"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Automated path exploration convergence vs. state space saturation on Baseline vs. Ensia Max."
                    </p>
                    <img src="benchmark/symbolic_execution_resilience.svg" alt="Symbolic Execution Resilience Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>
            </div>

            <div class="grid-2 mb-xl">
                // Chart 5: Barrier Protection Gap
                <div class="glass card-pad">
                    <h3 class="mb-sm">"5. Adversarial Stripping: Barrier Protection Gap"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Direct comparison of IR retention under opt -O3: respecting memory barriers vs. stripped barriers."
                    </p>
                    <img src="benchmark/barrier_protection_gap.svg" alt="Barrier Protection Gap Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>

                // Chart 6: Real-World SMT Crackme Defense
                <div class="glass card-pad">
                    <h3 class="mb-sm">"6. Real-World SMT & Symbolic Crackme Defense"</h3>
                    <p class="text-xs text-muted mb-md">
                        "Angr 9.3 + Z3 4.12 key-recovery latency: Standard Angr trapped by Constructor Trap; Preset Max triggers solver timeout."
                    </p>
                    <img src="benchmark/symbolic_crackme_resilience.svg" alt="Symbolic Crackme Resilience Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>
            </div>

            // Chart 7: Full Radar
            <div class="glass card-pad mb-xl text-center">
                <h3 class="mb-sm">"7. Multi-Dimensional Reverse-Engineering Resistance Profile"</h3>
                <p class="text-xs text-muted mb-md">
                    "8-Dimensional radar comparison showing balanced defense across Code Footprint, BB Density, CFG Transitions, Cyclomatic V(G), and SMT Resistance."
                </p>
                <div style="max-width: 680px; margin: 0 auto;">
                    <img src="benchmark/category_radar.svg" alt="Cryptographic Category Radar Chart" class="w-full rounded shadow" style="border: 1px solid var(--c-border); background: #0f172a;" />
                </div>
            </div>
        </section>

        // ── Methodology & Threat Model ───────────────────────────────────────
        <section class="section page-wrap">
            <div class="glass card-pad-lg policy-section mb-xl">
                <span class="section-chip">"Rigorous Scientific Methodology"</span>
                <h2>"Evaluation Threat Model & Metrics Protocol"</h2>
                <div class="grid-2 mt-md">
                    <div>
                        <h4>"1. Threat Model & Adversary Capabilities"</h4>
                        <p class="text-sm mt-xs">
                            "We assume a motivated reverse engineer equipped with modern state-of-the-art automated deobfuscation
                             frameworks: symbolic execution engines (Angr / KLEE), automated SMT constraint solvers (Z3 / Bitwuzla),
                             dynamic taint analyzers (Triton), and AST-level decompilers (Ghidra, IDA Pro). The adversary seeks to
                             automatically prune opaque predicates, recover flattened dispatch tables, unroll state machines, and strip fences."
                        </p>
                    </div>
                    <div>
                        <h4>"2. Controlled Verification & Correctness"</h4>
                        <p class="text-sm mt-xs">
                            "Every single obfuscated binary across all 79 cryptographic algorithms must strictly pass 100% of standard
                             known-answer test vectors (NIST CAVP / ISO vectors). In addition, all 16 compiler passes undergo automated LLVM IR
                             structural validation (llvm-as & opt -passes=verify) to guarantee zero broken modules or invalid SSA dominance trees."
                        </p>
                    </div>
                    <div class="mt-md" style="grid-column: 1 / -1;">
                        <h4>"3. Note on Post-Quantum Cryptography (PQC) Harnesses"</h4>
                        <p class="text-sm mt-xs text-muted">
                            "The PQC targets in this benchmark suite (ML-DSA-44, ML-KEM-512, ML-KEM-768) are code-size measurement stubs (SIZE_ONLY test harnesses). Because they do not contain multi-round polynomial NTT loops in the test wrapper, automated symbolic execution terminates normally in under 5 seconds (marked as OK) without triggering solver state-space saturation."
                        </p>
                    </div>
                </div>
            </div>
        </section>

        // ── Section 1: Empirical Pass Verification Matrix ────────────────────
        <section class="section page-wrap">
            <div class="mb-lg">
                <span class="section-chip">"Independent Ground-Truth Verification"</span>
                <h2>"Empirical Pass Verification & LLVM IR / ASM Structural Audit"</h2>
                <p class="mt-sm">
                    "Every transformation pass and preset was verified under automated disassembly, LLVM IR syntax/semantic validation ("
                    <code class="font-mono">"llvm-as"</code>
                    " and "
                    <code class="font-mono">"opt -passes=verify"</code>
                    "), and runtime execution to confirm that every protection layer actually applies in the native binary."
                </p>
            </div>

            <div class="grid-4 mb-lg">
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-success" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"16 / 16"</h3>
                    <p class="text-sm text-muted">"Passes Verified (100% Valid IR)"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"69,270"</h3>
                    <p class="text-sm text-muted">"Peak Memory Barriers (Preset Max)"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"835,824"</h3>
                    <p class="text-sm text-muted">"Peak ASM Output Lines (Preset Max)"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-success" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"100.0%"</h3>
                    <p class="text-sm text-muted">"Runtime CAVP Correctness"</p>
                </div>
            </div>

            <div class="glass card-pad mb-xl" style="overflow-x: auto;">
                <h4 class="mb-sm">"Pass Verification & Hardware-Enforced Invariant Audit (16 Passes + 4 Presets)"</h4>
                <table class="w-full text-left" style="border-collapse: collapse; font-size: 0.85rem;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--c-border); color: var(--c-text-muted);">
                            <th style="padding: 0.6rem 0.8rem;">"Pass / Profile ID"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Workload"</th>
                            <th style="padding: 0.6rem 0.8rem;">"IR Instructions"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Hardware Barriers"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Volatile Sinks"</th>
                            <th style="padding: 0.6rem 0.8rem;">"ASM Lines"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Canary / Probes"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Status"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Technical Evidence"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {PASS_VERIFICATION_DATA.iter().map(|p| {
                            let status_style = if p.status.contains("SUCCESS") || p.status.contains("VERIFIED") {
                                "color: var(--c-success); font-weight: bold;"
                            } else {
                                "color: var(--c-danger);"
                            };
                            view! {
                                <tr style="border-bottom: 1px solid var(--c-border-light);">
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace; font-weight: 600;">
                                        {p.name}
                                        <span class="text-xs text-muted block" style="font-family: monospace;">{p.id}</span>
                                    </td>
                                    <td style="padding: 0.5rem 0.8rem; color: var(--c-text-muted); font-family: monospace; font-size: 0.8rem;">{p.workload}</td>
                                    <td style="padding: 0.5rem 0.8rem;">
                                        {format!("{} ({:.1}x)", p.ir_insts, p.ir_ratio)}
                                    </td>
                                    <td style="padding: 0.5rem 0.8rem; font-weight: 600; color: var(--c-primary);">{p.barriers}</td>
                                    <td style="padding: 0.5rem 0.8rem;">{p.volatile_stores}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace;">{p.asm_lines}</td>
                                    <td style="padding: 0.5rem 0.8rem;">{p.canary_probes}</td>
                                    <td style=format!("padding: 0.5rem 0.8rem; {}", status_style)>{p.status}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-size: 0.8rem; color: var(--c-text-muted);">{p.evidence}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            </div>
        </section>

        // ── Section 2: Real-World SMT & Symbolic Execution Crackme Evaluation ─
        <section class="section page-wrap">
            <div class="mb-lg">
                <span class="section-chip">"Automated SMT & Symbolic Reverse-Engineering Defense"</span>
                <h2>"Real-World Crackme Solver Trapping & Latency Benchmark"</h2>
                <p class="mt-sm">
                    "Evaluated against state-of-the-art symbolic execution engine Angr 9.3 backed by Z3 4.12 on an authentic key-verification crackme workload.
                     Tested under dual adversary threat models: (1) Standard naive automated symbolic execution starting at "
                    <code class="font-mono">"main()"</code> ", and (2) Advanced constructor-aware symbolic execution executing all "
                    <code class="font-mono">".init_array"</code> " CRT constructors prior to symbolic exploration."
                </p>
            </div>

            <div class="grid-4 mb-lg">
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-success" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"0.88s"</h3>
                    <p class="text-sm text-muted">"Baseline Crackme Solving Time"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-danger" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"100.0%"</h3>
                    <p class="text-sm text-muted">"Standard Angr Trapping Rate (Trapped)"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"5.25x"</h3>
                    <p class="text-sm text-muted">"Production Solver Latency Dilation"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-danger" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"TIMEOUT"</h3>
                    <p class="text-sm text-muted">"Preset Max Solver Exhaustion (>60s)"</p>
                </div>
            </div>

            <div class="glass card-pad mb-xl" style="overflow-x: auto;">
                <h4 class="mb-sm">"Symbolic Execution Solving Latency & State Space Explosion Audit"</h4>
                <table class="w-full text-left" style="border-collapse: collapse; font-size: 0.85rem;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--c-border); color: var(--c-text-muted);">
                            <th style="padding: 0.6rem 0.8rem;">"Configuration"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Standard Angr Status"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Standard Time"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Constructor-Aware Status"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Aware Time"</th>
                            <th style="padding: 0.6rem 0.8rem;">"States Explored"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Trapping Mechanism & Defense Rationale"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {SMT_CRACKME_DATA.iter().map(|s| {
                            let std_style = if s.std_status == "EXHAUSTED" {
                                "color: var(--c-purple); font-weight: bold;"
                            } else {
                                "color: var(--c-success);"
                            };
                            let aware_style = if s.aware_status == "TIMEOUT" {
                                "color: var(--c-danger); font-weight: bold;"
                            } else if s.aware_time > 3.0 {
                                "color: var(--c-primary); font-weight: bold;"
                            } else {
                                "color: var(--c-success);"
                            };
                            view! {
                                <tr style="border-bottom: 1px solid var(--c-border-light);">
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace; font-weight: 600;">
                                        {s.name}
                                        <span class="text-xs text-muted block" style="font-family: monospace;">{s.id}</span>
                                    </td>
                                    <td style=format!("padding: 0.5rem 0.8rem; {}", std_style)>{s.std_status}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace;">{format!("{:.2}s", s.std_time)}</td>
                                    <td style=format!("padding: 0.5rem 0.8rem; {}", aware_style)>{s.aware_status}</td>
                                    <td style=format!("padding: 0.5rem 0.8rem; font-family: monospace; {}", aware_style)>{format!("{:.2}s", s.aware_time)}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-weight: 600;">{s.aware_states}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-size: 0.8rem; color: var(--c-text-muted);">{s.defense_mechanism}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            </div>

            <div class="grid-2 mb-xl">
                <div class="glass card-pad">
                    <h4>"\u{1F6E1} The Constructor Bypass Trap"</h4>
                    <p class="text-xs text-muted mt-xs">
                        "Automated symbolic execution frameworks (e.g. standard angr/KLEE) initialize state at entry point "
                        <code>"main()"</code> " and do not execute dynamic linker CRT constructors in " <code>".init_array"</code> "."
                        " Ensia entangles cryptographic constants with dynamic S-Boxes initialized in " <code>".init_array"</code> "."
                        " Naive exploration encounters uninitialized zeroes, triggering branch divergence and immediate solver exhaustion."
                    </p>
                </div>
                <div class="glass card-pad">
                    <h4>"\u{1F4A5} State-Space Saturation on Preset Max"</h4>
                    <p class="text-xs text-muted mt-xs">
                        "When Control Flow Flattening, Chaos State Machine, Bogus Control Flow, and Vector Obfuscation are cascaded in Preset Max,
                         active symbolic states exceed 850 within 60 seconds. Solver queries on chaotic polynomial attractor transitions
                         cause exponential path explosion, resulting in complete symbolic execution timeout (>60.0s)."
                    </p>
                </div>
            </div>
        </section>

        // ── Section 3: LLVM IR Optimization Stripping & De-Lifting Retention Audit ─────
        <section class="section page-wrap">
            <div class="mb-lg">
                <span class="section-chip">"Adversarial Red-Team Evaluation"</span>
                <h2>"LLVM IR Optimization Stripping & De-Lifting Retention Audit"</h2>
                <p class="mt-sm">
                    "Evaluated against aggressive compiler deobfuscation attacks: "
                    <code class="font-mono">"opt -passes=default<O3>"</code> " and "
                    <code class="font-mono">"opt -passes=sccp,simplifycfg,instcombine,dce,gvn"</code>
                    " applied directly to obfuscated IR, with and without polymorphic inline barriers stripped."
                </p>
            </div>

            <div class="grid-4 mb-lg">
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-success" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"84.0%"</h3>
                    <p class="text-sm text-muted">"MBA opt -O3 Retention"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"+51.2%"</h3>
                    <p class="text-sm text-muted">"Peak Barrier Protection Gap"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"100.0%"</h3>
                    <p class="text-sm text-muted">"Zero-SPOF Switch Retention (0 lost)"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-danger" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"100.0%"</h3>
                    <p class="text-sm text-muted">"Preset Stripped Retention (SSA Locked)"</p>
                </div>
            </div>

            <div class="glass card-pad mb-xl" style="overflow-x: auto;">
                <h4 class="mb-sm">"Per-Pass Adversarial Stripping Audit Metrics (Barrier-Respecting vs. Stripped)"</h4>
                <table class="w-full text-left" style="border-collapse: collapse; font-size: 0.85rem;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--c-border); color: var(--c-text-muted);">
                            <th style="padding: 0.6rem 0.8rem;">"Obfuscation Pass"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Target Workload"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Original IR"</th>
                            <th style="padding: 0.6rem 0.8rem;">"opt -O3 Retention"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Stripped Retention"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Protection Gap"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Barriers"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Architectural Protection Notes"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {BARRIER_RESILIENCE_DATA.iter().map(|b| {
                            let gap_style = if b.gap_pct > 30.0 {
                                "color: var(--c-amber); font-weight: bold;"
                            } else if b.gap_pct > 10.0 {
                                "color: var(--c-primary);"
                            } else {
                                "color: var(--c-text-muted);"
                            };
                            view! {
                                <tr style="border-bottom: 1px solid var(--c-border-light);">
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace; font-weight: 600;">
                                        {b.name}
                                        <span class="text-xs text-muted block" style="font-family: monospace;">{b.id}</span>
                                    </td>
                                    <td style="padding: 0.5rem 0.8rem; color: var(--c-text-muted); font-family: monospace; font-size: 0.8rem;">{b.workload}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace;">{b.orig_insts}</td>
                                    <td style="padding: 0.5rem 0.8rem; color: var(--c-success); font-weight: bold;">
                                        {format!("{} ({:.1}%)", b.respect_insts, b.respect_pct)}
                                    </td>
                                    <td style="padding: 0.5rem 0.8rem; font-weight: 600;">
                                        {format!("{} ({:.1}%)", b.stripped_insts, b.stripped_pct)}
                                    </td>
                                    <td style=format!("padding: 0.5rem 0.8rem; {}", gap_style)>
                                        {if b.gap_pct > 0.0 { format!("+{:.1}%", b.gap_pct) } else { "SSA Locked".to_string() }}
                                    </td>
                                    <td style="padding: 0.5rem 0.8rem; font-family: monospace;">{b.barriers_count}</td>
                                    <td style="padding: 0.5rem 0.8rem; font-size: 0.8rem; color: var(--c-text-muted);">{b.notes}</td>
                                </tr>
                            }
                        }).collect_view()}
                    </tbody>
                </table>
            </div>

            <div class="grid-2 mb-xl">
                <div class="glass card-pad">
                    <h4>"\u{1F517} The Barrier Protection Gap Explained"</h4>
                    <p class="text-xs text-muted mt-xs">
                        "Hardware memory barriers ("
                        <code class="font-mono">"prfm; dmb ishld; isb"</code>
                        " on ARM64, polymorphic lock fences on x86) create impenetrable optimization fences in the compiler SelectionDAG. When present, aggressive dead-code elimination (DCE) and instruction combining (InstCombine) are strictly prohibited from folding synthetic expressions across fences, yielding an empirical protection gap up to +51.2% in MBA and +49.0% in Vector Obfuscation."
                    </p>
                </div>
                <div class="glass card-pad">
                    <h4>"\u{26D3} Composite SSA Cyclic Defense in Presets"</h4>
                    <p class="text-xs text-muted mt-xs">
                        "In multi-pass cascading presets (Preset Low/Mid/High/Max), even if an adversary strips all inline memory barriers,
                         IR retention remains 100.0%. This occurs because Feistel round keys, Chaos State Machine state variables,
                         and Bogus Control Flow opaque predicates are mutually entangled in cyclic SSA def-use webs that standard LLVM passes cannot resolve."
                    </p>
                </div>
            </div>
        </section>

        // ── Section 4: Hardware Probing, Dynamic Taint Tracking & Anti-Patching ─
        <section class="section page-wrap">
            <div class="glass card-pad-lg policy-section mb-xl">
                <span class="section-chip">"Hardware Probing & Anti-Analysis"</span>
                <h2>"Dynamic Taint Tracking & Anti-Patching Resistance Audit"</h2>
                <div class="grid-3 mt-md">
                    <div class="glass card-pad">
                        <h4>"\u{1F6E1} 3-Tier Anti-Taint Engine"</h4>
                        <p class="text-xs text-muted mt-xs">
                            "1. Global Identity LUT memory dereferences break static taint propagation in Triton and Angr."
                        </p>
                        <p class="text-xs text-muted mt-xs">
                            "2. Implicit control-flow bit laundering evaluates " <code>"select"</code> " over pure constants to sever ALU register dependency chains."
                        </p>
                        <p class="text-xs text-muted mt-xs">
                            "3. 512-bit SIMD vector lane diffusion diffuses scalar taint across multiple vector register lanes."
                        </p>
                    </div>
                    <div class="glass card-pad">
                        <h4>"\u{1F50D} Anti-Debugging Silent Token Entanglement"</h4>
                        <p class="text-xs text-muted mt-xs">
                            "Direct kernel syscalls inspect " <code>"ptrace"</code> " (0x65), " <code>"prctl"</code> " (0x9d), RDTSC timing anomalies, DR0-DR7 hardware debug registers, and EFLAGS.TF single-stepping."
                        </p>
                        <p class="text-xs text-muted mt-xs">
                            "Silent Entanglement: If patched naively to return 0, downstream tokens evaluate cleanly. If traced dynamically, "
                            <code>"DbgToken != 0"</code> " silently injects arithmetic errors into cryptographic keys, generating corrupt outputs without raising crash alarms."
                        </p>
                    </div>
                    <div class="glass card-pad">
                        <h4>"\u{26A1} Anti-Hooking & AntiClassDump Abort"</h4>
                        <p class="text-xs text-muted mt-xs">
                            "Validates function prologue integrity against 5-byte " <code>"JMP rel32"</code> ", 14-byte " <code>"FF 25"</code> ", and Frida/Cydia Substrate trampolines (" <code>"B"</code> ", " <code>"BRK"</code> ", " <code>"LDR X16"</code> ")."
                        </p>
                        <p class="text-xs text-muted mt-xs">
                            "Objective-C runtime method replacement hooks (" <code>"class_replaceMethod"</code> ", " <code>"sel_registerName"</code> ") validated prior to dynamic registration. Active tampering triggers direct violent kernel syscall (" <code>"svc #0x80"</code> ") with SIGKILL."
                        </p>
                    </div>
                </div>
            </div>
        </section>

        // ── Full Interactive 79-Target Data Table ─────────────────────────────
        <section class="section page-wrap">
            <div class="mb-md flex items-center justify-between flex-wrap gap-md">
                <div>
                    <h2>"Full 79-Target Cryptographic Comparative Dataset"</h2>
                    <p class="text-sm text-muted">
                        "Real-world side-by-side empirical metrics: Baseline (unobfuscated) vs Ensia Max."
                    </p>
                </div>
                <div class="flex gap-sm flex-wrap items-center">
                    <input
                        type="text"
                        placeholder="Search algorithm..."
                        class="field-input text-sm"
                        style="width: 200px; padding: 0.4rem 0.8rem;"
                        prop:value=move || search_query.get()
                        on:input=move |e| search_query.set(event_target_value(&e))
                    />
                </div>
            </div>

            // Category filter pills
            <div class="flex gap-xs flex-wrap mb-md">
                {categories
                    .into_iter()
                    .map(|cat| {
                        let active = move || filter_cat.get() == cat;
                        view! {
                            <button
                                class="btn btn-ghost btn-sm"
                                class:active=active
                                style=move || if active() { "background: var(--c-primary); color: #fff;" } else { "" }
                                on:click=move |_| filter_cat.set(cat.to_string())
                            >
                                {cat}
                            </button>
                        }
                    })
                    .collect_view()}
            </div>

            // Responsive Data Table
            <div class="glass card-pad" style="overflow-x: auto;">
                <table class="w-full text-left" style="border-collapse: collapse; font-size: 0.85rem;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--c-border); color: var(--c-text-muted);">
                            <th style="padding: 0.6rem 0.8rem;">"Algorithm"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Category"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Binary Size (Exp)"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Basic Blocks (Exp)"</th>
                            <th style="padding: 0.6rem 0.8rem;">"CFG Edges (Exp)"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Cyclomatic V(G)"</th>
                            <th style="padding: 0.6rem 0.8rem;">"SMT Slowdown"</th>
                            <th style="padding: 0.6rem 0.8rem;">"Symbolic Status (Base / Max)"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let rows = filtered_rows();
                            if rows.is_empty() {
                                view! {
                                    <tr>
                                        <td colspan="8" class="text-center text-muted" style="padding: 2rem;">
                                            "No cryptographic algorithms matched your search."
                                        </td>
                                    </tr>
                                }.into_any()
                            } else {
                                rows.into_iter()
                                    .map(|r| {
                                        let sym_max_style = if r.max_timeout { "color: var(--c-danger); font-weight: bold;" } else { "color: var(--c-success);" };
                                        view! {
                                            <tr style="border-bottom: 1px solid var(--c-border-light);">
                                                <td style="padding: 0.5rem 0.8rem; font-family: monospace; font-weight: 600;">{r.algo}</td>
                                                <td style="padding: 0.5rem 0.8rem; color: var(--c-text-muted);">{r.category}</td>
                                                <td style="padding: 0.5rem 0.8rem;">
                                                    {format!("{} B → {} B ({:.1}x)", r.base_size, r.max_size, r.size_ratio)}
                                                </td>
                                                <td style="padding: 0.5rem 0.8rem;">
                                                    {format!("{} → {} ({:.1}x)", r.base_bbs, r.max_bbs, r.bb_ratio)}
                                                </td>
                                                <td style="padding: 0.5rem 0.8rem;">
                                                    {format!("{} → {} ({:.1}x)", r.base_edges, r.max_edges, r.edges_ratio)}
                                                </td>
                                                <td style="padding: 0.5rem 0.8rem;">
                                                    {format!("{} → {} ({:.1}x)", r.base_cyc, r.max_cyc, r.cyc_ratio)}
                                                </td>
                                                <td style="padding: 0.5rem 0.8rem; color: var(--c-primary);">
                                                    {format!("{:.1}x", r.z3_ratio)}
                                                </td>
                                                <td style="padding: 0.5rem 0.8rem;">
                                                    <span>{if r.base_timeout { "TIMEOUT" } else { "OK" }}</span>
                                                    " / "
                                                    <span style=sym_max_style>{if r.max_timeout { "TIMEOUT" } else { "OK" }}</span>
                                                </td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()
                                    .into_any()
                                }
                        }}
                    </tbody>
                </table>
            </div>
        </section>
    }
}
