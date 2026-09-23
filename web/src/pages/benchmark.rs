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
        base_size: 34576,
        max_size: 270872,
        size_ratio: 7.83,
        base_bbs: 18,
        max_bbs: 180,
        bb_ratio: 10.0,
        base_edges: 196,
        max_edges: 1561,
        edges_ratio: 7.96,
        base_cyc: 8,
        max_cyc: 52,
        cyc_ratio: 6.5,
        base_z3_s: 0.2784,
        max_z3_s: 1.9518,
        z3_ratio: 7.01,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes192_ecb",
        category: "Block Cipher",
        base_size: 30296,
        max_size: 274960,
        size_ratio: 9.08,
        base_bbs: 13,
        max_bbs: 94,
        bb_ratio: 7.23,
        base_edges: 187,
        max_edges: 1512,
        edges_ratio: 8.09,
        base_cyc: 4,
        max_cyc: 27,
        cyc_ratio: 6.75,
        base_z3_s: 0.2126,
        max_z3_s: 2.224,
        z3_ratio: 10.46,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes256_ecb",
        category: "Block Cipher",
        base_size: 30296,
        max_size: 258592,
        size_ratio: 8.54,
        base_bbs: 13,
        max_bbs: 120,
        bb_ratio: 9.23,
        base_edges: 187,
        max_edges: 1452,
        edges_ratio: 7.76,
        base_cyc: 4,
        max_cyc: 37,
        cyc_ratio: 9.25,
        base_z3_s: 0.2844,
        max_z3_s: 2.5042,
        z3_ratio: 8.81,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_cbc",
        category: "Block Cipher",
        base_size: 37640,
        max_size: 422648,
        size_ratio: 11.23,
        base_bbs: 17,
        max_bbs: 175,
        bb_ratio: 10.29,
        base_edges: 236,
        max_edges: 2096,
        edges_ratio: 8.88,
        base_cyc: 7,
        max_cyc: 52,
        cyc_ratio: 7.43,
        base_z3_s: 0.5218,
        max_z3_s: 1.8012,
        z3_ratio: 3.45,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ccm",
        category: "Block Cipher",
        base_size: 41216,
        max_size: 906688,
        size_ratio: 22.0,
        base_bbs: 16,
        max_bbs: 184,
        bb_ratio: 11.5,
        base_edges: 366,
        max_edges: 4155,
        edges_ratio: 11.35,
        base_cyc: 7,
        max_cyc: 56,
        cyc_ratio: 8.0,
        base_z3_s: 0.3813,
        max_z3_s: 2.6289,
        z3_ratio: 6.89,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_cfb",
        category: "Block Cipher",
        base_size: 37896,
        max_size: 484232,
        size_ratio: 12.78,
        base_bbs: 17,
        max_bbs: 150,
        bb_ratio: 8.82,
        base_edges: 240,
        max_edges: 2276,
        edges_ratio: 9.48,
        base_cyc: 7,
        max_cyc: 44,
        cyc_ratio: 6.29,
        base_z3_s: 0.5198,
        max_z3_s: 2.5466,
        z3_ratio: 4.9,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ctr",
        category: "Block Cipher",
        base_size: 37856,
        max_size: 394032,
        size_ratio: 10.41,
        base_bbs: 17,
        max_bbs: 202,
        bb_ratio: 11.88,
        base_edges: 225,
        max_edges: 1994,
        edges_ratio: 8.86,
        base_cyc: 8,
        max_cyc: 59,
        cyc_ratio: 7.38,
        base_z3_s: 0.384,
        max_z3_s: 2.1327,
        z3_ratio: 5.55,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ecb_mode",
        category: "Block Cipher",
        base_size: 37024,
        max_size: 578248,
        size_ratio: 15.62,
        base_bbs: 17,
        max_bbs: 145,
        bb_ratio: 8.53,
        base_edges: 212,
        max_edges: 2513,
        edges_ratio: 11.85,
        base_cyc: 7,
        max_cyc: 50,
        cyc_ratio: 7.14,
        base_z3_s: 0.5273,
        max_z3_s: 2.498,
        z3_ratio: 4.74,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_gcm",
        category: "Block Cipher",
        base_size: 43464,
        max_size: 935520,
        size_ratio: 21.52,
        base_bbs: 20,
        max_bbs: 291,
        bb_ratio: 14.55,
        base_edges: 402,
        max_edges: 4241,
        edges_ratio: 10.55,
        base_cyc: 10,
        max_cyc: 80,
        cyc_ratio: 8.0,
        base_z3_s: 0.5417,
        max_z3_s: 1.4417,
        z3_ratio: 2.66,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_ofb",
        category: "Block Cipher",
        base_size: 37576,
        max_size: 455576,
        size_ratio: 12.12,
        base_bbs: 17,
        max_bbs: 198,
        bb_ratio: 11.65,
        base_edges: 220,
        max_edges: 2239,
        edges_ratio: 10.18,
        base_cyc: 7,
        max_cyc: 56,
        cyc_ratio: 8.0,
        base_z3_s: 0.4621,
        max_z3_s: 1.1787,
        z3_ratio: 2.55,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_siv",
        category: "Block Cipher",
        base_size: 52080,
        max_size: 866088,
        size_ratio: 16.63,
        base_bbs: 12,
        max_bbs: 140,
        bb_ratio: 11.67,
        base_edges: 413,
        max_edges: 4348,
        edges_ratio: 10.53,
        base_cyc: 4,
        max_cyc: 40,
        cyc_ratio: 10.0,
        base_z3_s: 0.1849,
        max_z3_s: 1.3532,
        z3_ratio: 7.32,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "aes_xts",
        category: "Block Cipher",
        base_size: 45008,
        max_size: 513216,
        size_ratio: 11.4,
        base_bbs: 26,
        max_bbs: 359,
        bb_ratio: 13.81,
        base_edges: 313,
        max_edges: 2907,
        edges_ratio: 9.29,
        base_cyc: 15,
        max_cyc: 107,
        cyc_ratio: 7.13,
        base_z3_s: 0.7748,
        max_z3_s: 1.2146,
        z3_ratio: 1.57,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ascon_aead128",
        category: "Lightweight / AEAD",
        base_size: 29896,
        max_size: 474872,
        size_ratio: 15.88,
        base_bbs: 12,
        max_bbs: 90,
        bb_ratio: 7.5,
        base_edges: 370,
        max_edges: 2219,
        edges_ratio: 6.0,
        base_cyc: 4,
        max_cyc: 27,
        cyc_ratio: 6.75,
        base_z3_s: 0.1834,
        max_z3_s: 1.9965,
        z3_ratio: 10.89,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ascon_hash256",
        category: "Lightweight / AEAD",
        base_size: 23088,
        max_size: 200576,
        size_ratio: 8.69,
        base_bbs: 6,
        max_bbs: 35,
        bb_ratio: 5.83,
        base_edges: 142,
        max_edges: 1128,
        edges_ratio: 7.94,
        base_cyc: 1,
        max_cyc: 8,
        cyc_ratio: 8.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.3795,
        z3_ratio: 13795.0,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ascon_xof128",
        category: "Lightweight / AEAD",
        base_size: 23344,
        max_size: 200600,
        size_ratio: 8.59,
        base_bbs: 6,
        max_bbs: 14,
        bb_ratio: 2.33,
        base_edges: 164,
        max_edges: 1196,
        edges_ratio: 7.29,
        base_cyc: 1,
        max_cyc: 4,
        cyc_ratio: 4.0,
        base_z3_s: 0.0001,
        max_z3_s: 0.9219,
        z3_ratio: 9219.0,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "bcrypt",
        category: "KDF / Password",
        base_size: 33584,
        max_size: 426816,
        size_ratio: 12.71,
        base_bbs: 3,
        max_bbs: 11,
        bb_ratio: 3.67,
        base_edges: 302,
        max_edges: 2333,
        edges_ratio: 7.73,
        base_cyc: 1,
        max_cyc: 4,
        cyc_ratio: 4.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.2094,
        z3_ratio: 12094.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2b256",
        category: "Hash / Digest",
        base_size: 28408,
        max_size: 307424,
        size_ratio: 10.82,
        base_bbs: 7,
        max_bbs: 73,
        bb_ratio: 10.43,
        base_edges: 171,
        max_edges: 1759,
        edges_ratio: 10.29,
        base_cyc: 3,
        max_cyc: 20,
        cyc_ratio: 6.67,
        base_z3_s: 0.1121,
        max_z3_s: 1.4167,
        z3_ratio: 12.64,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2b512",
        category: "Hash / Digest",
        base_size: 28448,
        max_size: 315584,
        size_ratio: 11.09,
        base_bbs: 7,
        max_bbs: 92,
        bb_ratio: 13.14,
        base_edges: 175,
        max_edges: 1922,
        edges_ratio: 10.98,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.1282,
        max_z3_s: 1.4412,
        z3_ratio: 11.24,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2s128",
        category: "Hash / Digest",
        base_size: 28360,
        max_size: 229424,
        size_ratio: 8.09,
        base_bbs: 7,
        max_bbs: 64,
        bb_ratio: 9.14,
        base_edges: 171,
        max_edges: 1385,
        edges_ratio: 8.1,
        base_cyc: 3,
        max_cyc: 21,
        cyc_ratio: 7.0,
        base_z3_s: 0.0932,
        max_z3_s: 2.8666,
        z3_ratio: 30.76,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blake2s256",
        category: "Hash / Digest",
        base_size: 28368,
        max_size: 327920,
        size_ratio: 11.56,
        base_bbs: 7,
        max_bbs: 89,
        bb_ratio: 12.71,
        base_edges: 171,
        max_edges: 1828,
        edges_ratio: 10.69,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.0978,
        max_z3_s: 1.35,
        z3_ratio: 13.8,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "blowfish_ecb",
        category: "Block Cipher",
        base_size: 28536,
        max_size: 217056,
        size_ratio: 7.61,
        base_bbs: 13,
        max_bbs: 103,
        bb_ratio: 7.92,
        base_edges: 210,
        max_edges: 1289,
        edges_ratio: 6.14,
        base_cyc: 4,
        max_cyc: 33,
        cyc_ratio: 8.25,
        base_z3_s: 0.2329,
        max_z3_s: 1.7276,
        z3_ratio: 7.42,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "camellia_ecb",
        category: "Block Cipher",
        base_size: 24480,
        max_size: 278600,
        size_ratio: 11.38,
        base_bbs: 13,
        max_bbs: 148,
        bb_ratio: 11.38,
        base_edges: 190,
        max_edges: 1560,
        edges_ratio: 8.21,
        base_cyc: 4,
        max_cyc: 38,
        cyc_ratio: 9.5,
        base_z3_s: 0.2876,
        max_z3_s: 1.5461,
        z3_ratio: 5.38,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "cast128_ecb",
        category: "Block Cipher",
        base_size: 28400,
        max_size: 666016,
        size_ratio: 23.45,
        base_bbs: 13,
        max_bbs: 130,
        bb_ratio: 10.0,
        base_edges: 194,
        max_edges: 3770,
        edges_ratio: 19.43,
        base_cyc: 4,
        max_cyc: 36,
        cyc_ratio: 9.0,
        base_z3_s: 0.2319,
        max_z3_s: 1.3411,
        z3_ratio: 5.78,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "cast256_ecb",
        category: "Block Cipher",
        base_size: 27952,
        max_size: 421064,
        size_ratio: 15.06,
        base_bbs: 13,
        max_bbs: 152,
        bb_ratio: 11.69,
        base_edges: 188,
        max_edges: 2338,
        edges_ratio: 12.44,
        base_cyc: 4,
        max_cyc: 43,
        cyc_ratio: 10.75,
        base_z3_s: 0.222,
        max_z3_s: 1.3842,
        z3_ratio: 6.24,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "chacha20_poly1305",
        category: "Stream Cipher",
        base_size: 33400,
        max_size: 707208,
        size_ratio: 21.17,
        base_bbs: 12,
        max_bbs: 141,
        bb_ratio: 11.75,
        base_edges: 275,
        max_edges: 2921,
        edges_ratio: 10.62,
        base_cyc: 4,
        max_cyc: 34,
        cyc_ratio: 8.5,
        base_z3_s: 0.0001,
        max_z3_s: 1.4939,
        z3_ratio: 14939.0,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "chacha20_stream",
        category: "Stream Cipher",
        base_size: 27592,
        max_size: 499536,
        size_ratio: 18.1,
        base_bbs: 13,
        max_bbs: 74,
        bb_ratio: 5.69,
        base_edges: 238,
        max_edges: 2342,
        edges_ratio: 9.84,
        base_cyc: 4,
        max_cyc: 20,
        cyc_ratio: 5.0,
        base_z3_s: 0.223,
        max_z3_s: 1.6375,
        z3_ratio: 7.34,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "cmac_aes",
        category: "MAC / Authenticator",
        base_size: 33384,
        max_size: 417240,
        size_ratio: 12.5,
        base_bbs: 13,
        max_bbs: 154,
        bb_ratio: 11.85,
        base_edges: 207,
        max_edges: 2041,
        edges_ratio: 9.86,
        base_cyc: 4,
        max_cyc: 40,
        cyc_ratio: 10.0,
        base_z3_s: 0.2294,
        max_z3_s: 1.3411,
        z3_ratio: 5.85,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "cshake128",
        category: "Hash / Digest",
        base_size: 27680,
        max_size: 473448,
        size_ratio: 17.1,
        base_bbs: 7,
        max_bbs: 60,
        bb_ratio: 8.57,
        base_edges: 227,
        max_edges: 2440,
        edges_ratio: 10.75,
        base_cyc: 3,
        max_cyc: 17,
        cyc_ratio: 5.67,
        base_z3_s: 0.1255,
        max_z3_s: 1.6111,
        z3_ratio: 12.84,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "des_ecb",
        category: "Block Cipher",
        base_size: 27776,
        max_size: 327736,
        size_ratio: 11.8,
        base_bbs: 13,
        max_bbs: 144,
        bb_ratio: 11.08,
        base_edges: 143,
        max_edges: 1465,
        edges_ratio: 10.24,
        base_cyc: 4,
        max_cyc: 40,
        cyc_ratio: 10.0,
        base_z3_s: 0.2227,
        max_z3_s: 1.6669,
        z3_ratio: 7.48,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "des3_ecb",
        category: "Block Cipher",
        base_size: 28416,
        max_size: 308720,
        size_ratio: 10.86,
        base_bbs: 13,
        max_bbs: 111,
        bb_ratio: 8.54,
        base_edges: 149,
        max_edges: 1460,
        edges_ratio: 9.8,
        base_cyc: 4,
        max_cyc: 34,
        cyc_ratio: 8.5,
        base_z3_s: 0.2185,
        max_z3_s: 1.7214,
        z3_ratio: 7.88,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "dh2048",
        category: "Asymmetric / PKC",
        base_size: 40992,
        max_size: 1262960,
        size_ratio: 30.81,
        base_bbs: 5,
        max_bbs: 22,
        bb_ratio: 4.4,
        base_edges: 432,
        max_edges: 4209,
        edges_ratio: 9.74,
        base_cyc: 2,
        max_cyc: 14,
        cyc_ratio: 7.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.2581,
        z3_ratio: 12581.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "dsa2048",
        category: "Asymmetric / PKC",
        base_size: 40960,
        max_size: 1374160,
        size_ratio: 33.55,
        base_bbs: 7,
        max_bbs: 58,
        bb_ratio: 8.29,
        base_edges: 435,
        max_edges: 4596,
        edges_ratio: 10.57,
        base_cyc: 3,
        max_cyc: 20,
        cyc_ratio: 6.67,
        base_z3_s: 0.1293,
        max_z3_s: 1.2721,
        z3_ratio: 9.84,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ecdh_p256",
        category: "Asymmetric / PKC",
        base_size: 40960,
        max_size: 974512,
        size_ratio: 23.79,
        base_bbs: 6,
        max_bbs: 86,
        bb_ratio: 14.33,
        base_edges: 435,
        max_edges: 3432,
        edges_ratio: 7.89,
        base_cyc: 2,
        max_cyc: 18,
        cyc_ratio: 9.0,
        base_z3_s: 0.0001,
        max_z3_s: 0.7766,
        z3_ratio: 7766.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ecdsa_p256",
        category: "Asymmetric / PKC",
        base_size: 40992,
        max_size: 937664,
        size_ratio: 22.87,
        base_bbs: 9,
        max_bbs: 116,
        bb_ratio: 12.89,
        base_edges: 436,
        max_edges: 3435,
        edges_ratio: 7.88,
        base_cyc: 2,
        max_cyc: 30,
        cyc_ratio: 15.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.1895,
        z3_ratio: 11895.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ed25519",
        category: "Asymmetric / PKC",
        base_size: 32448,
        max_size: 749320,
        size_ratio: 23.09,
        base_bbs: 11,
        max_bbs: 74,
        bb_ratio: 6.73,
        base_edges: 387,
        max_edges: 3051,
        edges_ratio: 7.88,
        base_cyc: 4,
        max_cyc: 21,
        cyc_ratio: 5.25,
        base_z3_s: 0.1788,
        max_z3_s: 1.5034,
        z3_ratio: 8.41,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "gmac_aes",
        category: "MAC / Authenticator",
        base_size: 41248,
        max_size: 691064,
        size_ratio: 16.75,
        base_bbs: 18,
        max_bbs: 116,
        bb_ratio: 6.44,
        base_edges: 312,
        max_edges: 2940,
        edges_ratio: 9.42,
        base_cyc: 5,
        max_cyc: 32,
        cyc_ratio: 6.4,
        base_z3_s: 0.3582,
        max_z3_s: 1.4886,
        z3_ratio: 4.16,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "hkdf_sha256",
        category: "Hash / Digest",
        base_size: 37576,
        max_size: 419512,
        size_ratio: 11.16,
        base_bbs: 7,
        max_bbs: 64,
        bb_ratio: 9.14,
        base_edges: 226,
        max_edges: 2074,
        edges_ratio: 9.18,
        base_cyc: 3,
        max_cyc: 17,
        cyc_ratio: 5.67,
        base_z3_s: 0.1194,
        max_z3_s: 1.3414,
        z3_ratio: 11.23,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "hmac_sha256",
        category: "MAC / Authenticator",
        base_size: 37512,
        max_size: 382872,
        size_ratio: 10.21,
        base_bbs: 9,
        max_bbs: 64,
        bb_ratio: 7.11,
        base_edges: 203,
        max_edges: 1900,
        edges_ratio: 9.36,
        base_cyc: 4,
        max_cyc: 24,
        cyc_ratio: 6.0,
        base_z3_s: 0.1772,
        max_z3_s: 1.3653,
        z3_ratio: 7.7,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "idea_ecb",
        category: "Block Cipher",
        base_size: 28432,
        max_size: 290480,
        size_ratio: 10.22,
        base_bbs: 13,
        max_bbs: 128,
        bb_ratio: 9.85,
        base_edges: 196,
        max_edges: 1400,
        edges_ratio: 7.14,
        base_cyc: 4,
        max_cyc: 34,
        cyc_ratio: 8.5,
        base_z3_s: 0.2255,
        max_z3_s: 1.4552,
        z3_ratio: 6.45,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "kmac128",
        category: "Hash / Digest",
        base_size: 33416,
        max_size: 501952,
        size_ratio: 15.02,
        base_bbs: 7,
        max_bbs: 112,
        bb_ratio: 16.0,
        base_edges: 251,
        max_edges: 2551,
        edges_ratio: 10.16,
        base_cyc: 3,
        max_cyc: 29,
        cyc_ratio: 9.67,
        base_z3_s: 0.1171,
        max_z3_s: 1.3934,
        z3_ratio: 11.9,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "mars_ecb",
        category: "Block Cipher",
        base_size: 28656,
        max_size: 239928,
        size_ratio: 8.37,
        base_bbs: 13,
        max_bbs: 154,
        bb_ratio: 11.85,
        base_edges: 196,
        max_edges: 1500,
        edges_ratio: 7.65,
        base_cyc: 4,
        max_cyc: 42,
        cyc_ratio: 10.5,
        base_z3_s: 0.2268,
        max_z3_s: 1.7011,
        z3_ratio: 7.5,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "md5",
        category: "Hash / Digest",
        base_size: 27448,
        max_size: 622520,
        size_ratio: 22.68,
        base_bbs: 12,
        max_bbs: 120,
        bb_ratio: 10.0,
        base_edges: 148,
        max_edges: 2309,
        edges_ratio: 15.6,
        base_cyc: 5,
        max_cyc: 37,
        cyc_ratio: 7.4,
        base_z3_s: 0.1983,
        max_z3_s: 1.5831,
        z3_ratio: 7.98,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "mldsa44",
        category: "Post-Quantum (PQC)",
        base_size: 35128,
        max_size: 67392,
        size_ratio: 1.92,
        base_bbs: 4,
        max_bbs: 44,
        bb_ratio: 11.0,
        base_edges: 250,
        max_edges: 880,
        edges_ratio: 3.52,
        base_cyc: 1,
        max_cyc: 8,
        cyc_ratio: 8.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.0921,
        z3_ratio: 10921.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "mlkem512",
        category: "Post-Quantum (PQC)",
        base_size: 32672,
        max_size: 54768,
        size_ratio: 1.68,
        base_bbs: 4,
        max_bbs: 54,
        bb_ratio: 13.5,
        base_edges: 265,
        max_edges: 790,
        edges_ratio: 2.98,
        base_cyc: 1,
        max_cyc: 7,
        cyc_ratio: 7.0,
        base_z3_s: 0.0001,
        max_z3_s: 0.8719,
        z3_ratio: 8719.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "mlkem768",
        category: "Post-Quantum (PQC)",
        base_size: 47912,
        max_size: 56008,
        size_ratio: 1.17,
        base_bbs: 4,
        max_bbs: 20,
        bb_ratio: 5.0,
        base_edges: 375,
        max_edges: 790,
        edges_ratio: 2.11,
        base_cyc: 1,
        max_cyc: 4,
        cyc_ratio: 4.0,
        base_z3_s: 0.0001,
        max_z3_s: 0.6672,
        z3_ratio: 6672.0,
        base_timeout: false,
        max_timeout: false,
    },
    BenchmarkRow {
        algo: "pbkdf2_sha256",
        category: "Hash / Digest",
        base_size: 37576,
        max_size: 416960,
        size_ratio: 11.1,
        base_bbs: 7,
        max_bbs: 88,
        bb_ratio: 12.57,
        base_edges: 251,
        max_edges: 2068,
        edges_ratio: 8.24,
        base_cyc: 3,
        max_cyc: 24,
        cyc_ratio: 8.0,
        base_z3_s: 0.1219,
        max_z3_s: 1.4881,
        z3_ratio: 12.21,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "poly1305",
        category: "Hash / Digest",
        base_size: 32664,
        max_size: 215160,
        size_ratio: 6.59,
        base_bbs: 6,
        max_bbs: 42,
        bb_ratio: 7.0,
        base_edges: 207,
        max_edges: 1378,
        edges_ratio: 6.66,
        base_cyc: 1,
        max_cyc: 10,
        cyc_ratio: 10.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.4118,
        z3_ratio: 14118.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "present_ecb",
        category: "Block Cipher",
        base_size: 26984,
        max_size: 294664,
        size_ratio: 10.92,
        base_bbs: 13,
        max_bbs: 108,
        bb_ratio: 8.31,
        base_edges: 125,
        max_edges: 1298,
        edges_ratio: 10.38,
        base_cyc: 4,
        max_cyc: 33,
        cyc_ratio: 8.25,
        base_z3_s: 0.2215,
        max_z3_s: 1.5891,
        z3_ratio: 7.17,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "rc2_ecb",
        category: "Block Cipher",
        base_size: 28416,
        max_size: 278072,
        size_ratio: 9.79,
        base_bbs: 13,
        max_bbs: 129,
        bb_ratio: 9.92,
        base_edges: 191,
        max_edges: 1471,
        edges_ratio: 7.7,
        base_cyc: 4,
        max_cyc: 38,
        cyc_ratio: 9.5,
        base_z3_s: 0.2295,
        max_z3_s: 1.4988,
        z3_ratio: 6.53,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "rc4_stream",
        category: "Stream Cipher",
        base_size: 28368,
        max_size: 225336,
        size_ratio: 7.94,
        base_bbs: 13,
        max_bbs: 112,
        bb_ratio: 8.62,
        base_edges: 143,
        max_edges: 1260,
        edges_ratio: 8.81,
        base_cyc: 5,
        max_cyc: 32,
        cyc_ratio: 6.4,
        base_z3_s: 0.2274,
        max_z3_s: 1.6391,
        z3_ratio: 7.21,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "rc6_ecb",
        category: "Block Cipher",
        base_size: 28720,
        max_size: 182168,
        size_ratio: 6.34,
        base_bbs: 13,
        max_bbs: 135,
        bb_ratio: 10.38,
        base_edges: 191,
        max_edges: 1250,
        edges_ratio: 6.54,
        base_cyc: 4,
        max_cyc: 39,
        cyc_ratio: 9.75,
        base_z3_s: 0.2281,
        max_z3_s: 1.6019,
        z3_ratio: 7.02,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ripemd128",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 838640,
        size_ratio: 29.51,
        base_bbs: 7,
        max_bbs: 85,
        bb_ratio: 12.14,
        base_edges: 153,
        max_edges: 3140,
        edges_ratio: 20.52,
        base_cyc: 3,
        max_cyc: 21,
        cyc_ratio: 7.0,
        base_z3_s: 0.1245,
        max_z3_s: 1.7012,
        z3_ratio: 13.66,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "ripemd160",
        category: "Hash / Digest",
        base_size: 28464,
        max_size: 885568,
        size_ratio: 31.11,
        base_bbs: 7,
        max_bbs: 84,
        bb_ratio: 12.0,
        base_edges: 154,
        max_edges: 3340,
        edges_ratio: 21.69,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.1198,
        max_z3_s: 1.6881,
        z3_ratio: 14.09,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "rsa2048",
        category: "Asymmetric / PKC",
        base_size: 40992,
        max_size: 1506088,
        size_ratio: 36.74,
        base_bbs: 7,
        max_bbs: 100,
        bb_ratio: 14.29,
        base_edges: 435,
        max_edges: 4408,
        edges_ratio: 10.13,
        base_cyc: 3,
        max_cyc: 28,
        cyc_ratio: 9.33,
        base_z3_s: 0.1219,
        max_z3_s: 1.3411,
        z3_ratio: 11.0,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "salsa20_stream",
        category: "Stream Cipher",
        base_size: 32664,
        max_size: 172920,
        size_ratio: 5.29,
        base_bbs: 12,
        max_bbs: 63,
        bb_ratio: 5.25,
        base_edges: 209,
        max_edges: 1430,
        edges_ratio: 6.84,
        base_cyc: 4,
        max_cyc: 28,
        cyc_ratio: 7.0,
        base_z3_s: 0.0001,
        max_z3_s: 1.4881,
        z3_ratio: 14881.0,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "scrypt",
        category: "KDF / Password",
        base_size: 37576,
        max_size: 552240,
        size_ratio: 14.7,
        base_bbs: 7,
        max_bbs: 97,
        bb_ratio: 13.86,
        base_edges: 260,
        max_edges: 2342,
        edges_ratio: 9.01,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.1192,
        max_z3_s: 1.4112,
        z3_ratio: 11.84,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "seed_ecb",
        category: "Block Cipher",
        base_size: 28400,
        max_size: 181280,
        size_ratio: 6.38,
        base_bbs: 13,
        max_bbs: 139,
        bb_ratio: 10.69,
        base_edges: 184,
        max_edges: 1260,
        edges_ratio: 6.85,
        base_cyc: 4,
        max_cyc: 41,
        cyc_ratio: 10.25,
        base_z3_s: 0.2215,
        max_z3_s: 1.5891,
        z3_ratio: 7.17,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "serpent_ecb",
        category: "Block Cipher",
        base_size: 28400,
        max_size: 423856,
        size_ratio: 14.92,
        base_bbs: 13,
        max_bbs: 139,
        bb_ratio: 10.69,
        base_edges: 184,
        max_edges: 1974,
        edges_ratio: 10.73,
        base_cyc: 4,
        max_cyc: 44,
        cyc_ratio: 11.0,
        base_z3_s: 0.222,
        max_z3_s: 1.5019,
        z3_ratio: 6.77,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha1",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 272992,
        size_ratio: 9.61,
        base_bbs: 9,
        max_bbs: 102,
        bb_ratio: 11.33,
        base_edges: 162,
        max_edges: 1430,
        edges_ratio: 8.83,
        base_cyc: 5,
        max_cyc: 42,
        cyc_ratio: 8.4,
        base_z3_s: 0.1772,
        max_z3_s: 1.7012,
        z3_ratio: 9.6,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha224",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 240680,
        size_ratio: 8.47,
        base_bbs: 7,
        max_bbs: 92,
        bb_ratio: 13.14,
        base_edges: 173,
        max_edges: 1410,
        edges_ratio: 8.15,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.1245,
        max_z3_s: 1.6881,
        z3_ratio: 13.56,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha256",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 233360,
        size_ratio: 8.21,
        base_bbs: 8,
        max_bbs: 114,
        bb_ratio: 14.25,
        base_edges: 173,
        max_edges: 1378,
        edges_ratio: 7.97,
        base_cyc: 5,
        max_cyc: 46,
        cyc_ratio: 9.2,
        base_z3_s: 0.1415,
        max_z3_s: 1.5891,
        z3_ratio: 11.23,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha256_crypt",
        category: "Hash / Digest",
        base_size: 33504,
        max_size: 450112,
        size_ratio: 13.43,
        base_bbs: 7,
        max_bbs: 52,
        bb_ratio: 7.43,
        base_edges: 240,
        max_edges: 2120,
        edges_ratio: 8.83,
        base_cyc: 3,
        max_cyc: 27,
        cyc_ratio: 9.0,
        base_z3_s: 0.1192,
        max_z3_s: 1.4881,
        z3_ratio: 12.48,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha384",
        category: "Hash / Digest",
        base_size: 28456,
        max_size: 297800,
        size_ratio: 10.47,
        base_bbs: 7,
        max_bbs: 65,
        bb_ratio: 9.29,
        base_edges: 177,
        max_edges: 1614,
        edges_ratio: 9.12,
        base_cyc: 3,
        max_cyc: 21,
        cyc_ratio: 7.0,
        base_z3_s: 0.1284,
        max_z3_s: 1.5891,
        z3_ratio: 12.38,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha3_256",
        category: "Hash / Digest",
        base_size: 27448,
        max_size: 369168,
        size_ratio: 13.45,
        base_bbs: 7,
        max_bbs: 40,
        bb_ratio: 5.71,
        base_edges: 220,
        max_edges: 2204,
        edges_ratio: 10.02,
        base_cyc: 3,
        max_cyc: 14,
        cyc_ratio: 4.67,
        base_z3_s: 0.1245,
        max_z3_s: 1.4881,
        z3_ratio: 11.95,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha3_512",
        category: "Hash / Digest",
        base_size: 27448,
        max_size: 395048,
        size_ratio: 14.39,
        base_bbs: 7,
        max_bbs: 64,
        bb_ratio: 9.14,
        base_edges: 220,
        max_edges: 2185,
        edges_ratio: 9.93,
        base_cyc: 3,
        max_cyc: 20,
        cyc_ratio: 6.67,
        base_z3_s: 0.1219,
        max_z3_s: 1.5019,
        z3_ratio: 12.32,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sha512",
        category: "Hash / Digest",
        base_size: 28456,
        max_size: 288648,
        size_ratio: 10.14,
        base_bbs: 7,
        max_bbs: 68,
        bb_ratio: 9.71,
        base_edges: 177,
        max_edges: 1584,
        edges_ratio: 8.95,
        base_cyc: 3,
        max_cyc: 20,
        cyc_ratio: 6.67,
        base_z3_s: 0.1284,
        max_z3_s: 1.6019,
        z3_ratio: 12.48,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "shake128",
        category: "Hash / Digest",
        base_size: 27448,
        max_size: 311144,
        size_ratio: 11.34,
        base_bbs: 7,
        max_bbs: 64,
        bb_ratio: 9.14,
        base_edges: 220,
        max_edges: 2026,
        edges_ratio: 9.21,
        base_cyc: 3,
        max_cyc: 17,
        cyc_ratio: 5.67,
        base_z3_s: 0.1245,
        max_z3_s: 1.5891,
        z3_ratio: 12.76,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "shake256",
        category: "Hash / Digest",
        base_size: 27448,
        max_size: 293240,
        size_ratio: 10.68,
        base_bbs: 7,
        max_bbs: 77,
        bb_ratio: 11.0,
        base_edges: 220,
        max_edges: 1968,
        edges_ratio: 8.95,
        base_cyc: 3,
        max_cyc: 24,
        cyc_ratio: 8.0,
        base_z3_s: 0.1219,
        max_z3_s: 1.5891,
        z3_ratio: 13.04,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sm2",
        category: "Asymmetric / PKC",
        base_size: 40992,
        max_size: 1057488,
        size_ratio: 25.8,
        base_bbs: 10,
        max_bbs: 167,
        bb_ratio: 16.7,
        base_edges: 442,
        max_edges: 3734,
        edges_ratio: 8.45,
        base_cyc: 4,
        max_cyc: 49,
        cyc_ratio: 12.25,
        base_z3_s: 0.1834,
        max_z3_s: 1.2581,
        z3_ratio: 6.86,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sm3",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 271928,
        size_ratio: 9.57,
        base_bbs: 7,
        max_bbs: 40,
        bb_ratio: 5.71,
        base_edges: 173,
        max_edges: 1480,
        edges_ratio: 8.55,
        base_cyc: 3,
        max_cyc: 14,
        cyc_ratio: 4.67,
        base_z3_s: 0.1245,
        max_z3_s: 1.6881,
        z3_ratio: 13.56,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "sm4_ecb",
        category: "Block Cipher",
        base_size: 23344,
        max_size: 344008,
        size_ratio: 14.74,
        base_bbs: 13,
        max_bbs: 154,
        bb_ratio: 11.85,
        base_edges: 146,
        max_edges: 1478,
        edges_ratio: 10.12,
        base_cyc: 4,
        max_cyc: 44,
        cyc_ratio: 11.0,
        base_z3_s: 0.222,
        max_z3_s: 1.7019,
        z3_ratio: 7.67,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "tea_ecb",
        category: "Block Cipher",
        base_size: 21608,
        max_size: 208432,
        size_ratio: 9.65,
        base_bbs: 13,
        max_bbs: 107,
        bb_ratio: 8.23,
        base_edges: 122,
        max_edges: 1128,
        edges_ratio: 9.25,
        base_cyc: 4,
        max_cyc: 34,
        cyc_ratio: 8.5,
        base_z3_s: 0.2185,
        max_z3_s: 1.6881,
        z3_ratio: 7.73,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "tiger",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 143000,
        size_ratio: 5.03,
        base_bbs: 7,
        max_bbs: 106,
        bb_ratio: 15.14,
        base_edges: 173,
        max_edges: 1342,
        edges_ratio: 7.76,
        base_cyc: 3,
        max_cyc: 30,
        cyc_ratio: 10.0,
        base_z3_s: 0.1245,
        max_z3_s: 1.7012,
        z3_ratio: 13.66,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "twofish_ecb",
        category: "Block Cipher",
        base_size: 28400,
        max_size: 329712,
        size_ratio: 11.61,
        base_bbs: 13,
        max_bbs: 104,
        bb_ratio: 8.0,
        base_edges: 194,
        max_edges: 1460,
        edges_ratio: 7.52,
        base_cyc: 4,
        max_cyc: 32,
        cyc_ratio: 8.0,
        base_z3_s: 0.2295,
        max_z3_s: 1.6391,
        z3_ratio: 7.14,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "whirlpool",
        category: "Hash / Digest",
        base_size: 28416,
        max_size: 247568,
        size_ratio: 8.71,
        base_bbs: 7,
        max_bbs: 88,
        bb_ratio: 12.57,
        base_edges: 173,
        max_edges: 1422,
        edges_ratio: 8.22,
        base_cyc: 3,
        max_cyc: 24,
        cyc_ratio: 8.0,
        base_z3_s: 0.1245,
        max_z3_s: 1.6019,
        z3_ratio: 12.87,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "x25519",
        category: "Asymmetric / PKC",
        base_size: 32672,
        max_size: 243200,
        size_ratio: 7.44,
        base_bbs: 7,
        max_bbs: 83,
        bb_ratio: 11.86,
        base_edges: 387,
        max_edges: 1822,
        edges_ratio: 4.71,
        base_cyc: 3,
        max_cyc: 23,
        cyc_ratio: 7.67,
        base_z3_s: 0.1245,
        max_z3_s: 1.2581,
        z3_ratio: 10.11,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "xcbc_mac",
        category: "MAC / Authenticator",
        base_size: 33384,
        max_size: 432072,
        size_ratio: 12.94,
        base_bbs: 13,
        max_bbs: 111,
        bb_ratio: 8.54,
        base_edges: 207,
        max_edges: 1974,
        edges_ratio: 9.54,
        base_cyc: 4,
        max_cyc: 30,
        cyc_ratio: 7.5,
        base_z3_s: 0.222,
        max_z3_s: 1.4881,
        z3_ratio: 6.7,
        base_timeout: true,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "xtea_ecb",
        category: "Block Cipher",
        base_size: 21608,
        max_size: 237072,
        size_ratio: 10.97,
        base_bbs: 13,
        max_bbs: 128,
        bb_ratio: 9.85,
        base_edges: 122,
        max_edges: 1184,
        edges_ratio: 9.7,
        base_cyc: 4,
        max_cyc: 37,
        cyc_ratio: 9.25,
        base_z3_s: 0.2185,
        max_z3_s: 1.6391,
        z3_ratio: 7.5,
        base_timeout: false,
        max_timeout: true,
    },
    BenchmarkRow {
        algo: "zuc_stream",
        category: "Stream Cipher",
        base_size: 32664,
        max_size: 603208,
        size_ratio: 18.47,
        base_bbs: 13,
        max_bbs: 153,
        bb_ratio: 11.77,
        base_edges: 209,
        max_edges: 3055,
        edges_ratio: 14.62,
        base_cyc: 5,
        max_cyc: 44,
        cyc_ratio: 8.8,
        base_z3_s: 0.222,
        max_z3_s: 1.6881,
        z3_ratio: 7.6,
        base_timeout: true,
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
