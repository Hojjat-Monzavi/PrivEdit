// privedit_crypto.h -- PENC container.
//
// v3 (current):  Argon2id + XChaCha20-Poly1305 (AEAD)
// v1 (legacy):   PBKDF2-HMAC-SHA256 600k + AES-256-CBC + HMAC-SHA256
// v2 (legacy):   scrypt(N=2^17,r=8,p=1) + AES-256-CBC + HMAC-SHA256
//
// v3 layout:
//   [4]  "PENC"
//   [1]  version = 3
//   [16] salt
//   [24] nonce
//   [N]  XChaCha20-Poly1305 ciphertext (includes 16-byte Poly1305 tag)

#pragma once

#include <sodium.h>
#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace priv {

// ---------------------------------------------------------------- zlib ----
inline bool zCompress(const std::string& in, std::vector<uint8_t>& out) {
    uLongf bound = compressBound((uLong)in.size());
    out.resize(bound ? bound : 64);
    uLongf destLen = (uLongf)out.size();
    int ret = compress2(out.data(), &destLen,
                        reinterpret_cast<const Bytef*>(in.data()),
                        (uLong)in.size(), Z_BEST_COMPRESSION);
    if (ret != Z_OK) return false;
    out.resize(destLen);
    return true;
}

inline bool zDecompress(const uint8_t* in, size_t inLen, std::string& out) {
    uLongf bufLen = (uLongf)std::max<size_t>(inLen * 3, 4096);
    for (int tries = 0; tries < 24; ++tries) {
        out.resize(bufLen);
        uLongf destLen = bufLen;
        int ret = uncompress(reinterpret_cast<Bytef*>(&out[0]), &destLen,
                             reinterpret_cast<const Bytef*>(in), (uLong)inLen);
        if (ret == Z_OK) { out.resize(destLen); return true; }
        if (ret != Z_BUF_ERROR) return false;
        bufLen *= 2;
    }
    return false;
}

// -------------------------------------------------------------- crypto ----
namespace crypto {

// Must be called exactly once, before any other crypto:: call.
inline bool init() { return sodium_init() >= 0; }

// v3 (current) parameters.
constexpr size_t SALT_LEN_V3 = crypto_pwhash_SALTBYTES;                       // 16
constexpr size_t NONCE_LEN   = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
constexpr size_t KEY_LEN     = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;   // 32
constexpr size_t TAG_LEN     = crypto_aead_xchacha20poly1305_ietf_ABYTES;     // 16

// Argon2id "hard mode" -- OWASP 2025 recommendation.
constexpr unsigned long long ARGON2_OPS   = 3;
constexpr size_t             ARGON2_MEM   = 65536;   // 64 MiB
constexpr unsigned int       ARGON2_LANES = 4;

// PENC header constants.
constexpr char    MAGIC[4] = {'P','E','N','C'};
constexpr uint8_t VERSION_CURRENT = 3;

using Bytes = std::vector<uint8_t>;

inline void cleanse(Bytes& b) {
    if (!b.empty()) sodium_memzero(b.data(), b.size());
    b.clear();
}
inline void cleanse(std::string& s) {
    if (!s.empty()) sodium_memzero(&s[0], s.size());
    s.clear();
}

inline Bytes randomBytes(size_t n) {
    Bytes b(n);
    randombytes_buf(b.data(), n);
    return b;
}

// Convenience: fresh v3 salt.
inline Bytes randomSalt() { return randomBytes(SALT_LEN_V3); }

// --------------------------------------------------------------------------
//  DerivedKeys -- move-only, self-wiping.
// --------------------------------------------------------------------------
struct DerivedKeys {
    Bytes   salt;
    Bytes   key;      // 32-byte XChaCha20-Poly1305 key
    uint8_t version = 0;
    bool    valid   = false;

    DerivedKeys() = default;
    ~DerivedKeys() { wipe(); }

    DerivedKeys(const DerivedKeys&)            = delete;
    DerivedKeys& operator=(const DerivedKeys&) = delete;

    DerivedKeys(DerivedKeys&& o) noexcept { moveFrom(o); }
    DerivedKeys& operator=(DerivedKeys&& o) noexcept {
        if (this != &o) { wipe(); moveFrom(o); }
        return *this;
    }

    void moveFrom(DerivedKeys& o) noexcept {
        salt    = std::move(o.salt);
        key     = std::move(o.key);
        version = o.version;
        valid   = o.valid;
        o.version = 0;
        o.valid   = false;
    }

    void wipe() {
        cleanse(salt);
        cleanse(key);
        version = 0;
        valid   = false;
    }
};

// --------------------------------------------------------------------------
//  Argon2id key derivation (v3)
// --------------------------------------------------------------------------
inline DerivedKeys deriveKeysArgon2id(const std::string& pw, const Bytes& salt) {
    DerivedKeys d;
    d.salt = salt;
    d.key.resize(KEY_LEN);
    if (crypto_pwhash(d.key.data(), d.key.size(),
                      pw.data(), pw.size(),
                      salt.data(),
                      ARGON2_OPS, ARGON2_MEM,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        cleanse(d.key);
        throw std::runtime_error("Argon2id failed (out of memory?)");
    }
    d.version = VERSION_CURRENT;
    d.valid   = true;
    return d;
}

// --------------------------------------------------------------------------
//  XChaCha20-Poly1305 AEAD -- seal / unseal (v3)
// --------------------------------------------------------------------------
inline Bytes sealWithKeys(const std::string& plain, const DerivedKeys& k) {
    if (!k.valid || k.version != VERSION_CURRENT)
        throw std::runtime_error("no keys");

    Bytes nonce(NONCE_LEN);
    randombytes_buf(nonce.data(), nonce.size());

    Bytes cipher(plain.size() + TAG_LEN);
    unsigned long long cipherLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            cipher.data(), &cipherLen,
            reinterpret_cast<const unsigned char*>(plain.data()), plain.size(),
            nullptr, 0,
            nullptr,
            nonce.data(), k.key.data()) != 0) {
        throw std::runtime_error("XChaCha20-Poly1305 encryption failed");
    }
    cipher.resize((size_t)cipherLen);

    Bytes blob;
    blob.reserve(4 + 1 + k.salt.size() + NONCE_LEN + cipher.size());
    blob.insert(blob.end(), MAGIC, MAGIC + 4);
    blob.push_back(k.version);
    blob.insert(blob.end(), k.salt.begin(),  k.salt.end());
    blob.insert(blob.end(), nonce.begin(),   nonce.end());
    blob.insert(blob.end(), cipher.begin(),  cipher.end());
    return blob;
}

inline std::string unseal(const Bytes& blob, const std::string& pw,
                          DerivedKeys* outKeys = nullptr) {
    if (blob.size() < 5)
        throw std::runtime_error("not an encrypted file");
    if (memcmp(blob.data(), MAGIC, 4))
        throw std::runtime_error("not an encrypted file");

    const uint8_t version = blob[4];
    if (version != VERSION_CURRENT)
        throw std::runtime_error(
            "Unsupported PENC version. This build reads v3 only; "
            "convert legacy v1/v2 files with an older build first.");

    const size_t minLen = 4 + 1 + SALT_LEN_V3 + NONCE_LEN + TAG_LEN;
    if (blob.size() < minLen)
        throw std::runtime_error("corrupted (truncated)");

    size_t off = 5;
    Bytes salt(blob.begin() + off, blob.begin() + off + SALT_LEN_V3);
    off += SALT_LEN_V3;
    Bytes nonce(blob.begin() + off, blob.begin() + off + NONCE_LEN);
    off += NONCE_LEN;

    DerivedKeys k = deriveKeysArgon2id(pw, salt);

    Bytes plain(blob.size() - off);
    unsigned long long plainLen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain.data(), &plainLen,
            nullptr,
            blob.data() + off, (unsigned long long)(blob.size() - off),
            nullptr, 0,
            nonce.data(), k.key.data()) != 0) {
        throw std::runtime_error("wrong password or tampered file");
    }
    plain.resize((size_t)plainLen);

    std::string result(reinterpret_cast<char*>(plain.data()), plain.size());
    if (outKeys) *outKeys = std::move(k);
    return result;
}

} // namespace crypto

// ------------------------------------------------------ self-contained ----
inline constexpr unsigned char PRIVEXE_MAGIC[16] = {
    0x0A,'P','R','I','V','E','X','E','-','N','O','T','E','-','1',0x0A
};

inline bool findPrivexeMarker(const std::vector<uint8_t>& data,
                              size_t& markerOffset, uint64_t& payloadLen) {
    const size_t mlen = sizeof(PRIVEXE_MAGIC);
    if (data.size() < mlen + 8) return false;
    for (size_t i = data.size() - mlen - 8 + 1; i-- > 0; ) {
        if (memcmp(data.data() + i, PRIVEXE_MAGIC, mlen) != 0) continue;
        uint64_t n = 0;
        for (int j = 0; j < 8; ++j)
            n = (n << 8) | (uint64_t)data[i + mlen + j];
        if (i + mlen + 8 + n == data.size()) {
            markerOffset = i;
            payloadLen   = n;
            return true;
        }
        if (i == 0) break;
    }
    return false;
}

inline std::string packPayload(const std::string& cover,
                               const std::string& content) {
    std::string raw;
    uint32_t cl = (uint32_t)cover.size();
    raw.push_back((char)((cl >> 24) & 0xff));
    raw.push_back((char)((cl >> 16) & 0xff));
    raw.push_back((char)((cl >>  8) & 0xff));
    raw.push_back((char)( cl        & 0xff));
    raw += cover;
    raw += content;

    std::vector<uint8_t> comp;
    std::string out;
    if (zCompress(raw, comp) && comp.size() + 1 < raw.size()) {
        out.push_back(1);
        out.append(reinterpret_cast<const char*>(comp.data()), comp.size());
    } else {
        out.push_back(0);
        out += raw;
    }
    return out;
}

inline bool unpackPayload(const std::string& plain,
                          std::string& cover, std::string& content) {
    if (plain.size() < 1) return false;
    uint8_t format = (uint8_t)plain[0];
    std::string raw;
    if (format == 0) {
        raw.assign(plain, 1, std::string::npos);
    } else if (format == 1) {
        if (!zDecompress(reinterpret_cast<const uint8_t*>(plain.data() + 1),
                         plain.size() - 1, raw)) return false;
    } else {
        return false;
    }
    if (raw.size() < 4) return false;
    uint32_t cl = ((uint32_t)(unsigned char)raw[0] << 24)
                | ((uint32_t)(unsigned char)raw[1] << 16)
                | ((uint32_t)(unsigned char)raw[2] <<  8)
                |  (uint32_t)(unsigned char)raw[3];
    if ((uint64_t)cl + 4 > raw.size()) return false;
    cover.assign  (raw, 4, cl);
    content.assign(raw, 4 + cl, std::string::npos);
    return true;
}

inline std::vector<uint8_t> buildSelfContained(
        const std::vector<uint8_t>& stub,
        const std::string& cover,
        const std::string& content,
        const crypto::DerivedKeys& keys)
{
    std::string plain = packPayload(cover, content);
    crypto::Bytes blob = crypto::sealWithKeys(plain, keys);
    crypto::cleanse(plain);

    std::vector<uint8_t> out;
    out.reserve(stub.size() + sizeof(PRIVEXE_MAGIC) + 8 + blob.size());
    out.insert(out.end(), stub.begin(), stub.end());
    out.insert(out.end(), PRIVEXE_MAGIC, PRIVEXE_MAGIC + sizeof(PRIVEXE_MAGIC));

    uint64_t n = blob.size();
    for (int i = 7; i >= 0; --i)
        out.push_back((uint8_t)((n >> (8 * i)) & 0xff));

    out.insert(out.end(), blob.begin(), blob.end());
    return out;
}

} // namespace priv