#include "Esp32Crypto.hpp"
#include "mbedtls_compat.h"
#include <cstring>
#include <esp_err.h>
#include <esp_log.h>
#include <mutex>
#include <psa/crypto.h>
#include <sodium.h>
#include <vector>

static const char *TAG = "Esp32Crypto";

// RFC 5054 3072-bit Group N
static const char *SRP_N_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static const char *SRP_g_HEX = "05";

struct Esp32SRPSession : public hap::platform::SRPSession {
  Esp32SRPSession(std::array<uint8_t, 16> s, std::vector<uint8_t> v,
                  std::string u, std::string p)
      : hap::platform::SRPSession(s, std::move(v), std::move(u), std::move(p)) {
  }

  std::vector<uint8_t> b;
  std::vector<uint8_t> B;
  std::vector<uint8_t> S;
  std::vector<uint8_t> K;
};

Esp32Crypto::Esp32Crypto() {}

static void ensure_psa_init() {
  static std::once_flag flag;
  std::call_once(flag, []() {
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
      ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)status);
    }
  });
}

static bool sha512_multi(std::initializer_list<std::span<const uint8_t>> parts,
                         uint8_t out[64]) {
  ensure_psa_init();
  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  if (psa_hash_setup(&op, PSA_ALG_SHA_512) != PSA_SUCCESS) {
    return false;
  }
  bool ok = true;
  for (auto part : parts) {
    if (psa_hash_update(&op, part.data(), part.size()) != PSA_SUCCESS) {
      ok = false;
      break;
    }
  }
  size_t len = 0;
  if (ok && psa_hash_finish(&op, out, 64, &len) != PSA_SUCCESS) {
    ok = false;
  }
  if (!ok) {
    psa_hash_abort(&op);
  }
  return ok;
}

static bool sha512_one(const uint8_t *data, size_t len, uint8_t out[64]) {
  return sha512_multi({std::span<const uint8_t>(data, len)}, out);
}

static bool hmac_sha512(std::span<const uint8_t> key,
                        std::span<const uint8_t> data,
                        uint8_t mac[64]) {
  constexpr size_t kBlock = 128;  // SHA-512 block size
  uint8_t k0[kBlock];
  memset(k0, 0, sizeof(k0));
  if (key.size() > kBlock) {
    if (!sha512_one(key.data(), key.size(), k0)) {
      return false;
    }
  } else {
    memcpy(k0, key.data(), key.size());
  }

  uint8_t ipad[kBlock];
  uint8_t opad[kBlock];
  for (size_t i = 0; i < kBlock; i++) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }

  uint8_t inner[64];
  uint8_t buf[kBlock + 64];
  memcpy(buf, ipad, kBlock);
  if (data.size() > 0) {
    memcpy(buf + kBlock, data.data(), data.size());
  }
  if (!sha512_one(buf, kBlock + data.size(), inner)) {
    return false;
  }

  memcpy(buf, opad, kBlock);
  memcpy(buf + kBlock, inner, 64);
  return sha512_one(buf, kBlock + 64, mac);
}

void Esp32Crypto::sha512(std::span<const uint8_t> data,
                         std::span<uint8_t, 64> output) {
  if (!sha512_multi({data}, output.data())) {
    ESP_LOGE(TAG, "SHA-512 failed");
  }
}

void Esp32Crypto::hkdf_sha512(std::span<const uint8_t> key,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t> info,
                              std::span<uint8_t> output) {
  // RFC 5869: PRK = HMAC-SHA512(salt, IKM); OKM = T(1..N) where
  // T(i) = HMAC-SHA512(PRK, T(i-1) | info | i).
  std::vector<uint8_t> prk(64);
  if (!hmac_sha512(salt, key, prk.data())) {
    ESP_LOGE(TAG, "HKDF extract failed");
    return;
  }

  uint8_t t[64];
  size_t t_len = 0;  // T(i-1), empty for i=1
  size_t offset = 0;
  for (uint8_t counter = 1; offset < output.size(); ++counter) {
    uint8_t block[64 + 255];
    size_t block_len = 0;
    if (t_len > 0) {
      memcpy(block, t, t_len);
      block_len = t_len;
    }
    memcpy(block + block_len, info.data(), info.size());
    block_len += info.size();
    block[block_len++] = counter;

    if (!hmac_sha512(std::span<const uint8_t>(prk.data(), prk.size()),
                     std::span<const uint8_t>(block, block_len), t)) {
      ESP_LOGE(TAG, "HKDF expand failed");
      return;
    }
    t_len = 64;
    size_t n = output.size() - offset;
    if (n > 64) {
      n = 64;
    }
    memcpy(output.data() + offset, t, n);
    offset += n;
  }
}

void Esp32Crypto::ed25519_generate_keypair(std::span<uint8_t, 32> public_key,
                                           std::span<uint8_t, 64> private_key) {
  crypto_sign_ed25519_keypair(public_key.data(), private_key.data());
}

void Esp32Crypto::ed25519_sign(std::span<const uint8_t, 64> private_key,
                               std::span<const uint8_t> message,
                               std::span<uint8_t, 64> signature) {
  unsigned long long sig_len;
  crypto_sign_ed25519_detached(signature.data(), &sig_len, message.data(),
                               message.size(), private_key.data());
}

bool Esp32Crypto::ed25519_verify(std::span<const uint8_t, 32> public_key,
                                 std::span<const uint8_t> message,
                                 std::span<const uint8_t, 64> signature) {
  return crypto_sign_ed25519_verify_detached(signature.data(), message.data(),
                                             message.size(),
                                             public_key.data()) == 0;
}

void Esp32Crypto::x25519_generate_keypair(std::span<uint8_t, 32> public_key,
                                          std::span<uint8_t, 32> private_key) {
  randombytes_buf(private_key.data(), 32);
  crypto_box_keypair(public_key.data(), private_key.data());
}

void Esp32Crypto::x25519_shared_secret(
    std::span<const uint8_t, 32> private_key,
    std::span<const uint8_t, 32> peer_public_key,
    std::span<uint8_t, 32> shared_secret) {
  int ret = crypto_scalarmult(shared_secret.data(), private_key.data(),
                              peer_public_key.data());
  (void)ret;
}

bool Esp32Crypto::chacha20_poly1305_encrypt_and_tag(
    std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> aad, std::span<const uint8_t> plaintext,
    std::span<uint8_t> ciphertext, std::span<uint8_t, 16> tag) {
  unsigned long long ciphertext_len;
  int ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
      ciphertext.data(), tag.data(), &ciphertext_len, plaintext.data(),
      plaintext.size(), aad.data(), aad.size(), NULL, nonce.data(), key.data());
  return ret == 0;
}

bool Esp32Crypto::chacha20_poly1305_decrypt_and_verify(
    std::span<const uint8_t, 32> key, std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> aad, std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, 16> tag, std::span<uint8_t> plaintext) {
  int ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
      plaintext.data(), NULL, ciphertext.data(), ciphertext.size(), tag.data(),
      aad.data(), aad.size(), nonce.data(), key.data());
  return ret == 0;
}

// --- SRP Utilities ---

static void mpi_to_bytes(const mbedtls_mpi *x, std::vector<uint8_t> &out) {
  size_t len = mbedtls_mpi_size(x);
  out.resize(len);
  mbedtls_mpi_write_binary(x, out.data(), len);
}

static void mpi_to_bytes_pad(const mbedtls_mpi *x, std::vector<uint8_t> &out,
                             size_t pad_len) {
  out.resize(pad_len);
  size_t len = mbedtls_mpi_size(x);
  if (len > pad_len)
    len = pad_len;
  mbedtls_mpi_write_binary(x, out.data() + (pad_len - len), len);
}

static size_t count_leading_zeros(const uint8_t *data, size_t len) {
  size_t z = 0;
  while (z < len && data[z] == 0) {
    z++;
  }
  return z;
}
std::unique_ptr<hap::platform::SRPSession>
Esp32Crypto::srp_new_verifier(std::string_view username,
                              std::string_view password) {
  std::array<uint8_t, 16> s;
  randombytes_buf(s.data(), s.size());

  // x = H(s | H(I | ":" | P))
  std::vector<uint8_t> inner_hash(64);
  {
    const uint8_t colon = ':';
    uint8_t inner[64];
    if (!sha512_multi({std::span<const uint8_t>(
                               reinterpret_cast<const uint8_t *>(username.data()),
                               username.size()),
                           std::span<const uint8_t>(&colon, 1),
                           std::span<const uint8_t>(
                               reinterpret_cast<const uint8_t *>(password.data()),
                               password.size())},
                          inner)) {
      ESP_LOGE(TAG, "srp_new_verifier: inner hash failed");
      return nullptr;
    }
    inner_hash.assign(inner, inner + 64);
  }

  std::vector<uint8_t> x_hash(64);
  if (!sha512_multi({s, inner_hash}, x_hash.data())) {
    ESP_LOGE(TAG, "srp_new_verifier: x hash failed");
    return nullptr;
  }

  // v = g^x mod N
  mbedtls_mpi N, g, x, v;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&g);
  mbedtls_mpi_init(&x);
  mbedtls_mpi_init(&v);

  int ret = mbedtls_mpi_read_string(&N, 16, SRP_N_HEX);
  if (ret != 0) {
    ESP_LOGE(TAG, "srp_new_verifier: Failed to parse SRP_N_HEX: %d", ret);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&v);
    return nullptr;
  }
  ret = mbedtls_mpi_read_string(&g, 16, SRP_g_HEX);
  if (ret != 0) {
    ESP_LOGE(TAG, "srp_new_verifier: Failed to parse SRP_g_HEX: %d", ret);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&v);
    return nullptr;
  }
  mbedtls_mpi_read_binary(&x, x_hash.data(), x_hash.size());

  ret = mbedtls_mpi_exp_mod(&v, &g, &x, &N, NULL);
  if (ret != 0) {
    ESP_LOGE(TAG, "srp_new_verifier: mbedtls_mpi_exp_mod failed: %d", ret);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&v);
    return nullptr;
  }

  std::vector<uint8_t> v_bytes;
  mpi_to_bytes(&v, v_bytes);
  ESP_LOGI(TAG, "SRP verifier generated: %zu bytes", v_bytes.size());

  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&g);
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&v);

  return std::make_unique<Esp32SRPSession>(s, v_bytes, std::string(username),
                                           std::string(password));
}

std::array<uint8_t, 16>
Esp32Crypto::srp_get_salt(hap::platform::SRPSession *session) {
  return session->salt;
}

std::vector<uint8_t>
Esp32Crypto::srp_get_public_key(hap::platform::SRPSession *session) {
  auto ess = static_cast<Esp32SRPSession *>(session);

  ess->b.resize(32);
  randombytes_buf(ess->b.data(), ess->b.size());

  mbedtls_mpi N, g, v, b, B, k_mpi, tmp;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&g);
  mbedtls_mpi_init(&v);
  mbedtls_mpi_init(&b);
  mbedtls_mpi_init(&B);
  mbedtls_mpi_init(&k_mpi);
  mbedtls_mpi_init(&tmp);

  int ret = mbedtls_mpi_read_string(&N, 16, SRP_N_HEX);
  if (ret != 0) {
    ESP_LOGE(TAG, "Failed to parse SRP_N_HEX: %d", ret);
    return {};
  }
  ret = mbedtls_mpi_read_string(&g, 16, SRP_g_HEX);
  if (ret != 0) {
    ESP_LOGE(TAG, "Failed to parse SRP_g_HEX: %d", ret);
    return {};
  }
  mbedtls_mpi_read_binary(&v, ess->verifier.data(), ess->verifier.size());
  mbedtls_mpi_read_binary(&b, ess->b.data(), ess->b.size());

  // k = H(N | PAD(g))
  // RFC 5054 says PAD(g). N is 3072 bits (384 bytes).
  std::vector<uint8_t> N_bytes, g_bytes_padded;
  mpi_to_bytes(&N, N_bytes);
  mpi_to_bytes_pad(&g, g_bytes_padded, N_bytes.size()); // Pad g to N size

  std::vector<uint8_t> k_hash(64);
  if (!sha512_multi({N_bytes, g_bytes_padded}, k_hash.data())) {
    ESP_LOGE(TAG, "k hash failed");
    return {};
  }

  mbedtls_mpi_read_binary(&k_mpi, k_hash.data(), k_hash.size());

  // B = (k*v + g^b) mod N
  // tmp = g^b mod N
  mbedtls_mpi_exp_mod(&tmp, &g, &b, &N, NULL);
  // B = k*v
  mbedtls_mpi_mul_mpi(&B, &k_mpi, &v);
  // B = B mod N (ADK does this before addition)
  mbedtls_mpi_mod_mpi(&B, &B, &N);
  // B = B + tmp
  mbedtls_mpi_add_mpi(&B, &B, &tmp);
  // B = B mod N
  mbedtls_mpi_mod_mpi(&B, &B, &N);

  mpi_to_bytes(&B, ess->B);
  ESP_LOGI(TAG, "SRP public key B generated: %zu bytes", ess->B.size());

  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&g);
  mbedtls_mpi_free(&v);
  mbedtls_mpi_free(&b);
  mbedtls_mpi_free(&B);
  mbedtls_mpi_free(&k_mpi);
  mbedtls_mpi_free(&tmp);

  session->server_public_key = ess->B;
  return ess->B;
}

bool Esp32Crypto::srp_set_client_public_key(
    hap::platform::SRPSession *session,
    std::span<const uint8_t> client_public) {
  session->client_public_key.assign(client_public.begin(), client_public.end());
  return true;
}

bool Esp32Crypto::srp_verify_client_proof(hap::platform::SRPSession *session,
                                          std::span<const uint8_t> proof) {
  auto ess = static_cast<Esp32SRPSession *>(session);

  mbedtls_mpi N, A, B, v, b, S, u_mpi;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&A);
  mbedtls_mpi_init(&B);
  mbedtls_mpi_init(&v);
  mbedtls_mpi_init(&b);
  mbedtls_mpi_init(&S);
  mbedtls_mpi_init(&u_mpi);

  mbedtls_mpi_read_string(&N, 16, SRP_N_HEX);
  mbedtls_mpi_read_binary(&A, session->client_public_key.data(),
                          session->client_public_key.size());
  mbedtls_mpi_read_binary(&B, ess->B.data(), ess->B.size());
  mbedtls_mpi_read_binary(&v, ess->verifier.data(), ess->verifier.size());
  mbedtls_mpi_read_binary(&b, ess->b.data(), ess->b.size());

  // u = H(PAD(A) | PAD(B))
  std::vector<uint8_t> A_pad, B_pad;
  size_t param_len = mbedtls_mpi_size(&N);
  mpi_to_bytes_pad(&A, A_pad, param_len);
  mpi_to_bytes_pad(&B, B_pad, param_len);

  std::vector<uint8_t> u_hash(64);
  if (!sha512_multi({A_pad, B_pad}, u_hash.data())) {
    ESP_LOGE(TAG, "u hash failed");
    return false;
  }

  mbedtls_mpi_read_binary(&u_mpi, u_hash.data(), u_hash.size());

  // S = (A * v^u)^b mod N
  // tmp = v^u mod N
  mbedtls_mpi tmp;
  mbedtls_mpi_init(&tmp);
  mbedtls_mpi_exp_mod(&tmp, &v, &u_mpi, &N, NULL);
  // tmp = A * tmp
  mbedtls_mpi_mul_mpi(&tmp, &A, &tmp);
  // S = tmp^b mod N
  mbedtls_mpi_exp_mod(&S, &tmp, &b, &N, NULL);
  mbedtls_mpi_free(&tmp);

  mpi_to_bytes(&S, ess->S);

  // K = H(S) where S has leading zeros stripped (HAP spec)
  size_t z_S = count_leading_zeros(ess->S.data(), ess->S.size());
  ess->K.resize(64);
  if (!sha512_multi(
          {std::span<const uint8_t>(ess->S.data() + z_S, ess->S.size() - z_S)},
          ess->K.data())) {
    ESP_LOGE(TAG, "K hash failed");
    return false;
  }

  // M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)
  // HAP Spec: A and B are padded to 384 bytes (SRP_PUBLIC_KEY_BYTES)
  // but leading zeros are stripped before hashing (HAP SRP flag)
  std::vector<uint8_t> hN(64), hg(64), hI(64);
  std::vector<uint8_t> N_bytes, g_bytes;
  mbedtls_mpi g_mpi;
  mbedtls_mpi_init(&g_mpi);
  mbedtls_mpi_read_string(&g_mpi, 16, SRP_g_HEX);
  mpi_to_bytes(&N, N_bytes);
  mpi_to_bytes(&g_mpi, g_bytes);

  if (!sha512_multi({N_bytes}, hN.data()) ||
      !sha512_multi({g_bytes}, hg.data()) ||
      !sha512_multi({std::span<const uint8_t>(
                            reinterpret_cast<const uint8_t *>(
                                session->username.data()),
                            session->username.size())},
                        hI.data())) {
    ESP_LOGE(TAG, "M1 pre-hash failed");
    mbedtls_mpi_free(&g_mpi);
    return false;
  }

  for (size_t i = 0; i < 64; i++)
    hN[i] ^= hg[i];

  std::vector<uint8_t> A_padded, B_padded;
  size_t param_size = 384;
  mpi_to_bytes_pad(&A, A_padded, param_size);
  mpi_to_bytes_pad(&B, B_padded, param_size);

  size_t z_A = count_leading_zeros(A_padded.data(), A_padded.size());
  size_t z_B = count_leading_zeros(B_padded.data(), B_padded.size());

  std::vector<uint8_t> M1_calc(64);
  if (!sha512_multi({hN, hI, ess->salt,
                         std::span<const uint8_t>(A_padded.data() + z_A,
                                                  A_padded.size() - z_A),
                         std::span<const uint8_t>(B_padded.data() + z_B,
                                                  B_padded.size() - z_B),
                         ess->K},
                        M1_calc.data())) {
    ESP_LOGE(TAG, "M1 hash failed");
    mbedtls_mpi_free(&g_mpi);
    return false;
  }

  if (proof.size() != M1_calc.size() ||
      std::memcmp(proof.data(), M1_calc.data(), proof.size()) != 0) {
    ESP_LOGE(TAG, "SRP Client Proof Failed");
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&u_mpi);
    mbedtls_mpi_free(&g_mpi);
    return false;
  }

  // M2 = H(A | M1 | K)
  ess->M2.resize(64);
  if (!sha512_multi({A_padded, M1_calc, ess->K}, ess->M2.data())) {
    ESP_LOGE(TAG, "M2 hash failed");
    mbedtls_mpi_free(&g_mpi);
    return false;
  }

  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&A);
  mbedtls_mpi_free(&B);
  mbedtls_mpi_free(&v);
  mbedtls_mpi_free(&b);
  mbedtls_mpi_free(&S);
  mbedtls_mpi_free(&u_mpi);
  mbedtls_mpi_free(&g_mpi);

  return true;
}

std::vector<uint8_t>
Esp32Crypto::srp_get_server_proof(hap::platform::SRPSession *session) {
  return session->M2;
}

std::vector<uint8_t>
Esp32Crypto::srp_get_session_key(hap::platform::SRPSession *session) {
  auto ess = static_cast<Esp32SRPSession *>(session);
  return ess->K;
}
