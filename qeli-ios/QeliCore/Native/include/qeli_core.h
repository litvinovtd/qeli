#ifndef QELI_CORE_H
#define QELI_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void qeli_realtls_buf_free(uint8_t *ptr, size_t len);

void *qeli_realtls_new(
    const uint8_t *reality_pub,
    const uint8_t *short_id,
    const char *sni,
    uint8_t **out_hello,
    size_t *out_hello_len
);
int32_t qeli_realtls_recv(
    void *handle,
    const uint8_t *data,
    size_t len,
    uint8_t **out,
    size_t *out_len
);
int32_t qeli_realtls_seal(
    void *handle,
    const uint8_t *data,
    size_t len,
    uint8_t **out,
    size_t *out_len
);
int32_t qeli_realtls_open(
    void *handle,
    const uint8_t *data,
    size_t len,
    uint8_t **out,
    size_t *out_len
);
void qeli_realtls_free(void *handle);

void *qeli_mlkem_keygen(uint8_t **out_ek, size_t *out_ek_len);
int32_t qeli_mlkem_decapsulate(
    void *handle,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t **out_secret,
    size_t *out_secret_len
);
void qeli_mlkem_free(void *handle);

int32_t qeli_build_faketls_clienthello(
    const uint8_t *x25519_pub,
    const uint8_t *mlkem_ek,
    size_t mlkem_ek_len,
    const char *sni,
    size_t pad_to_min,
    uint8_t **out,
    size_t *out_len
);

#ifdef __cplusplus
}
#endif
#endif

