#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-25s: ", label);

    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02X", data[i]);
    }

    printf("...\n");
}

double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1e6;
}

int main() {

    printf("\n");
    printf("=============================================\n");
    printf(" ML-KEM-768 (Kyber) Key Exchange Simulation\n");
    printf("=============================================\n");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem == NULL) {
        printf("ERROR: ML-KEM-768 not supported!\n");
        return 1;
    }

    printf("\nAlgorithm Details\n");
    printf("------------------------------\n");

    printf("Algorithm Name      : %s\n", kem->method_name);
    printf("Public Key Length   : %zu bytes\n", kem->length_public_key);
    printf("Secret Key Length   : %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext Length   : %zu bytes\n", kem->length_ciphertext);
    printf("Shared Secret Length: %zu bytes\n", kem->length_shared_secret);

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);

    uint8_t *ciphertext = malloc(kem->length_ciphertext);

    uint8_t *shared_secret_alice = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_bob = malloc(kem->length_shared_secret);

    struct timespec start, end;

    printf("\n[1] Alice generates keypair...\n");

    clock_gettime(CLOCK_MONOTONIC, &start);

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed!\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double keygen_time = time_diff_ms(start, end);

    printf("SUCCESS\n");
    printf("Key Generation Time : %.3f ms\n", keygen_time);

    print_hex("Public Key", public_key, kem->length_public_key);

    printf("\n[2] Bob encapsulates shared secret...\n");

    clock_gettime(CLOCK_MONOTONIC, &start);

    if (OQS_KEM_encaps(kem,
                       ciphertext,
                       shared_secret_bob,
                       public_key) != OQS_SUCCESS) {

        printf("Encapsulation failed!\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double encaps_time = time_diff_ms(start, end);

    printf("SUCCESS\n");
    printf("Encapsulation Time  : %.3f ms\n", encaps_time);

    print_hex("Ciphertext", ciphertext, kem->length_ciphertext);

    printf("\n[3] Alice decapsulates ciphertext...\n");

    clock_gettime(CLOCK_MONOTONIC, &start);

    if (OQS_KEM_decaps(kem,
                       shared_secret_alice,
                       ciphertext,
                       secret_key) != OQS_SUCCESS) {

        printf("Decapsulation failed!\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double decaps_time = time_diff_ms(start, end);

    printf("SUCCESS\n");
    printf("Decapsulation Time  : %.3f ms\n", decaps_time);

    printf("\n[4] Verifying shared secrets...\n");

    if (memcmp(shared_secret_alice,
               shared_secret_bob,
               kem->length_shared_secret) == 0) {

        printf("SUCCESS: Shared secrets MATCH!\n");

    } else {

        printf("ERROR: Shared secrets DO NOT match!\n");
    }

    print_hex("Alice Shared Secret",
              shared_secret_alice,
              kem->length_shared_secret);

    print_hex("Bob Shared Secret",
              shared_secret_bob,
              kem->length_shared_secret);

    printf("\nBandwidth Analysis\n");
    printf("------------------------------\n");

    size_t total_bandwidth =
        kem->length_public_key +
        kem->length_ciphertext;

    printf("Client -> Server : %zu bytes\n",
           kem->length_public_key);

    printf("Server -> Client : %zu bytes\n",
           kem->length_ciphertext);

    printf("Total Exchange   : %zu bytes (%.2f KB)\n",
           total_bandwidth,
           total_bandwidth / 1024.0);

    printf("\nTiming Summary\n");
    printf("------------------------------\n");

    printf("Key Generation : %.3f ms\n", keygen_time);
    printf("Encapsulation  : %.3f ms\n", encaps_time);
    printf("Decapsulation  : %.3f ms\n", decaps_time);

    printf("\nSimulation Completed Successfully!\n");

    free(public_key);
    free(secret_key);
    free(ciphertext);

    free(shared_secret_alice);
    free(shared_secret_bob);

    OQS_KEM_free(kem);

    return 0;
}
