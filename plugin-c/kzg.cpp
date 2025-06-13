#include "eip4844/eip4844.h"
#include "plugin_util.h"
#include "setup/setup.h"

/* The following values for the parameters of the trusted setup have been *
 * copied from setup/setup.c */
/* The number of bytes in a g1 point. */
#define BYTES_PER_G1 48
/* The number of bytes in a g2 point. */
#define BYTES_PER_G2 96
/* The number of g1 points in a trusted setup. */
#define NUM_G1_POINTS FIELD_ELEMENTS_PER_BLOB
/* The number of g2 points in a trusted setup. */
#define NUM_G2_POINTS 65

extern const uint8_t g1_monomial_bytes[];
extern const uint8_t g1_lagrange_bytes[];
extern const uint8_t g2_monomial_bytes[];

extern "C" {

static void setup(KZGSettings *s) {
  C_KZG_RET ret;

  ret = load_trusted_setup(
      s,
      g1_monomial_bytes,
      NUM_G1_POINTS * BYTES_PER_G1,
      g1_lagrange_bytes,
      NUM_G1_POINTS * BYTES_PER_G1,
      g2_monomial_bytes,
      NUM_G2_POINTS * BYTES_PER_G2,
      0
  );

  if (ret != C_KZG_OK) {
    throw std::runtime_error("unable to load trusted setup");
  }
  return;
}

bool hook_KRYPTO_verifyKZGProof(struct string *commitment, struct string *z,
                                struct string *y, struct string *proof) {
  static thread_local KZGSettings settings;
  static thread_local bool once = true;
  if (once) {
    setup(&settings);
    once = false;
  }
  bool res;
  verify_kzg_proof(&res, (Bytes48 *)&commitment->data[0],
                   (Bytes32 *)&z->data[0], (Bytes32 *)&y->data[0],
                   (Bytes48 *)&proof->data[0], &settings);
  return res;
}
}
