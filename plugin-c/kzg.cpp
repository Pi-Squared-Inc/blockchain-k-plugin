#include "eip4844/eip4844.h"
#include "plugin_util.h"
#include "setup/setup.h"
#include "common/alloc.h"

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

extern const char *trusted_setup_str;

extern "C" {

static void setup(KZGSettings *s) {
  /* We adapt the code of load_trusted_setup_file (setup/setup.c) to parse *
   * the contents of the mainnet trusted setup string */
  C_KZG_RET ret;
  int num_matches;
  uint64_t num_g1_points;
  uint64_t num_g2_points;
  uint8_t *g1_monomial_bytes = NULL;
  uint8_t *g1_lagrange_bytes = NULL;
  uint8_t *g2_monomial_bytes = NULL;
  int skip;
  int skip_total = 0;

  /* Allocate space for points */
  ret = c_kzg_calloc((void **)&g1_monomial_bytes, NUM_G1_POINTS, BYTES_PER_G1);
  if (ret != C_KZG_OK) goto out;
  ret = c_kzg_calloc((void **)&g1_lagrange_bytes, NUM_G1_POINTS, BYTES_PER_G1);
  if (ret != C_KZG_OK) goto out;
  ret = c_kzg_calloc((void **)&g2_monomial_bytes, NUM_G2_POINTS, BYTES_PER_G2);
  if (ret != C_KZG_OK) goto out;

  /* Read the number of g1 points */
  num_matches = sscanf(trusted_setup_str + skip_total, "%" SCNu64 "%n", &num_g1_points, &skip);
  if (num_matches != 1 || num_g1_points != NUM_G1_POINTS) {
    ret = C_KZG_BADARGS;
    goto out;
  }
  skip_total += skip;

  /* Read the number of g2 points */
  num_matches = sscanf(trusted_setup_str + skip_total, "%" SCNu64 "%n", &num_g2_points, &skip);
  if (num_matches != 1 || num_g2_points != NUM_G2_POINTS) {
    ret = C_KZG_BADARGS;
    goto out;
  }
  skip_total += skip;

  /* Read all of the g1 points in Lagrange form, byte by byte */
  for (size_t i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
    num_matches = sscanf(trusted_setup_str + skip_total, "%2hhx%n", &g1_lagrange_bytes[i], &skip);
    if (num_matches != 1) {
      ret = C_KZG_BADARGS;
      goto out;
    }
    skip_total += skip;
  }

  /* Read all of the g2 points in monomial form, byte by byte */
  for (size_t i = 0; i < NUM_G2_POINTS * BYTES_PER_G2; i++) {
    num_matches = sscanf(trusted_setup_str + skip_total, "%2hhx%n", &g2_monomial_bytes[i], &skip);
    if (num_matches != 1) {
      ret = C_KZG_BADARGS;
      goto out;
    }
    skip_total += skip;
  }

  /* Read all of the g1 points in monomial form, byte by byte */
  for (size_t i = 0; i < NUM_G1_POINTS * BYTES_PER_G1; i++) {
    num_matches = sscanf(trusted_setup_str + skip_total, "%2hhx%n", &g1_monomial_bytes[i], &skip);
    if (num_matches != 1) {
      ret = C_KZG_BADARGS;
      goto out;
    }
    skip_total += skip;
  }

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

out:
  c_kzg_free(g1_monomial_bytes);
  c_kzg_free(g1_lagrange_bytes);
  c_kzg_free(g2_monomial_bytes);
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
