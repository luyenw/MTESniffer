/*
 * LTESniffer multi-cell refactor — Step 1.
 *
 * RfSampleSource: thin adapter from ISampleSource to srsran_rf_*.
 *
 * The behaviour matches the legacy srsran_rf_recv_wrapper that lived in
 * LTESniffer_Core.cc: it forwards to srsran_rf_recv_with_time_multi and
 * ignores the timestamp (passing NULL for time/ti), as the legacy code
 * did. We deliberately keep that quirk so the single-cell regression
 * behaviour is bit-identical.
 */
#include "include/RfSampleSource.h"

#include <iostream>

// srsRAN debug macro (no-op unless verbose mode is enabled).
#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/phy/utils/debug.h"
#ifdef __cplusplus
}
#undef I
#endif

RfSampleSource::RfSampleSource(srsran_rf_t* rf) : rf_(rf) {}

int RfSampleSource::pull(cf_t* out[SRSRAN_MAX_PORTS],
                         uint32_t nsamples,
                         srsran_timestamp_t* /* t */) {
  if (stopped_.load(std::memory_order_acquire) || rf_ == nullptr) {
    return -1;
  }

  DEBUG(" ----  Receive %d samples  ----", nsamples);

  // srsran_rf_recv_with_time_multi takes void** (non-const); cast through
  // a local array, identical to the legacy wrapper.
  void* ptr[SRSRAN_MAX_PORTS];
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    ptr[i] = out[i];
  }

  // bforce_overwrite = true, end_time = NULL, ts = NULL — same as legacy.
  return srsran_rf_recv_with_time_multi(rf_, ptr, nsamples,
                                        /* bforce_overwrite */ true,
                                        /* end_time         */ nullptr,
                                        /* ts               */ nullptr);
}

void RfSampleSource::stop() {
  stopped_.store(true, std::memory_order_release);
}
