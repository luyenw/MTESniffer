/*
 * LTESniffer multi-cell refactor — Step 1.
 *
 * RfSampleSource wraps a srsran_rf_t* and exposes it through the
 * ISampleSource seam. In the legacy single-cell path it replaces the
 * old srsran_rf_recv_wrapper free function; later steps will reuse the
 * same class as the "raw wideband" reader feeding WidebandCapture.
 */
#pragma once

#include <atomic>
#include "ISampleSource.h"

// C-only srsRAN header
#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/phy/rf/rf.h"
#ifdef __cplusplus
}
#undef I
#endif

class RfSampleSource : public ISampleSource {
public:
  explicit RfSampleSource(srsran_rf_t* rf);
  ~RfSampleSource() override = default;

  // ISampleSource
  int pull(cf_t* out[SRSRAN_MAX_PORTS],
           uint32_t nsamples,
           srsran_timestamp_t* t) override;
  void stop() override;

private:
  srsran_rf_t*       rf_;
  std::atomic<bool>  stopped_{false};
};
