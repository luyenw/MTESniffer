/*
 * LTESniffer multi-cell refactor — Step 1.
 *
 * ISampleSource is the seam between the RF/front-end and any downstream
 * consumer (a single ue_sync in legacy mode, or a per-cell CellPipeline
 * once the multi-cell refactor lands). It abstracts the way samples are
 * produced so the rest of the codebase never has to know whether the
 * data came from a USRP, an IQ file, or a decimated channel.
 *
 * Invariants from the multi-cell spec:
 *   - Pull is blocking: returns the requested nsamples per port, or a
 *     negative value when stop() has been requested.
 *   - Consumers register exactly one pull() at a time; concurrent pulls
 *     on the same source are not supported here (they will be owned by
 *     dedicated per-cell channels in later steps).
 */
#pragma once

#include "srsran/phy/common/phy_common.h"  // SRSRAN_MAX_PORTS, cf_t
#include "srsran/phy/common/timestamp.h"   // srsran_timestamp_t

class ISampleSource {
public:
  virtual ~ISampleSource() = default;

  /*
   * Read nsamples complex samples per antenna port into out[].
   *   out[i]         : pointer to a buffer of at least nsamples cf_t (i in [0, nof_ports))
   *   nsamples       : number of samples to deliver per port
   *   t              : optional timestamp pointer (may be nullptr)
   * Returns nsamples on success, or a negative value if the source has
   * been stopped (or otherwise cannot satisfy the request).
   */
  virtual int pull(cf_t* out[SRSRAN_MAX_PORTS],
                   uint32_t nsamples,
                   srsran_timestamp_t* t) = 0;

  /*
   * Request the source to release any blocking pull() and never return
   * a positive sample count again. Safe to call from any thread.
   */
  virtual void stop() = 0;
};

/*
 * C-style callback bridging ISampleSource to srsRAN's ue_sync callback
 * signature. Used wherever a consumer needs an opaque void* handle
 * (e.g. srsran_ue_sync_init_multi_decim).
 */
inline int sample_source_recv_wrapper(void* h,
                                      cf_t* data_[SRSRAN_MAX_PORTS],
                                      uint32_t nsamples,
                                      srsran_timestamp_t* t) {
  return static_cast<ISampleSource*>(h)->pull(data_, nsamples, t);
}
