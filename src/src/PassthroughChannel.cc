/*
 * LTESniffer multi-cell refactor — Step 3.
 */
#include "include/PassthroughChannel.h"
#include "include/RingBuffer.h"

PassthroughChannel::PassthroughChannel(RingBuffer* ring) : ring_(ring) {}

int PassthroughChannel::pull(cf_t* out[SRSRAN_MAX_PORTS],
                             uint32_t nsamples,
                             srsran_timestamp_t* /* t */) {
  if (ring_ == nullptr) return -1;
  return ring_->read(out, nsamples);
}

void PassthroughChannel::stop() {
  if (ring_) ring_->stop();
}
