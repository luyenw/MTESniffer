/*
 * LTESniffer multi-cell refactor — Step 3.
 *
 * PassthroughChannel is an ISampleSource backed by a RingBuffer. It is
 * used for the cell whose nof_prb equals the capture sample rate (i.e.
 * the widest cell in the set). It performs no DSP — it just pulls from
 * the ring.
 */
#pragma once

#include "ISampleSource.h"

class RingBuffer;  // forward

class PassthroughChannel : public ISampleSource {
public:
  explicit PassthroughChannel(RingBuffer* ring);
  ~PassthroughChannel() override = default;

  int pull(cf_t* out[SRSRAN_MAX_PORTS],
           uint32_t nsamples,
           srsran_timestamp_t* t) override;
  void stop() override;

private:
  RingBuffer* ring_;
};
