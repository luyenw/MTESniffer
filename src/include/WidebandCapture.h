/*
 * LTESniffer multi-cell refactor — Step 3.
 *
 * WidebandCapture owns a single ISampleSource (typically an
 * RfSampleSource) and runs one thread that pulls fixed-size blocks and
 * broadcasts them to every registered RingBuffer sink.
 *
 * The capture thread is the only writer to each ring, so the SPSC
 * invariant of RingBuffer is preserved.
 *
 * Timestamps are intentionally ignored (passed as NULL to the source),
 * matching the legacy srsran_rf_recv_wrapper behaviour — there is no
 * need to synchronise timestamps across cells.
 */
#pragma once

#include <atomic>
#include <thread>
#include <vector>

#include "ISampleSource.h"

class RingBuffer;  // forward

class WidebandCapture {
public:
  /*
   * Build a capture that reads from `source` in blocks of `block_samples`
   * complex samples per port. The source must outlive the capture.
   */
  WidebandCapture(ISampleSource* source, uint32_t block_samples);
  ~WidebandCapture();

  WidebandCapture(const WidebandCapture&) = delete;
  WidebandCapture& operator=(const WidebandCapture&) = delete;

  /*
   * Register a sink. Must be called before start(). The ring must
   * outlive the capture (or be stopped before capture destruction).
   */
  void registerSink(RingBuffer* sink);

  /*
   * Start the capture thread. Returns false if no sink is registered
   * or the thread is already running.
   */
  bool start();

  /*
   * Stop the capture thread and wait for it to exit. Idempotent.
   */
  void stop();

  bool isRunning() const { return running_.load(std::memory_order_acquire); }

private:
  void runLoop();

  ISampleSource*        source_;
  uint32_t              block_samples_;
  std::vector<RingBuffer*> sinks_;

  std::thread           thread_;
  std::atomic<bool>     running_{false};
  std::atomic<bool>     stop_requested_{false};

  // Scratch buffers reused across pulls (one per port).
  std::vector<std::vector<cf_t>> scratch_;
};
