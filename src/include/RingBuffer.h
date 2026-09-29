/*
 * LTESniffer multi-cell refactor — Step 3.
 *
 * RingBuffer is a multi-port, SPSC (single-producer / single-consumer)
 * sample queue used between WidebandCapture (writer) and one channel
 * (reader). When the writer would overflow the buffer, the oldest
 * samples are dropped and a counter is incremented — this matches the
 * "drop-oldest + count drops" policy from the spec.
 *
 * Invariants:
 *   - Exactly one writer thread calls write().
 *   - Exactly one reader thread calls read().
 *   - stop() unblocks any pending read() and causes it to return <0.
 *
 * For Step 3 simplicity uses two mutexes (write + read). Per the spec,
 * a lock-free / refcount optimisation may be done later if profiling
 * shows it matters.
 */
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <vector>

#include "srsran/phy/common/phy_common.h"  // cf_t, SRSRAN_MAX_PORTS

class RingBuffer {
public:
  /*
   * Build a ring buffer for `nof_ports` antenna ports with `capacity`
   * samples of slack per port (in addition to one block of headroom for
   * the writer). Typical: 8–16 × SRSRAN_SF_LEN_PRB(prb).
   */
  RingBuffer(uint32_t nof_ports, uint32_t capacity);

  // Disable copy/move for thread-safety clarity.
  RingBuffer(const RingBuffer&) = delete;
  RingBuffer& operator=(const RingBuffer&) = delete;

  /*
   * Writer: copy n samples per port from src[port] into the ring.
   * Non-blocking. If the ring would overflow, drops the oldest samples
   * and increments the drop counter.
   */
  void write(const cf_t* const* src, uint32_t n);

  /*
   * Reader: copy n samples per port from the ring into dst[port].
   * Blocks until n samples are available OR stop() is called.
   * Returns n on success, or < 0 if stopped.
   */
  int read(cf_t* const* dst, uint32_t n);

  /*
   * Wake up any blocked reader and prevent future reads from blocking.
   * Safe to call from any thread; idempotent.
   */
  void stop();

  uint64_t dropCount() const { return drop_count_.load(std::memory_order_acquire); }
  uint64_t writeCount() const { return write_count_.load(std::memory_order_acquire); }
  uint64_t readCount()  const { return read_count_.load(std::memory_order_acquire); }
  uint32_t numPorts()   const { return nof_ports_; }
  uint32_t capacity()   const { return capacity_; }
  bool     isStopped()  const { return stopped_.load(std::memory_order_acquire); }

private:
  // Per-port circular buffer of `capacity_` samples.
  std::vector<std::vector<cf_t>> buffers_;

  uint32_t nof_ports_;
  uint32_t capacity_;

  // Monotonic sample indices (in samples, not slots).
  std::atomic<uint64_t> write_count_{0};   // total samples ever written
  std::atomic<uint64_t> read_count_{0};    // total samples ever consumed
  std::atomic<uint64_t> drop_count_{0};    // samples dropped due to overflow
  std::atomic<bool>     stopped_{false};

  std::mutex           write_mutex_;       // protects write_count_ advancement + drop
  std::mutex           read_mutex_;
  std::condition_variable read_cv_;        // signals "data available" / "stopped"
};
