/*
 * LTESniffer multi-cell refactor — Step 3.
 *
 * FileSampleSource is an ISampleSource that reads complex samples from
 * a binary file (cf_t interleaved per port, or one file per port — see
 * constructor). It is intended for offline testing of the multi-cell
 * pipeline without SDR hardware.
 *
 * File format: raw cf_t (float complex, 8 bytes per sample), one port
 * after another (port 0 block, then port 1 block, ...). This matches
 * the layout srsran uses for IQ capture files.
 */
#pragma once

#include <atomic>
#include <cstdio>
#include <string>

#include "ISampleSource.h"

class FileSampleSource : public ISampleSource {
public:
  /*
   * Open `path` for reading. `nof_ports` is the number of antenna
   * ports interleaved in the file.
   */
  FileSampleSource(const std::string& path, uint32_t nof_ports);
  ~FileSampleSource() override;

  int pull(cf_t* out[SRSRAN_MAX_PORTS],
           uint32_t nsamples,
           srsran_timestamp_t* t) override;
  void stop() override;

private:
  std::FILE*       fp_;
  uint32_t         nof_ports_;
  std::atomic<bool> stopped_{false};
};
