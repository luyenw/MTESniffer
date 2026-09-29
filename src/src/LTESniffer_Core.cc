#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

// C++11 polyfill for std::make_unique (C++14 feature).
// The multi-cell refactor uses make_unique; the srsRAN fork we build
// against is C++11-only and breaks under -std=c++14 -Werror, so we
// stay on C++11 and provide make_unique locally.
#include <memory>
#if __cplusplus < 201402L
namespace std {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
#endif

#include "include/LTESniffer_Core.h"
#include "include/RingBuffer.h"
#include "include/PassthroughChannel.h"
#include "include/DecimChannel.h"
#include "include/RationalResampler.h"
#include "include/WidebandCapture.h"

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/common/crash_handler.h"
#include "srsran/common/gen_mch_tables.h"
#include "srsran/phy/io/filesink.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif

#define ENABLE_AGC_DEFAULT
using namespace std;

LTESniffer_Core::LTESniffer_Core(const Args& args):
  args(args),
  nof_workers(args.nof_sniffer_thread),
  sniffer_mode(args.sniffer_mode),
  api_mode(args.api_mode)
{
  // Step 2 (multi-cell refactor): the core is now a thin orchestrator.
  // All per-cell state (Phy, pcap, MCSTracking, HARQ, ULSchedule, ue_sync,
  // ue_mib, ta_buffer, est_cfo) lives inside CellPipeline.
  auto now = std::chrono::system_clock::now();
  std::time_t cur_time = std::chrono::system_clock::to_time_t(now);
  std::string str_cur_time(std::ctime(&cur_time));
  std::cout << str_cur_time << std::endl;
}

bool LTESniffer_Core::run(){
  // Step 3: dispatch to single-cell or multi-cell path based on
  // whether --cells was provided.
  if (args.cells.empty()) {
    return runSingleCell();
  }
  return runMultiCell();
}

bool LTESniffer_Core::runSingleCell(){
  // Step 2 path: one RF, one CellPipeline, legacy pcap filename.
  cell_search_cfg_t cell_detect_config = {.max_frames_pbch    = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
                                          .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
                                          .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
                                          .init_agc             = 0,
                                          .force_tdd            = false};
  srsran_cell_t cell;
  int ret;
  float search_cell_cfo = 0;

  /* Set CPU affinity (orchestrator thread) */
  if (args.cpu_affinity > -1) {
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();
    for (int i = 0; i < 8; i++) {
      if (((args.cpu_affinity >> i) & 0x01) == 1) {
        printf("Setting pdsch_ue with affinity to core %d\n", i);
        CPU_SET((size_t)i, &cpuset);
      }
    }
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset)) {
      ERROR("Error setting main thread affinity to %d", args.cpu_affinity);
      exit(-1);
    }
  }

#ifndef DISABLE_RF
  srsran_rf_t rf;
#endif
  std::unique_ptr<RfSampleSource> rf_source;

#ifndef DISABLE_RF
  if (args.input_file_name == "") {
    printf("Opening RF device with %d RX antennas...\n", args.rf_nof_rx_ant);
    char rfArgsCStr[1024];
    strncpy(rfArgsCStr, args.rf_args.c_str(), 1024);
    if (srsran_rf_open_multi(&rf, rfArgsCStr, args.rf_nof_rx_ant)) {
      fprintf(stderr, "Error opening rf\n");
      exit(-1);
    }
    rf_source.reset(new RfSampleSource(&rf));

    if (args.rf_gain > 0) {
      srsran_rf_set_rx_gain(&rf, args.rf_gain);
    } else {
      printf("Starting AGC thread...\n");
      if (srsran_rf_start_gain_thread(&rf, false)) {
        ERROR("Error opening rf");
        exit(-1);
      }
      srsran_rf_set_rx_gain(&rf, srsran_rf_get_rx_gain(&rf));
      cell_detect_config.init_agc = srsran_rf_get_rx_gain(&rf);
    }

    if (sniffer_mode == UL_MODE && args.ul_freq != 0) {
      printf("Tunning DL receiver to %.3f MHz\n",
             (args.rf_freq + args.file_offset_freq) / 1000000);
      if (srsran_rf_set_rx_freq(&rf, 0, args.rf_freq + args.file_offset_freq)) {}
      printf("Tunning UL receiver to %.3f MHz\n", (double)(args.ul_freq / 1000000));
      if (srsran_rf_set_rx_freq(&rf, 1, args.ul_freq)) {}
    } else if (sniffer_mode == UL_MODE && args.ul_freq == 0) {
      ERROR("Uplink Frequency must be defined in the UL Sniffer Mode \n");
    } else if (sniffer_mode == DL_MODE && args.ul_freq == 0) {
      printf("Tunning receiver to %.3f MHz\n",
             (args.rf_freq + args.file_offset_freq) / 1000000);
      srsran_rf_set_rx_freq(&rf, args.rf_nof_rx_ant,
                            args.rf_freq + args.file_offset_freq);
    } else if (sniffer_mode == DL_MODE && args.ul_freq != 0) {
      ERROR("Uplink Frequency must be 0 in the DL Sniffer Mode \n");
    }

    if (args.cell_search) {
      uint32_t ntrial = 0;
      do {
        ret = rf_search_and_decode_mib(&rf, args.rf_nof_rx_ant,
                                       &cell_detect_config, args.force_N_id_2,
                                       &cell, &search_cell_cfo);
        if (ret < 0) {
          ERROR("Error searching for cell");
          exit(-1);
        } else if (ret == 0 && !go_exit.load(std::memory_order_acquire)) {
          printf("Cell not found after %d trials. Trying again (Press Ctrl+C to exit)\n",
                 ntrial++);
        }
      } while (ret == 0 && !go_exit.load(std::memory_order_acquire));
    } else {
      cell.nof_prb          = args.nof_prb;
      cell.id               = args.cell_id;
      cell.nof_ports        = 2;
      cell.cp               = SRSRAN_CP_NORM;
      cell.phich_length     = SRSRAN_PHICH_NORM;
      cell.phich_resources  = SRSRAN_PHICH_R_1_6;
    }
    srsran_rf_stop_rx_stream(&rf);
    if (go_exit.load(std::memory_order_acquire)) {
      srsran_rf_close(&rf);
      exit(0);
    }

    int srate = srsran_sampling_freq_hz(cell.nof_prb);
    if (srate != -1) {
      printf("Setting sampling rate %.2f MHz\n", (float)srate / 1000000);
      float srate_rf = srsran_rf_set_rx_srate(&rf, (double)srate);
      if (srate_rf != srate) {
        ERROR("Could not set sampling rate");
        exit(-1);
      }
    } else {
      ERROR("Invalid number of PRB %d", cell.nof_prb);
      exit(-1);
    }
    INFO("Stopping RF and flushing buffer...\r");
  } else {
    cell.id              = args.file_cell_id;
    cell.cp              = SRSRAN_CP_NORM;
    cell.phich_length    = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1_6;
    cell.nof_ports       = args.file_nof_ports;
    cell.nof_prb         = args.nof_prb;
  }
#else
  cell.id              = args.file_cell_id;
  cell.cp              = SRSRAN_CP_NORM;
  cell.phich_length    = SRSRAN_PHICH_NORM;
  cell.phich_resources = SRSRAN_PHICH_R_1_6;
  cell.nof_ports       = args.file_nof_ports;
  cell.nof_prb         = args.nof_prb;
#endif

  CellPipeline pipeline(args,
                        rf_source.get(),
                        cell,
                        sniffer_mode,
                        api_mode,
                        /* legacy_pcap_name */ true);
  active_pipelines_.push_back(&pipeline);

#ifndef DISABLE_RF
  if (args.input_file_name == "") {
    srsran_rf_start_rx_stream(&rf, false);
    if (args.rf_gain < 0) {
      srsran_rf_info_t* rf_info = srsran_rf_get_info(&rf);
      pipeline.startAgc(rf_info->min_rx_gain,
                        rf_info->max_rx_gain,
                        static_cast<double>(cell_detect_config.init_agc));
    }
  }
#endif

  bool ok = pipeline.run();

  active_pipelines_.clear();

#ifndef DISABLE_RF
  if (args.input_file_name == "") {
    srsran_rf_close(&rf);
  }
#endif

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

bool LTESniffer_Core::runMultiCell(){
  // Step 5: N cells, same EARFCN, arbitrary PRB (any ratio).
  // Each cell gets either a PassthroughChannel (ratio=1), a
  // DecimChannel (integer ratio>1), or a RationalResampler
  // (non-integer ratio), plus its own CellPipeline, all fed by a
  // single WidebandCapture reading from one RF.

  printf("Multi-cell mode: %zu cell(s) configured\n", args.cells.size());
  for (const auto& c : args.cells) {
    printf("  cell: PCI=%u  PRB=%u\n", c.pci, c.nof_prb);
  }

  // ---- 1. Determine capture sample rate (max PRB across cells) ----
  uint32_t max_prb = 0;
  for (const auto& c : args.cells) {
    if (c.nof_prb > max_prb) max_prb = c.nof_prb;
  }
  int fs_capture = srsran_sampling_freq_hz(max_prb);
  if (fs_capture <= 0) {
    ERROR("Invalid max PRB %u (sampling_freq_hz returned %d)\n", max_prb, fs_capture);
    return false;
  }
  printf("Capture sample rate: %.2f MHz (max PRB = %u)\n",
         (float)fs_capture / 1e6f, max_prb);

  // Step 5: any ratio is supported.
  //   ratio == 1            -> PassthroughChannel
  //   ratio integer > 1     -> DecimChannel (anti-aliased FIR)
  //   ratio non-integer     -> RationalResampler (srsran_resampler)
  for (const auto& c : args.cells) {
    if (c.nof_prb > max_prb) {
      ERROR("Cell PCI=%u has PRB=%u > max PRB=%u. This is a configuration error.\n",
            c.pci, c.nof_prb, max_prb);
      return false;
    }
  }

  // ---- 2. Open RF, set freq, set sample rate ----
#ifndef DISABLE_RF
  srsran_rf_t rf;
  std::unique_ptr<RfSampleSource> rf_source;
  if (args.input_file_name == "") {
    printf("Opening RF device with %d RX antennas...\n", args.rf_nof_rx_ant);
    char rfArgsCStr[1024];
    strncpy(rfArgsCStr, args.rf_args.c_str(), 1024);
    if (srsran_rf_open_multi(&rf, rfArgsCStr, args.rf_nof_rx_ant)) {
      fprintf(stderr, "Error opening rf\n");
      return false;
    }
    rf_source.reset(new RfSampleSource(&rf));

    // Step 3 invariant: fixed gain in multi-cell mode (no AGC).
    if (args.rf_gain > 0) {
      srsran_rf_set_rx_gain(&rf, args.rf_gain);
    } else {
      printf("[multi-cell] WARNING: no fixed gain set (-g). Using current SDR gain.\n");
    }

    // Tune to the shared EARFCN.
    printf("Tunning receiver to %.3f MHz\n",
           (args.rf_freq + args.file_offset_freq) / 1e6);
    srsran_rf_set_rx_freq(&rf, args.rf_nof_rx_ant,
                          args.rf_freq + args.file_offset_freq);

    // Set sample rate to the widest cell's native rate.
    float srate_rf = srsran_rf_set_rx_srate(&rf, (double)fs_capture);
    if (srate_rf != fs_capture) {
      ERROR("Could not set sampling rate %.2f MHz (got %.2f)\n",
            (float)fs_capture / 1e6f, srate_rf / 1e6f);
      srsran_rf_close(&rf);
      return false;
    }
  }
#endif

  // ---- 3. Build per-cell channel + pipeline ----
  // Block size: one subframe at the capture rate.
  const uint32_t block_samples = SRSRAN_SF_LEN_PRB(max_prb);

  // We need to keep the rings and channels alive for the duration of
  // runMultiCell(). Use unique_ptr for clear ownership.
  std::vector<std::unique_ptr<RingBuffer>>       rings;
  std::vector<std::unique_ptr<ISampleSource>>    channels;
  std::vector<std::unique_ptr<CellPipeline>>     pipelines;
  std::vector<std::thread>                       pipeline_threads;

  rings.reserve(args.cells.size());
  channels.reserve(args.cells.size());
  pipelines.reserve(args.cells.size());
  pipeline_threads.reserve(args.cells.size());

  for (const auto& c : args.cells) {
    // Ring capacity: 8 subframes of slack per port (at the CAPTURE rate,
    // since the ring sits between capture and the per-cell channel).
    const uint32_t cap = 8 * SRSRAN_SF_LEN_PRB(max_prb);
    rings.push_back(std::make_unique<RingBuffer>(args.rf_nof_rx_ant, cap));

    // Choose the channel type based on the decimation ratio.
    const uint32_t ratio = max_prb / c.nof_prb;
    if (ratio == 1) {
      // Same bandwidth as capture: passthrough.
      channels.push_back(
          std::make_unique<PassthroughChannel>(rings.back().get()));
    } else if ((max_prb % c.nof_prb) == 0) {
      // Integer ratio: anti-aliased FIR decimator.
      channels.push_back(
          std::make_unique<DecimChannel>(rings.back().get(), ratio));
    } else {
      // Non-integer ratio: srsran_resampler.
      channels.push_back(
          std::make_unique<RationalResampler>(rings.back().get(),
                                              max_prb, c.nof_prb));
    }

    srsran_cell_t cell = {};
    cell.id              = c.pci;
    cell.nof_prb         = c.nof_prb;
    cell.nof_ports       = 2;
    cell.cp              = SRSRAN_CP_NORM;
    cell.phich_length    = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1_6;

    pipelines.push_back(std::make_unique<CellPipeline>(
        args, channels.back().get(), cell, sniffer_mode, api_mode,
        /* legacy_pcap_name */ false));
    active_pipelines_.push_back(pipelines.back().get());
  }

  // ---- 4. Build WidebandCapture and register all rings ----
#ifndef DISABLE_RF
  WidebandCapture capture(rf_source.get(), block_samples);
#else
  // DISABLE_RF + multi-cell: not supported in Step 3 (would need a
  // FileSampleSource per cell). Refuse early.
  ERROR("Multi-cell mode requires RF (DISABLE_RF not supported in Step 3)\n");
  return false;
#endif
  for (auto& r : rings) capture.registerSink(r.get());
  active_capture_ = &capture;

  // ---- 5. Start capture + all pipelines ----
#ifndef DISABLE_RF
  srsran_rf_start_rx_stream(&rf, false);
#endif
  if (!capture.start()) {
    ERROR("WidebandCapture failed to start\n");
    active_capture_ = nullptr;
#ifndef DISABLE_RF
    srsran_rf_close(&rf);
#endif
    return false;
  }

  for (auto& p : pipelines) {
    // Capture a raw pointer by value. [&p] would alias the loop variable
    // (all threads end up calling pipelines.back()->run()); [p] won't
    // compile because unique_ptr is non-copyable. The CellPipeline is
    // owned by the unique_ptr in `pipelines`, which outlives these
    // threads (we join before the vector goes out of scope).
    CellPipeline* p_raw = p.get();
    pipeline_threads.emplace_back([p_raw] { p_raw->run(); });
  }

  // ---- 6. Wait for Ctrl+C (or any pipeline to exit) ----
  for (auto& t : pipeline_threads) {
    if (t.joinable()) t.join();
  }
  capture.stop();
  active_capture_ = nullptr;

#ifndef DISABLE_RF
  srsran_rf_close(&rf);
#endif
  active_pipelines_.clear();

  // Report per-ring drop counts.
  for (size_t i = 0; i < rings.size(); i++) {
    printf("Cell %zu (PCI=%u): ring drops=%llu\n",
           i, args.cells[i].pci,
           (unsigned long long)rings[i]->dropCount());
  }

  return EXIT_SUCCESS;
}

void LTESniffer_Core::stop() {
  cout << "LTESniffer_Core: Exiting..." << endl;
  go_exit.store(true, std::memory_order_release);
  for (auto* p : active_pipelines_) {
    if (p) p->stop();
  }
  if (active_capture_) active_capture_->stop();
}

void LTESniffer_Core::handleSignal() {
  stop();
}

LTESniffer_Core::~LTESniffer_Core(){
  // Per-cell resources (pcap, phy, harq, ...) live inside CellPipeline
  // and are released by its destructor.
  printf("Deleted DL Sniffer core\n");
}

