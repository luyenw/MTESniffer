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
#include <future>
#include <thread>
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
#include "include/DdcChannel.h"
#include "include/FileSampleSource.h"
#include "include/RfSampleSource.h"
#include "include/WidebandCapture.h"
#include "include/Feasibility.h"

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
  // Dispatcher: legacy 2-field form goes to runMultiCellLegacy(),
  // new 3-field form runs Feasibility + DdcChannel path.
  if (!args.cells_have_dl_earfcn) {
    return runMultiCellLegacy();
  }
  return runMultiCellNew();
}

bool LTESniffer_Core::runMultiCellLegacy(){
  // Step 3: N cells, same EARFCN (global -f), arbitrary PRB.
  // Each cell gets either a PassthroughChannel (ratio=1), a
  // DecimChannel (integer ratio>1), or a RationalResampler
  // (non-integer ratio), plus its own CellPipeline, all fed by a
  // single WidebandCapture reading from one RF.
  //
  // This is the EXACT same logic as main branch's runMultiCell().
  // DdcChannel is NOT used here because it always applies a 5-tap LPF
  // which can interfere with PSS detection for ratio=1 cells.

  printf("Multi-cell mode (legacy): %zu cell(s) configured\n", args.cells.size());
  for (const auto& c : args.cells) {
    printf("  cell: PCI=%u PRB=%u (shared EARFCN from -f = %.3f MHz)\n",
           c.pci, c.nof_prb, args.rf_freq / 1e6);
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

  // Validate: no cell can have PRB > max_prb.
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
  } else {
    ERROR("File input not supported in legacy multi-cell mode\n");
    return false;
  }
#else
  ERROR("RF disabled: legacy multi-cell mode requires RF\n");
  return false;
#endif

  // ---- 3. Build per-cell channel + pipeline ----
  // Block size: one subframe at the capture rate.
  const uint32_t block_samples = SRSRAN_SF_LEN_PRB(max_prb);

  std::vector<std::unique_ptr<RingBuffer>>       rings;
  std::vector<std::unique_ptr<ISampleSource>>    channels;
  std::vector<std::unique_ptr<CellPipeline>>     pipelines;
  std::vector<std::thread>                       pipeline_threads;

  rings.reserve(args.cells.size());
  channels.reserve(args.cells.size());
  pipelines.reserve(args.cells.size());
  pipeline_threads.reserve(args.cells.size());

  for (const auto& c : args.cells) {
    // Ring capacity: 8 subframes of slack per port (at the CAPTURE rate).
    const uint32_t cap = 8 * SRSRAN_SF_LEN_PRB(max_prb);
    rings.push_back(std::make_unique<RingBuffer>(args.rf_nof_rx_ant, cap));

    // Choose the channel type based on the decimation ratio.
    //   ratio == 1            -> PassthroughChannel (pure passthrough)
    //   ratio integer > 1     -> DecimChannel (anti-aliased FIR)
    //   ratio non-integer     -> RationalResampler (srsran_resampler)
    const uint32_t ratio = max_prb / c.nof_prb;
    if (ratio == 1) {
      channels.push_back(
          std::make_unique<PassthroughChannel>(rings.back().get()));
    } else if ((max_prb % c.nof_prb) == 0) {
      channels.push_back(
          std::make_unique<DecimChannel>(rings.back().get(), ratio));
    } else {
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
  ERROR("Multi-cell mode requires RF (DISABLE_RF not supported)\n");
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
    CellPipeline* p_raw = p.get();
    pipeline_threads.emplace_back([p_raw] { p_raw->run(); });
  }

  // ---- 6. Wait for exit ----
  for (auto& t : pipeline_threads) t.join();
  capture.stop();
  for (auto* pl : active_pipelines_) delete pl;
  active_pipelines_.clear();
  active_capture_ = nullptr;
  return true;
}

bool LTESniffer_Core::runMultiCellNew(){
  // Step 3b: N cells, possibly different EARFCN, arbitrary PRB.
  // Each cell gets a DdcChannel (NCO + LPF + resample) plus its own
  // CellPipeline, all fed by a single WidebandCapture reading from one RF.
  //
  // The capture plan (f_c, Fs_capture, Δk, ratio_k) is computed by
  // Feasibility::validate() — the orchestrator does NOT recompute it.

  printf("Multi-cell mode (new): %zu cell(s) configured\n", args.cells.size());
  for (const auto& c : args.cells) {
    printf("  cell: DL_EARFCN=%u PCI=%u PRB=%u\n",
           c.dl_earfcn, c.pci, c.nof_prb);
  }

  // ---- -1. Open RF (fixed gain) ----
  // Opened before Feasibility because cells without a PRB need a
  // pre-scan (PSS/SSS + MIB) to learn their bandwidth.
#ifndef DISABLE_RF
  srsran_rf_t rf;
  std::unique_ptr<RfSampleSource> rf_source;
  const bool use_rf = (args.input_file_name == "");
  if (use_rf) {
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
  }
  auto close_rf = [&] { if (use_rf) srsran_rf_close(&rf); };
#else
  const bool use_rf = false;
  auto close_rf = [] {};
#endif

  // ---- -0.5. Cell search + MIB for every cell (RF only) ----
  // Gives the PRB when it was not passed (EARFCN:PCI), and for every cell
  // the antenna port count, PHICH config and CFO. The pipeline must start
  // with the real port count: workers initialised with a wrong value do
  // not recover (no PDCCH/PDSCH decode even after the MIB is read).
  std::vector<float>         search_cfo(args.cells.size(), 0.0f);
  std::vector<bool>          search_cfo_valid(args.cells.size(), false);
  std::vector<srsran_cell_t> search_cell(args.cells.size(), srsran_cell_t{});
  for (size_t ci = 0; ci < args.cells.size(); ci++) {
    auto& c = args.cells[ci];
    const bool prb_given = (c.nof_prb != 0);
    if (!use_rf) {
      if (prb_given) continue;  // file input: use the configured cell as-is
      ERROR("Cell EARFCN=%u PCI=%u has no PRB; auto-detect needs RF input\n",
            c.dl_earfcn, c.pci);
      close_rf();
      return false;
    }
#ifndef DISABLE_RF
    double f_dl = args.rf_freq;
    if (c.dl_earfcn != 0) {
      std::string band;
      if (!feas::earfcnToFreq(c.dl_earfcn, band, f_dl)) {
        ERROR("DL_EARFCN=%u not in any known band\n", c.dl_earfcn);
        close_rf();
        return false;
      }
    }
    printf("[cell-search] EARFCN=%u PCI=%u: tuning to %.3f MHz, decoding MIB...\n",
           c.dl_earfcn, c.pci, f_dl / 1e6);
    srsran_rf_set_rx_freq(&rf, args.rf_nof_rx_ant, f_dl);

    cell_search_cfg_t cs_cfg = {.max_frames_pbch      = SRSRAN_DEFAULT_MAX_FRAMES_PBCH,
                                .max_frames_pss       = SRSRAN_DEFAULT_MAX_FRAMES_PSS,
                                .nof_valid_pss_frames = SRSRAN_DEFAULT_NOF_VALID_PSS_FRAMES,
                                .init_agc             = 0,
                                .force_tdd            = false};
    const int kMaxTrials = 5;
    bool found = false;
    for (int trial = 0; trial < kMaxTrials && !found &&
                        !go_exit.load(std::memory_order_acquire); trial++) {
      srsran_cell_t found_cell = {};
      float cfo = 0;
      int ret = rf_search_and_decode_mib_cell_id(&rf, args.rf_nof_rx_ant, &cs_cfg,
                                                 static_cast<int>(c.pci),
                                                 &found_cell, &cfo);
      if (ret > 0 && found_cell.id == c.pci &&
          srsran_nofprb_isvalid(found_cell.nof_prb)) {
        if (!prb_given) {
          c.nof_prb = found_cell.nof_prb;
        } else if (found_cell.nof_prb != c.nof_prb) {
          printf("[cell-search] EARFCN=%u PCI=%u: MIB says PRB=%u, keeping configured PRB=%u\n",
                 c.dl_earfcn, c.pci, found_cell.nof_prb, c.nof_prb);
        }
        search_cfo[ci] = cfo;
        search_cfo_valid[ci] = true;
        search_cell[ci] = found_cell;
        found = true;
        printf("[cell-search] EARFCN=%u PCI=%u -> PRB=%u ports=%u CFO=%.1f Hz\n",
               c.dl_earfcn, c.pci, c.nof_prb, found_cell.nof_ports, cfo);
      } else if (ret > 0) {
        printf("[cell-search] trial %d: found PCI=%u (want %u) PRB=%u, retrying\n",
               trial + 1, found_cell.id, c.pci, found_cell.nof_prb);
      } else {
        printf("[cell-search] trial %d: cell not found, retrying\n", trial + 1);
      }
    }
    if (!found && prb_given) {
      printf("[cell-search] EARFCN=%u PCI=%u: MIB not decoded, using configured cell "
             "(2 ports assumed, PHICH 1/6 normal)\n", c.dl_earfcn, c.pci);
    } else if (!found) {
      ERROR("Could not decode MIB for EARFCN=%u PCI=%u after %d trials. "
            "Pass the PRB explicitly (DL_EARFCN:PCI:PRB).\n",
            c.dl_earfcn, c.pci, kMaxTrials);
      close_rf();
      return false;
    }
#endif
  }

  // ---- 0. Build Feasibility input ----
  // New 3-field form (DL_EARFCN:PCI:PRB): each cell may have its own DL EARFCN.
  // If a cell's DL_EARFCN is 0, inherit the global -f DL EARFCN.
  std::vector<feas::CellInput> feas_cells;
  feas_cells.reserve(args.cells.size());
  for (const auto& c : args.cells) {
    feas::CellInput ci{};
    if (c.dl_earfcn != 0) {
      ci.dl_earfcn = c.dl_earfcn;
    } else {
      // Inherit global -f. args.rf_freq is in Hz; for FDD bands
      // f_dl_low is a multiple of 100 kHz, so DL_EARFCN ≈ rf_freq / 100000.
      ci.dl_earfcn = static_cast<uint32_t>(args.rf_freq / 100000.0);
    }
    ci.pci     = c.pci;
    ci.nof_prb = c.nof_prb;
    feas_cells.push_back(ci);
  }

  feas::HwCaps hw;
  hw.sdr_model = args.rf_args;  // used for static-table lookup

  feas::Options fopts;
  fopts.force              = args.force;
  fopts.guard_hz           = args.guard_hz;
  fopts.nof_rx_ant         = args.rf_nof_rx_ant;
  fopts.agc_enabled        = (args.rf_gain < 0);
  fopts.fixed_gain_set     = (args.rf_gain > 0);

  feas::Report report = feas::validate(feas_cells, hw, fopts);
  feas::printReport(report);

  // Gate: NO_GO always blocks; GO_WITH_WARN needs --force.
  if (report.verdict == feas::Verdict::NO_GO) {
    ERROR("Feasibility NO_GO — refusing to start capture. See report above.\n");
    close_rf();
    return false;
  }
  if (report.verdict == feas::Verdict::GO_WITH_WARN && !args.force) {
    ERROR("Feasibility GO_WITH_WARN — pass --force to proceed.\n");
    close_rf();
    return false;
  }

  const feas::CapturePlan& plan = report.plan;
  const double fs_capture = plan.fs_capture_hz;
  const double f_c        = plan.f_c_hz;
  const uint32_t max_prb  = plan.max_prb;

  if (fs_capture <= 0.0 || max_prb == 0) {
    ERROR("Invalid capture plan (fs_capture=%.0f, max_prb=%u)\n",
          fs_capture, max_prb);
    close_rf();
    return false;
  }

  // ---- 1. Set freq + sample rate on the RF opened in step -1 ----
#ifndef DISABLE_RF
  if (use_rf) {
    // Tune to f_c (the centre of the span), NOT to args.rf_freq.
    printf("Tunning receiver to f_c = %.3f MHz\n", f_c / 1e6);
    srsran_rf_set_rx_freq(&rf, args.rf_nof_rx_ant, f_c);

    // Set sample rate to the capture rate from the plan.
    float srate_rf = srsran_rf_set_rx_srate(&rf, fs_capture);
    if (std::fabs(srate_rf - fs_capture) > 1.0) {
      ERROR("Could not set sampling rate %.2f MHz (got %.2f MHz)\n",
            fs_capture / 1e6, srate_rf / 1e6);
      srsran_rf_close(&rf);
      return false;
    }
  }
#endif

  // ---- 2. Build per-cell channel + pipeline ----
  // Block size: one subframe at the capture rate.
  const uint32_t block_samples = SRSRAN_SF_LEN_PRB(max_prb);

  std::vector<std::unique_ptr<RingBuffer>>       rings;
  std::vector<std::unique_ptr<ISampleSource>>    channels;
  std::vector<std::unique_ptr<CellPipeline>>     pipelines;
  std::vector<std::thread>                       pipeline_threads;

  rings.reserve(args.cells.size());
  channels.reserve(args.cells.size());
  pipelines.reserve(args.cells.size());
  pipeline_threads.reserve(args.cells.size());

  for (size_t i = 0; i < args.cells.size(); i++) {
    const auto& c = args.cells[i];
    const auto& cp = plan.cells[i];

    // Ring capacity: 128 subframes (128 ms) of slack per port at the
    // CAPTURE rate. 8 ms was not enough: cell threads stalled longer than
    // that while sharing cores with srsenb, and every overflow drops samples
    // (timing jump + DDC phase jump -> lost sync, runaway CFO).
    // 128 ms at 23.04 MS/s ~= 23.6 MB per port.
    const uint32_t cap = 128 * SRSRAN_SF_LEN_PRB(max_prb);
    rings.push_back(std::make_unique<RingBuffer>(args.rf_nof_rx_ant, cap));

    // Choose channel type:
    //   delta=0, ratio=1 -> PassthroughChannel (single cell, nothing to reject)
    //   otherwise        -> DdcChannel (NCO + LPF + resample)
    // DecimChannel is NOT used here even for delta=0: its short FIR
    // (4*ratio+1 taps) lets the neighbouring cells alias on top of the
    // target cell after decimation.
    const double ratio = fs_capture / cp.fs_k_hz;
    const bool is_passthrough = std::fabs(cp.delta_hz) < 1.0 &&
                                std::fabs(ratio - 1.0) < 1e-6;
    if (is_passthrough) {
      channels.push_back(
          std::make_unique<PassthroughChannel>(rings.back().get()));
    } else {
      channels.push_back(std::make_unique<DdcChannel>(
          rings.back().get(),
          cp.delta_hz,
          fs_capture,
          cp.fs_k_hz,
          cp.occupied_bw_hz));
    }

    srsran_cell_t cell = {};
    cell.id              = c.pci;
    cell.nof_prb         = c.nof_prb;
    cell.nof_ports       = 2;
    cell.cp              = SRSRAN_CP_NORM;
    cell.phich_length    = SRSRAN_PHICH_NORM;
    cell.phich_resources = SRSRAN_PHICH_R_1_6;
    if (search_cell[i].nof_ports != 0) {
      // Real values from the cell search MIB.
      cell.nof_ports       = search_cell[i].nof_ports;
      cell.cp              = search_cell[i].cp;
      cell.phich_length    = search_cell[i].phich_length;
      cell.phich_resources = search_cell[i].phich_resources;
    }

    pipelines.push_back(std::make_unique<CellPipeline>(
        args, channels.back().get(), cell, sniffer_mode, api_mode,
        /* legacy_pcap_name */ false));
    if (search_cfo_valid[i]) pipelines.back()->setInitialCfo(search_cfo[i]);
    active_pipelines_.push_back(pipelines.back().get());
  }

  // ---- 3. Build WidebandCapture and register all rings ----
#ifndef DISABLE_RF
  WidebandCapture capture(rf_source.get(), block_samples);
#else
  ERROR("Multi-cell mode requires RF (DISABLE_RF not supported in Step 3b)\n");
  return false;
#endif
  for (auto& r : rings) capture.registerSink(r.get());
  active_capture_ = &capture;

  // ---- 4. Start capture + all pipelines ----
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
    CellPipeline* p_raw = p.get();
    pipeline_threads.emplace_back([p_raw] { p_raw->run(); });
  }

  // ---- 5. Wait for Ctrl+C (or any pipeline to exit) ----
  // Every 10 s, report samples each ring dropped (consumer too slow) and
  // how full it is. Drops are gaps in the stream: they shift timing and
  // the DDC phase, which shows up as lost sync and a drifting CFO.
  std::atomic<bool> ring_report_stop{false};
  std::thread ring_report([&] {
    std::vector<uint64_t> last(rings.size(), 0);
    int ticks = 0;
    while (!ring_report_stop.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (++ticks < 100) continue;
      ticks = 0;
      for (size_t i = 0; i < rings.size(); i++) {
        const uint64_t drops = rings[i]->dropCount();
        const uint64_t fill  = rings[i]->writeCount() - rings[i]->readCount();
        printf("[ring] PCI=%u drops +%llu (total %llu) fill %.0f%%\n",
               args.cells[i].pci,
               (unsigned long long)(drops - last[i]),
               (unsigned long long)drops,
               100.0 * (double)fill / rings[i]->capacity());
        last[i] = drops;
      }
      fflush(stdout);
    }
  });

  for (auto& t : pipeline_threads) {
    if (t.joinable()) t.join();
  }
  ring_report_stop.store(true, std::memory_order_release);
  ring_report.join();
  capture.stop();
  active_capture_ = nullptr;

  // Destroy the pipelines first: ~CellPipeline closes (flushes) the pcap,
  // so it must not depend on srsran_rf_close() returning.
  active_pipelines_.clear();
  pipelines.clear();

#ifndef DISABLE_RF
  // Closing UHD with the RX stream still running can block forever.
  srsran_rf_stop_rx_stream(&rf);
  // srsRAN's UHD close can still hang joining its async thread; everything
  // worth keeping (pcap, stats) is already flushed, so don't wait forever.
  {
    std::promise<void> closed;
    std::future<void>  done = closed.get_future();
    std::thread closer([&rf, &closed] { srsran_rf_close(&rf); closed.set_value(); });
    if (done.wait_for(std::chrono::seconds(3)) == std::future_status::ready) {
      closer.join();
    } else {
      printf("Warning: RF close timed out, exiting without it\n");
      fflush(stdout);
      closer.detach();
      std::_Exit(0);  // the detached closer still references `rf` on this stack
    }
  }
#endif

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

