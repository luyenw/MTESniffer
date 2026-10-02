/*
 * LTESniffer multi-cell refactor — Step 2.
 *
 * CellPipeline owns everything needed to decode one LTE cell:
 *   - ue_sync / ue_mib / dl_sf / pdsch_cfg / falcon_ue_dl
 *   - Phy (worker pool)
 *   - pcap writer, MCSTracking, HARQ, UL_HARQ, ULSchedule
 *   - TA buffer, CFO estimate
 *
 * It receives samples through an ISampleSource* (nullptr for file mode).
 * It does NOT touch srsran_rf_* directly — that is the orchestrator's
 * job (LTESniffer_Core). The only RF interaction is startAgc(), which
 * the orchestrator calls after creating the pipeline.
 *
 * In Step 2 there is exactly one CellPipeline per run(); later steps
 * will instantiate N pipelines in parallel.
 */
#pragma once

#include <atomic>
#include <string>

#include "ArgManager.h"
#include "ISampleSource.h"
#include "Phy.h"
#include "PcapWriter.h"
#include "MCSTracking.h"
#include "HARQ.h"
#include "ULSchedule.h"
#include "Sniffer_dependency.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "srsran/phy/utils/debug.h"
#include "falcon/phy/falcon_ue/falcon_ue_dl.h"
#include "srsran/srsran.h"
#ifdef __cplusplus
}
#undef I
#endif

#define UL_SNIFFER_UL_MAX_OFFSET 200
#define UL_SNIFFER_UL_OFFSET_32 32
#define UL_SNIFFER_UL_OFFSET_64 64

typedef struct {
  cf_t* ta_temp_buffer;
  cf_t  ta_last_sample[UL_SNIFFER_UL_MAX_OFFSET];
  int   cnt =  0;
  int   sf_sample_size;
} UL_Sniffer_ta_buffer_t;

class CellPipeline {
public:
  /*
   * Build a pipeline for one cell.
   *   args              : global configuration (read-only reference; must outlive pipeline)
   *   sample_source     : ISampleSource delivering samples at the cell's native rate.
   *                       Pass nullptr to run in file mode (args.input_file_name).
   *   cell              : cell configuration (PCI, nof_prb, ports, ...). Copied.
   *   sniffer_mode      : DL_MODE or UL_MODE
   *   api_mode          : -1 (off) or 0..3 (see ArgManager)
   *   legacy_pcap_name  : if true, use the legacy single-cell pcap filename
   *                       (ltesniffer_<dl|ul>_mode.pcap). If false (default),
   *                       use the per-cell filename ltesniffer_<dl|ul>_cell<PCI>.pcap.
   *                       Step 3 sets this true only for the N==1 legacy path.
   */
  CellPipeline(const Args& args,
               ISampleSource* sample_source,
               const srsran_cell_t& cell,
               int sniffer_mode,
               int api_mode,
               bool legacy_pcap_name = false);
  ~CellPipeline();

  CellPipeline(const CellPipeline&) = delete;
  CellPipeline& operator=(const CellPipeline&) = delete;

  /*
   * Start AGC on the internal ue_sync. The orchestrator is responsible
   * for querying the RF device and passing the gain bounds here, so
   * CellPipeline never touches srsran_rf_* directly.
   * Only meaningful in RF mode (sample_source != nullptr).
   */
  void startAgc(double min_rx_gain, double max_rx_gain, double init_agc);

  /*
   * Initial CFO (Hz) measured by the orchestrator's cell search, applied
   * by run() so ue_sync starts already corrected. Call before run().
   */
  void setInitialCfo(float cfo_hz) { initial_cfo_hz_ = cfo_hz; has_initial_cfo_ = true; }

  /*
   * Run the main decode loop. Blocks until stop() is called or
   * args.nof_subframes is reached. Returns true on clean exit.
   */
  bool run();

  void stop();

private:
  // ---- configuration (references / copies) ----
  const Args&       args_;
  ISampleSource*    sample_source_;   // not owned
  srsran_cell_t     cell_;
  srsran_cell_t     cell_init_;   // pristine config; used to detect/repair bogus MIB overwrites
  int               sniffer_mode_;
  int               api_mode_;
  bool              legacy_pcap_name_;

  // ---- state ----
  std::atomic<bool> go_exit_{false};
  enum receiver_state { DECODE_MIB, DECODE_PDSCH } state_;

  // ---- PHY objects ----
  srsran_ue_sync_t   ue_sync_;
  srsran_ue_mib_t    ue_mib_;
  srsran_dl_sf_cfg_t dl_sf_;
  srsran_pdsch_cfg_t pdsch_cfg_;
  falcon_ue_dl_t     falcon_ue_dl_;

  // ---- owned helpers ----
  Phy*                    phy_;
  LTESniffer_pcap_writer  pcapwriter_;
  srsran::mac_pcap        mac_pcap_;
  MCSTracking             mcs_tracking_;
  ULSchedule              ulsche_;
  UL_HARQ                 ul_harq_;
  HARQ                    harq_;

  // ---- buffers / shared atomic ----
  UL_Sniffer_ta_buffer_t  ta_buffer_;
  std::atomic<float>      est_cfo_;

  // ---- mode flags ----
  float initial_cfo_hz_ = 0.0f;
  bool  has_initial_cfo_ = false;  // true once setInitialCfo() was called
  static constexpr float kMaxCfoDevHz = 1000.0f;  // max tracked CFO deviation from initial
  bool  plmn_checked_ = false;  // MCC/MNC filter already evaluated
  int mcs_tracking_mode_;
  int harq_mode_;

  // ---- helpers ----
  void initUeSyncRf();
  void initUeSyncFile();
  srsran_cell_t mibCell() const;
  void initUeMib(cf_t* buffer);
  void configureCfo(float search_cell_cfo);
  void configurePdsch();
  void setupRntiManager();
  void printApiHeader();
};
