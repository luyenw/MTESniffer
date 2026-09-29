/*
 * Copyright (c) 2019 Robert Falkenberg.
 *
 * This file is part of FALCON 
 * (see https://github.com/falkenber9/falcon).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 */
#pragma once

#include <atomic>
#include <ctime>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include "ArgManager.h"
#include "falcon/common/SignalManager.h"
#include "ISampleSource.h"
#include "RfSampleSource.h"
#include "CellPipeline.h"

// include C-only headers
#ifdef __cplusplus
    extern "C" {
#endif

#include "srsran/phy/utils/debug.h"
#include "srsran/srsran.h"
#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"

#ifdef __cplusplus
}
#undef I // Fix complex.h #define I nastiness when using C++
#endif
using namespace srsran;

static SRSRAN_AGC_CALLBACK(srsran_rf_set_rx_gain_th_wrapper_)
{
  srsran_rf_set_rx_gain_th((srsran_rf_t*)h, gain_db);
}

class LTESniffer_Core : public SignalHandler {
public:
  LTESniffer_Core(const Args& args);
  LTESniffer_Core(const LTESniffer_Core&) = delete; //prevent copy
  LTESniffer_Core& operator=(const LTESniffer_Core&) = delete; //prevent copy
  virtual ~LTESniffer_Core() override;

  bool run();
  void stop();
private:

  void handleSignal() override;

  // Run the legacy single-cell path (Step 2 behaviour, preserved when
  // args.cells is empty).
  bool runSingleCell();

  // Run the multi-cell path (Step 3+). Builds a WidebandCapture,
  // one PassthroughChannel per cell (Step 3 only supports equal-PRB
  // cells), and one CellPipeline per cell, each on its own thread.
  bool runMultiCell();

  Args                    args;
  int                     nof_workers;
  int                     sniffer_mode;     //-m
  int                     api_mode    ;     // -z
  std::atomic<bool>       go_exit{false};

  // Step 2/3: list of pipelines currently running (set by runSingleCell
  // or runMultiCell). stop() forwards to all of them.
  std::vector<CellPipeline*> active_pipelines_;

  // Step 3: WidebandCapture (multi-cell only). Non-owning.
  class WidebandCapture* active_capture_ = nullptr;
};
