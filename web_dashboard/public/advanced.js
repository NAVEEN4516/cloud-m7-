/* Derived experimental views; every value comes from the selected analysis. */
'use strict';
function renderAdvancedTracks(data) {
  const tracks = data.advanced_tracks;
  if (!tracks) throw new Error('Advanced analysis missing. Restart the updated dashboard server.');
  $('advanced-summary').replaceChildren();
  for (const text of [`${data.summary.total_events} selected events`, '6 experimental tracks', `${tracks.processing_time_ms} ms measured`]) {
    const chip = document.createElement('span'); chip.className = 'chip'; chip.textContent = text;
    $('advanced-summary').append(chip);
  }
  const hw = tracks.track1_ebpf_hpc;
  table('advanced-hardware', ['Simulated field', 'Example value'], [
    ['Scenario profile', hw.ebpf_lsm.is_anomaly ? 'Attack-labelled scenario' : 'Nominal scenario'],
    ['Hook name', hw.ebpf_lsm.hook_name], ['PID', hw.ebpf_lsm.pid],
    ['Instructions / cycle', hw.hpc_registers.ipc], ['Cache miss rate (%)', hw.hpc_registers.cache_miss_rate_pct]
  ]);
  $('hardware-attestation').textContent = 'Hardware attestation unavailable. The sample digest uses a public software demo key.';
  const graph = tracks.track2_gnn_entropy, entropy = graph.entropy_reduction;
  $('advanced-entropy').textContent = `${entropy.original_edges} → ${entropy.pruned_edges} derived edges · Reachability ${entropy.reachability_preserved ? 'preserved' : 'FAILED'} · ${entropy.information_entropy_bits} entropy bits`;
  table('advanced-scores', ['Event', 'Tier', 'Structure score'], graph.top_gnn_anomalies.map(s => [s.node_id, s.tier, s.anomaly_score]));
  const rl = tracks.track3_rl_containment;
  $('rl-state').textContent = `Selected model state: ${rl.initial_state}`;
  table('advanced-policy', ['Model state', 'Learned action'], Object.entries(rl.optimal_policy));
  $('advanced-rl').textContent = JSON.stringify({episodes: rl.episodes_trained, convergence_episode: rl.convergence_episode,
    observed_training_action_shares: rl.action_distribution, simulated_trajectory: rl.simulation_trajectory}, null, 2);
  const proof = tracks.track4_zk_provenance, cut = proof.graph_cut_check;
  $('zk-status').textContent = 'Cryptographic proof unavailable · simulated bundles are never accepted as valid proofs.';
  $('advanced-cut').textContent = cut.status === 'checked'
    ? `Removing ${cut.candidate_node} leaves ${cut.sources_still_reaching_target} of ${cut.sources_checked} inspected sources reaching the target. Graph computation only; no containment deployed.`
    : 'Not applicable: no reconstructed incident with a candidate cut to inspect.';
  $('advanced-proof').textContent = JSON.stringify(proof, null, 2);
  const shield = tracks.track5_adversarial_shield;
  $('shield-status').textContent = shield.coverage_complete ? 'Available checks completed; inspect the results below.'
    : 'Overall integrity not established: verification coverage is incomplete.';
  table('advanced-checks', ['Check', 'Status', 'Checked', 'Failed', 'Unavailable'],
    shield.checks.map(c => [c.name, c.status, c.checked, c.failed, c.unavailable]));
  $('advanced-findings').textContent = JSON.stringify(shield.findings, null, 2);
  const intel = tracks.track6_stix_streaming, stream = intel.streaming_metrics;
  $('advanced-export-status').textContent = `${intel.trajectory_steps_exported} trajectory steps exported · ${intel.stix_bundle.objects.length} objects · internal structural checks passed.`;
  table('advanced-stream', ['Selected-event aggregation', 'Measured / configured value'], [
    ['Events received', stream.events_received], ['Events accepted', stream.events_ingested],
    ['Late events dropped', stream.dropped_late_events], ['Windows aggregated', stream.windows_processed],
    ['Processing time (ms)', stream.processing_time_ms], ['In-memory throughput (events/s)', stream.throughput_events_per_sec],
    ['Configured window (s)', stream.tumbling_window_size_sec], ['Configured watermark lag (ms)', stream.watermark_delay_ms]
  ]);
}
