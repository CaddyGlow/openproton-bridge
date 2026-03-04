# Parity Test Overlap Ledger

## Goal
Track whether each `parity`-named test overlaps existing non-parity coverage, and define the refactor action so parity tests become normal tests without redundant duplication.

Note: Inventory entries use pre-refactor test names (`parity_*`) as the audit baseline.

## Legend
- Overlap: `none`, `partial`, `high`
- Action: `keep+rename`, `merge+rename`, `merge+delete`

## Post-Refactor Test File Names
- `tests/parity_golden_logs.rs` -> `tests/golden_log_validation.rs`
- `tests/parity_matrix.rs` -> `tests/fixture_matrix.rs`
- `tests/parity_store_interop.rs` -> `tests/store_interop.rs`
- `tests/parity_api_event.rs` -> `tests/api_event_compatibility.rs`
- `tests/parity_grpc_wire.rs` -> `tests/grpc_wire_contract.rs`
- `tests/parity_imap_smtp_tls.rs` -> `tests/imap_smtp_tls_integration.rs`
- `tests/parity_runtime_events.rs` -> `tests/runtime_events_e2e.rs`
- `tests/parity_observability.rs` -> `tests/observability_runtime.rs`
- `tests/gluon_parity_integration.rs` -> `tests/gluon_integration.rs`

## Inventory
| Parity test | Area | Existing non-parity overlap | Overlap | Action | Rationale |
|---|---|---|---|---|---|
| `tests/parity_golden_logs.rs::parity_golden_fixture_defines_required_scenarios` | parity log fixtures | none found | none | keep+rename | Fixture-contract coverage is unique. |
| `tests/parity_golden_logs.rs::parity_log_validator_help_mentions_required_flags` | parity log validator CLI | none found | none | keep+rename | Only test that validates CLI flags for `scripts/validate_parity_logs.py`. |
| `tests/parity_golden_logs.rs::parity_log_validator_passes_when_milestones_are_in_order` | parity log validator behavior | none found | none | keep+rename | Unique positive path for validator script. |
| `tests/parity_golden_logs.rs::parity_log_validator_reports_missing_and_out_of_order_milestones` | parity log validator behavior | none found | none | keep+rename | Unique failure-path validator contract. |
| `tests/parity_matrix.rs::parity_matrix_manifest_references_existing_fixtures` | fixture matrix integrity | none found | none | keep+rename | Unique fixture-manifest consistency check. |
| `tests/parity_matrix.rs::parity_matrix_event_fixtures_cover_single_and_array_shapes` | fixture payload shape | `src/api/types.rs` event-shape parsing tests | partial | merge+rename | Keep fixture-level check, but remove duplicated semantic assertions after folding into canonical API tests. |
| `tests/parity_matrix.rs::parity_matrix_grpc_login_fixtures_cover_base64_and_two_password_flow` | grpc fixture shape | `src/frontend/grpc/rpc.rs` password decode + two-password tests | partial | merge+rename | Fixture structure is useful; behavior assertions overlap. |
| `tests/parity_matrix.rs::parity_matrix_tls_transcripts_include_starttls_markers` | protocol fixture transcripts | `tests/parity_imap_smtp_tls.rs` STARTTLS behavior tests | partial | keep+rename | Transcript presence is fixture-contract, not runtime behavior. |
| `tests/parity_grpc_wire.rs::parity_grpc_wire_login_request_password_is_bytes` | proto type contract | none found | none | keep+rename | Small but unique compile/runtime assertion for protobuf bytes field. |
| `tests/parity_observability.rs::parity_observability_runtime_paths_include_session_and_crash_dirs` | runtime path derivation | none found | none | keep+rename | Unique filesystem-path contract check. |
| `tests/parity_observability.rs::parity_observability_sensitive_values_are_redacted_by_default` | redaction | `src/api/client.rs::test_redact_sensitive_for_log_defaults_to_redaction` | high | merge+delete | Same core function assertions should live in one canonical unit test block. |
| `tests/parity_observability.rs::parity_observability_session_logs_are_created_and_pruned` | session log rotation | none found | none | keep+rename | Unique log lifecycle behavior coverage. |
| `tests/parity_observability.rs::parity_observability_support_bundle_collects_diagnostics` | support bundle generation | none found | none | keep+rename | Unique support-bundle artifact behavior. |
| `tests/parity_store_interop.rs::parity_store_interop_loads_proton_profile_fixture` | vault/profile interop | `src/vault.rs` fixture load tests | partial | merge+rename | Integration-level multi-account fixture contract still valuable; avoid duplicate assertions line-for-line. |
| `tests/parity_store_interop.rs::parity_store_interop_roundtrip_preserves_metadata_fields` | vault roundtrip preservation | `src/vault.rs::test_save_session_preserves_unknown_vault_fields` | partial | merge+rename | Keep integration roundtrip contract, but centralize repeated field-preservation expectations. |
| `tests/parity_api_event.rs::parity_api_event_accepts_single_event_shape` | events API shape compatibility | `src/api/events.rs` + `src/api/types.rs` event parsing tests | partial | merge+rename | Single-event alias coverage should be canonicalized in API module tests. |
| `tests/parity_api_event.rs::parity_api_event_keeps_events_array_shape` | events API shape compatibility | `src/api/events.rs::get_events_with_cursor` | high | merge+delete | Largely duplicate array-shape behavior. |
| `tests/parity_api_event.rs::parity_api_event_attachment_error_returns_api_error_payload` | attachment API error semantics | `src/api/messages.rs` tests (non-401 attachment paths) | partial | keep+rename | 401 JSON attachment error path is distinct and should be retained. |
| `tests/parity_runtime_events.rs::parity_runtime_events_check_update_emits_is_latest_then_finished` | grpc runtime e2e events | none equivalent found in non-parity tests | none | keep+rename | True end-to-end runtime stream ordering coverage. |
| `tests/parity_runtime_events.rs::parity_runtime_events_mail_settings_changed_then_finished_in_order` | grpc runtime e2e events | unit/event tests in `src/frontend/grpc/mod.rs` are adjacent but not equivalent e2e | partial | keep+rename | Different level (server e2e vs in-process unit). |
| `tests/parity_runtime_events.rs::parity_runtime_events_gui_ready_emits_all_users_loaded_then_main_window` | grpc runtime e2e events | no direct non-parity e2e equivalent | none | keep+rename | Unique streamed app-event ordering contract. |
| `tests/parity_imap_smtp_tls.rs::parity_imap_starttls_upgrade_and_capability_reflects_tls_state` | IMAP STARTTLS | none found outside parity file | none | keep+rename | Only IMAP STARTTLS upgrade integration test. |
| `tests/parity_imap_smtp_tls.rs::parity_smtp_starttls_upgrade_and_auth_login_parity` | SMTP STARTTLS + AUTH LOGIN | `tests/smtp_integration.rs` basic SMTP flow tests | partial | merge+rename | Keep stronger STARTTLS/AUTH LOGIN assertions; fold shared setup and remove duplicated basic EHLO/auth-failure checks. |
| `tests/parity_imap_smtp_tls.rs::parity_capabilities_without_tls_do_not_advertise_starttls` | no-TLS capability surface | partial overlap with `tests/smtp_integration.rs` EHLO checks | partial | keep+rename | IMAP+SMTP no-TLS STARTTLS-negation contract remains unique. |
| `src/frontend/grpc/rpc.rs::parity_grpc_wire_password_decode_accepts_utf8_and_base64_payload` | grpc login password decode | none equivalent outside parity module | none | keep+rename | Core decode compatibility contract. |
| `src/frontend/grpc/rpc.rs::parity_grpc_wire_login2_passwords_requires_pending_login` | grpc login state machine | none equivalent outside parity module | none | keep+rename | Distinct failed-precondition branch. |
| `src/frontend/grpc/rpc.rs::parity_grpc_wire_two_password_stage_emits_event_and_completes_login` | grpc two-password flow | nearby grpc tests cover other login branches | partial | keep+rename | Event sequence for two-password flow is specific and should stay. |
| `src/frontend/grpc/rpc.rs::parity_grpc_wire_lagged_stream_emits_generic_error_event` | grpc stream lag handling | none found | none | keep+rename | Unique lagged broadcast handling test. |
| `src/frontend/grpc/mod.rs::parity_integration_proton_fixture_reuse_survives_service_restart` | grpc service startup fixture reuse | none equivalent found | none | keep+rename | Unique restart persistence for fixture-backed sessions. |
| `src/frontend/grpc/mod.rs::parity_integration_login_then_logout_updates_user_list_and_emits_disconnect` | grpc login/logout lifecycle | `send_bad_event_user_feedback_without_resync_logs_user_out_and_emits_disconnect` | partial | keep+rename | Similar disconnect assertion but different action path (logout vs bad-event flow). |
| `src/frontend/grpc/mod.rs::parity_integration_disk_cache_move_persists_across_service_restart` | disk cache move persistence | `set_disk_cache_path_moves_payload_and_updates_effective_path`, `set_disk_cache_path_moves_live_gluon_store_and_updates_bootstrap_path` | high | merge+rename | Strong overlap; keep one canonical restart-persistence scenario and merge assertions. |
| `src/frontend/grpc/mod.rs::parity_integration_restart_and_quit_signal_shutdown` | app lifecycle signals | none equivalent found | none | keep+rename | Only restart/quit shutdown signal contract test. |
| `tests/gluon_parity_integration.rs::be031_startup_parity_recovers_fixture_layout_without_mutating_sync_sidecars` | gluon startup fixture recovery | `tests/gluon_recovery_integration.rs` startup recovery family | partial | keep+rename | Unique sync-sidecar non-mutation assertion. |
| `tests/gluon_parity_integration.rs::be031_sync_restart_parity_preserves_uid_and_modseq_continuity` | store restart continuity | `tests/gluon_store_mutation.rs` continuity/restart tests | partial | merge+rename | Same domain; consolidate overlapping continuity assertions. |
| `tests/gluon_parity_integration.rs::be031_delete_parity_removes_blob_and_keeps_restart_state_consistent` | delete + restart consistency | `tests/gluon_store_mutation.rs` delete/uid continuity coverage | partial | merge+rename | Keep restart-state checks, dedupe shared mutation assertions. |
| `tests/gluon_parity_integration.rs::be031_cache_move_parity_keeps_store_readable_after_root_relocation` | cache root relocation | `tests/gluon_recovery_integration.rs` move/recovery behavior | partial | merge+rename | Similar relocation domain; merge where assertions are equivalent. |
| `tests/gluon_parity_integration.rs::be031_event_parity_persists_checkpoints_across_restart_and_session_delete` | checkpoint persistence/deletion | none equivalent found | none | keep+rename | Unique event-checkpoint lifecycle coverage. |

## Summary
- `keep+rename`: 23
- `merge+rename`: 10
- `merge+delete`: 3

## Execution order for refactor
1. Rename-only pass (`parity_*` -> normal names), no behavior edits.
2. Apply `merge+delete` first (lowest risk, obvious duplicates).
3. Apply `merge+rename` by module (`api`, `smtp/imap`, `grpc`, `gluon`).
4. Re-run full suite and targeted module tests after each module migration.

## Validation commands
- `cargo test --locked`
- `cargo test --locked --test smtp_integration`
- `cargo test --locked --test runtime_events_e2e`
- `cargo test --locked --test gluon_integration`
- `cargo test --locked --lib`
