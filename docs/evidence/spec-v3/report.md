# .neapp v3 spec — offline vector evidence

Host-side spec evidence only: no real Host compilation, no resource or
device writes, no Line Crossing Web, no device PKA (spec §14).
The CONFIG_APPLY golden is an opaque-payload transport vector: it proves
control-wire framing/quota/session forwarding only, NOT real business
config availability (candidate schema/validation and the full readable
active-config projection belong to App #21; NE301 #57 consumes its
reviewed public schema). App-owned persistent state (lc_stateblob.c 152B,
counters/window/report_seq) is not a writable config candidate.

| vector | expected | result | detail |
| --- | --- | --- | --- |
| golden.tbs_length | 244 | PASS | 244B |
| golden.tbs_sha256 | d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e | PASS | d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e |
| golden.native_crc32 | 0xde8e3439 | PASS | 0xde8e3439 |
| golden.native_sha256 | aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69 | PASS | aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69 |
| golden.der_deterministic | 304402204646fc74c70bbbefcabc29afb8228bc121ad8b432104254d0b3f09819e9b6de50220251fd81c3f8976906785871c0016bad865f5e3c7f460b67b76e6fc1cce5bab50 | PASS | 70B |
| golden.package_length | 314 | PASS | 314B |
| golden.package_sha256 | c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342 | PASS | c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342 |
| golden.full_accept_v3 | ACCEPT | PASS | structure->trust->signature->policy order accepts golden v3 package |
| golden.full_accept_without_trust_map | PUBLISHER_UNTRUSTED | PASS | publisher_id 'test-publisher' not trusted |
| golden.openssl_cross_verify | Verified OK | PASS |  |
| resign.unknown_capability_bit8 | BAD_PACKAGE | PASS | unknown capability bits 0x00000100 |
| resign.control_max_zero_with_bit6 | BAD_PACKAGE | PASS | control_receive requires nonzero control_max |
| resign.snapshot_max_without_bit7 | BAD_PACKAGE | PASS | snapshot_max set without business_snapshot |
| resign.reserved_184_191_nonzero | BAD_PACKAGE | PASS | manifest reserved[184..191] not zero |
| resign.run_profile_1_in_v3 | BAD_PACKAGE | PASS | unknown run_profile 1 |
| resign.profile2_missing_bit5 | BAD_PACKAGE | PASS | profile 2 must declare session_lifecycle (bit5) |
| resign.profile2_missing_bit6 | BAD_PACKAGE | PASS | profile 2 must declare control_receive (bit6) |
| resign.line_crossing_missing_bit3 | BAD_PACKAGE | PASS | report_max set without report_submit |
| resign.event_max_below_1576 | RESOURCE_LIMIT | PASS | event_max 1024 < 1576 |
| resign.report_max_below_6144 | RESOURCE_LIMIT | PASS | report_max 4096 < 6144 |
| resign.control_max_below_generic_wire_min | RESOURCE_LIMIT | PASS | control_max 16 < 32 (generic 32B control wire header) |
| resign.control_max_above_host | RESOURCE_LIMIT | PASS | control_max exceeds host control capacity |
| resign.snapshot_max_above_host | RESOURCE_LIMIT | PASS | snapshot_max exceeds host snapshot RAM |
| resign.quota_without_capability_bit | BAD_PACKAGE | PASS | ai_events requires nonzero event_max |
| resign.reserved_58_59_nonzero | BAD_PACKAGE | PASS | manifest reserved[58..59] not zero |
| resign.wrong_board | TARGET_INCOMPATIBLE | PASS | board 0x00003011 |
| resign.untrusted_key_fingerprint | PUBLISHER_UNTRUSTED | PASS | publisher_key_sha256 mismatch for 'test-publisher' |
| resign.abi_v2_value_in_nmf3 | BAD_PACKAGE | PASS | required_host_abi 0x00020000 != 0x00030000 |
| resign.native_abi_v2_mismatch | BAD_PACKAGE | PASS | native abi 0x00020000 != manifest required_host_abi |
| resign.native_reserved0_nonzero | BAD_PACKAGE | PASS | native header reserved0 != 0 |
| resign.unknown_publisher_id | PUBLISHER_UNTRUSTED | PASS | publisher_id 'other-publisher' not trusted |
| resign.v3_new_caps_on_v2_caps_host | ABI_INCOMPATIBLE | PASS | host does not provide capability bits 0x000000c0 |
| tamper.signed_payload_payload_byte | SIGNATURE_INVALID | PASS | ECDSA P-256 verification failed |
| tamper.signed_manifest_byte | SIGNATURE_INVALID | PASS | ECDSA P-256 verification failed |
| tamper.der_byte | SIGNATURE_INVALID | PASS | ECDSA P-256 verification failed |
| der.trailing_byte | BAD_PACKAGE | PASS | DER SEQUENCE length not minimal/exact |
| der.truncated | BAD_PACKAGE | PASS | DER SEQUENCE length not minimal/exact |
| container.truncated_image | BAD_PACKAGE | PASS | package too short |
| interop.v1_golden_tbs_rebuilt | 5035e6512c0c003490b228b9ae0dc6351166a04b0dc96a3ff053bb7fe348fe91 | PASS | 212B |
| interop.v1_pkg_on_v1_semantics_host | ACCEPT | PASS | v1 package accepted under frozen v1 rules only (16B table log/tick) |
| interop.v1_pkg_on_v3_host | BAD_PACKAGE | PASS | container magic 4e45415050010000 != v3 |
| interop.v1_pkg_on_v2_host | BAD_PACKAGE | PASS | container magic != v2 |
| interop.v2_golden_tbs_rebuilt | e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278 | PASS | 244B |
| interop.v2_golden_pkg_rebuilt | 3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e | PASS | 314B |
| interop.v2_pkg_on_v2_semantics_host | ACCEPT | PASS | v2 package accepted under frozen v2 rules only (48B table, caps<=bit5) |
| interop.v2_pkg_on_v3_host | BAD_PACKAGE | PASS | container magic 4e45415050020000 != v3 |
| interop.v2_pkg_on_v1_host | BAD_PACKAGE | PASS | container magic != v1 |
| interop.v3_pkg_on_v3_host | ACCEPT | PASS | v3 golden accepted under v3 rules (60B table, caps bits0..7) |
| interop.nmf2_manifest_inside_v3_container | BAD_PACKAGE | PASS | manifest magic 4e4d4632 != NMF3 |
| interop.nmf3_manifest_inside_v2_container | BAD_PACKAGE | PASS | manifest magic != NMF2 |
| interop.abi_table_sizes_distinct | 16/48/60 | PASS |  |
| command.golden_config_apply_opaque_payload_184B | e6fafa1183d9fadd84ee17721994ce2f758b8b988970a7c5b8f5fb6d7ecec3ca | PASS | 184B opaque transport vector, not a real business config candidate |
| command.validate_config_apply | ok | PASS |  |
| command.golden_counters_reset_32B | 5d0a37ef0587533cbb141da8ad08fadb43b0e88d4ed115bb52d1ab4aeb8f43fb | PASS | 32B |
| command.validate_counters_reset | ACCEPT | PASS |  |
| command.negative.bad_proto_magic | BAD_CONTROL_WIRE | PASS | proto magic b'MFC3' != NFC3 |
| command.negative.header_version_2 | BAD_CONTROL_WIRE | PASS | header version 2 != 1 |
| command.negative.unknown_msg_type | BAD_CONTROL_WIRE | PASS | unknown msg_type 5 |
| command.negative.total_len_mismatch | BAD_CONTROL_WIRE | PASS | total_len 255 != buffer 184 |
| command.negative.session_generation_zero | BAD_CONTROL_WIRE | PASS | command session_generation must be nonzero |
| command.negative.request_id_zero | BAD_CONTROL_WIRE | PASS | command request_id must be nonzero |
| command.negative.expected_generation_zero | BAD_CONTROL_WIRE | PASS | command expected_config_generation must be nonzero |
| command.negative.state_revision_nonzero | BAD_CONTROL_WIRE | PASS | command state_revision must be zero |
| command.negative.unknown_flag_bit1 | BAD_CONTROL_WIRE | PASS | unknown command flags 0x00000002 |
| command.negative.config_apply_empty_payload | BAD_CONTROL_WIRE | PASS | CONFIG_APPLY requires a payload |
| command.negative.counters_reset_with_payload | BAD_CONTROL_WIRE | PASS | COUNTERS_RESET must carry empty payload |
| command.negative.reply_type_is_not_command | BAD_CONTROL_WIRE | PASS | msg_type 3 is not a command |
| reply.golden_applied_32B | 054b7356b81fb555d6bdbc05f6d666cedb0d84a98555476a06cb32df09d87eed | PASS | 32B |
| reply.validate_applied | ok | PASS |  |
| reply.validate_rejected_stale | ACCEPT | PASS |  |
| reply.negative.unknown_result_status | BAD_CONTROL_WIRE | PASS | unknown result_status 8 |
| reply.negative.applied_zero_generation | BAD_CONTROL_WIRE | PASS | reply active/new_config_generation must be nonzero |
| reply.negative.payload_not_allowed | BAD_CONTROL_WIRE | PASS | total_len 32 != buffer 33 |
| reply.negative.zero_generation | BAD_CONTROL_WIRE | PASS | reply active/new_config_generation must be nonzero |
| snapshot.golden_771B | 9e1031d07cb4b1217429a927bc3f69909c9cad84ef9036975fab99afa77403b5 | PASS | 771B |
| snapshot.validate_golden | ok | PASS |  |
| snapshot.negative.duplicate_json_key | BAD_SNAPSHOT | PASS | duplicate JSON object keys |
| snapshot.negative.invalid_utf8 | BAD_SNAPSHOT | PASS | snapshot payload not valid UTF-8 |
| snapshot.negative.trailing_data | BAD_SNAPSHOT | PASS | snapshot JSON has trailing data |
| snapshot.negative.top_level_not_object | BAD_SNAPSHOT | PASS | snapshot JSON must be an object |
| snapshot.negative.nan_constant | BAD_SNAPSHOT | PASS | non-JSON constant NaN |
| snapshot.negative.app_filled_session_generation | BAD_CONTROL_WIRE | PASS | snapshot session_generation must be zero |
| snapshot.negative.app_filled_request_id | BAD_CONTROL_WIRE | PASS | snapshot request_id must be zero |
| snapshot.negative.zero_config_generation | BAD_CONTROL_WIRE | PASS | snapshot config_generation must be nonzero |
| snapshot.negative.oversize_quota | QUOTA_EXCEEDED | PASS | snapshot 2040B exceeds snapshot_max 1024 |
| session.register_without_session | UNAUTHORIZED | PASS |  |
| session.control_next_without_session | UNAUTHORIZED | PASS |  |
| session.snapshot_without_session | UNAUTHORIZED | PASS |  |
| session.control_next_no_event | NO_EVENT=1 | PASS |  |
| session.register_config_apply | PENDING | PASS |  |
| session.control_next_buffer_too_small_keeps_pending | BUFFER_TOO_SMALL + pending kept | PASS |  |
| session.second_pending_busy | BUSY | PASS |  |
| session.control_next_delivers_184B | OK 184B | PASS |  |
| session.delivered_bytes_exact | match | PASS |  |
| session.control_next_after_delivery_no_event | NO_EVENT=1 | PASS |  |
| session.reply_wrong_request_id | INVALID_ARGUMENT | PASS |  |
| session.reply_right_request_id | OK | PASS |  |
| session.known_generation_advanced_by_applied | 2 | PASS |  |
| session.dedup_same_id_same_semantics_cached | CACHED | PASS |  |
| session.dedup_same_id_different_payload_rejected | DUPLICATE_ID_CONFLICT | PASS |  |
| session.register_next_new_id | PENDING | PASS |  |
| session.stale_expected_generation_conflict | CONFLICT | PASS |  |
| session.no_baseline_registration_allowed | PENDING | PASS |  |
| session.counters_reset_unconfirmed_rejected | UNCONFIRMED | PASS |  |
| session.oversize_command_quota | QUOTA_EXCEEDED | PASS |  |
| snapshot.fresh_at_5000ms | current | PASS |  |
| snapshot.stale_at_10001ms | stale | PASS |  |
| snapshot.refresh_clears_stale | current | PASS |  |
| snapshot.version_increments | 2 | PASS |  |
| session.close_marks_delivered_unknown | 1 unknown | PASS |  |
| session.snapshot_unavailable_after_close | unavailable | PASS |  |
| session.reconcile_before_snapshot_unknown | UNKNOWN | PASS |  |
| session.reconcile_after_snapshot_read_only | RECONCILED | PASS |  |
| session.reconcile_does_not_replay | no pending/delivered | PASS |  |
| txn.host_learns_baseline_from_snapshot | 1 | PASS |  |
| txn.register_accepted_pending_only | PENDING | PASS |  |
| txn.delivered_to_app | OK | PASS |  |
| txn.applied_reply_new_generation | APPLIED gen2 rev1 | PASS |  |
| txn.host_accepts_reply | OK | PASS |  |
| txn.known_generation_after_apply | 2 | PASS |  |
| txn.snapshot_after_apply_matches | gen2 | PASS |  |
| txn.config_apply_preserves_counters | kept | PASS |  |
| txn.candidate_cannot_backfill_persistent_state | counters/report_seq unchanged | PASS |  |
| txn.backfill_candidate_reply_cached | OK | PASS |  |
| txn.no_event_when_no_pending | NO_EVENT=1 | PASS |  |
| txn.stale_expected_generation_rejected_at_app | REJECTED_STALE_CONFIG | PASS |  |
| txn.stale_rejection_keeps_generation | 2 | PASS |  |
| txn.cas_conflict_fails_not_applied | FAILED_STATE_CONFLICT | PASS |  |
| txn.cas_conflict_preserves_persisted | kept | PASS |  |
| txn.io_error_fails_not_applied | FAILED_STORAGE_IO | PASS |  |
| txn.storage_unknown_not_applied | FAILED_STORAGE_UNKNOWN | PASS |  |
| txn.storage_unknown_restriction_on | restricted | PASS |  |
| txn.restricted_app_blocks_destructive | FAILED_STORAGE_UNKNOWN | PASS |  |
| txn.recovery_restores_operation | restricted cleared | PASS |  |
| txn.counters_reset_applied | APPLIED | PASS |  |
| txn.counters_reset_keeps_config_generation | gen unchanged 3 | PASS |  |
| txn.counters_reset_advances_state_revision | rev 9 | PASS |  |
| txn.counters_reset_zeroes_counters_keeps_report_seq | 0/0 seq41 | PASS |  |
| migration.v2_same_identity_restores_state | counters 55/44 gen1 | PASS |  |
| migration.cross_identity_refused | FORBIDDEN | PASS | FORBIDDEN |
| session.generation_wrap_forbidden | refused | PASS | BAD_CONTROL_WIRE |
| abi.table_60B | 60 | PASS | 60B |
| abi.validate_v3_table | ACCEPT | PASS |  |
| abi.thirteen_callbacks | 13 | PASS | log,tick_ms,event_next,model_meta,class_name,report_submit,report_status,state_read,state_commit,should_stop,control_next,control_reply,snapshot_publish |
| abi.new_callbacks_at_48_52_56 | control_next/control_reply/snapshot_publish | PASS |  |
| abi.negative.table_size_48 | ABI_INCOMPATIBLE | PASS | table_size 48 != 60 |
| abi.negative.abi_0x00020000 | ABI_INCOMPATIBLE | PASS | abi_version 0x00020000 != 0x00030000 |
| abi.negative.length_48_prefix | ABI_INCOMPATIBLE | PASS | v3 table length 48 != 60 |
| abi.negative.null_pointer_offset_56 | ABI_INCOMPATIBLE | PASS | null pointer at offset 56 |
| abi.control_next_no_event_is_1 | 1 | PASS |  |

## Pinned hashes

- golden_tbs_sha256: `d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e`
- golden_package_sha256: `c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342`
- golden_der: `304402204646fc74c70bbbefcabc29afb8228bc121ad8b432104254d0b3f09819e9b6de50220251fd81c3f8976906785871c0016bad865f5e3c7f460b67b76e6fc1cce5bab50`
- spki_sha256: `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`
- command_config_apply_sha256: `e6fafa1183d9fadd84ee17721994ce2f758b8b988970a7c5b8f5fb6d7ecec3ca`
- command_counters_reset_sha256: `5d0a37ef0587533cbb141da8ad08fadb43b0e88d4ed115bb52d1ab4aeb8f43fb`
- reply_applied_sha256: `054b7356b81fb555d6bdbc05f6d666cedb0d84a98555476a06cb32df09d87eed`
- snapshot_sha256: `9e1031d07cb4b1217429a927bc3f69909c9cad84ef9036975fab99afa77403b5`
- v1_golden_tbs_sha256: `5035e6512c0c003490b228b9ae0dc6351166a04b0dc96a3ff053bb7fe348fe91`
- v2_golden_tbs_sha256: `e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278`
- v2_golden_package_sha256: `3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e`
