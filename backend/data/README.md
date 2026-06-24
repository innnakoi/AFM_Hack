# SOC log datasets

Downloaded safe JSONL event logs from OTRF Security-Datasets:

https://github.com/OTRF/Security-Datasets

Included datasets:

- `cmd_mshta_javascript_getobject_sct`: Windows Security events for MSHTA SCT execution.
- `cmd_sam_copy_esentutl`: Windows Security events for SAM copy via `esentutl`.
- `empire_mimikatz_logonpasswords`: Windows Security events for Mimikatz logonpasswords behavior.
- `msf_record_mic`: Windows/Application/Security events for microphone collection behavior.
- `reg_disable_eventlog_service_startuptype_modification_via_registry`: Windows events for event log service modification.

The original zip archives are not kept in the project because security datasets may contain signatures or lab artifacts that endpoint protection tools can flag. The extracted JSONL files are plain text logs and are consumed by `backend/soc_logs.py`.

To use the data:

1. Start the backend.
2. Open the dashboard.
3. Click `Load SOC`.

The backend exposes:

- `GET /api/soc/datasets`
- `POST /api/soc/load`
- `POST /api/soc/clear`
- `GET /api/soc/events`
