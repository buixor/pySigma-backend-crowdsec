![pylint](https://github.com/buixor/pySigma-backend-crowdsec/actions/workflows/pylint.yml/badge.svg)

![pytest](https://github.com/buixor/pySigma-backend-crowdsec/actions/workflows/pytest.yml/badge.svg)

# pySigma crowdsec Backend

This is a **WIP** (but functional) crowdsec backend+pipeline for [pySigma](https://github.com/SigmaHQ/pySigma/).

# Testing

Use `poetry` and install `sigma-cli` to test rules conversion:

```bash
poetry shell
poetry install
pip3 install sigma-cli
```

# Converting Crowdsec Rules

_note: `sigma` outputs everything in one file._

```bash
for i in `find /path/to/sigma_core/rules/windows/process_creation/ -type f` ; do echo ${i} ; sigma convert -p crowdsec -t crowdsec  ${i} > /path/to/$(basename ${i}) ; done
```

# Example output

```yaml
#sigma convert -p crowdsec -t crowdsec .../sigma_core/rules/windows/process_creation/proc_creation_win_lolbin_msdt_answer_file.yml
type: trigger
name: sigmahq/proc_creation_win_lolbin_msdt_answer_file
description: |
  Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab)
filter: |
  (evt.Meta.service == 'sysmon' && evt.Parsed.EventID == '1') && (evt.Parsed.Image endsWith '\\msdt.exe' && evt.Parsed.CommandLine contains '\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml' && (evt.Parsed.CommandLine contains ' -af ' || evt.Parsed.CommandLine contains ' /af ') && not (evt.Parsed.ParentImage endsWith '\\pcwrun.exe'))
blackhole: 2m
#status: test
labels:
  service: windows
  confidence: 1
  spoofable: 0
  classification:
   - attack.t1218

  label: "Execute MSDT Via Answer File"
  behavior : "windows:audit"
  remediation: false

scope:
  type: ParentProcessId
  expression: evt.Parsed.ParentProcessId
```

# Support Categories

- [x] WebServer
- [x] Windows / `registry_add`
- [x] Windows / `process_creation`
