# Restic cryptographic proposal

This proposal introduces a more advanced cryptographic system for restic designed to mitigate host-compromise threats, particularly the two most common consequences of such incidents: data exfiltration, by preventing historical backup data from being readable, and ransomware, by preventing attackers from destroying historical backups.

Full text of the proposal is available in the [design.md](design.md) file.
