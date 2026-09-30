# Bundled detection tools

Sentinel invokes these independent upstream programs through their command-line interfaces; it does not incorporate their source into its MIT-licensed application. Their original license and copyright notices are distributed in `resources/engines`.

| Component | Version | License / corresponding source                                                                                               |
| --------- | ------- | ---------------------------------------------------------------------------------------------------------------------------- |
| ClamAV    | 1.5.4   | GPLv2; [complete release source](https://github.com/Cisco-Talos/clamav/archive/refs/tags/clamav-1.5.4.tar.gz)                |
| YARA-X    | 1.21.0  | BSD-3-Clause; [source and license](https://github.com/VirusTotal/yara-x/tree/v1.21.0)                                        |
| Radare2   | 6.2.2   | LGPLv3 and component notices; [complete release source](https://github.com/radareorg/radare2/archive/refs/tags/6.2.2.tar.gz) |
| osquery   | 5.23.1  | Apache-2.0 and bundled component notices; [source](https://github.com/osquery/osquery/tree/5.23.1)                           |

The optional curated YARA feed comes from [Neo23x0 Signature Base](https://github.com/Neo23x0/signature-base). Downloaded rule source, author metadata and the upstream [Detection Rule License 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) are retained in the profile's `monitor/rules/<commit>` directory. Individual rule notices remain authoritative. Match messages include the supplied author attribution. The feed is a selected subset, not the entire upstream repository.

Amaru was reviewed as architecture inspiration only. No Amaru source was incorporated.
