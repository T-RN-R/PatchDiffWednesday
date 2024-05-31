# Patch Diff Wednesday
On the second Tuesday of each month, Microsoft has something called [Patch Tuesday](https://en.wikipedia.org/wiki/Patch_Tuesday). On this day, Microsoft releases security updates for their software. The day after, I have dubbed Patch Diff Wednesday. This repository is my attempt to understand security changes made to their software, primarily Windows. 

## Objectives
I try to do at least 1 patch diff for every Patch Tuesday (Although currently I am on pace to do this once a year...). This helps me learn a few things:
1. What do common vulnerabilities in Windows look like?
2. Are there any novel vulnerability classes/attack surfaces present?
3. How can the security community better the state of software security?

## CVEs

| CVE                                                | Description                             | Component      | In the Wild |
| -------------------------------------------------- | --------------------------------------- | -------------- | ----------- |
| [CVE-2021-42285](Windows/CVE-2021-42285/README.md) | EoP in `NtQuerySystemInformation`       | Windows Kernel | No          |
| [CVE-2022-24528](Windows/CVE-2022-24528/README.md) | Remote buffer overflow                  | RPC Runtime    | No          |
| [CVE-2023-21554](Windows/CVE-2023-21554/README.md) | OOB Read/Write                          | MSMQ           | No          |
| [CVE-2024-26209](Windows/CVE-2024-26209/README.md) | Information disclosure                  | LSASRV.dll     | No          |
| [CVE-2024-30018](Windows/CVE-2024-30018/README.md) | Bug in `NtSetInformationWorkerFactory`? | Windows Kernel | No          |


## What tools do I use?
I primarly use [Ghidra](https://github.com/NationalSecurityAgency/ghidra), along with the excellent [Ghidra Patch Diff Correlator](https://github.com/clearbluejar/ghidra-patchdiff-correlator). I sometimes use IDA Pro, along with the [Diaphora](https://github.com/joxeankoret/diaphora) plugin if I'm not quite getting the results I want from Ghidra.

## How do I learn this?
I recommend one uses [Patch Diffing in the Dark](https://github.com/VulnerabilityResearchCentre/patch-diffing-in-the-dark)  and [CVE North Stars](https://cve-north-stars.github.io) as guiding resources.
