# Windows trust and deployment status

The preview is unsigned. Code signing requires a real publisher identity. `npm run dist` supports electron-builder's `CSC_LINK` / `CSC_KEY_PASSWORD` configuration; set `SENTINEL_REQUIRE_SIGNING=1` to reject a release build without a configured identity. Never commit a certificate, password or signing token. Sign the owned service helper separately with your organization's signing service before packaging; vendor signatures and upstream licenses must be retained. Verify signatures on the app, helper and installer before calling a release signed.

Signing authenticates the publisher; it does not guarantee immediate SmartScreen reputation or prevent false-positive detection. No automatic Defender exclusions, antivirus disabling, or reputation bypass is implemented.

[`IWscProduct`](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproduct) exposes product information; it is not a public self-registration/whitelisting API. A production antivirus integration needs the relevant Microsoft vendor program and eligibility work, including [MVI requirements](https://learn.microsoft.com/unified-secops/virus-initiative-criteria). Registering a product does not make arbitrary bundled utilities exempt from Defender inspection.

Kernel deployment also needs the [Microsoft driver signing process](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-), a minifilter altitude, native service integration and validation in disposable Windows VMs. The experimental driver directory is excluded from both `files` and `extraResources`. There is no driver installer or automatic driver load.

No signing certificate was available during this build. SCM service installation, Secure Boot/HVCI behavior, Driver Verifier/HLK, laptop power transitions and clean-machine installation were not validated. The shipped background host's process job, restart recovery and packaged runtime were exercised separately; those checks are not substitutes for those deployment tests.
