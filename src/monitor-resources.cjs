const os = require('node:os');
const { execFile } = require('node:child_process');
let previousCpu;
function cpuUsage() {
  const next = os.cpus().reduce(
    (sum, cpu) => ({
      idle: sum.idle + cpu.times.idle,
      total: sum.total + Object.values(cpu.times).reduce((a, b) => a + b, 0)
    }),
    { idle: 0, total: 0 }
  );
  const delta = previousCpu ? next.total - previousCpu.total : 0;
  const percent =
    delta > 0 ? Math.max(0, Math.min(100, Math.round(100 * (1 - (next.idle - previousCpu.idle) / delta)))) : null;
  previousCpu = next;
  return percent;
}

// Battery status works in session 0 as well as the desktop. Idle information is supplied by the
// authenticated desktop connection and expires; service-session input age is not user idle time.
async function sample(pid) {
  const value = {
    freeMB: Math.round(os.freemem() / 1048576),
    totalMB: Math.round(os.totalmem() / 1048576),
    cpuPercent: cpuUsage(),
    battery: null
  };
  if (process.platform !== 'win32') return { ...value, battery: false };
  const script = `Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class SentinelPower { [DllImport("kernel32.dll")] public static extern bool GetSystemPowerStatus(out Status s); [StructLayout(LayoutKind.Sequential)] public struct Status { public byte AC, Flags, Percent, Reserved; public uint Life, Full; }}'; $s = New-Object SentinelPower+Status; $ok = [SentinelPower]::GetSystemPowerStatus([ref]$s); $p = Get-Process -Id ${Number.isInteger(pid) ? pid : 0} -ErrorAction SilentlyContinue; @{ battery = $(if ($ok -and $s.AC -ne 255) { $s.AC -eq 0 } else { $null }); engineMB = $(if ($p) { [math]::Round($p.WorkingSet64 / 1MB) } else { 0 }); cpuSeconds = $(if ($p) { $p.CPU } else { 0 }) } | ConvertTo-Json -Compress`;
  try {
    const output = await new Promise((resolve, reject) =>
      execFile(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        { windowsHide: true, timeout: 10000, maxBuffer: 8192 },
        (err, stdout) => (err ? reject(err) : resolve(stdout))
      )
    );
    return { ...value, ...JSON.parse(output) };
  } catch {
    return value;
  }
}

module.exports = { sample };
