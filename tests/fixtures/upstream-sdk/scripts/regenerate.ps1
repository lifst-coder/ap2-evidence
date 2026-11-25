# Re-mint every upstream-sdk fixture with the official AP2 SDK and samples, then copy the
# public material into tests/fixtures/upstream-sdk/ (private keys are never copied).
#
#   powershell -File regenerate.ps1 -Upstream C:\src\AP2 -SdkPython C:\venvs\ap2sdk\Scripts\python.exe -Out C:\tmp\interop-out
#
# -Upstream   clone of github.com/google-agentic-commerce/AP2 checked out at e1ea56d (v0.2.0)
# -SdkPython  python.exe of a venv with the upstream SDK and sample dependencies installed
#             (pip install -e <Upstream>/code/sdk/python plus the samples' requirements)
# -Out        empty scratch folder; it receives throwaway PRIVATE keys, keep it out of the repo
# Combined from the run_all.ps1 / run_tamper.ps1 used for the committed fixtures; the
# verification step of those scripts is replaced by tests/test_upstream_sdk.py.
param(
  [Parameter(Mandatory = $true)][string]$Upstream,
  [Parameter(Mandatory = $true)][string]$SdkPython,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$env:PYTHONIOENCODING = 'utf-8'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fixtures = Split-Path -Parent $here
$variants = [ordered]@{
  'card'         = @('mint_upstream', 'card')
  'x402'         = @('mint_upstream', 'x402')
  'v_issuerhash' = @('mint_variants', 'hash_mode=issuer_jwt_hash')
  'v_extras_usd' = @('mint_variants', 'extras=1')
  'v_extras_jpy' = @('mint_variants', 'extras=1', 'currency=JPY')
  'v_extras_kwd' = @('mint_variants', 'extras=1', 'currency=KWD')
  'v_redact'     = @('mint_variants', 'redact=1')
  'v_hp'         = @('mint_variants', 'hp=1')
}
foreach ($name in $variants.Keys) {
  $a = $variants[$name]
  & $SdkPython -I "$here\$($a[0]).py" "$Out\$name" $a[1..($a.Count - 1)]
}
& $SdkPython -I "$here\tamper.py" "$Out\card" "$Out\x402" "$Out\tamper"
& $SdkPython -I "$here\probes.py" "$Out\card" "$Out\probes"
& $SdkPython -I "$here\drive_samples.py" $Upstream "$Out\samples_hnp_card"
& $SdkPython -I "$here\collect_fixtures.py" $Out $fixtures
