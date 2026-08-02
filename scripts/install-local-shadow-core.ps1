param(
    [string]$CoreRepository = (Join-Path $PSScriptRoot '..\..\shadow-core'),
    [string]$Python = (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe')
)

$ErrorActionPreference = 'Stop'
$CoreRepository = (Resolve-Path -LiteralPath $CoreRepository).Path
$WheelDirectory = Join-Path $CoreRepository 'build\claw-integration-wheel'

& $Python -m build --no-isolation --outdir $WheelDirectory $CoreRepository
$wheel = Get-ChildItem -LiteralPath $WheelDirectory -Filter 'shadow_core-0.1.0.dev0-*.whl' |
    Sort-Object Name |
    Select-Object -Last 1
if ($null -eq $wheel) {
    throw 'Shadow Core wheel was not produced.'
}
& $Python -m pip install --force-reinstall $wheel.FullName
