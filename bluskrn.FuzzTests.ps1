# bluskrn.FuzzTests.ps1
# Basic fuzz testing for bluskrn.ps1

. "$PSScriptRoot\bluskrn.ps1"

function Invoke-FuzzTest {
    param (
        [int]$Iterations = 100
    )

    Write-Host "Starting fuzz testing with $Iterations iterations..." -ForegroundColor Cyan

    for ($i = 1; $i -le $Iterations; $i++) {
        Write-Host "Iteration $i" -ForegroundColor Yellow

        # Generate random strings for paths
        $randomDumpPath = [System.IO.Path]::Combine($env:TEMP, [System.Guid]::NewGuid().ToString())
        $randomOutputPath = [System.IO.Path]::Combine($env:TEMP, [System.Guid]::NewGuid().ToString())
        $randomKBPath = [System.IO.Path]::Combine($env:TEMP, [System.Guid]::NewGuid().ToString() + ".json")
        $randomDriversDBPath = [System.IO.Path]::Combine($env:TEMP, [System.Guid]::NewGuid().ToString() + ".json")

        try {
            # Randomly call initialization functions with random paths
            $script:DumpPath = $randomDumpPath
            $script:OutputPath = $randomOutputPath
            $script:KnowledgeBasePath = $randomKBPath
            $script:DriversDBPath = $randomDriversDBPath

            Initialize-Environment
            Initialize-BugcheckKnowledgeBase
            Initialize-DriversDatabase

            # Randomly call Get-LatestCrashDump
            Get-LatestCrashDump -DumpDirectory $randomDumpPath | Out-Null

            # Randomly call Get-BugcheckAnalysis with random data
            $fakeCrashMetadata = @{
                BugcheckCode = "0x" + (Get-Random -Minimum 0 -Maximum 0xFFFFFF).ToString("X")
                BugcheckName = [System.Guid]::NewGuid().ToString()
            }
            Get-BugcheckAnalysis -CrashMetadata $fakeCrashMetadata | Out-Null

        } catch {
            Write-Warning "Exception caught during fuzz testing iteration $i: $_"
        } finally {
            # Cleanup
            Remove-Item -Path $randomDumpPath, $randomOutputPath, $randomKBPath, $randomDriversDBPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Fuzz testing completed." -ForegroundColor Green
}

# Run fuzz test with default 100 iterations
Invoke-FuzzTest -Iterations 100 