# bluskrn.Tests.ps1
# Unit tests for bluskrn.ps1 using Pester

Import-Module Pester

Describe "bluskrn.ps1 Unit Tests" {

    BeforeAll {
        . "$PSScriptRoot\bluskrn.ps1"
    }

    Context "Initialize-Environment" {
        It "Creates output directory if it doesn't exist" {
            $testOutputPath = Join-Path -Path $env:TEMP -ChildPath "BSODTestOutput"
            Remove-Item -Path $testOutputPath -Recurse -Force -ErrorAction SilentlyContinue

            $script:OutputPath = $testOutputPath
            Initialize-Environment

            Test-Path $testOutputPath | Should -BeTrue

            Remove-Item -Path $testOutputPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context "Get-LatestCrashDump" {
        It "Returns null if dump directory does not exist" {
            $result = Get-LatestCrashDump -DumpDirectory "C:\NonExistentPath"
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Initialize-BugcheckKnowledgeBase" {
        It "Creates a valid JSON knowledge base file" {
            $testKBPath = Join-Path -Path $env:TEMP -ChildPath "BugcheckKB_Test.json"
            Remove-Item -Path $testKBPath -Force -ErrorAction SilentlyContinue

            $script:KnowledgeBasePath = $testKBPath
            Initialize-BugcheckKnowledgeBase

            Test-Path $testKBPath | Should -BeTrue
            $content = Get-Content $testKBPath -Raw | ConvertFrom-Json
            $content | Should -Not -BeNullOrEmpty

            Remove-Item -Path $testKBPath -Force -ErrorAction SilentlyContinue
        }
    }

    Context "Initialize-DriversDatabase" {
        It "Creates a valid JSON drivers database file" {
            $testDBPath = Join-Path -Path $env:TEMP -ChildPath "DriversDB_Test.json"
            Remove-Item -Path $testDBPath -Force -ErrorAction SilentlyContinue

            $script:DriversDBPath = $testDBPath
            Initialize-DriversDatabase

            Test-Path $testDBPath | Should -BeTrue
            $content = Get-Content $testDBPath -Raw | ConvertFrom-Json
            $content | Should -Not -BeNullOrEmpty

            Remove-Item -Path $testDBPath -Force -ErrorAction SilentlyContinue
        }
    }
} 