# Fake wsb.exe mimicking `wsb --raw` behaviour observed on 2026-11-01:
#   exec exits 0 once the guest process launched and reports {"ExitCode": n}.
# Guest commands understood: 'cmd.exe /c exit <n>', 'launch-fail', 'no-json'.
$argv = @($args)
if ($argv[0] -eq '--raw') { $argv = $argv[1..($argv.Count - 1)] }
switch ($argv[0]) {
    'list' { '{"WindowsSandboxEnvironments": []}'; exit 0 }
    'start' { '{"Id": "00000000-0000-0000-0000-000000000001"}'; exit 0 }
    'share' { exit 0 }
    'stop' { exit 0 }
    'exec' {
        $command = $argv[[Array]::IndexOf($argv, '-c') + 1]
        if ($command -eq 'launch-fail') {
            'Fehler beim Starten des Prozesses: (0x80070520)'
            exit -2147023584
        }
        if ($command -eq 'no-json') { 'unexpected'; exit 0 }
        if ($command -match 'exit (\d+)$') { "{`"ExitCode`": $($Matches[1])}"; exit 0 }
        '{"ExitCode": 0}'; exit 0
    }
    default { "unknown command $($argv[0])"; exit 1 }
}
