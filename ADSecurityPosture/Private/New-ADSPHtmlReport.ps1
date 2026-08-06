function ConvertTo-ADSPHtmlEncoded {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $t = [string]$Value
    $t = $t.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'","&#39;")
    return $t
}

function New-ADSPHtmlReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Path)
    $esc = ${function:ConvertTo-ADSPHtmlEncoded}
    $sevCards = foreach ($s in @('Critical','High','Medium','Low','Informational')) {
        $c = 0
        if ($Report.severity_counts.PSObject.Properties.Name -contains $s) { $c = [int]$Report.severity_counts.$s }
        "<div class='card'><div class='n'>$c</div><div class='l'>$s</div></div>"
    }
    $findingRows = foreach ($f in @($Report.findings | Select-Object -First 50)) {
        "<tr><td>$(& $esc $f.severity)</td><td>$(& $esc $f.rule_id)</td><td>$(& $esc $f.title)</td><td>$(& $esc $f.target_id)</td><td>$(& $esc $f.result)</td><td>$(& $esc $f.message)</td></tr>"
    }
    $banner = if ($Report.synthetic) {
        '<div class="banner">SYNTHETIC DEMONSTRATION DATA — This report contains synthetic Active Directory security-posture data created exclusively for demonstration, testing, and documentation purposes. No real domain, forest, user, group, computer, trust, GPO, ACL, credential, or organization information is included.</div>'
    } else { '<div class="banner warn">Raw directory snapshots and reports can contain sensitive identity metadata. Protect accordingly.</div>' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>AD Security Posture Report</title>
<style>
body{font-family:Segoe UI,Tahoma,sans-serif;margin:0;background:#f3f6f8;color:#1b242c}
header{background:linear-gradient(120deg,#0b3d4a,#145c6b 55%,#1f7a66);color:#fff;padding:28px 32px}
h1{margin:0 0 6px;font-size:28px}
.sub{opacity:.9;font-size:14px}
.banner{background:#fff3cd;color:#664d03;padding:12px 32px;border-bottom:1px solid #ffe69c;font-weight:600}
.banner.warn{background:#f8d7da;color:#842029;border-color:#f5c2c7}
main{padding:24px 32px}
.score{display:flex;gap:24px;align-items:center;margin:16px 0 24px}
.grade{width:96px;height:96px;border-radius:16px;background:#0b3d4a;color:#fff;display:flex;align-items:center;justify-content:center;font-size:40px;font-weight:700}
.meta{font-size:14px;line-height:1.5}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:#fff;border:1px solid #d7e0e6;border-radius:12px;padding:14px 18px;min-width:110px}
.card .n{font-size:28px;font-weight:700}
.card .l{font-size:12px;color:#5b6b76}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d7e0e6}
th,td{padding:8px 10px;border-bottom:1px solid #e6eef2;text-align:left;font-size:13px;vertical-align:top}
th{background:#eaf2f5}
footer{padding:20px 32px;color:#5b6b76;font-size:12px}
section{margin:28px 0}
h2{margin:0 0 10px;font-size:18px}
</style>
</head>
<body>
<header>
<h1>Active Directory Security Posture Auditor</h1>
<div class="sub">Offline security-posture assessment · Policy-driven findings · Defense in depth prioritization</div>
</header>
$banner
<main>
<section class="score">
<div class="grade">$(& $esc $Report.grade)</div>
<div class="meta">
<div><strong>Score:</strong> $(& $esc $Report.score) / 100</div>
<div><strong>Policy:</strong> $(& $esc $Report.policy)</div>
<div><strong>Privacy:</strong> $(& $esc $Report.privacy_mode)</div>
<div><strong>Snapshot integrity:</strong> $(& $esc $Report.snapshot_hash_status)</div>
<div><strong>Completeness:</strong> $(& $esc $Report.snapshot_completeness)</div>
<div><strong>Exit code:</strong> $(& $esc $Report.exit_code)</div>
</div>
</section>
<section>
<h2>Severity summary</h2>
<div class="cards">$($sevCards -join '')</div>
</section>
<section>
<h2>Privileged-access summary</h2>
<p>Direct/transitive privileged membership findings require operational review. Counts are prioritization aids.</p>
<pre>$(& $esc (($Report.privileged_access_summary | ConvertTo-Json -Compress -Depth 4)))</pre>
</section>
<section>
<h2>Findings (first 50)</h2>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Target</th><th>Result</th><th>Message</th></tr></thead>
<tbody>$($findingRows -join '')</tbody>
</table>
</section>
<section>
<h2>Limitations</h2>
<ul>$(@($Report.collection_limitations) | ForEach-Object { "<li>$(& $esc $_)</li>" })</ul>
</section>
<section>
<h2>Security notice</h2>
<p>$(& $esc $Report.security_notice)</p>
</section>
</main>
<footer>
active-directory-security-posture-auditor $(& $esc $Report.tool_version) · Standalone HTML · No external resources · Score is not certification
</footer>
</body>
</html>
"@
    Assert-ADSPNoBlockedAttributes -Object $Report -PathHint 'html-report'
    [IO.File]::WriteAllText($Path, $html, [Text.UTF8Encoding]::new($false))
}
