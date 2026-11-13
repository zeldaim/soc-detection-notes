# KISA 윈도우 보안 점검 스크립트 정리

> 원본: 개인 학습 노트(Notion)에서 옮겨 정리. 스크린샷은 생략했습니다.

> KISA 보안 교육 실습 | Windows 10 + Windows Server 2016

### 전체 구조
```plain text
실습 흐름:
*_settings.ps1 실행 → run_all.ps1 실행 → result/ 확인 → 수동 하드닝 → 재실행
```

- _settings.ps1 : 취약 환경을 의도적으로 만드는 스크립트 (실습 준비용)
- _check.ps1 : 각 항목을 점검하고 result 폴더에 Good/Bad/Review 파일 저장
- run_all.ps1 : _check.ps1 파일을 자동 탐색해서 전부 실행

### run_all.ps1
```powershell
Get-ChildItem -Path "." -Filter "*_check.ps1" | ForEach-Object { & $_.FullName }
```

핵심 포인트:

- 현재 디렉토리에서 _check.ps1 패턴의 파일을 모두 찾아서 순서대로 실행
- 새 점검 항목 추가 시 파일만 추가하면 됨 — run_all.ps1 수정 불필요
- & $_.FullName : 찾은 파일의 전체 경로로 실행

### PC 세트 (Windows 10)

#### PC_settings.ps1 — 취약 환경 조성
```powershell
#Requires -RunAsAdministrator

# PC-02 : 최소 암호 길이 0 설정
net accounts /minpwlen:0 | Out-Null

# PC-05 : Print Spooler 서비스 강제 실행
$spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -ne "Running") {
    Set-Service -Name "Spooler" -StartupType Automatic
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
}

# PC-15 : 공용 네트워크 방화벽 비활성화
Set-NetFirewallProfile -Profile Public -Enabled False
```

#### PC02_check.ps1 — 패스워드 정책 점검
```powershell
$tmpCfg = "$env:TEMP\secpol_pc02.cfg"
secedit /export /cfg $tmpCfg /quiet

$minLength  = [int](Get-Content $tmpCfg | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
$complexity = [int](Get-Content $tmpCfg | Select-String "PasswordComplexity").ToString().Split("=")[1].Trim()

Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue

$lengthOk     = ($minLength -ge 8)
$complexityOk = ($complexity -eq 1)
```

점검 기준 (KISA W-02):

- MinimumPasswordLength ≥ 8
- PasswordComplexity = 1 (활성화)
- 둘 다 만족 → Good / 하나라도 미달 → Bad

핵심 패턴 — secedit 파싱:
```plain text
secedit /export → .cfg 파일 생성
→ Select-String으로 원하는 줄 찾기
→ Split("=")[1]로 값 추출
→ 임시 파일 삭제
```

수동 하드닝: secpol.msc → 계정 정책 → 암호 정책

#### PC05_check.ps1 — 불필요한 서비스 점검
```powershell
$targets = @("Spooler", "RemoteRegistry")

foreach ($svcName in $targets) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue

    if ($svc -eq $null) {
        # 서비스 없음 → 문제 없음
    } elseif ($svc.Status -eq "Running") {
        $badItems += "$displayName = Running"
    }
}
```

점검 대상:

- Spooler (Print Spooler) : PrintNightmare 취약점 관련
- RemoteRegistry : 원격에서 레지스트리 접근 허용

판정: 하나라도 Running이면 Bad

수동 하드닝: services.msc → 해당 서비스 → 중지 + 시작 유형 수동/사용 안 함

#### PC13_check.ps1 — 백신 서명 업데이트 점검
```powershell
$mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($mpStatus -eq $null) {
    # Defender 없음 → Review (환경 문제일 수 있음)
    return
}

$lastUpdate = $mpStatus.AntivirusSignatureLastUpdated
$daysSince  = ((Get-Date) - $lastUpdate).Days

# 7일 이내 업데이트 → Good
```

PC13 vs PC14 비교:

설계 의도: PC13은 환경 문제일 수 있어 Review, PC14는 없으면 무조건 보안 위협

#### PC14_check.ps1 — 실시간 보호 점검
```powershell
$rtEnabled = $mpStatus.RealTimeProtectionEnabled

if ($rtEnabled) { Good } else { Bad }
```

수동 하드닝: Windows 보안 → 바이러스 및 위협 방지 → 실시간 보호 켜기

#### PC15_check.ps1 — 방화벽 설정 점검
```powershell
$profiles = Get-NetFirewallProfile  # Domain / Private / Public 세 프로필

foreach ($profile in $profiles) {
    if (-not $profile.Enabled) {
        $badItems += "$($profile.Name) = Disabled"
    }
}
```

판정: 세 프로필 중 하나라도 비활성화 → Bad

PC_settings에서 Public만 비활성화 → 실습 시 Public = Disabled Bad 생성

수동 하드닝: wf.msc → 각 프로필 속성 → 방화벽 상태 켜기

### 서버 세트 (Windows Server 2016)

#### W_settings.ps1 — 취약 환경 조성
```powershell
# W-01 : Administrator 계정명 원복
Rename-LocalUser -Name $adminAccount.Name -NewName "Administrator"

# W-02 : Guest 계정 활성화
Enable-LocalUser -Name "Guest"

# W-03 : 불필요한 계정 생성
New-LocalUser -Name "test02" -Password $pw -PasswordNeverExpires

# W-06 : Jack을 Administrators 그룹에 추가
Add-LocalGroupMember -Group "Administrators" -Member "Jack"

# W-40 : 감사 로깅 비활성화
auditpol /set /category:"Account Management" /success:disable /failure:disable
```

#### W01_check.ps1 — Administrator 계정명 변경 점검
```powershell
# 이름이 아니라 SID로 찾는 이유:
# 이름을 바꿔도 SID -500은 불변 → 정확한 탐지 가능
$adminAccount = Get-LocalUser | Where-Object { $_.SID.Value -like "S-1-5-21-*-500" }

if ($currentName -eq "Administrator") { Bad } else { Good }
```

핵심: S-1-5-21-*-500 = Windows 빌트인 Administrator의 고유 SID

이름 기반 검색은 이름 변경 시 탐지 불가 → SID 기반이 올바른 접근

수동 하드닝: lusrmgr.msc → Administrator 계정 → 이름 바꾸기

#### W02_check.ps1 — Guest 계정 비활성화 점검
```powershell
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

if ($guest.Enabled -eq $false) { Good } else { Bad }
```

수동 하드닝: lusrmgr.msc → Guest → 계정 사용 안 함 체크

#### W03_check.ps1 — 불필요한 계정 점검 (Review)
```powershell
$accounts = (Get-LocalUser | Select-Object -ExpandProperty Name) -join ", "
# 항상 Review — 어떤 계정이 불필요한지는 자동 판단 불가
```

설계 의도: 목록만 출력하고 담당자가 직접 확인

W01~W06 중 유일하게 Good/Bad 없이 Review만 존재

#### W04_check.ps1 — 계정 잠금 임계값 점검
```powershell
secedit /export → LockoutBadCount 파싱

if ($threshold -ge 1 -and $threshold -le 5) { Good } else { Bad }
```

기준:

- 0 = 잠금 없음 (무제한 로그인 시도 가능) → Bad
- 1~5 = KISA 권고 범위 → Good
- 6 이상 = 너무 관대 → Bad

수동 하드닝: secpol.msc → 계정 정책 → 계정 잠금 정책 → 계정 잠금 임계값

#### W05_check.ps1 — 평문 암호 저장 비활성화 점검
```powershell
secedit /export → ClearTextPassword 파싱

if ($value -eq 0) { Good } else { Bad }
```

보안 의미: ClearTextPassword = 1이면 비밀번호가 복호화 가능한 형태로 저장

→ 사실상 평문 저장과 같은 수준의 위험

수동 하드닝: secpol.msc → 계정 정책 → 암호 정책 → 해독 가능한 암호화 사용 → 사용 안 함

#### W06_check.ps1 — Administrators 그룹 멤버 점검
```powershell
$members  = Get-LocalGroupMember -Group "Administrators"

# SID -500 (빌트인 Administrator)만 있어야 정상
$nonAdmin = $members | Where-Object {
    $_.SID.Value -notlike "S-1-5-21-*-500"
}

if ($nonAdmin) { Bad } else { Good }
```

수동 하드닝: lusrmgr.msc → 그룹 → Administrators → 불필요한 계정 제거

#### W18_check.ps1 — 불필요한 서비스 (Simple TCP/IP)
```powershell
$svc = Get-Service -Name "simptcp" -ErrorAction SilentlyContinue

# null(미설치) → Good
# Running    → Bad
# 그 외(Stopped) → Good
```

simptcp란: Simple TCP/IP Services — echo, daytime, chargen 등 레거시 서비스

기본 미설치 환경이 대부분이라 일반적으로 Good

#### W39_check.ps1 — 백신 서명 업데이트 점검

PC13과 동일한 로직, 서버 환경용 버전

Defender 없을 때 → Review (서버는 다른 백신 사용 가능성 있음)

#### W40_check.ps1 — 감사 정책 점검 (가장 복잡)
```powershell
$audit = auditpol /get /category:* /r | ConvertFrom-Csv

$policies = @(
    @{ Subcategory = "User Account Management";  Expected = "Failure"            },
    @{ Subcategory = "Credential Validation";    Expected = "Success and Failure" },
    @{ Subcategory = "Sensitive Privilege Use";  Expected = "Success and Failure" },
    @{ Subcategory = "Directory Service Access"; Expected = "Failure"            },
    @{ Subcategory = "Logon";                    Expected = "Success and Failure" },
    @{ Subcategory = "Audit Policy Change";      Expected = "Success and Failure" }
)

foreach ($policy in $policies) {
    $current = $row."Inclusion Setting".Trim()
    if ($current -ne $policy.Expected) {
        $badItems += ...  # 미달 항목 기록
    }
}
```

핵심 기법: auditpol /get /category:* /r | ConvertFrom-Csv

→ auditpol 출력을 CSV로 변환해 PowerShell 객체로 파싱

KISA 권고 기준:

수동 하드닝: secpol.msc → 로컬 정책 → 감사 정책

#### W41_check.ps1 — NTP 시간 동기화 점검
```powershell
$regPath   = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
$ntpServer = (Get-ItemProperty -Path $regPath -Name "NtpServer").NtpServer.Split(",")[0].Trim()

if ($ntpServer -eq "time.windows.com") { Good } else { Review }
```

Review인 이유: 사내 NTP 서버 사용도 정상이므로 자동 Bad 판정 불가

#### W42_check.ps1 — 보안 이벤트 로그 설정 점검
```powershell
$log      = Get-WinEvent -ListLog Security
$maxSizeKB = [math]::Floor($log.MaximumSizeInBytes / 1024)
$logMode  = $log.LogMode  # Circular / AutoBackup / Retain

$sizeOk = ($maxSizeKB -ge 10240)   # 10MB 이상
$modeOk = ($logMode -eq "AutoBackup")
```

로그 모드 비교:

수동 하드닝: eventvwr.msc → Windows 로그 → 보안 → 속성 → 최대 크기 설정 + 보관 방법 선택

#### W43_check.ps1 — 이벤트 로그 파일 접근 제어 점검
```powershell
$targetPaths = @(
    "$env:SystemRoot\system32\config",
    "$env:SystemRoot\system32\LogFiles"
)

foreach ($path in $targetPaths) {
    $acl         = Get-Acl -Path $path
    $everyoneAce = $acl.Access | Where-Object { $_.IdentityReference -match "Everyone" }
    if ($everyoneAce) { $badItems += $path }
}
```

보안 의미: Everyone 권한이 있으면 일반 사용자도 로그 삭제/변조 가능

→ 감사 자체를 무력화할 수 있어 심각한 취약점

상속 주의: system32 폴더에서 권한 상속받는 구조 → 상위 폴더 권한도 확인 필요

#### W45_check.ps1 — 백신 설치 여부 점검
```powershell
if ($mpStatus -ne $null) { Good } else { Bad }
```

W39와 차이: W45는 존재 여부, W39는 업데이트 상태

Defender 없으면 W45 = Bad (서버에서는 보안 위협)

#### W50_check.ps1 — CrashOnAuditFail 점검
```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$value   = (Get-ItemProperty -Path $regPath -Name "CrashOnAuditFail").CrashOnAuditFail

if ($value -eq 0) { Good } else { Bad }
```

보안 의미:

- CrashOnAuditFail = 1 → 감사 로그 기록 실패 시 시스템 강제 BSOD
- 공격자가 이를 악용해 의도적으로 시스템 다운 가능 (DoS)
- KISA 권고: 비활성화(0)

수동 하드닝: regedit → HKLM\SYSTEM\CurrentControlSet\Control\Lsa → CrashOnAuditFail = 0

#### W64_check.ps1 — 방화벽 설정 점검

PC15와 동일한 로직, 서버 환경용 버전

Domain / Private / Public 세 프로필 모두 활성화 확인

### 공통 패턴 정리

#### result 디렉토리 자동 생성 (모든 스크립트 공통)
```powershell
$resultDir = Join-Path $PSScriptRoot "result"
if (-not (Test-Path $resultDir)) {
    New-Item -ItemType Directory -Path $resultDir | Out-Null
}
```

#### secedit 파싱 패턴 (W02, W04, W05 등)
```powershell
$tmpCfg = "$env:TEMP\secpol_xx.cfg"
secedit /export /cfg $tmpCfg /quiet
$value = (Get-Content $tmpCfg | Select-String "항목명").ToString().Split("=")[1].Trim()
Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
```

#### 서비스 점검 패턴 (PC05, W18)
```powershell
$svc = Get-Service -Name "서비스명" -ErrorAction SilentlyContinue
# null → 미설치 / Running → 취약 / Stopped → 양호
```

#### 판정 결과 파일 저장 패턴 (모든 스크립트 공통)
```powershell
$content = "ITEM_NAME : XX`r`nSTATUS    : ..`r`nRESULT    : $result"
Set-Content -Path (Join-Path $resultDir $fileName) -Value $content -Encoding UTF8
```
