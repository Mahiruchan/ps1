param(
    [string]$Url,
    [int]$MemoryThreshold,
    [string]$RestartTimes
)

# ����Ƿ��Թ���Ա�������
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# �����Թ���Ա��������ű�
function Start-AsAdmin {
    if (-not (Test-Administrator)) {
        Write-Host "��Ҫ����ԱȨ�ޣ�������������..." -ForegroundColor Yellow
        
        # ������ʱ�ű��ļ�
        $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
        
        # ��ȡ��ǰ�ű�����
        $scriptContent = $MyInvocation.MyCommand.ScriptContents
        if (-not $scriptContent) {
            # ����޷���ȡ�ű����ݣ����Դ��ļ���ȡ
            if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
                $scriptContent = Get-Content $PSCommandPath -Raw
            } else {
                Write-Host "���ֶ��Թ���Ա�������PowerShell��ִ�д˽ű�" -ForegroundColor Yellow
                Read-Host "���س����˳�"
                exit 1
            }
        }
        
        # д����ʱ�ű�
        $scriptContent | Out-File -FilePath $tempScript -Encoding UTF8
        
        # ��������
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`""
        if ($Url) { $arguments += " -Url '$Url'" }
        if ($MemoryThreshold) { $arguments += " -MemoryThreshold $MemoryThreshold" }
        if ($RestartTimes) { $arguments += " -RestartTimes '$RestartTimes'" }
        
        try {
            Start-Process PowerShell -Verb RunAs -ArgumentList $arguments -Wait
            # ������ʱ�ļ�
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "��������Ա����ʧ��: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "���ֶ��Թ���Ա�������PowerShell" -ForegroundColor Yellow
            Read-Host "���س����˳�"
        }
        exit
    }
}

# ��ȡ�û�����
function Get-UserInput {
    # ��ȡURL
    if (-not $Url) {
        do {
            $Url = Read-Host "������Ҫ��Kioskģʽ����ʾ��URL"
        } while ([string]::IsNullOrWhiteSpace($Url))
    }
    
    # ��ȡ�ڴ���ֵ
    if (-not $MemoryThreshold) {
        do {
            $input = Read-Host "�������ڴ�������ֵ (MB��Ĭ��1000)"
            if ([string]::IsNullOrWhiteSpace($input)) {
                $MemoryThreshold = 1000
                break
            }
            if ([int]::TryParse($input, [ref]$MemoryThreshold) -and $MemoryThreshold -gt 0) {
                break
            }
            Write-Host "��������Ч��������" -ForegroundColor Red
        } while ($true)
    }
    
    # ��ȡ����ʱ��
    if (-not $RestartTimes) {
        Write-Host "�������Զ�����ʱ��� (24Сʱ�ƣ���ʽ: HH:MM�����ʱ���ö��ŷָ�)"
        Write-Host "ʾ��: 03:00,12:00,20:00 (���ձ�ʾ�����ö�ʱ����)"
        do {
            $input = Read-Host "����ʱ��"
            if ([string]::IsNullOrWhiteSpace($input)) {
                $RestartTimes = ""
                break
            }
            
            # ��֤ʱ���ʽ
            $timePattern = '^(\d{1,2}:\d{2})(,\d{1,2}:\d{2})*$'
            if ($input -match $timePattern) {
                $validTimes = $true
                foreach ($time in $input.Split(',')) {
                    $timeParts = $time.Trim().Split(':')
                    $hour = [int]$timeParts[0]
                    $minute = [int]$timeParts[1]
                    if ($hour -lt 0 -or $hour -gt 23 -or $minute -lt 0 -or $minute -gt 59) {
                        $validTimes = $false
                        break
                    }
                }
                if ($validTimes) { 
                    $RestartTimes = $input
                    break 
                }
            }
            Write-Host "ʱ���ʽ��Ч����ʹ�� HH:MM ��ʽ" -ForegroundColor Red
        } while ($true)
    }
    
    return @{
        Url = $Url
        MemoryThreshold = $MemoryThreshold
        RestartTimes = $RestartTimes
    }
}

# ����Kiosk�ű�
function New-KioskScript {
    param(
        [string]$Url,
        [int]$MemoryThreshold,
        [string]$RestartTimes
    )
    
    # ��������ʱ��
    $restartTimesString = ""
    if (-not [string]::IsNullOrWhiteSpace($RestartTimes)) {
        $restartTimeArray = @()
        foreach ($time in $RestartTimes.Split(',')) {
            $timeParts = $time.Trim().Split(':')
            $restartTimeArray += "    @{Hour=$($timeParts[0]); Minute=$($timeParts[1])}"
        }
        $restartTimesString = $restartTimeArray -join ",`n"
    } else {
        $restartTimesString = "    # δ���ö�ʱ����"
    }
    
    $scriptContent = @"
`$url = "$Url"
`$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# �ڴ���ֵ����λ MB��
`$memoryThresholdMB = $MemoryThreshold   # ���� ${MemoryThreshold}MB ������

# ��ʱ����ʱ���б�24Сʱ�ƣ�
`$restartTimes = @(
$restartTimesString
)

# ����ֹͣ��־�ļ�·��
`$stopFlagFile = "C:\KioskMonitor\stop.flag"

# ���ÿ���̨�����Ա�ʶ��
`$Host.UI.RawUI.WindowTitle = "Kiosk Monitor - `$url"

function Start-Edge {
    Write-Output "���� Edge Kiosk ģʽ"
    Start-Process `$edge "--kiosk `$url --edge-kiosk-type=fullscreen"
}

Write-Output "=== Kiosk �ػ��������� ==="
Write-Output "�ڴ���ֵ: `$memoryThresholdMB MB"
Write-Output "ֹͣ����: �� Ctrl+C ��ֹ"
Write-Output ""

# ��������һ�� Edge
Start-Edge

while (`$true) {
    # ���ֹͣ��־
    if (Test-Path `$stopFlagFile) {
        Write-Output "��⵽ֹͣ�źţ����ڹر�..."
        Get-Process "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
        Remove-Item `$stopFlagFile -Force -ErrorAction SilentlyContinue
        Write-Output "Kiosk �ػ���ֹͣ"
        exit 0
    }
    
    `$process = Get-Process "msedge" -ErrorAction SilentlyContinue

    if (`$process) {
        # �������� Edge ���̵����ڴ�ռ�ã�MB��
        `$totalMemUsageMB = [math]::Round(((`$process | Measure-Object WorkingSet64 -Sum).Sum) / 1MB, 2)

        # ������ֵ������
        if (`$totalMemUsageMB -gt `$memoryThresholdMB) {
            Write-Output "Edge ռ�� `$totalMemUsageMB MB��������ֵ `$memoryThresholdMB MB����������..."
            Stop-Process -Name "msedge" -Force
            Start-Edge
        }

        # ����Ƿ񵽴�ָ��ʱ���
        if (`$restartTimes.Count -gt 0) {
            `$now = Get-Date
            foreach (`$t in `$restartTimes) {
                if (`$now.Hour -eq `$t.Hour -and `$now.Minute -eq `$t.Minute) {
                    Write-Output "���ﶨʱ����ʱ�� `$(`$t.Hour):`$(`$t.Minute)����������..."
                    Stop-Process -Name "msedge" -Force
                    Start-Edge
                    Start-Sleep -Seconds 60  # ����һ�����ڶ�δ���
                }
            }
        }
    }
    else {
        # Edge û��������
        Start-Edge
    }

    Start-Sleep -Seconds 30   # ÿ 30 ����һ��
}

# �������ʱ������
Write-Output "Kiosk �ػ��������˳�"
"@
    
    return $scriptContent
}

# ж������Kiosk����
function Uninstall-ExistingKiosk {
    Write-Host "���ڼ�鲢ж������Kiosk����..." -ForegroundColor Yellow
    
    # ֹͣ���н���
    $kioskProcesses = Get-Process | Where-Object { $_.MainWindowTitle -like "Kiosk Monitor*" }
    if ($kioskProcesses) {
        Write-Host "���������е�Kiosk�ػ����̣�����ֹͣ..." -ForegroundColor Yellow
        $kioskProcesses | Stop-Process -Force
        Write-Host "��ֹͣ����Kiosk�ػ�����" -ForegroundColor Green
    }
    
    # ֹͣEdge����
    $edgeProcesses = Get-Process "msedge" -ErrorAction SilentlyContinue
    if ($edgeProcesses) {
        Write-Host "����ֹͣEdge����..." -ForegroundColor Yellow
        $edgeProcesses | Stop-Process -Force
        Write-Host "��ֹͣEdge����" -ForegroundColor Green
    }
    
    # ɾ������ƻ�
    $taskName = "KioskMonitor"
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "��ɾ������ƻ�: $taskName" -ForegroundColor Green
    }
    
    # ɾ��������ע�����
    $startupRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $startupKeyName = "KioskMonitor"
    if (Get-ItemProperty -Path $startupRegPath -Name $startupKeyName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $startupRegPath -Name $startupKeyName -Force
        Write-Host "��ɾ��������ע���: $startupKeyName" -ForegroundColor Green
    }
    
    # ɾ���û������ļ����еĿ�ݷ�ʽ
    $startupFolder = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolder "KioskMonitor.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Host "��ɾ�������ļ��п�ݷ�ʽ" -ForegroundColor Green
    }
    
    # ɾ�������ļ�
    $scriptDir = "C:\KioskMonitor"
    if (Test-Path $scriptDir) {
        Remove-Item $scriptDir -Recurse -Force
        Write-Host "��ɾ������Kiosk�ļ�Ŀ¼" -ForegroundColor Green
    }
    
    Write-Host "����Kiosk����ж�����" -ForegroundColor Green
}

# ��װKiosk�ű�
function Install-KioskScript {
    param(
        [string]$ScriptContent
    )
    
    # ��ж�����з���
    Uninstall-ExistingKiosk
    
    $scriptPath = "C:\KioskMonitor\kiosk-monitor.ps1"
    $scriptDir = Split-Path $scriptPath -Parent
    
    # ����Ŀ¼
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    Write-Host "�Ѵ���Ŀ¼: $scriptDir" -ForegroundColor Green
    
    # д��ű��ļ�
    $ScriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
    Write-Host "�Ѵ���Kiosk�ػ��ű�: $scriptPath" -ForegroundColor Green
    
    # ���������ű�
    $startupScript = @"
# Kiosk �����ű�
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
PowerShell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$scriptPath"
"@
    
    $startupPath = "$scriptDir\start-kiosk.ps1"
    $startupScript | Out-File -FilePath $startupPath -Encoding UTF8 -Force
    Write-Host "�Ѵ��������ű�: $startupPath" -ForegroundColor Green
    
    # ���ÿ���������
    Write-Host ""
    Write-Host "��ѡ�񿪻���������ʽ:" -ForegroundColor Cyan
    Write-Host "1. ����ƻ����� (�Ƽ���ϵͳ����)" -ForegroundColor White
    Write-Host "2. �û������� (��ǰ�û�)" -ForegroundColor White
    Write-Host "3. ������������" -ForegroundColor White
    
    do {
        $choice = Read-Host "��ѡ�� (1/2/3)"
    } while ($choice -notin @('1', '2', '3'))
    
    switch ($choice) {
        '1' {
            try {
                # ����Windows����ƻ�
                $taskName = "KioskMonitor"
                $taskDescription = "Kioskģʽ�ػ�����"
                
                # ��ȡ��ǰ�û���Ϣ
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
                $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 0)
                
                Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
                
                Write-Host "����������ƻ�������" -ForegroundColor Green
                Write-Host "  ��������: $taskName" -ForegroundColor Cyan
                Write-Host "  ����ʽ: ����ƻ�����" -ForegroundColor Cyan
                $autoStartMethod = "����ƻ�����"
                
            } catch {
                Write-Host "��������ƻ�ʧ��: $($_.Exception.Message)" -ForegroundColor Red
                $autoStartMethod = "����ʧ��"
            }
        }
        '2' {
            try {
                # ��ӵ��û�������ע���
                $startupRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                $startupKeyName = "KioskMonitor"
                $startupCommand = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                
                Set-ItemProperty -Path $startupRegPath -Name $startupKeyName -Value $startupCommand -Force
                
                Write-Host "�������û�������" -ForegroundColor Green
                Write-Host "  ע���λ��: $startupRegPath" -ForegroundColor Cyan
                Write-Host "  ����: $startupKeyName" -ForegroundColor Cyan
                $autoStartMethod = "�û�������"
                
            } catch {
                Write-Host "�����û�������ʧ��: $($_.Exception.Message)" -ForegroundColor Red
                $autoStartMethod = "����ʧ��"
            }
        }
        '3' {
            Write-Host "��������������" -ForegroundColor Yellow
            $autoStartMethod = "δ����"
        }
    }
    
    # ѯ���Ƿ���������
    $start = Read-Host "�Ƿ���������Kiosk�ػ�? (y/N)"
    if ($start -eq 'y' -or $start -eq 'Y') {
        Write-Host "��������Kiosk�ػ�..." -ForegroundColor Yellow
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        Write-Host "Kiosk�ػ�������!" -ForegroundColor Green
    }
    
    Write-Host "`n��װ���" -ForegroundColor Green
    Write-Host ""
    Write-Host "�ļ�λ��:" -ForegroundColor Cyan
    Write-Host "  �ػ��ű�: $scriptPath" -ForegroundColor White
    Write-Host "  �����ű�: $startupPath" -ForegroundColor White
    Write-Host ""
    Write-Host "ʹ�÷���:" -ForegroundColor Cyan
    Write-Host "  �����ػ�: PowerShell -ExecutionPolicy Bypass -File `"$startupPath`"" -ForegroundColor White
    Write-Host "  ֹͣ�ػ�: ���ػ����ڰ� Ctrl+C �򴴽��ļ� C:\KioskMonitor\stop.flag" -ForegroundColor White
    Write-Host "  ���°�װ: �ٴ����д˰�װ�ű�" -ForegroundColor White
    Write-Host ""
    Write-Host "����������: $autoStartMethod" -ForegroundColor $(if ($autoStartMethod -eq "δ����") { "Yellow" } elseif ($autoStartMethod -eq "����ʧ��") { "Red" } else { "Green" })
    Write-Host ""
    Write-Host "ע������:" -ForegroundColor Gray
    Write-Host "  �ػ���������ʱ���ڱ�����ʾ 'Kiosk Monitor - URL'" -ForegroundColor Gray
    Write-Host "  �������а�װ�ű����Զ�ж�����з���" -ForegroundColor Gray
}

# ������
try {
    Write-Host "=== Kiosk ������� ===" -ForegroundColor Cyan
    Write-Host ""
    
    # ������ԱȨ�޲��Զ�����
    Start-AsAdmin
    
    # ѡ�����ģʽ
    Write-Host "��ѡ�����:" -ForegroundColor Yellow
    Write-Host "  [I] ��װ Kiosk �ػ�����" -ForegroundColor White
    Write-Host "  [R] �Ƴ� Kiosk �ػ�����" -ForegroundColor White
    Write-Host ""
    
    do {
        $operation = Read-Host "������ѡ�� (I/R)"
        $operation = $operation.ToUpper()
    } while ($operation -notin @('I', 'R'))
    
    if ($operation -eq 'R') {
        # ִ��ж�ز���
        Write-Host ""
        Write-Host "=== ��ʼж�� Kiosk �ػ����� ===" -ForegroundColor Red
        Uninstall-ExistingKiosk
        Write-Host ""
        Write-Host "ж�����" -ForegroundColor Green
        Write-Host "���� Kiosk �ػ������Ѵ�ϵͳ���Ƴ�" -ForegroundColor Cyan
        return
    }
    
    # ִ�а�װ����
    Write-Host ""
    Write-Host "=== ��ʼ��װ Kiosk �ػ����� ===" -ForegroundColor Green
    
    # ��ȡ�û�����
    $config = Get-UserInput
    
    Write-Host ""
    Write-Host "������Ϣ:" -ForegroundColor Yellow
    Write-Host "URL: $($config.Url)" -ForegroundColor White
    Write-Host "�ڴ���ֵ: $($config.MemoryThreshold) MB" -ForegroundColor White
    Write-Host "����ʱ��: $($config.RestartTimes)" -ForegroundColor White
    Write-Host ""
    
    $confirm = Read-Host "ȷ�ϰ�װ? (Y/n)"
    if ($confirm -eq 'n' -or $confirm -eq 'N') {
        Write-Host "��װ��ȡ��" -ForegroundColor Yellow
        exit
    }
    
    # ���ɲ���װ�ű�
    $scriptContent = New-KioskScript -Url $config.Url -MemoryThreshold $config.MemoryThreshold -RestartTimes $config.RestartTimes
    Install-KioskScript -ScriptContent $scriptContent
    
} catch {
    Write-Host "��װ�����з�������: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "����Ȩ�޺���������" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "��������˳�..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")