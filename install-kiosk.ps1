param(
    [string]$Url,
    [int]$MemoryThreshold,
    [string]$RestartTimes
)

# 检查是否以管理员身份运行
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 重新以管理员身份启动脚本
function Start-AsAdmin {
    if (-not (Test-Administrator)) {
        Write-Host "需要管理员权限，正在重新启动..." -ForegroundColor Yellow
        
        # 创建临时脚本文件
        $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
        
        # 获取当前脚本内容
        $scriptContent = $MyInvocation.MyCommand.ScriptContents
        if (-not $scriptContent) {
            # 如果无法获取脚本内容，尝试从文件读取
            if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
                $scriptContent = Get-Content $PSCommandPath -Raw
            } else {
                Write-Host "或手动以管理员身份运行PowerShell后执行此脚本" -ForegroundColor Yellow
                Read-Host "按回车键退出"
                exit 1
            }
        }
        
        # 写入临时脚本
        $scriptContent | Out-File -FilePath $tempScript -Encoding UTF8
        
        # 构建参数
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`""
        if ($Url) { $arguments += " -Url '$Url'" }
        if ($MemoryThreshold) { $arguments += " -MemoryThreshold $MemoryThreshold" }
        if ($RestartTimes) { $arguments += " -RestartTimes '$RestartTimes'" }
        
        try {
            Start-Process PowerShell -Verb RunAs -ArgumentList $arguments -Wait
            # 清理临时文件
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "启动管理员进程失败: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "请手动以管理员身份运行PowerShell" -ForegroundColor Yellow
            Read-Host "按回车键退出"
        }
        exit
    }
}

# 获取用户输入
function Get-UserInput {
    # 获取URL
    if (-not $Url) {
        do {
            $Url = Read-Host "请输入要在Kiosk模式下显示的URL"
        } while ([string]::IsNullOrWhiteSpace($Url))
    }
    
    # 获取内存阈值
    if (-not $MemoryThreshold) {
        do {
            $input = Read-Host "请输入内存限制阈值 (MB，默认1000)"
            if ([string]::IsNullOrWhiteSpace($input)) {
                $MemoryThreshold = 1000
                break
            }
            if ([int]::TryParse($input, [ref]$MemoryThreshold) -and $MemoryThreshold -gt 0) {
                break
            }
            Write-Host "请输入有效的正整数" -ForegroundColor Red
        } while ($true)
    }
    
    # 获取重启时间
    if (-not $RestartTimes) {
        Write-Host "请输入自动重启时间点 (24小时制，格式: HH:MM，多个时间用逗号分隔)"
        Write-Host "示例: 03:00,12:00,20:00 (留空表示不设置定时重启)"
        do {
            $input = Read-Host "重启时间"
            if ([string]::IsNullOrWhiteSpace($input)) {
                $RestartTimes = ""
                break
            }
            
            # 验证时间格式
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
            Write-Host "时间格式无效，请使用 HH:MM 格式" -ForegroundColor Red
        } while ($true)
    }
    
    return @{
        Url = $Url
        MemoryThreshold = $MemoryThreshold
        RestartTimes = $RestartTimes
    }
}

# 生成Kiosk脚本
function New-KioskScript {
    param(
        [string]$Url,
        [int]$MemoryThreshold,
        [string]$RestartTimes
    )
    
    # 解析重启时间
    $restartTimesString = ""
    if (-not [string]::IsNullOrWhiteSpace($RestartTimes)) {
        $restartTimeArray = @()
        foreach ($time in $RestartTimes.Split(',')) {
            $timeParts = $time.Trim().Split(':')
            $restartTimeArray += "    @{Hour=$($timeParts[0]); Minute=$($timeParts[1])}"
        }
        $restartTimesString = $restartTimeArray -join ",`n"
    } else {
        $restartTimesString = "    # 未设置定时重启"
    }
    
    $scriptContent = @"
`$url = "$Url"
`$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# 内存阈值（单位 MB）
`$memoryThresholdMB = $MemoryThreshold   # 超过 ${MemoryThreshold}MB 就重启

# 定时重启时间列表（24小时制）
`$restartTimes = @(
$restartTimesString
)

# 创建停止标志文件路径
`$stopFlagFile = "C:\KioskMonitor\stop.flag"

# 设置控制台标题以便识别
`$Host.UI.RawUI.WindowTitle = "Kiosk Monitor - `$url"

function Start-Edge {
    Write-Output "启动 Edge Kiosk 模式"
    Start-Process `$edge "--kiosk `$url --edge-kiosk-type=fullscreen"
}

Write-Output "=== Kiosk 守护程序启动 ==="
Write-Output "内存阈值: `$memoryThresholdMB MB"
Write-Output "停止方法: 按 Ctrl+C 终止"
Write-Output ""

# 立即启动一次 Edge
Start-Edge

while (`$true) {
    # 检查停止标志
    if (Test-Path `$stopFlagFile) {
        Write-Output "检测到停止信号，正在关闭..."
        Get-Process "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
        Remove-Item `$stopFlagFile -Force -ErrorAction SilentlyContinue
        Write-Output "Kiosk 守护已停止"
        exit 0
    }
    
    `$process = Get-Process "msedge" -ErrorAction SilentlyContinue

    if (`$process) {
        # 计算所有 Edge 进程的总内存占用（MB）
        `$totalMemUsageMB = [math]::Round(((`$process | Measure-Object WorkingSet64 -Sum).Sum) / 1MB, 2)

        # 超过阈值则重启
        if (`$totalMemUsageMB -gt `$memoryThresholdMB) {
            Write-Output "Edge 占用 `$totalMemUsageMB MB，超过阈值 `$memoryThresholdMB MB，正在重启..."
            Stop-Process -Name "msedge" -Force
            Start-Edge
        }

        # 检查是否到达指定时间点
        if (`$restartTimes.Count -gt 0) {
            `$now = Get-Date
            foreach (`$t in `$restartTimes) {
                if (`$now.Hour -eq `$t.Hour -and `$now.Minute -eq `$t.Minute) {
                    Write-Output "到达定时重启时间 `$(`$t.Hour):`$(`$t.Minute)，正在重启..."
                    Stop-Process -Name "msedge" -Force
                    Start-Edge
                    Start-Sleep -Seconds 60  # 避免一分钟内多次触发
                }
            }
        }
    }
    else {
        # Edge 没开则启动
        Start-Edge
    }

    Start-Sleep -Seconds 30   # 每 30 秒检查一次
}

# 程序结束时的清理
Write-Output "Kiosk 守护程序已退出"
"@
    
    return $scriptContent
}

# 卸载现有Kiosk服务
function Uninstall-ExistingKiosk {
    Write-Host "正在检查并卸载现有Kiosk服务..." -ForegroundColor Yellow
    
    # 停止现有进程
    $kioskProcesses = Get-Process | Where-Object { $_.MainWindowTitle -like "Kiosk Monitor*" }
    if ($kioskProcesses) {
        Write-Host "发现运行中的Kiosk守护进程，正在停止..." -ForegroundColor Yellow
        $kioskProcesses | Stop-Process -Force
        Write-Host "已停止现有Kiosk守护进程" -ForegroundColor Green
    }
    
    # 停止Edge进程
    $edgeProcesses = Get-Process "msedge" -ErrorAction SilentlyContinue
    if ($edgeProcesses) {
        Write-Host "正在停止Edge进程..." -ForegroundColor Yellow
        $edgeProcesses | Stop-Process -Force
        Write-Host "已停止Edge进程" -ForegroundColor Green
    }
    
    # 删除任务计划
    $taskName = "KioskMonitor"
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "已删除任务计划: $taskName" -ForegroundColor Green
    }
    
    # 删除启动项注册表项
    $startupRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $startupKeyName = "KioskMonitor"
    if (Get-ItemProperty -Path $startupRegPath -Name $startupKeyName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $startupRegPath -Name $startupKeyName -Force
        Write-Host "已删除启动项注册表: $startupKeyName" -ForegroundColor Green
    }
    
    # 删除用户启动文件夹中的快捷方式
    $startupFolder = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolder "KioskMonitor.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force
        Write-Host "已删除启动文件夹快捷方式" -ForegroundColor Green
    }
    
    # 删除现有文件
    $scriptDir = "C:\KioskMonitor"
    if (Test-Path $scriptDir) {
        Remove-Item $scriptDir -Recurse -Force
        Write-Host "已删除现有Kiosk文件目录" -ForegroundColor Green
    }
    
    Write-Host "现有Kiosk服务卸载完成" -ForegroundColor Green
}

# 安装Kiosk脚本
function Install-KioskScript {
    param(
        [string]$ScriptContent
    )
    
    # 先卸载现有服务
    Uninstall-ExistingKiosk
    
    $scriptPath = "C:\KioskMonitor\kiosk-monitor.ps1"
    $scriptDir = Split-Path $scriptPath -Parent
    
    # 创建目录
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    Write-Host "已创建目录: $scriptDir" -ForegroundColor Green
    
    # 写入脚本文件
    $ScriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
    Write-Host "已创建Kiosk守护脚本: $scriptPath" -ForegroundColor Green
    
    # 创建启动脚本
    $startupScript = @"
# Kiosk 启动脚本
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
PowerShell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$scriptPath"
"@
    
    $startupPath = "$scriptDir\start-kiosk.ps1"
    $startupScript | Out-File -FilePath $startupPath -Encoding UTF8 -Force
    Write-Host "已创建启动脚本: $startupPath" -ForegroundColor Green
    
    # 设置开机自启动
    Write-Host ""
    Write-Host "请选择开机自启动方式:" -ForegroundColor Cyan
    Write-Host "1. 任务计划程序 (推荐，系统级别)" -ForegroundColor White
    Write-Host "2. 用户启动项 (当前用户)" -ForegroundColor White
    Write-Host "3. 不设置自启动" -ForegroundColor White
    
    do {
        $choice = Read-Host "请选择 (1/2/3)"
    } while ($choice -notin @('1', '2', '3'))
    
    switch ($choice) {
        '1' {
            try {
                # 创建Windows任务计划
                $taskName = "KioskMonitor"
                $taskDescription = "Kiosk模式守护程序"
                
                # 获取当前用户信息
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
                $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 0)
                
                Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
                
                Write-Host "已设置任务计划自启动" -ForegroundColor Green
                Write-Host "  任务名称: $taskName" -ForegroundColor Cyan
                Write-Host "  管理方式: 任务计划程序" -ForegroundColor Cyan
                $autoStartMethod = "任务计划程序"
                
            } catch {
                Write-Host "设置任务计划失败: $($_.Exception.Message)" -ForegroundColor Red
                $autoStartMethod = "设置失败"
            }
        }
        '2' {
            try {
                # 添加到用户启动项注册表
                $startupRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
                $startupKeyName = "KioskMonitor"
                $startupCommand = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
                
                Set-ItemProperty -Path $startupRegPath -Name $startupKeyName -Value $startupCommand -Force
                
                Write-Host "已设置用户启动项" -ForegroundColor Green
                Write-Host "  注册表位置: $startupRegPath" -ForegroundColor Cyan
                Write-Host "  键名: $startupKeyName" -ForegroundColor Cyan
                $autoStartMethod = "用户启动项"
                
            } catch {
                Write-Host "设置用户启动项失败: $($_.Exception.Message)" -ForegroundColor Red
                $autoStartMethod = "设置失败"
            }
        }
        '3' {
            Write-Host "跳过自启动设置" -ForegroundColor Yellow
            $autoStartMethod = "未设置"
        }
    }
    
    # 询问是否立即启动
    $start = Read-Host "是否立即启动Kiosk守护? (y/N)"
    if ($start -eq 'y' -or $start -eq 'Y') {
        Write-Host "正在启动Kiosk守护..." -ForegroundColor Yellow
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        Write-Host "Kiosk守护已启动!" -ForegroundColor Green
    }
    
    Write-Host "`n安装完成" -ForegroundColor Green
    Write-Host ""
    Write-Host "文件位置:" -ForegroundColor Cyan
    Write-Host "  守护脚本: $scriptPath" -ForegroundColor White
    Write-Host "  启动脚本: $startupPath" -ForegroundColor White
    Write-Host ""
    Write-Host "使用方法:" -ForegroundColor Cyan
    Write-Host "  启动守护: PowerShell -ExecutionPolicy Bypass -File `"$startupPath`"" -ForegroundColor White
    Write-Host "  停止守护: 在守护窗口按 Ctrl+C 或创建文件 C:\KioskMonitor\stop.flag" -ForegroundColor White
    Write-Host "  重新安装: 再次运行此安装脚本" -ForegroundColor White
    Write-Host ""
    Write-Host "开机自启动: $autoStartMethod" -ForegroundColor $(if ($autoStartMethod -eq "未设置") { "Yellow" } elseif ($autoStartMethod -eq "设置失败") { "Red" } else { "Green" })
    Write-Host ""
    Write-Host "注意事项:" -ForegroundColor Gray
    Write-Host "  守护程序运行时窗口标题显示 'Kiosk Monitor - URL'" -ForegroundColor Gray
    Write-Host "  重新运行安装脚本会自动卸载现有服务" -ForegroundColor Gray
}

# 主程序
try {
    Write-Host "=== Kiosk 管理程序 ===" -ForegroundColor Cyan
    Write-Host ""
    
    # 检查管理员权限并自动提升
    Start-AsAdmin
    
    # 选择操作模式
    Write-Host "请选择操作:" -ForegroundColor Yellow
    Write-Host "  [I] 安装 Kiosk 守护服务" -ForegroundColor White
    Write-Host "  [R] 移除 Kiosk 守护服务" -ForegroundColor White
    Write-Host ""
    
    do {
        $operation = Read-Host "请输入选择 (I/R)"
        $operation = $operation.ToUpper()
    } while ($operation -notin @('I', 'R'))
    
    if ($operation -eq 'R') {
        # 执行卸载操作
        Write-Host ""
        Write-Host "=== 开始卸载 Kiosk 守护服务 ===" -ForegroundColor Red
        Uninstall-ExistingKiosk
        Write-Host ""
        Write-Host "卸载完成" -ForegroundColor Green
        Write-Host "所有 Kiosk 守护服务已从系统中移除" -ForegroundColor Cyan
        return
    }
    
    # 执行安装操作
    Write-Host ""
    Write-Host "=== 开始安装 Kiosk 守护服务 ===" -ForegroundColor Green
    
    # 获取用户输入
    $config = Get-UserInput
    
    Write-Host ""
    Write-Host "配置信息:" -ForegroundColor Yellow
    Write-Host "URL: $($config.Url)" -ForegroundColor White
    Write-Host "内存阈值: $($config.MemoryThreshold) MB" -ForegroundColor White
    Write-Host "重启时间: $($config.RestartTimes)" -ForegroundColor White
    Write-Host ""
    
    $confirm = Read-Host "确认安装? (Y/n)"
    if ($confirm -eq 'n' -or $confirm -eq 'N') {
        Write-Host "安装已取消" -ForegroundColor Yellow
        exit
    }
    
    # 生成并安装脚本
    $scriptContent = New-KioskScript -Url $config.Url -MemoryThreshold $config.MemoryThreshold -RestartTimes $config.RestartTimes
    Install-KioskScript -ScriptContent $scriptContent
    
} catch {
    Write-Host "安装过程中发生错误: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "请检查权限和网络连接" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "按任意键退出..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")