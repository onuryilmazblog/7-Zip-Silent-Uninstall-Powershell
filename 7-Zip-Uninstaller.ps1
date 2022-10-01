# Define Parameters
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$True,Position=0)]
    [String]$Log = "$env:SystemDrive\Windows\Logs\Software\7-Zip-Uninstall.log"
)

##*=============================================
##* VARIABLE DECLARATION
##*=============================================
[string]$SystemDrive = $env:SystemDrive
[string]$ComputerName = $env:COMPUTERNAME
[string]$envProgramData = [Environment]::GetFolderPath('CommonApplicationData')
[string]$envProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
[string]$envProgramFilesX86 = ${env:ProgramFiles(x86)}
[string]$AppName = "7-Zip"


##*=============================================
##* FUNCTIONS
##*=============================================

## Log Builder
## Example: Write-Log -Message "Uygulama kaldırma işlemi başlatıldı."
function Write-Log() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        
        # Log File Path
        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path=$Log,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info"
    )

    Begin {
        $VerbosePreference = 'Continue'
    }
    Process {
		if ((Test-Path $Path)) {
			$LogSize = (Get-Item -Path $Path).Length/1MB
			$MaxLogSize = 5
		}
                
        # Log File Check
        if ((Test-Path $Path) -AND $LogSize -gt $MaxLogSize) {
            Write-Error "Log dosyası $Path yolunda zaten var ve maximum dosya boyutunu aşıyor. Yeniden oluşturuluyor."
            Remove-Item $Path -Force
            $NewLogFile = New-Item $Path -Force -ItemType File
        }

        # Create Log Folder
        elseif (-NOT(Test-Path $Path)) {
            Write-Verbose "$Path oluşturuluyor."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else { 
        }

        # Log file date
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Mesaj types
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Log çıktı
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}

## Get App
function InstalledApplication {
    $InstalledApplicationx86 = Get-ChildItem HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | foreach-object {Get-ItemProperty $_.PsPath} -ErrorAction SilentlyContinue
    $global:DisplayAppx86 = $InstalledApplicationx86 | ? { $_.displayname -like "*$AppName*" } | Select-Object DisplayVersion,UninstallString,PSPath -ErrorAction SilentlyContinue

    $InstalledApplicationx64 = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | foreach-object {Get-ItemProperty $_.PsPath} -ErrorAction SilentlyContinue
    $global:DisplayAppx64 = $InstalledApplicationx64 | ? { $_.displayname -like "*$AppName*" } | Select-Object DisplayVersion,UninstallString,PSPath -ErrorAction SilentlyContinue
}

## Example: StopProcess "7zFM.exe,7zG.exe,7z.exe"
Function StopProcess ($ProcessList) {
    $ProcessList = $ProcessList -split ","
    foreach ($ProcessName in $ProcessList) {
        $RunningAppID = Get-WmiObject Win32_Process -Filter "name = ""$ProcessName""" -ErrorAction SilentlyContinue | Select -ExpandProperty ProcessId -ErrorAction SilentlyContinue
        if ($RunningAppID -ne $null) {
            Write-Log -Level Warn -Message "Akif çalışan $ProcessName uygulaması bulundu."
            try {
                Stop-Process -Id $RunningAppID -Force -ErrorAction SilentlyContinue
                Write-Log -Level Warn -Message "Akif çalışan $ProcessName uygulaması sonlandırıldı."
            }
            catch {
                Write-Log -Level Error -Message "Akif çalışan $ProcessName uygulaması sonlandırılamadı."
            }
        }
        else {
            Write-Log -Message "Akif çalışan $ProcessName uygulaması bulunmadı."
        }
    }
}

##
## ************************************************ ##
##

Write-Log -Message "$AppName uygulama kaldırma işlemi başlatıldı."
Write-Log -Message "Bilgisayar adı: $ComputerName"
Write-Log -Message "$AppName uygulama kurulum durumu kontrol ediliyor."

InstalledApplication

$DiplayVersionx86 = $Appx86.DisplayVersion
$UninstallStringx86 = $Appx86.UninstallString
$DiplayVersionx64 = $DisplayAppx64.DisplayVersion
$UninstallStringx64 = $DisplayAppx64.UninstallString

if (($DiplayVersionx86 -eq $null) -and ($DiplayVersionx64 -eq $null)) { Write-Log -Level Warn -Message "$AppName uygulamasının kurulumu tespit edilmemiştir." }

## 32 bit versiyon kontrolü
if ($DiplayVersionx86 -ne $null) {
    foreach ($Appx86 in $DisplayAppx86) {
        $DiplayVersionx86 = $Appx86.DisplayVersion
        $UninstallStringx86 = $Appx86.UninstallString
        Write-Log -Message "32 Bit $DiplayVersionx86 versiyon $AppName uygulamasının varlığı tespit edilmiştir."
        Write-Log -Message "UninstallString: $UninstallStringx86"
        if ($UninstallStringx86 -like "*msiexec*") {
            Write-Log -Message "32 bit MSI kurulum tespit edilmiştir."
            ## Convert Product Code
            $UninstallStringx86 = ($UninstallStringx86.Split("{")[1]).Trim()
            $ProductCodex86 = ($UninstallStringx86.Split("}")[0]).Trim()

            Write-Log -Message "Product Code: $ProductCodex86"
            if ($ProductCodex86 -ne $null) {
                Try {
                    ## Uninstall
                    StopProcess "7zFM.exe,7zG.exe,7z.exe"
                    $Argx86 = "/x {$ProductCodex86} /q REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable"
                    Start-Process -FilePath "msiexec.exe" -ArgumentList $Argx86 -Wait
                    if (Test-Path "$envProgramFilesX86\7-Zip") { Remove-Item -Path "$envProgramFilesX86\7-Zip" -Recurse -Force -ErrorAction SilentlyContinue; Write-Log -Level Warn -Message "Program Files x86 klasöründe kalıntı 7-Zip klasörü bulundu ve silindi." }
                    InstalledApplication
                    if ($DisplayAppx86.UninstallString -like "*msiexec*") {
                        Write-Log -Level Error -Message "MSI kaldırma işlemi başarısız oldu."
                        Write-Log -Message "$AppName uygulamasının kaldırma işlemi tekrar deneniyor."
                    
                        ## Delete Install Folder Path
                        if (Test-Path "$envProgramFiles\7-Zip") { $InstallPath = "$envProgramFiles\7-Zip"}
                        if (Test-Path "$envProgramFilesX86\7-Zip") { $InstallPath = "$envProgramFilesX86\7-Zip"};
                        Write-Log -Message "Uyguluma kurulum adresi: $InstallPath"
                        if ($InstallPath -ne $null) {
                            Remove-Item -Path "$InstallPath" -Recurse -Force
                        }

                        ## Delete shortcut path
                        if (Test-Path "$envProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip") { Remove-Item -Path "$envProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip" -Recurse -Force } 

                        ## Delete Registery Install Path
                        if (!(Test-Path $InstallPath)) { Write-Log -Message "$AppName kurulum dosyaları başarıyla silinmiştir." } else { Write-Log -Level Error -Message "$AppName kurulum dosyaları silinemedi." }
                        $ErrorActionPreference = "SilentlyContinue"
                        $RegPath = $DisplayAppx86.PSPath.replace('Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE','HKLM:')
                        $ErrorActionPreference = "Continue"
                        if (Test-Path "$RegPath") {
                            $RegCheck = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'DisplayName' -ErrorAction SilentlyContinue
                            if ($RegCheck -like "*7-zip*") {
                                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue 
                            }
                        }

                        if (!(Test-Path $RegPath)) { Write-Log -Message "$AppName regedit kayıtları başarıyla silinmiştir." } else { Write-Log -Level Error -Message "$AppName kurulum dosyaları silinemedi." }
                        InstalledApplication
                        if ($DisplayAppx86.DisplayVersion -eq $null) {
                            Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                        }

                        else {
                            Write-Log -Level Error -Message "$AppName uygulamasının kaldırma işlemi başarısız oldu."
                            [System.Environment]::Exit(999)
                        }
                    }
                    else {
                        Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                    }
                }
                Catch {
                    Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
                }
            }
            else {
                Write-Log -Level Error -Message "MSI Product kod tespit edilemedi."
            }
        }
        if ($UninstallStringx86 -like "*Program*") {
            Write-Log -Message "32 bit Exe kurulum tespit edilmiştir."
            try {
                StopProcess "7zFM.exe,7zG.exe,7z.exe"
                Start -FilePath $UninstallStringx86 -ArgumentList "/S" -Wait
                InstalledApplication
                if ($DisplayAppx86.UninstallString -like "*Program*") {
                    Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
                }
                else {
                    Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                }
            } 
            catch {
                Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
            }
        }
    }
}

## 64 bit versiyon kontrolü
if ($DiplayVersionx64 -ne $null) {
    foreach ($Appx64 in $DisplayAppx64) {
        $DiplayVersionx64 = $Appx64.DisplayVersion
        $UninstallStringx64 = $Appx64.UninstallString
        Write-Log -Message "64 Bit $DiplayVersionx64 versiyon $AppName uygulamasının varlığı tespit edilmiştir."
        Write-Log -Message "UninstallString: $UninstallStringx64"
        if ($UninstallStringx64 -like "*msiexec*") {
            Write-Log -Message "64 bit MSI kurulum tespit edilmiştir."
            ## Convert Product Code
            $UninstallStringx64 = ($UninstallStringx64.Split("{")[1]).Trim()
            $ProductCodex64 = ($UninstallStringx64.Split("}")[0]).Trim()

            Write-Log -Message "Product Code: $ProductCodex64"
            if ($ProductCodex64 -ne $null) {
                Try {
                    ## Uninstall
                    StopProcess "7zFM.exe,7zG.exe,7z.exe"
                    $Argx64 = "/x {$ProductCodex64} /q REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable"
                    Start-Process -FilePath "msiexec.exe" -ArgumentList $Argx64 -Wait
                    if (Test-Path "$envProgramFiles\7-Zip") { Remove-Item -Path "$envProgramFiles\7-Zip" -Recurse -Force -ErrorAction SilentlyContinue; Write-Log -Level Warn -Message "Program Files klasöründe kalıntı 7-Zip klasörü bulundu ve silindi." }
                    InstalledApplication
                    if ($DisplayAppx64.UninstallString -like "*msiexec*") {
                        Write-Log -Level Error -Message "MSI kaldırma işlemi başarısız oldu."
                        Write-Log -Message "$AppName uygulamasının kaldırma işlemi tekrar deneniyor."
                    
                        ## Delete Install Folder Path
                        if (Test-Path "$envProgramFiles\7-Zip") { $InstallPath = "$envProgramFiles\7-Zip"}
                        if (Test-Path "$envProgramFilesX86\7-Zip") { $InstallPath = "$envProgramFilesX86\7-Zip"};
                        Write-Log -Message "Uyguluma kurulum adresi: $InstallPath"
                        if ($InstallPath -ne $null) {
                            Remove-Item -Path "$InstallPath" -Recurse -Force
                        }

                        ## Delete shortcut path
                        if (Test-Path "$envProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip") { Remove-Item -Path "$envProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip" -Recurse -Force }

                        ## Delete Registery Install Path
                        if (!(Test-Path $InstallPath)) { Write-Log -Message "$AppName kurulum dosyaları başarıyla silinmiştir." } else { Write-Log -Level Error -Message "$AppName kurulum dosyaları silinemedi." }
                        $ErrorActionPreference = "SilentlyContinue"
                        $RegPath = $DisplayAppx64.PSPath.replace('Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE','HKLM:')
                        $ErrorActionPreference = "Continue"
                        if (Test-Path "$RegPath") {
                            $RegCheck = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'DisplayName' -ErrorAction SilentlyContinue
                            if ($RegCheck -like "*7-zip*") {
                                Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue 
                            }
                        }

                        if (!(Test-Path $RegPath)) { Write-Log -Message "$AppName regedit kayıtları başarıyla silinmiştir." } else { Write-Log -Level Error -Message "$AppName kurulum dosyaları silinemedi." }
                        InstalledApplication
                        if ($DisplayAppx64.DisplayVersion -eq $null) {
                            Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                        }

                        else {
                            Write-Log -Level Error -Message "$AppName uygulamasının kaldırma işlemi başarısız oldu."
                            [System.Environment]::Exit(999)
                        }
                    }
                    else {
                        Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                    }
                }
                Catch {
                    Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
                }
            }
            else {
                Write-Log -Level Error -Message "MSI Product kod tespit edilemedi."
            }
        }
        if ($UninstallStringx64 -like "*Program*") {
            Write-Log -Message "64 bit Exe kurulum tespit edilmiştir."
            try {
                StopProcess "7zFM.exe,7zG.exe,7z.exe"
                Start -FilePath $UninstallStringx64 -ArgumentList "/S" -Wait
                InstalledApplication
                if ($DisplayAppx64.UninstallString -like "*Program*") {
                    Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
                }
                else {
                    Write-Log -Message "$AppName uygulamasının kaldırma işlemi başarılı olmuştur."
                }
            } 
            catch {
                Write-Log -Level Error -Message "Kaldırma işlemi başarısız oldu."
            }
        }
    }
}


## Set Zip Default Windows Explorer
$InstalledApplicationx86 = Get-ChildItem HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | foreach-object {Get-ItemProperty $_.PsPath} -ErrorAction SilentlyContinue
$DisplayAppx86 = $InstalledApplicationx86 | ? { $_.displayname -like "*7-zip*" } | Select-Object DisplayName -ErrorAction SilentlyContinue

$InstalledApplicationx64 = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue | foreach-object {Get-ItemProperty $_.PsPath} -ErrorAction SilentlyContinue
$DisplayAppx64 = $InstalledApplicationx64 | ? { $_.displayname -like "*7-zip*" } | Select-Object DisplayName -ErrorAction SilentlyContinue

if (($DisplayAppx86 -eq $null) -and ($DisplayAppx64 -eq $null))
{
    ## Change HKLM:\SOFTWARE\Classes\.zip = Default registery value
    $DefaultZip_Reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\.zip' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '(default)' -ErrorAction SilentlyContinue
    if ( $DefaultZip_Reg -eq "7-Zip.zip" ) { 
        New-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.zip" -Name "(default)" -Value "CompressedFolder" -Force -ErrorAction Continue | Out-Null
        ## Delete HKLM:\SOFTWARE\Classes\.rar
        $Classes_rar = (Test-Path "HKLM:\SOFTWARE\Classes\.rar" -ErrorAction SilentlyContinue)
        if ($Classes_rar -eq $True) { Remove-Item -Path "HKLM:\SOFTWARE\Classes\.rar" -Recurse -Force -ErrorAction Continue | Out-Null }
    }


    ## Delete HKLM:\SOFTWARE\Classes\7-Zip.7z
    $Classes_7Zip7z = (Test-Path "HKLM:\SOFTWARE\Classes\7-Zip.7z" -ErrorAction SilentlyContinue)
    if ($Classes_7Zip7z -eq $True) { Remove-Item -Path "HKLM:\SOFTWARE\Classes\7-Zip.7z" -Recurse -Force -ErrorAction Continue | Out-Null }


    ## Delete HKLM:\SOFTWARE\Classes\7-Zip.7z
    $Classes_7ZipRar = (Test-Path "HKLM:\SOFTWARE\Classes\7-Zip.rar" -ErrorAction SilentlyContinue)
    if ($Classes_7ZipRar -eq $True) { Remove-Item -Path "HKLM:\SOFTWARE\Classes\7-Zip.rar" -Recurse -Force -ErrorAction Continue | Out-Null }


    ## Delete HKLM:\SOFTWARE\Classes\7-Zip.7z
    $Classes_7ZipZip = (Test-Path "HKLM:\SOFTWARE\Classes\7-Zip.zip" -ErrorAction SilentlyContinue)
    if ($Classes_7ZipZip -eq $True) { Remove-Item -Path "HKLM:\SOFTWARE\Classes\7-Zip.zip" -Recurse -Force -ErrorAction Continue | Out-Null }


    ## Delete HKLM:\SOFTWARE\Classes\.7z
    $Classes_7z = (Test-Path "HKLM:\SOFTWARE\Classes\.7z" -ErrorAction SilentlyContinue)
    if ($Classes_7z -eq $True) { Remove-Item -Path "HKLM:\SOFTWARE\Classes\.7z" -Recurse -Force -ErrorAction Continue | Out-Null }
}


Write-Log -Message "**********************************************************"