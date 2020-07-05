Set-ExecutionPolicy -Scope Process Bypass

## Setting Time Zone to East Coast
Write-Host "Setting Time Zone"
Set-TimeZone -Name "Eastern Standard Time"

Write-Host "Setting Computer Name:"
$input = Read-Host “: ”
Rename-Computer -newname “$input”

## Installing the NuGet PSGallery
Write-Host "Installing the NuGet PSGallery"
Install-PackageProvider NuGet -Force
Import-PackageProvider NuGet -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

## Installing Windows Update Powershell and Updating
Write-Host "Installing Windows Updates"
Install-Module -Name PSWindowsUpdate 
Get-WUInstall -MicrosoftUpdate -AcceptAll
Install-WindowsUpdate -AcceptAll

## Chocolatey Install
Write-Host "Installing Chocolatey"
iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex

## Enable global confirmation in Chocolatey
choco feature enable -n=allowGlobalConfirmation

## Software Install
Write-Host "Installing Software"

choco install dotnet3.5 -y
choco install dotnet4.6.2  -y
choco install jre8 -y
choco install 7zip.install -y
choco install -y vlc
choco install googlechrome -y

## Removing default Win10 Bloatware
Write-Host "Removing Bloatware"
Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
Get-AppxPackage *CandyCrushSaga* | Remove-AppxPackage
Get-AppxPackage *CandyCrushSodaSaga* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage
Get-AppxPackage *DisneyMagicKingdoms* | Remove-AppxPackage
Get-AppxPackage *LinkedInforWindows* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MinecraftUWP* | Remove-AppxPackage
Get-AppxPackage *DisneyMagicKingdoms* | Remove-AppxPackage
Get-AppxPackage *HiddenCityMysteryofShadows* | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage                                                                                                                     
Get-AppxPackage *Keeper* | Remove-AppxPackage
Get-AppxPackage *McAfee* | Remove-AppxPackage
Get-AppxPackage *Dropbox* | Remove-AppxPackage
Get-AppxPackage *Facebook* | Remove-AppxPackage
Get-AppxPackage *BubbleWitch* | Remove-AppxPackage
Get-AppxPackage *bing* | Remove-AppxPackage
Get-AppxPackage *Autodesk* | Remove-AppxPackage
Get-AppxPackage *Netflix* | Remove-AppxPackage
Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
Get-AppxPackage *Twitter* | Remove-AppxPackage
Get-AppxPackage *Adobe* | Remove-AppxPackage
Get-AppxPackage *Minecraft* | Remove-AppxPackage
Get-AppxPackage *Solitare* | Remove-AppxPackage
Get-AppxPackage *Tower* | Remove-AppxPackage
Get-AppxPackage *Office* | Remove-AppxPackage
