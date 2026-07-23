$ErrorActionPreference = "Stop"
dotnet publish "$PSScriptRoot/src/ConquerRsaTool.Wpf/ConquerRsaTool.Wpf.csproj" `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o "$PSScriptRoot/publish/win-x64"
Write-Host "Publicado en publish/win-x64"
