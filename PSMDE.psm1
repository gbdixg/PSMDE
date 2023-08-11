Get-ChildItem $psscriptroot\public\*.ps1 -Recurse | ForEach-Object {
    . $_.FullName
}

Get-ChildItem $psscriptroot\private\*.ps1 -Recurse | ForEach-Object {
    . $_.FullName
}