# FileSignatureDetector
PowerShell File Signature Detector

This scripts solves a problem that I encountered while working with files that were either without file extensions or files that were renamed with the wrong extensions. I needed a clean solution for determining the actual file type based upon reading the file directly. Thus, this script was written to read file signatures as well as parse for some common file types.

## Detected File Types
The script currently can reasonably accurately detect the following file types:

|Type|Notes|
|-------|-------------------------|
|.accdb|MS Access database|
|.bmp|Bitmap image|
|.doc|MS Word before 2007|
|.docx|MS Word|
|.dot|Word template before 2007|
|.dotx|Word template|
|.gif|Graphic Interchange Format|
|.htm/html|HTML|
|.ics|Calendar file|
|.jpg|JPEG|
|.max|3DS Max|
|.mdb|MS Access database|
|.mid|MIDI|
|.mix|PhotoDraw|
|.mpg|MPEG|
|.mp4|MP4|
|.mpp|MS Project|
|.msg|Outlook item|
|.msi|MS Installer|
|.msp|MS Installer patch|
|.mst|MS Installer Script|
|.odp|OpenDocument Presentation|
|.ods|OpenDocument Spreadsheet|
|.odt|OpenDocument Text|
|.pdf|Portable Document Format|
|.png|PNG image|
|.pot|PowerPoint template before 2007|
|.potx|PowerPoint template|
|.ppt|PowerPoint presentation before 2007|
|.pptx|PowerPoint presentation|
|.psd|PhotoShop|
|.pst|Outlook PST|
|.pub|MS Publisher|
|.rtf|Rich Text Format|
|.sda|StarDraw|
|.sdc|StarCalc|
|.sdw|StarWriter|
|.shw|Corel Presentation|
|.smf|StarMath|
|.swf|Adobe Flash|
|.tar.z|Compressed archive|
|.txt|Text file|
|.vcf/vcs|Calendar event file|
|.vsd|MS Visio|
|.vsdx|MS Visio|
|.wdb|MS Works database|
|.wps|MS Works document|
|.xls|MS Excel spreadsheet before 2007|
|.xlsx|MS Excel spreadsheet|
|.xltx|MS Excel template before 2007|
|.xlt|MS Excel template|
|.xml|XML|
|.z|Compressed archive|
|.zip|Compressed archive|
|.7z|7-Zip archive|

The code does not have any dependencies on external libraries or helper applications. Instead, it performs binary reads against target files and takes action based upon what it finds. If the file is in CBF format, it will read the format to determine the CLSID of the associated application. If the file is an archive, it will commonly open the archive temporarily, inspect the contents to determine the file type, and then delete the expanded files.

## How to Use the Script
The script is easy to use in that the only thing needed is to call the function. The function can be called inline as follows:

```
GetFileTypeFromFile -filePath "C:\Temp\Samples\Test.doc"
```

Additionally, the function supports cmdlet binding and can be called in a nested script:

```
$filesToProcess = Get-ChildItem -path ".\Samples" | Select-Object FullName
foreach ($filePath in $filesToProcess) {
    $out = GetFileTypeFromFile -filePath $filePath.FullName
    Write-Host $filePath.FullName, $out
}
```

This code is a work in progress but does serve as a good working instance for determining the file types listed above.
