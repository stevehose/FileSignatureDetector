#FileSignatureDetector.ps1
# This script contains the components necessary to decode common file types based upon their binary signature.
# Usage: $out = GetFileTypeFromFile -filePath $filePath
#   $filePath is the path and name of a file. Can be relative or full.
# Relies on Get-FileSignature which was published at https://mcpmag.com/articles/2018/07/25/file-signatures-using-powershell.aspx
# Original by Steve Hose, Microsoft, 4/5/2023
# Updated 4/25/23, Steve Hose, Microsoft
# - Added new file types
# - Fixed bug reading CFB files
# Updated 5/9/23, Steve Hose, Microsoft
# - Fixed divide by zero error in Get-TextFile
# Updated 5/10/23, Steve Hose, Microsoft
# - Added logging to log file
# - Refactored to optimize code - reduced processing time by 22%

function GetFileTypeFromFile{
    # Function to pull hexadecimal string to that should contain the binary file signature
    # Pulled from http://en.wikipedia.org/wiki/list_of_file_signatures
    # By Steve Hose, Microsoft, 4/5/2023
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [string]$filePath,

       [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [string]$logfilePath
    )

    # Added logging to capture processing time
    if($logfilePath.Length -gt 0){
        Write-log -Level INFO -logfile $logfilePath -Message 'Started processing ' $filePath
    }

    # Get the file size so that we know what we are working with
    $file = get-item -Path $filePath
    $fileSize = $file.Length # Get the size in bytes

    if($fileSize -gt 14){
        # Read the part of the file that contains the binary signature one time, then process
        $fileSignature = (Get-FileSignature -Path $filePath -ByteLimit 14).HexSignature

        # For each byte size, get the signature and try to figure out the file type
        switch ($fileSignature.Substring(0,4))
        {
            '1F9D' {$fileType = '.tar.z'; break}
            '1FA0' {$fileType = '.tar.z'; break}
            '424D' {$fileType = '.bmp'; break}
        }

        if($null -eq $fileType){
            switch ($fileSignature.Substring(0,6))
            {
                'EFBBBF' {$fileType = '.txt'; break} # specific to UTF-8 with a byte order mark prefix
            }
        }

        if($null -eq $fileType){
            Switch ($fileSignature.Substring(0,8))
            {
                #'42454749' {$fileType = '.ics'; break} # ICS
                'FFD8FFD8' {$fileType = '.jpg'; break} # JPEG
                'FFD8FFE0' {$fileType = '.jpg'; break} # JPEG
                'FFD8FFEE' {$fileType = '.jpg'; break} # JPEG
                'FFD8FFE1' {$fileType = '.jpg'; break} # JPEG
                '00000020' {$fileType = '.mp4'; break} # MP4?
                '000001BA' {$fileType = '.mpg'; break} # MPEG
                '000001B3' {$fileType = '.mpg'; break} # MPEG
                '4D546864' {$fileType = '.mid'; break} # MIDI
                '25504446' {$fileType = '.pdf'; break} # PDF
                '38425053' {$fileType = '.psd'; break} # PSD
                '2142444E' {$fileType = '.pst'; break} # PST
                #'42454749' {$fileType = '.vcf'; break} # VCF/VCS
            }

            # .ics, .vcs, .vcf
            if($null -eq $fileType -and $fileSignature.substring(0,8) -eq '42454749'){
                $fileType = Get-CalendarFileType -filePath $filePath
            }

            # This is a compressed file, so we need to crack it open to see what it is
            if ($null -eq $fileType){
                if ($null -eq $fileType -and $fileSignature.substring(0,8) -eq '504B0304'){
                    # This might be an Open Office Document type. Let's check that first
                    $fileType = Get-OpenOfficeDocType -filePath $filePath

                    if($null -eq $fileType){
                        #Zip or Office File - expand and resubmit
                        $fileType = ExpandArchiveResubmit -filePath $filePath
                    }
                }
            }
        }

        if($null -eq $fileType){
            switch ($fileSignature.Substring(0,12))
            {
                '474946383761' {$fileType = '.gif'; break} #GIF87a
                '474946383961' {$fileType = '.gif'; break} #GIF89a
                '7B5C72746631' {$fileType = '.rtf'; break} #UTF-8 explicitly encoded RTF (uncommon)
                '377ABCAF271C' {$fileType = '.7z'; break} # 7-Zip archive
            }
        }

        if($null -eq $fileType){
            switch ($fileSignature.Substring(0,16))
            {
                '89504E470D0A1A0A' {$fileType = '.png'; break}
            }

            # These are the older Office file formats. Have to inspect the file to determine its type
            if ($null -eq $fileType){
                if($filesignature.Substring(0,16) -eq 'D0CF11E0A1B11AE1'){
                    $fileType = Get-FileTypeFromCFB -filePath $filePath
                }
            }
        }

        if($null -eq $fileType){
            if ($null -eq $fileType){
                Switch ($fileSignature.Substring(0,28))
                {
                    '000100005374616E646172642041' {$fileType = '.accdb'; break}
                    '000100005374616E64617264204A' {$fileType = '.mdb'; break}
                }
            }
        }
    }
    # If we made it this far, then we likely have a file that doesn't have a signature. Time to invoke parsing...
    if ($null -eq $fileType){
        $fileType = Get-FileTypeByParse -filePath $filePath
    }

    # If we still don't know what the file is, we can check to see if is a printable/readable .txt file
    if ($null -eq $fileType){
        $fileType = Get-TextFile -filePath $filePath
    }

    if ($null -eq $fileType){$fileType = 'Unknown'}

        # Added logging to capture processing time
        if($logfilePath.Length -gt 0){
            Write-log -Level INFO -logfile $logfilePath -Message 'Stopped processing ' $filePath
        }

    return $fileType
}

#region Helper Functions
function Get-FileSignature { 
    <# .synopsis="Displays a file signature for specified file or files .description displays a file signature for specified file or files. 
        Determined by getting the bytes of a file and looking at the number of bytes to return and where in the byte array to start. 
        .parameter path the path to a file. can be multiple files. 
        .parameter hexfilter a filter that can be used to find specific hex signatures. allows "*" wildcard. 
        .parameter bytelimit how many bytes of the file signature to return. default value is 2. (display first 2 bytes) 
        .parameter byteoffset where in the byte array to start displaying the signature. default value is 0 (first byte) 
        .notes 
        name: get-filesignature 
        author: boe prox 
        .outputs system.io.fileinfo.signature 
        .link http://en.wikipedia.org/wiki/list_of_file_signatures 
    #>
    #Requires -Version 3.0
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [Alias("PSPath","FullName")]
       [string]$Path,
       [parameter()]
       [Alias('Filter')]
       [string]$HexFilter = "*",
       [parameter()]
       [int]$ByteLimit = 4,
       [parameter()]
       [Alias('OffSet')]
       [int]$ByteOffset = 0
    )
    Begin {
        #Determine how many bytes to return if using the $ByteOffset
        $TotalBytes = $ByteLimit + $ByteOffset

        #Clean up filter so we can perform a regex match
        #Also remove any spaces so we can make it easier to match
        [regex]$pattern = ($HexFilter -replace '\*','.*') -replace '\s',''
    }
    Process {  
        ForEach ($item in $Path) { 
            $filestream = $null #reset
            Try {                     
                $item = Get-Item -LiteralPath (Convert-Path $item) -Force -ErrorAction Stop
            } Catch {
                Write-Warning "$($item): $($_.Exception.Message)"
                Return
            }
            If (Test-Path -Path $item -Type Container) {
                Write-Warning ("Cannot find signature on directory: {0}" -f $item)
            } Else {
                Try {
                    If ($Item.length -ge $TotalBytes) {
                        #Open a FileStream to the file; this will prevent other actions against file until it closes
                        $filestream = New-Object IO.FileStream($Item, [IO.FileMode]::Open, [IO.FileAccess]::Read)

                        #Determine starting point
                        [void]$filestream.Seek($ByteOffset, [IO.SeekOrigin]::Begin)

                        #Create Byte buffer to read into and then read bytes from starting point to pre-determined stopping point
                        $bytebuffer = New-Object "Byte[]" ($filestream.Length - ($filestream.Length - $ByteLimit))
                        [void]$filestream.Read($bytebuffer, 0, $bytebuffer.Length)

                        #Create string builder objects for hex and ascii display
                        $hexstringBuilder = New-Object Text.StringBuilder
                        $stringBuilder = New-Object Text.StringBuilder

                        #Begin converting bytes
                        For ($i=0;$i -lt $ByteLimit;$i++) {
                            If ($i%2) {
                                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                            } Else {
                                If ($i -eq 0) {
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                } Else {
                                    [void]$hexstringBuilder.Append(" ")
                                    [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
                                }        
                            }
                            If ([char]::IsLetterOrDigit($bytebuffer[$i])) {
                                [void]$stringBuilder.Append([char]$bytebuffer[$i])
                            } Else {
                                [void]$stringBuilder.Append(".")
                            }
                        }
                        If (($hexstringBuilder.ToString() -replace '\s','') -match $pattern) {
                            $object = [pscustomobject]@{
                                Name = ($item -replace '.*\\(.*)','$1')
                                FullName = $item
                                HexSignature = ($hexstringBuilder.ToString() -replace '\s','') #Clear spaces. Don't need them.
                                ASCIISignature = $stringBuilder.ToString()
                                Length = $item.length
                                Extension = $Item.fullname -replace '.*\.(.*)','$1'
                            }
                            $object.pstypenames.insert(0,'System.IO.FileInfo.Signature')
                            Write-Output $object
                        }
                    } ElseIf ($Item.length -eq 0) {
                        Write-Warning ("{0} has no data ({1} bytes)!" -f $item.name,$item.length)
                    } Else {
                        Write-Warning ("{0} size ({1}) is smaller than required total bytes for signature detection ({2})" -f $item.name,$item.length,$TotalBytes)
                    }
                } Catch {
                    Write-Warning ("{0}: {1}" -f $item,$_.Exception.Message)
                }

                #Close the file stream so the file is no longer locked by the process
                if ($filestream){
                    $FileStream.Close()
                }
            }
        }
    }
}

function Get-BytesFromFilestream{
    # This is a function that takes a path and returns a string of bytes read from it.
    # Note that this function reads files and blocks them until the file is closed.
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory=$true)]
       [string]$filePath,
       [parameter()]
       [int]$bytesToRead,
       [parameter()]
       [Alias('OffSet')]
       [int]$ByteOffset
    )

    # Check for errors using the passed in parameters
    If (Test-Path -Path $filePath -Type Container) {
        Write-Host ("Skipping reading for a directory entry: {0}" -f $item)
        Return
    }
    Try {                     
        $testFile = Get-Item -LiteralPath (Convert-Path $filePath) -Force -ErrorAction Stop
    } Catch {
        Write-Warning "$($filePath): $($_.Exception.Message)"
        Return
    }
    #Determine how many bytes to return if using the $ByteOffset
    $TotalBytes = $bytesToRead + $ByteOffset
    If ($testFile.length -le $TotalBytes) {
        Write-Warning "$($filePath): Cannot read farther into a file than its length."
        Return
    }

    # Open a FileStream to the file; this will prevent other actions against file until it closes
    $filePath = Resolve-Path $filePath
    $filestream = New-Object IO.FileStream($filePath, [IO.FileMode]::Open, [IO.FileAccess]::Read)

    # Create Byte buffer to read into and then read bytes from starting point to pre-determined stopping point
    $bytebuffer = New-Object Byte[]($bytesToRead)

    # Set the starting point
    [void]$filestream.Seek($ByteOffset, [IO.SeekOrigin]::Begin) # Point the reader to the first byte

    # read the portion of the file into the byte array
    [void]$filestream.Read($bytebuffer, 0, $bytesToRead)

    # Create string builder objects for hex and ascii display
    $hexstringBuilder = New-Object Text.StringBuilder
    $stringBuilder = New-Object Text.StringBuilder

    # Begin converting bytes. Now that we have read the portion of the file, let's decode it
    For ($i=0;$i -lt $bytesToRead;$i++) {
        If ($i%2) {
            [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
        } Else {
            If ($i -eq 0) {
                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
            } Else {
                [void]$hexstringBuilder.Append(" ")
                [void]$hexstringBuilder.Append(("{0:X}" -f $bytebuffer[$i]).PadLeft(2, "0"))
            }        
        }
        If ([char]::IsLetterOrDigit($bytebuffer[$i])) {
            [void]$stringBuilder.Append([char]$bytebuffer[$i])
        } Else {
            [void]$stringBuilder.Append(".")
        }
    }

    #Close the file stream so the file is no longer locked by the process
    if ($filestream){
        $FileStream.Close()
    }
    $output = $hexstringBuilder.ToString() -replace '\s',''
    return $output
}

function ExpandArchiveResubmit {
    # Designed to open archive/zip files and submit the expanded file for evaluation
    # By Steve Hose, Microsoft, 4/5/2023
    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [string]$filePath
    )

    # Crack open the archive, retaining the attributes
    $inFile = Get-Item $filePath
    $path = $inFile.DirectoryName + '\' + $infile.Name + '.out'
    Expand-Archive -Path $filePath -DestinationPath $path -Force

    # We have an expanded archive, let's see what is inside of it
    Get-ChildItem -path $path | ForEach-Object{
        switch ($_.Name)
        {
            'word'  {$fileType = '.docx'; break}
            'xl'    {$fileType = '.xlsx'; break}
            'ppt'   {$fileType = '.pptx'; break}
            'visio' {$fileType = '.vsdx'; break}
        }
    }
    if ($null -eq $fileType){$fileType = '.zip'} # We know it is a packed archive, but if we didn't find it, it is a zip

    # Clean up what we unpacked
    Remove-Item -Path $path -Recurse

    # Return what we found
    return $fileType
}

#>
function Get-FileTypeFromCFB{
    <# .synopsis="Attempts to read the Compound Binary File (CFB) pseudo file system to determine the file type. Accomplished by getting the bytes of a file and 
    looking at the number of bytes to return and where in the byte array to start. 
    #>
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory=$true)]
       [Alias("PSPath","FullName")]
       [string]$filePath
    )

    # Get the file size so that we know what we are working with
    $file = get-item -Path $filePath
    $fileSize = $file.Length # Get the size in bytes

    if($null -eq $fileType -and $fileSize -gt 16){
        $fileSignature = Get-BytesFromFilestream -filePath $filePath -bytesToRead 16 -ByteOffset 0
        if($filesignature.Substring(0,16) -ne 'D0CF11E0A1B11AE1'){return}
    }

    # Get the sector size by reading
    # Value at 1E specifies this as the power of two. The only valid values are 9 or 12, which gives 512 or 4096 byte sector size.
    $sectorSizeHex = Get-BytesFromFilestream -filePath $filePath -bytesToRead 1 -ByteOffset 30
    switch ([UInt16]$sectorSizeHex){
        9 {$sectorSize = 512} # Microsoft Office files are normally 512
        12 {$sectorSize = 4096}
    }

    # Read first directory sector index at offset 48 in the header
    $rootDirIndexHex = Get-BytesFromFilestream -filePath $filePath -bytesToRead 4 -ByteOffset 48
    # $rootDirIndexHex is little-endian so it needs to be reversed
    $rootDirIndexHex = Convert-LittleEndianBytesToBigEndianBytes -bigBytes $rootDirIndexHex
    $rootDirIndex = [Uint32]"0x$rootDirIndexHex"
    $rootDirAddress = $sectorSize + ($rootDirIndex * $sectorSize)
    $guidAddress = $rootDirAddress + 80

    # File header is one sector wide. After that we can address the sector directly using the sector index
    $guid = Get-BytesFromFilestream -filePath $filePath -bytesToRead 16 -ByteOffset $guidAddress

    # It is a 128 bit GUID, encoded as "DWORD, WORD, WORD, BYTE[8]", little endian for the first DWORD
    # Let's convert it into something we can compare
    $first = $guid.Substring(6,2)
    $second = $guid.Substring(4,2)
    $third = $guid.Substring(2,2)
    $fourth = $guid.Substring(0,2)
    $guidString = $first + $second + $third + $fourth + '-'
    $guidString = $guidString + $guid.Substring(8,4) + '-'
    $guidString = $guidString + $guid.Substring(12,4) + '-'
    $guidString = $guidString + $guid.Substring(16,4) + '-'
    $guidString = $guidString + $guid.Substring(20,12)

    # Compare the GUID to the known types and return the result
    switch ($guidString.ToUpper()) {
        '00020810-0000-0000-C000-000000000046' {$fileType = '.xls'; break} #MS Excel before 2007
        '00020820-0000-0000-C000-000000000046' {$fileType = '.xls'; break} #MS Excel before 2007
        '00020900-0000-0000-C000-000000000046' {$fileType = '.doc'; break} #MS Word before 2007
        '00020906-0000-0000-C000-000000000046' {$fileType = '.doc'; break} #MS Word before 2007
        '00020C0B-0000-0000-C000-000000000046' {$fileType = '.msg'; break} #Outlook item
        '00020D0B-0000-0000-C000-000000000046' {$fileType = '.msg'; break} #Outlook item
        '00021201-0000-0000-00C0-000000000046' {$fileType = '.pub'; break} #Microsoft Publisher
        '00021302-0000-0000-C000-000000000046' {$fileType = '.wps'; break} #Microsoft Works 3-4 WordProcessor
        '00021303-0000-0000-C000-000000000046' {$fileType = '.wdb'; break} #Microsoft Works 3-4 database
        '00021A13-0000-0000-C000-000000000046' {$fileType = '.vsd'; break} #Visio before 2007
        '00021A14-0000-0000-C000-000000000046' {$fileType = '.vsd'; break} #Visio to 2010
        '00044851-0000-0000-C000-000000000046' {$fileType = '.ppt'; break} #PowerPoint before 2007
        '000C1082-0000-0000-C000-000000000046' {$fileType = '.mst'; break} #Windows Installer Script MST
        '000C1084-0000-0000-C000-000000000046' {$fileType = '.msi'; break} #MSI
        '000C1086-0000-0000-C000-000000000046' {$fileType = '.msp'; break} #Windows Installer Patch MSP
        '02B3B7E1-4225-11D0-89CA-008029E4B0B1' {$fileType = '.smf'; break} #StarMath 4.0
        '0EA45AB2-9E0A-11D1-A407-00C04FB932BA' {$fileType = '.wps'; break} #Microsoft Works 5-6 WordProcessor
        '18B8D021-B4FD-11D0-A97E-00A0C905410D' {$fileType = '.mix'; break} #MIX (PhotoDraw)
        '1CDD8C7B-81C0-45A0-9FED-04143144CC1E' {$fileType = '.max'; break} #MAX (3ds Max)
        '21000000-00D8-FD8D-8FAC-000000B60000' {$fileType = '.ppt'; break} #PowerPoint before 2007
        '28CDDBC2-0AE2-11CE-A29A-00AA004A1A72' {$fileType = '.wps'; break} #Microsoft Works 4 WordProcessor
        '28CDDBC3-0AE2-11CE-A29A-00AA004A1A72' {$fileType = '.wdb'; break} #Microsoft Works 4 database
        '2E8905A0-85BD-11D1-89D0-008029E4B0B1' {$fileType = '.sda'; break} #StarDraw 5.0
        '3F543FA0-B6A6-101B-9961-04021C007002' {$fileType = '.sdc'; break} #StarCalc 3.0
        '402EFE62-1999-101B-99AE-04021C007002' {$fileType = '.shw'; break} #Corel 7-X3 presentation
        '519873FF-2DAD-0220-1937-0000929679CD' {$fileType = '.wpd'; break} #WordPerfect document
        '56616800-C154-11CE-8553-00AA00A1F95B' {$fileType = '.mix'; break} #MIX (PhotoDraw)
        '597CAA70-72AA-11CF-831E-524153480000' {$fileType = '.swf'; break} #Adobe Flash
        '6361D441-4235-11D0-89CB-008029E4B0B1' {$fileType = '.sdc'; break} #StarCalc 4.0
        '64818D10-4F9B-11CF-86EA-00AA00B929E8' {$fileType = '.ppt'; break} #PowerPoint before 2007
        '64818D10-9B4F-CF11-86EA-00AA00B929E8' {$fileType = '.ppt'; break} #PowerPoint before 2007
        '74B78F3A-C8C8-11D1-BE11-00C04FB6FAF1' {$fileType = '.pub'; break} #Microsoft Publisher
        '74B78F3A-C8C8-D111-BE11-00C04FB6FAF1' {$fileType = '.mpp'; break} #Microsoft Project
        '8B04E9B0-420E-11D0-A45E-00A0249D57B1' {$fileType = '.sdw'; break} #StarWriter 4.0
        'AF10AAE0-B36D-101B-9961-04021C007002' {$fileType = '.sda'; break} #StarDraw 3.0
        'C20CF9D1-85AE-11D1-AAB4-006097DA561A' {$fileType = '.sdw'; break} #StarWriter 5.0
        'C6A5B861-85D6-11D1-89CB-008029E4B0B1' {$fileType = '.sdc'; break} #StarCalc 5.0
        'D4590460-35FD-101C-B12A-04021C007002' {$fileType = '.smf'; break} #StarMath 3.0
        'DC5C7E40-B35C-101B-9961-04021C007002' {$fileType = '.sdw'; break} #StarWriter 3.0
        'EA7BAE70-FB3B-11CD-A903-00AA00510EA3' {$fileType = '.ppt'; break} #PowerPoint before 2007
        'F908C7A8-096E-57B7-CA50-D009AF6A5CB7' {$fileType = '.ppt'; break} #PowerPoint before 2007
        'FFB5E640-85DE-11D1-89D0-008029E4B0B1' {$fileType = '.smf'; break} #StarMath 5.0
        default{
            $fileType = 'Unknown'
        }
    }

    return $fileType
}

function Convert-LittleEndianBytesToBigEndianBytes{
    # This is a simple helper function to convert a string representing bytes
    Param(
        [Parameter(Mandatory=$true)]
        [string]$bigBytes
     )

    # Do we have a valid string to work with?
    if (($bigBytes.Length % 2) -ne 0){
        Write-Warning "Bad bigBytes format."
        Return
    }
    if ($bigBytes.Substring(0,2) -eq '0x'){
        # If the string is prefixed with 0x, strip it out as we don't need it
        $bigBytes = $bigBytes.Substring(2)
    }

    # Process the string
    $bytes = [System.Collections.ArrayList]@()
    $iterations = $bigBytes.Length - 1
    for ($i = 0; $i -le $iterations; $i += 2) {
        $null = $bytes.Add($bigBytes.Substring($i, 2))
    }

    $i = $bytes.Count - 1
    while($i -gt -1) {
        $littleBytes = $littleBytes + $bytes[$i]
        $i = $i - 1
    }
    Return $littleBytes
}

function Get-FileTypeByParse{
# Designed to open files and parse the contents to determine file type
# By Steve Hose, Microsoft, 4/17/2023
# Updated, 4/17/2023, Steve Hose, Microsoft

    [CmdletBinding()]
    Param(
       [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
       [string]$filePath
    )

    [Int16]$score = 0

    # Crack open the archive, retaining the attributes
    $fileContents = Get-Content -Path $filePath

    # Test for HTML - how deeply do we need to check?
    if($null -eq $fileType -and $fileContents -like  "*<html*"){
        if($fileContents -like  "*<html*"){$score = 25}
        if($fileContents -like "*</html>*"){$score = $score + 25}
        if($fileContents -like "*<body*"){$score = $score + 25}
        if($fileContents -like "*</body>*"){$score = $score + 25}
        if($fileContents -like  "*<table*"){$score = 25}
        if($fileContents -like "*</table>*"){$score = $score + 25}
        if($score -ge 50){
            $fileType = ".htm"
        }
    }

    # Test for XML
    if($null -eq $fileType){
        if($fileContents -like  "*<*xml*"){
            if($fileContents -like "*<*xml*"){$score = 25}
            if($fileContents -like "*</xml>*"){$score = $score + 25}
            if($fileContents -like "*xmlns*"){$score = $score + 25}
            if($fileContents -like "*dtd*"){$score = $score + 25}
            if($score -ge 50){
                $fileType = ".xml"
            }
        }
    }

    return $fileType
}

function Get-CalendarFileType{
# Designed to open calendar files and parse the contents to determine file type
# By Steve Hose, Microsoft, 4/17/2023
# Updated, 4/17/2023, Steve Hose, Microsoft

    [CmdletBinding()]
    Param(
    [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
    [string]$filePath
    )

    [Int16]$score = 0

    # Crack open the archive, retaining the attributes
    $fileContents = Get-Content -Path $filePath

    # Test for vcard
    if($fileContents -like  "*VCARD*"){
        if($fileContents -like  "*BEGIN:VCARD*"){$score = 25}
        if($fileContents -like "*VOICE*"){$score = $score + 25}
        if($fileContents -like "*FN*"){$score = $score + 25}
        if($fileContents -like "*END:VCARD*"){$score = $score + 25}
        if($score -ge 50){
            $fileType = ".vcf"
        }
    }

    # Test for .ics, .vcs
    if($fileContents -like  "*VCALENDAR*"){
        if($fileContents -like  "*BEGIN:VCALENDAR*"){$score = 25}
        if($fileContents -like "*END:VCALENDAR*"){$score = $score + 25}
        if($score -ge 50){
            if($fileContents -like "*VERSION:2.0*"){
                $fileType = ".ics"
            }else{
                $fileType = ".vcs"
            }
        }
    }

    return $fileType
}

function Get-OpenOfficeDocType{
    # Designed to read Open Office document files and parse the contents to determine file type
    # By Steve Hose, Microsoft, 4/17/2023
    # Updated, 4/17/2023, Steve Hose, Microsoft

    [CmdletBinding()]
    Param(
    [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
    [string]$filePath
    )

    # Read the file
    $fileContents = Get-Content -Path $filePath

    # Test for Open Office Document file formats
    if($null -eq $fileType){
        if($fileContents -like  "*mimetypeapplication/vnd.oasis.opendocument.presentationPK*"){$fileType = '.odp'}
        if($fileContents -like  "*mimetypeapplication/vnd.oasis.opendocument.spreadsheetPK*"){$fileType = '.ods'}
        if($fileContents -like  "*mimetypeapplication/vnd.oasis.opendocument.textPK*"){$fileType = '.odt'}
    }

    return $fileType
}

function Get-TextFile {
    # Designed to read Open Office document files and parse the contents to determine file type
    # By Steve Hose, Microsoft, 4/17/2023
    # Updated, 4/17/2023, Steve Hose, Microsoft

    [CmdletBinding()]
    Param(
    [Parameter(Position=0,Mandatory=$true, ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$True)]
    [string]$filePath
    )

    # Read the file
    $fileContents = Get-Content -Path $filePath

    # Test the characters
    $chars = 0
    $score = 0
    $currentLine = 0

    # read the file a line at a time
    foreach ($line in $fileContents) {
        # Count how many lines we've read. We should know pretty quickly if we have something other than a text file.
        $currentLine = $currentLine + 1
        if ($currentLine -eq 20) {break} # Currently breaking out of reading the file at 20 lines

        # Process the current line
        $len = $line.Length
        $chars = $chars + $len
        for ($i = 0; $i -lt $len-1; $i++) {
            $isCommonChar = $false
            $isCommonChar = IsCommonCharacter -character $line.Substring($i,1) -ErrorAction SilentlyContinue
            if($isCommonChar){$score = $score + 1} # up the score if the character is printable ASCII
        }
    }
    # We have the score, let's determine the results. If a high percentage of the characters are common ASCII
    # printable characters, it is very likely a text file.
    if($score/$chars -gt .9){ # Currently using 90% printable as the threshold
        return '.txt'
    }
}

function IsCommonCharacter {
    #(byte $ascii)
    Param(
    [Parameter(Mandatory=$true)]
        [string]$character
    )

    # Convert the character to decimal
    $ascii = [BYTE][CHAR]$character
    $test = $false

    # Test to see if the character is in the common set of ASCII characters that are printable
    if ($ascii -eq 9) {$test = $true} #tab
    if ($ascii -eq 10) {$test = $true} #lf
    if ($ascii -eq 13) {$test = $true} #cr
    if ($ascii -ge 32 -and $ascii -le 126) {$test = $true} # In the range of printable characters

    return $test
}

function GenerateFilename{
    # This function encapsulates the business rules used to create file names from processing properties
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$fileName,

        [Parameter(Mandatory=$True)]
        [string]$actualExtension,

        [Parameter(Mandatory=$True)]
        [string]$detectedExtension
    )

    if ($actualExtension -eq $detectedExtension){
        $useExtention = $actualExtension
    } else {
        switch ($detectedExtension){
            'txt' { # Could be any of several possible actual file types
                $useExtention = $actualExtension
            }
            'Unknown' {
                $useExtention = $actualExtension
            }
            default {
                $useExtention = $detectedExtension
            }
        }
    }

    $generatedFilename = $fileName + '.' + $useExtention
    return $generatedFilename
}
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String]$Level,

        [Parameter(Mandatory=$False)]
        [string]$Id,

        [Parameter(Mandatory=$True)]
        [string]$Message,

        [Parameter(Mandatory=$False)]
        [string]$logfile
    )

    #$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Stamp = get-date -format FileDateTime
    $Line = "$Stamp`t$Id`t$Level`t$Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

#endregion Helper Functions

#region Examples

<#
#$filePath = "C:\Dev\File Signature Detector\Samples2\SQL Server FineBuild Reference Revision 1.doc"
$filePath = "C:\Dev\File Signature Detector\Samples\Test.pst"
$out = GetFileTypeFromFile -filePath $filePath
write-host "ChangedFileName$out"
#>
<#
GetFileTypeFromFile -filePath "C:\Dev\File Signature Detector\Samples\Test.pst"
#>

#Process a folder of files
#$filesToProcess = Get-ChildItem -path ".\Samples" | Select-Object FullName
#$filesToProcess = Get-ChildItem -path ".\Text Samples" | Select-Object FullName
#$filesToProcess = Get-ChildItem -path "F:\zArchive\iNAVSEA" | Select-Object FullName

<#
$filesToProcess = Get-ChildItem -path ".\Samples" | Select-Object FullName
foreach ($filePath in $filesToProcess) {
    $out = GetFileTypeFromFile -filePath $filePath.FullName -logfilePath ".\GetFileType202510-1115.log"
    Write-Host $filePath.FullName, $out
}
#>

#endregion Examples
