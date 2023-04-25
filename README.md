# FileSignatureDetector
PowerShell File Signature Detector

This scripts solves a problem that I encountered while working with files that were either without file extensions or files that were renamed with the wrong extensions. I needed a clean solution for determining the actual file type based upon reading the file directly. Thus, this script was written to read file signatures as well as parse for some common file types. The script currently can reasonably accurately detect the following file types:

Type	Notes
.accdb	
.bmp	Bitmap image
.doc	
.docx	
.dot	Word template
.dotx	Word template
.gif	Graphic Interchange Format
.htm/html	HTML
.ics	
.jpg	
.max	3DS Max
.mdb	
.mid	
.mix	PhotoDraw
.mpg	
.mp4	
.mpp	MS Project
.msg	
.msi	MS Installer
.msp	MS Installer patch
.mst	MS Installer Script
.odp	OpenDocument Presentation
.ods	OpenDocument Spreadsheet
.odt	OpenDocument Text
.pdf	
.png	
.pot	PowerPoint template
.potx	PowerPoint template
.ppt	
.pptx	
.psd	PhotoShop
.pst	Outlook PST
.pub	MS Publisher
.rtf	
.sda	StarDraw
.sdc	StarCalc
.sdw	StarWriter
.shw	Corel Presentation
.smf	StarMath
.swf	Adobe Flash
.tar.z	Compressed archive
.txt	
.vcf/vcs	
.vsd	MS Visio
.vsdx	
.wdb	MS Works database
.wps	MS Works document
.xls	
.xlsx	
.xltx	Excel template
.xlt	Excel template
.xml	
.z	
.zip	
.7z	7-Zip
