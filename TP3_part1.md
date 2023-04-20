

```shell
export vfile=/home/ubuntu/Downloads/dump_practice.dmp/dump_practice.dmp

```

```bash
python2 vol.py  -f $vfile imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/home/ubuntu/Downloads/dump_practice.dmp/dump_practice.dmp)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054c060L
          Number of Processors : 1
     Image Type (Service Pack) : 2
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-01-03 23:00:28 UTC+0000
     Image local date and time : 2016-01-03 15:00:28 -0800
```

```bash
python2 vol.py  -f $vfile pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c89c8 System                    4      0     51      249 ------      0                                                              
0x821b4020 smss.exe                492      4      3       21 ------      0 2015-12-23 09:25:39 UTC+0000                                 
0x8229f020 csrss.exe               560    492     13      390      0      0 2015-12-23 09:25:39 UTC+0000                                 
0x8217b510 winlogon.exe            584    492     16      418      0      0 2015-12-23 09:25:39 UTC+0000                                 
0x82176b28 services.exe            628    584     16      263      0      0 2015-12-23 09:25:39 UTC+0000                                 
0x821b7da0 lsass.exe               640    584     20      344      0      0 2015-12-23 09:25:39 UTC+0000                                 
0x8213e7e8 VBoxService.exe         788    628      8      103      0      0 2015-12-23 09:25:39 UTC+0000                                 
0x8212a658 svchost.exe             844    628     17      209      0      0 2015-12-23 00:25:41 UTC+0000                                 
0x82118918 svchost.exe             920    628      9      273      0      0 2015-12-23 00:25:41 UTC+0000                                 
0x820fdda0 svchost.exe            1016    628     51     1210      0      0 2015-12-23 00:25:41 UTC+0000                                 
0x820f3a88 svchost.exe            1068    628      6       81      0      0 2015-12-23 00:25:41 UTC+0000                                 
0x82104020 svchost.exe            1212    628     15      200      0      0 2015-12-23 00:25:41 UTC+0000                                 
0x820cbda0 spoolsv.exe            1428    628     10      108      0      0 2015-12-23 00:25:42 UTC+0000                                 
0x820e4da0 explorer.exe           1596   1568     12      379      0      0 2015-12-23 00:25:42 UTC+0000                                 
0x820a9848 VBoxTray.exe           1676   1596     11      133      0      0 2015-12-23 00:25:42 UTC+0000                                 
0x82015da0 alg.exe                1064    628      6      107      0      0 2015-12-23 00:25:53 UTC+0000                                 
0x820189f0 wscntfy.exe            1484   1016      1       27      0      0 2015-12-23 00:25:55 UTC+0000                                 
0x82032020 wpabaln.exe             308    584      1       57      0      0 2015-12-23 00:27:42 UTC+0000                                 
0x820095c8 wmplayer.exe           1360   1776     29      701      0      0 2015-12-23 00:31:30 UTC+0000                                 
0x82077020 notepad.exe            1260   1596      0 --------      0      0 2015-12-23 01:20:49 UTC+0000   2015-12-23 01:40:40 UTC+0000  
0x8230ada0 mspaint.exe            1772   1596      4       98      0      0 2015-12-23 01:39:56 UTC+0000                                 
0x8231a020 svchost.exe            1248    628      6      130      0      0 2015-12-23 01:39:56 UTC+0000                                 
0x821739f8 procexp.exe            1204   1596     11      267      0      0 2015-12-23 01:40:03 UTC+0000                                 
0x8230d910 notepad.exe            1928   1596      0 --------      0      0 2015-12-23 01:40:43 UTC+0000   2015-12-23 01:42:11 UTC+0000  
0x81f819c8 notepad.exe            1788   1596      0 --------      0      0 2015-12-23 01:42:15 UTC+0000   2016-01-03 22:55:04 UTC+0000  
0x820e8928 wuauclt.exe            1504   1016      4      128      0      0 2016-01-03 22:55:21 UTC+0000                                 
0x81fc8020 notepad.exe            1088   1596      1       27      0      0 2016-01-03 22:56:02 UTC+0000 
```

```shell
python2 vol.py  -f $vfile psscan
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Name                PID   PPID PDB        Time created                   Time exited                   
------------------ ---------------- ------ ------ ---------- ------------------------------ ------------------------------
0x0000000001f83e68 notepad.exe        1788   1596 0x12f9f000 2015-12-23 01:42:15 UTC+0000   2016-01-03 22:55:04 UTC+0000  
0x0000000001fca4c0 notepad.exe        1088   1596 0x0288f000 2016-01-03 22:56:02 UTC+0000                                 
0x000000000200ba68 wmplayer.exe       1360   1776 0x0fdcc000 2015-12-23 00:31:30 UTC+0000                                 
0x0000000002018240 alg.exe            1064    628 0x0de80000 2015-12-23 00:25:53 UTC+0000                                 
0x000000000201ae90 wscntfy.exe        1484   1016 0x0e0c5000 2015-12-23 00:25:55 UTC+0000                                 
0x00000000020344c0 wpabaln.exe         308    584 0x17ccf000 2015-12-23 00:27:42 UTC+0000                                 
0x00000000020794c0 notepad.exe        1260   1596 0x13680000 2015-12-23 01:20:49 UTC+0000   2015-12-23 01:40:40 UTC+0000  
0x00000000020abce8 VBoxTray.exe       1676   1596 0x0a349000 2015-12-23 00:25:42 UTC+0000                                 
0x00000000020ce240 spoolsv.exe        1428    628 0x08c99000 2015-12-23 00:25:42 UTC+0000                                 
0x00000000020e7240 explorer.exe       1596   1568 0x09786000 2015-12-23 00:25:42 UTC+0000                                 
0x00000000020eadc8 wuauclt.exe        1504   1016 0x0fe11000 2016-01-03 22:55:21 UTC+0000                                 
0x00000000020f5f28 svchost.exe        1068    628 0x06869000 2015-12-23 00:25:41 UTC+0000                                 
0x0000000002100240 svchost.exe        1016    628 0x06850000 2015-12-23 00:25:41 UTC+0000                                 
0x00000000021064c0 svchost.exe        1212    628 0x07a31000 2015-12-23 00:25:41 UTC+0000                                 
0x000000000211adb8 svchost.exe         920    628 0x066c2000 2015-12-23 00:25:41 UTC+0000                                 
0x000000000212caf8 svchost.exe         844    628 0x06293000 2015-12-23 00:25:41 UTC+0000                                 
0x0000000002140c88 VBoxService.exe     788    628 0x05f38000 2015-12-23 09:25:39 UTC+0000                                 
0x0000000002175e98 procexp.exe        1204   1596 0x085f1000 2015-12-23 01:40:03 UTC+0000                                 
0x0000000002178fc8 services.exe        628    584 0x053b0000 2015-12-23 09:25:39 UTC+0000                                 
0x000000000217d9b0 winlogon.exe        584    492 0x04b90000 2015-12-23 09:25:39 UTC+0000                                 
0x00000000021b64c0 smss.exe            492      4 0x037f3000 2015-12-23 09:25:39 UTC+0000                                 
0x00000000021ba240 lsass.exe           640    584 0x0554d000 2015-12-23 09:25:39 UTC+0000                                 
0x00000000022a14c0 csrss.exe           560    492 0x0480a000 2015-12-23 09:25:39 UTC+0000                                 
0x000000000230d240 mspaint.exe        1772   1596 0x002ca000 2015-12-23 01:39:56 UTC+0000                                 
0x000000000230fdb0 notepad.exe        1928   1596 0x02ab7000 2015-12-23 01:40:43 UTC+0000   2015-12-23 01:42:11 UTC+0000  
0x000000000231c4c0 svchost.exe        1248    628 0x030da000 2015-12-23 01:39:56 UTC+0000                                 
0x00000000023cae68 System                4      0 0x00039000     
```

3. Le "moment de capture" fait référence à l'instant précis où la copie de la mémoire a été réalisée. Cela peut être important pour déterminer l'état du système à un moment donné, ou pour identifier les événements qui se sont produits avant ou après cette capture.

Pour garantir la cohérence de la mémoire, il est important de minimiser les modifications apportées au système pendant le processus de capture. Cela peut être réalisé en minimisant l'activité du système pendant la capture, en évitant de lancer de nouveaux processus ou de modifier les données existantes.

Il est également important de noter les informations spécifiques sur l'outil de copie de mémoire utilisé, telles que la version et les paramètres de configuration. Cela permettra de reproduire les résultats de la capture de manière cohérente et de garantir la fiabilité des données collectées.

Enfin, pour garantir la cohérence de la mémoire, il est souvent recommandé d'effectuer la capture de la mémoire à plusieurs reprises, en utilisant des outils différents ou des paramètres de configuration différents, afin de vérifier la fiabilité des résultats.

```shell 
python2 vol.py  -f $vfile handles -p 1596      #1596 = notepad
Volatility Foundation Volatility Framework 2.6.1
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0xe10096a0   1596        0x4    0xf0003 KeyedEvent       CritSecOutOfMemoryEvent
0xe1459f58   1596        0x8        0x3 Directory        KnownDlls
0x8217f1c0   1596        0xc   0x100020 File             \Device\HarddiskVolume1\Documents and Settings\pero
0xe1436c98   1596       0x10    0xf001f Section          
0xe13f5ec8   1596       0x14    0xf000f Directory        Windows
0xe159cd50   1596       0x18  0x21f0001 Port             
0xe195eeb0   1596       0x1c  0x20f003f Key              MACHINE
0x82102248   1596       0x20  0x21f0003 Event            
0xe136ed10   1596       0x24    0x2000f Directory        BaseNamedObjects
0x821707e0   1596       0x28    0xf037f WindowStation    WinSta0
0x82179038   1596       0x2c    0xf01ff Desktop          Default
0x821707e0   1596       0x30    0xf037f WindowStation    WinSta0
0x82166f38   1596       0x34   0x1f0003 Semaphore        shell.{A48F1A32-A340-11D1-BC6B-00A0C90312E1}
0x82186438   1596       0x38   0x100000 Event            crypt32LogoffEvent
0x820cc328   1596       0x3c   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.2180_x-ww_a84f1ff9
0x82102340   1596       0x40   0x100001 File             \Device\KsecDD
0x820c11a0   1596       0x44   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.2180_x-ww_a84f1ff9
0x820d8aa0   1596       0x48   0x1f0001 Mutant           
0x820d49a0   1596       0x4c   0x1f0003 Event            
0x820d8a60   1596       0x50   0x1f0001 Mutant           
0x820d8a30   1596       0x54   0x1f0003 Event            
0x820d8a00   1596       0x58   0x1f0003 Event            
0xe181f520   1596       0x5c  0x20f003f Key              USER\S-1-5-21-823518204-854245398-839522115-1004
0x820d8970   1596       0x60   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.2180_x-ww_a84f1ff9
0xe1989140   1596       0x64    0x2001f Key              USER\S-1-5-21-823518204-854245398-839522115-1004\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\INTERNET SETTINGS
0x820d87f0   1596       0x68   0x1f0003 Event            
0x820d8760   1596       0x6c   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.2180_x-ww_a84f1ff9
0x820d8620   1596       0x70   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.2180_x-ww_a84f1ff9
0xe16c5fb8   1596       0x74  0x20f003f Key              USER\S-1-5-21-823518204-854245398-839522115-1004_CLASSES

```

4. Quelque types de handles q'on voi :
	1. KeyedEvent
	2. Directory
	3. File
	4. Section
	5. Port
	6. Key
	7. Event
	8. Mutant

```shell
python2 vol.py  -f $vfile userassist
Volatility Foundation Volatility Framework 2.6.1
----------------------------
Registry: \Device\HarddiskVolume1\Documents and Settings\pero\NTUSER.DAT 
Path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{5E6AB780-7743-11CF-A12B-00AA004AE837}\Count
Last updated: 2016-01-03 22:58:33 UTC+0000

Subkeys:

Values:

REG_BINARY    UEME_CTLSESSION : Raw Data:
0x00000000  d2 33 8a 0e 02 00 00 00                           .3......
----------------------------
Registry: \Device\HarddiskVolume1\Documents and Settings\pero\NTUSER.DAT 
Path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}\Count
Last updated: 2016-01-03 22:58:35 UTC+0000

Subkeys:

Values:

REG_BINARY    UEME_CTLSESSION : Raw Data:
0x00000000  c1 e8 89 0e 01 00 00 00                           ........

REG_BINARY    UEME_RUNPIDL:%csidl2%\MSN.lnk : 
ID:             1
Count:          14
Last updated:   2015-12-23 00:22:13 UTC+0000
Raw Data:
0x00000000  01 00 00 00 13 00 00 00 f2 4b ca f8 17 3d d1 01   .........K...=..

REG_BINARY    UEME_RUNPIDL:%csidl2%\Windows Media Player.lnk : 
ID:             1
Count:          14
Last updated:   2015-12-23 00:31:20 UTC+0000
Raw Data:
0x00000000  01 00 00 00 13 00 00 00 90 62 e1 3e 19 3d d1 01   .........b.>.=..


```

```bash

python2 vol.py  -f $vfile modules
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Name                 Base             Size File
---------- -------------------- ---------- ---------- ----
0x823fc3a0 ntoskrnl.exe         0x804d7000   0x214200 \WINDOWS\system32\ntoskrnl.exe
0x823fc338 hal.dll              0x806ec000    0x13d80 \WINDOWS\system32\hal.dll
0x823fc2d0 kdcom.dll            0xf8a50000     0x2000 \WINDOWS\system32\KDCOM.DLL
0x823fc260 BOOTVID.dll          0xf8960000     0x3000 \WINDOWS\system32\BOOTVID.dll
0x823fc1f8 ACPI.sys             0xf8501000    0x2e000 ACPI.sys
0x823fc188 WMILIB.SYS           0xf8a52000     0x2000 \WINDOWS\system32\DRIVERS\WMILIB.SYS
0x823fc120 pci.sys              0xf84f0000    0x11000 pci.sys
0x823fc0b0 isapnp.sys           0xf8550000     0x9000 isapnp.sys
0x823fc040 compbatt.sys         0xf8964000     0x3000 compbatt.sys
0x823ed008 BATTC.SYS            0xf8968000     0x4000 \WINDOWS\system32\DRIVERS\BATTC.SYS
0x823edf98 intelide.sys         0xf8a54000     0x2000 intelide.sys
0x823edf28 PCIIDEX.SYS          0xf87d0000     0x7000 \WINDOWS\system32\DRIVERS\PCIIDEX.SYS
0x823edeb8 MountMgr.sys         0xf8560000     0xb000 MountMgr.sys
0x823ede48 ftdisk.sys           0xf84d1000    0x1f000 ftdisk.sys
0x823eddd8 PartMgr.sys          0xf87d8000     0x5000 PartMgr.sys
0x823edd68 VolSnap.sys          0xf8570000     0xd000 VolSnap.sys
0x823edd00 atapi.sys            0xf84b9000    0x18000 atapi.sys
0x823edc90 cercsr6.sys          0xf87e0000     0x8000 cercsr6.sys
0x823edc20 SCSIPORT.SYS         0xf84a1000    0x18000 \WINDOWS\System32\Drivers\SCSIPORT.SYS
0x823edbb8 disk.sys             0xf8580000     0x9000 disk.sys
0x823edb48 CLASSPNP.SYS         0xf8590000     0xd000 \WINDOWS\system32\DRIVERS\CLASSPNP.SYS
0x823edad8 fltMgr.sys           0xf8482000    0x1f000 fltMgr.sys
0x823eda70 sr.sys               0xf8470000    0x12000 sr.sys
0x823eda00 KSecDD.sys           0xf8459000    0x17000 KSecDD.sys
0x823ed990 VBoxGuest.sys        0xf8433000    0x26000 VBoxGuest.sys
0x823ed928 Ntfs.sys             0xf83a6000    0x8d000 Ntfs.sys
0x823ed8c0 NDIS.sys             0xf8379000    0x2d000 NDIS.sys
0x823ed858 Mup.sys              0xf835e000    0x1b000 Mup.sys
0x82392008 i8042prt.sys         0xf85a0000     0xd000 \SystemRoot\system32\DRIVERS\i8042prt.sys
0x823eaf98 kbdclass.sys         0xf8808000     0x6000 \SystemRoot\system32\DRIVERS\kbdclass.sys
0x82399c40 VBoxMouse.sys        0xf72f8000    0x1e000 \SystemRoot\system32\DRIVERS\VBoxMouse.sys
0x823dfdb0 mouclass.sys         0xf8810000     0x6000 \SystemRoot\system32\DRIVERS\mouclass.sys

```

```shell
python2 vol.py  -f $vfile driverscan
Volatility Foundation Volatility Framework 2.6.1
Offset(P)              #Ptr     #Hnd Start            Size Service Key          Name         Driver Name
------------------ -------- -------- ---------- ---------- -------------------- ------------ -----------
0x0000000002037c50        3        0 0xf55c4000    0x52180 Srv                  Srv          \FileSystem\Srv
0x0000000002038030        5        0 0xf546b000    0x40380 HTTP                 HTTP         \Driver\HTTP
0x0000000002084488        3        0 0xf568f000    0x2c400 MRxDAV               MRxDAV       \FileSystem\MRxDAV
0x000000000208d030        3        0 0xf59c8000     0xed80 sysaudio             sysaudio     \Driver\sysaudio
0x00000000020a41a0        6        0 0xf58a3000    0x14400 wdmaud               wdmaud       \Driver\wdmaud
0x00000000020b5030        3        0 0xf5237000    0x29f00 kmixer               kmixer       \Driver\kmixer
0x00000000020f7a18        3        0 0xf5c80000     0x3280 Ndisuio              Ndisuio      \Driver\Ndisuio
0x000000000211eb58        3        0 0xf5a6c000     0x2f80 mouhid               mouhid       \Driver\mouhid
0x000000000211ec50        4        0 0xf5958000     0x2580 hidusb               hidusb       \Driver\hidusb
0x00000000021756c0        3        0 0xf8908000     0x4380 PROCEXP141           PROCEXP141   \Driver\PROCEXP141
0x0000000002177c68       12        0 0x00000000        0x0 \Driver\Win32k       Win32k       \Driver\Win32k
0x00000000021b5e00        4        0 0xf86c0000     0xf900 Cdfs                 Cdfs         \FileSystem\Cdfs
0x00000000021d3518        4        0 0xf6fe4000    0x6e380 MRxSmb               MRxSmb       \FileSystem\MRxSmb
0x00000000021d61d8        3        0 0xf70c3000    0x21d00 AFD                  AFD          \Driver\AFD
0x00000000021d63f0        3        0 0xf707f000    0x44000 VBoxSF               VBoxSF       \FileSystem\VBoxSF
0x00000000021da368        3        0 0xf8670000     0x8700 NetBIOS              NetBIOS      \FileSystem\NetBIOS
0x00000000021da730        3        0 0xf8660000     0x8700 Wanarp               Wanarp       \Driver\Wanarp
0x00000000021de5a0        3        0 0xf86a0000     0x8880 Fips                 Fips         \Driver\Fips
0x00000000021f7580        5        0 0xf7106000    0x27c00 NetBT                NetBT        \Driver\NetBT
0x00000000021fad48        7        0 0xf712e000    0x57a80 Tcpip                Tcpip        \Driver\Tcpip
0x00000000021fb030        3        0 0xf7186000    0x12400 IPSec                IPSec        \Driver\IPSec
0x00000000021fce20        3        0 0xf7332000     0x2280 RasAcd               RasAcd       \Driver\RasAcd
0x00000000021fdc20        3        0 0xf8a78000     0x1080 RDPCDD               RDPCDD       \Driver\RDPCDD
0x00000000021fe9d8        3        0 0xf7053000    0x2b180 Rdbss                Rdbss        \FileSystem\Rdbss
0x00000000021ff4b8        3        0 0xf88d0000     0x7880 Npfs                 Npfs         \FileSystem\Npfs
0x00000000021ffca0        3        0 0xf88c0000     0x4a80 Msfs                 Msfs         \FileSystem\Msfs
0x0000000002200d08        3        0 0xf70e5000    0x20f00 IpNat                IpNat        \Driver\IpNat
0x00000000022ac2c8        4        0 0xf8650000     0xe100 usbhub               usbhub       \Driver\usbhub
0x00000000022b0158        3        0 0xf8a74000     0x1080 mnmdd                mnmdd        \Driver\mnmdd
0x00000000022b04b8        3        0 0xf8630000     0x9480 NDProxy              NDProxy      \Driver\NDProxy
0x00000000022b8658        3        0 0xf8a24000     0x3c80 mssmbios             mssmbios     \Driver\mssmbios
0x00000000022b8d98        3        0 0xf71e1000    0x33200 Update               Update       \Driver\Update
0x00000000022b9d00       11        0 0xf8a62000     0x1100 swenum               swenum       \Driver\swenum
0x00000000022ba348        3        0 0xf88b0000     0x5200 VgaSave              VgaSave      \Driver\VgaSave
0x00000000022bbac8        5        0 0xf8620000     0x9f00 TermDD               TermDD       \Driver\TermDD
0x00000000022bd2c0        3        0 0xf8878000     0x4080 Raspti               Raspti       \Driver\Raspti
0x00000000022bdf38        6        0 0xf8868000     0x4580 Ptilink              Ptilink      \Driver\Ptilink
0x00000000022be7f8        3        0 0xf8a70000     0x1080 Beep                 Beep         \Driver\Beep
0x00000000022bf8d0        3        0 0xf8610000     0x8900 Gpc                  Gpc          \Driver\Gpc
0x00000000022bfdf8        5        0 0xf7215000    0x10e00 PSched               PSched       \Driver\PSched


```

On remarque l'existance de quelque modules sous le nom de : VBoxGuest, VBoxMouse ... donc on constate que le logiciel de virtualisation utilisé est *VirtualBox*

```shell 
python2 vol.py  -f $vfile connections
Volatility Foundation Volatility Framework 2.6.1
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x81feed00 10.0.2.15:1242            50.31.192.83:554          1360

```
 Port 554: Port utilisé par Real Time Streaming Protocol (RTSP) pour les services de diffusion en continu de Microsoft Windows Media et QuickTime Streaming Server (QTSS).

```shell 
python2 vol.py  -f $vfile iehistory
Volatility Foundation Volatility Framework 2.6.1
**************************************************
Process: 1596 explorer.exe
Cache type "DEST" at 0x15ceef
Last modified: 2015-12-22 17:23:19 UTC+0000
Last accessed: 2015-12-23 01:23:20 UTC+0000
URL: pero@http://sc1.slable.com:8126
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15100
Record length: 0x100
Location: Visited: pero@about:Home
Last modified: 2015-12-23 00:23:58 UTC+0000
Last accessed: 2015-12-23 00:23:58 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x84
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15200
Record length: 0x100
Location: Visited: pero@res://C:\WINDOWS\system32\shdoclc.dll/dnserror.htm
Last modified: 2015-12-23 00:28:37 UTC+0000
Last accessed: 2015-12-23 00:28:37 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15300
Record length: 0x100
Location: Visited: pero@http://www.microsoft.com/isapi/redir.dll?prd=ie&pver=6&ar=msnhome
Last modified: 2015-12-23 00:26:12 UTC+0000
Last accessed: 2015-12-23 00:26:12 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb8
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15580
Record length: 0x100
Location: Visited: pero@http://agar.io
Last modified: 2015-12-23 00:26:31 UTC+0000
Last accessed: 2015-12-23 00:26:31 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x88
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15680
Record length: 0x100
Location: Visited: pero@https://minecraft.net/download
Last modified: 2015-12-23 00:28:35 UTC+0000
Last accessed: 2015-12-23 00:28:35 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x98
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15780
Record length: 0x100
Location: Visited: pero@http://java.com/en/download/windows_ie.jsp
Last modified: 2015-12-23 00:30:28 UTC+0000
Last accessed: 2015-12-23 00:30:28 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xa4
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15880
Record length: 0x100
Location: Visited: pero@http://java.com/en/download
Last modified: 2015-12-23 00:30:25 UTC+0000
Last accessed: 2015-12-23 00:30:25 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x94
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15980
Record length: 0x100
Location: Visited: pero@http://java.com/download
Last modified: 2015-12-23 00:30:25 UTC+0000
Last accessed: 2015-12-23 00:30:25 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0x90
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15a80
Record length: 0x100
Location: Visited: pero@http://javadl.sun.com/webapps/download/AutoDL?BundleId=113226
Last modified: 2015-12-23 00:30:29 UTC+0000
Last accessed: 2015-12-23 00:30:29 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xb4
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15b80
Record length: 0x100
Location: Visited: pero@http://www.windowsmedia.com/redir/mediaguide.asp?WMPFriendly=true&locale=409&version=9.0.0.3250
Last modified: 2015-12-23 00:31:30 UTC+0000
Last accessed: 2015-12-23 00:31:30 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xd8
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15c80
Record length: 0x180
Location: Visited: pero@http://sdlc-esd.oracle.com/ESD6/JSCDL/jdk/8u66-b18/JavaSetup8u66.exe?GroupName=JSC&FilePath=/ESD6/JSCDL/jdk/8u66-b18/JavaSetup8u66.exe&BHost=javadl.sun.com&File=JavaSetup8u66.exe&AuthParam=1450831777_20262592fe7044ab00d171e28a4deaee&ext=.exe
Last modified: 2015-12-23 00:29:38 UTC+0000
Last accessed: 2015-12-23 00:29:38 UTC+0000
File Offset: 0x180, Data Offset: 0x0, Data Length: 0x168
**************************************************
Process: 1596 explorer.exe
Cache type "URL " at 0xb15e00
Record length: 0x100
Location: Visited: pero@http://java.com/inc/BrowserRedirect1.jsp?locale=en
Last modified: 2015-12-23 00:30:27 UTC+0000
Last accessed: 2015-12-23 00:30:27 UTC+0000
File Offset: 0x100, Data Offset: 0x0, Data Length: 0xac
**************************************************

```
