Overview
------------
When we began allowing users to initiate password changes in Active Directory and feed those passwords into the identity management system (IDM), it was imperative that the passwords set in AD comply with the IDM password policy. Otherwise passwords were set in AD that were *not* set in the IDM system or other downstream managed directories. 

Microsoft does not have a password policy that allows the same level of control as the OUD policy, however password changes can be passed to DLL programs for farther evaluation (or, as in the case of the hook that forwards passwords to OIDM – the DLL can just return TRUE to accept the password but do something completely different with the password like send it along to an external system). See https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx for details from Microsoft. 

This password filter is based on the Open Password Filter project at (https://github.com/jephthai/OpenPasswordFilter). The communication between the DLL and the service is changed to use localhost (127.0.0.1). The DLL accepts the password on failure (this is a point of discussion for each implementation to ensure you get the behaviour ***you*** want). In the event of a service failure, non-compliant passwords ***are*** accepted. It is possible for workstation-initiated password changes to get rejected by the IDM system. The user would then have one password in Active Directory and their old password will remain in all of the other connected systems (additionally, their IDM password expiry date would not advance, so they’d continue to receive notification of their pending password expiry).

While the DLL has access to the user ID and password, only the password is passed to the service. This means a potential compromise of the service (obtaining a memory dump, for example) will yield only passwords. If the password change occurred at an off time and there’s only one password changed in that timeframe, it may be possible to correlate the password to a user ID (although if someone is able to stack trace or grab memory dumps from our domain controller … we’ve got bigger problems!)

The service which performs the filtering has been modified to search the proposed password for any word contained in a text file *as a substring*. If the case insensitive banned string appears anywhere within the proposed password, the password is rejected and the user gets an error indicating that the password does not meet the password complexity requirements.

Other password requirements (character length, character composition, cannot contain UID, cannot contain given name or surname) are implemented through the normal Microsoft password complexity requirements. This service is purely analyzing the proposed password for case insensitive matches of any string within the dictionary file.

Implementing
--------------
The filter needs to be installed and functional on ALL domain controllers within the domain. If one is missing, users can set a non-compliant password on *that* domain controller. 

1. Install the Visual Studio 2017 C++ redistributable 'stuff' -- https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
1. Copy OpenPasswordFilter.dll to SYSTEM32
1. Register DLL (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages – append, as a new line, the string OpenPasswordFilter)
1. Make an \OPF folder somewhere & copy OPFService.exe into that directory (testing and documentation uses D:\OPF)
1. Copy opfdict.txt to the same folder as the OPFService.exe
1. Create service (sc create OpenPasswordFilter binPath= d:\opf\opfservice.exe )
1. Reboot
1. Start service (set to autostart once you know everything is working; this first time, start it manually!)
1. Test (Set password to something that should fail, and it should fail. Use a string that should work, and it should work.). Load test. 

Monitoring
------------
Verify that the “OpenPasswordFilter” is running – restart / alert if it is not running.

Use dsmod to set a test account password to a good value (Something-YYYYMMDDHHMMSS) and a bad value (BannedWord-YYYYMMDDHHMMSS). If good value fails or bad value succeeds, alert.

Updating Banned Word List
--------------------------
The following steps need to be performed on EACH domain controller:
1. Stop the OpenPasswordFilter service
1. Identify the location of OPFService.exe; in that folder you will find a text file, opfdict.txt
1. Copy opfdict.txt to opfdict-YYYYMMDD
1. Open opfdict.txt in notepad and edit as needed (one word per line, all lower case). Save file.
1. Start the OpenPasswordFilter service
1. Test – verify a password containing the new string is rejected

To simplify distribution, I maintain the banned word list in a Git project. The list within the project can be updated by Security staff as needed. A job on the domain controller will pull the changes when updates are made. 

Troubleshooting
----------------
Technique #1 -- Netcap on the loopback
There are utilities that allow you to capture network traffic across the loopback interface. This is helpful in isolating problems in the service binary or inter-process communication. 

Technique #2 -- Recompile
There are a number of commented out event log writes within the DLL (obviously, it's not a good idea in production to log out candidate passwords in clear text!). They are incredibly useful, however, in determining where something is failing -- especially when the service binary returns correct results but the DLL response is incorrect. 

Technique #3 -- Debuggers
Attaching a debugger to lsass.exe is not fun. Use a remote debugger -- until you g the debugger, the DC OS is pretty much useless. And if the OS is waiting on you to click something running locally, you are quite out of luck. Install the SDK debugging utilities on your domain controller and another box. On the domain controller, find the PID of LSASS.

From the domain controller, run dbgsrv.exe -t tcp:port=2345,password=s0m3passw0rd

windbg.exe -y "srv:c:\symbols_pub*http://msdl.microsoft.com/downloads/symbols" -premote tcp:server=10.10.5.5,port=2345,password=s0m3passw0rd -p <PIDOFLSASS>

Wait for it ... this may take a long time to load up, during which time your DC is vegged. But eventually, you'll be connected. Send 'g' to the debugger to commence. 

