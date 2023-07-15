In this blog series, we'll delve into how iOS applications detect the presence of a jailbroken device, and explore various methods to bypass these detection mechanisms using both static and dynamic analysis. In this initial post, we'll start with the fundamental concepts and techniques needed to bypass these detections.

*__Tools__*
[DVIA-V2 (Damn Vulnerable iOS Application)](https://github.com/prateek147/DVIA-v2)
[Frida iOS Dump](https://github.com/AloneMonkey/frida-ios-dump)
[Frida](https://frida.re/)
[Hex-rays IDA Pro](https://hex-rays.com/ida-pro/)


*__First Steps __*
Before we jump into bypassing the jailbreak detection, there are a few preliminary steps that need to be taken. The first is to utilize `frida-ps` to confirm that the application we want to analyze is currently running on the device. It's important to keep in mind that in order to use any Frida tool, the mobile device must either be connected via USB or have OpenSSH enabled, so that we can communicate via SSH. Additionally, it's necessary to ensure that the `frida-server` is running for proper functionality.

We can use the following command `frida-ps -U` to get a list of running processes on the device and their associated  PID's. In the output, we can see that DVIA-v2 is indeed running on the device with the PID 3293.
```
650  CommCenterMobileHelper                                  
746  ContainerMetadataExtractor                              
753  ContextService                                          
1720  CoreSpotlightService                                    
2784  Cydia                                                   
1701  DPSubmissionService                                     
3293  DVIA-v2                                                 
1597  EscrowSecurityAlert                                     
1441  GeneralMapsWidget                                       
1719  Health                  
```

In general, Mach-O binaries that run on iOS devices can be quite large and contain a multitude of functions, data, strings, and more. As a result, it can be challenging to analyze them through static analysis alone. That's why starting with dynamic analysis, such as function tracing, can often be a more efficient approach. By using function tracing, we can more easily identify and track the various functions and operations within the binary as they're executed. 

To conduct function tracing on the DVIA-v2 application and track any changes made within the app on the device, we can utilize `frida-trace`. This dynamic analysis tool allows us to trace various functions and operations as they occur in real time. To begin function tracing, we can run the following command: `frida-trace -U -i "*jailbreak*" 3293`.
```
Instrumenting...                                                        
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest2TappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_6aa20fff.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_8217c5bc.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest1TappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_f34069fe.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest3TappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_ab2cd03f.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest5TappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_43991a7c.js"
_T07DVIA_v240ApplicationPatchingDetailsViewControllerC19jailbreakTestTappedyypF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v240ApplicationPatching_bdca7b85.js"
_T07DVIA_v232JailbreakDetectionViewControllerC14jailbreakTest3yyF: Auto-generated handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_f03b6d58.js"

Started tracing 7 functions. Press Ctrl+C to stop.                      
/* TID 0x303 */
 10819 ms _T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest1TappedyypF()

```

Clicking on the first jailbreak detection option in the DVIA-v2 application triggers the function `_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest1TappedyypF()`.

*__Dumping IPAs (iOS Applications)__*

Apple uses a Digital Rights Management (DRM) system called FairPlay to encrypt IPA (iOS application) files. FairPlay is designed to prevent unauthorized access and distribution of iOS apps by encrypting the binary executable, as well as any other supporting files or resources that make up the app package. 

However, in some cases, researchers may not have direct access to the application files and need to dump them. As IPA files are encrypted, the application files must also be dynamically dumped from memory to be accessed for static analysis. 

One way to dynamically dump the application from memory is to use Frida iOS Dump. By running the command `python3 dump.py DVIA-v2`, we can dump the DVIA-v2 application from memory.
```
libswiftObjectiveC.dylib.fid: 100%|██████████████████████████████████████████████████████████████████████████| 76.9k/76.9k [00:00<00:00, 470kB/s]
start dump /Applications/DVIA-v2.app/Frameworks/libswiftQuartzCore.dylib
libswiftQuartzCore.dylib.fid: 100%|██████████████████████████████████████████████████████████████████████████| 63.3k/63.3k [00:00<00:00, 378kB/s]
start dump /Applications/DVIA-v2.app/Frameworks/libswiftSwiftOnoneSupport.dylib
libswiftSwiftOnoneSupport.dylib.fid: 100%|████████████████████████████████████████████████████████████████████| 489k/489k [00:00<00:00, 2.80MB/s]
start dump /Applications/DVIA-v2.app/Frameworks/libswiftUIKit.dylib
libswiftUIKit.dylib.fid: 100%|█████████████████████████████████████████████████████████████████████████████████| 113k/113k [00:00<00:00, 674kB/s]
start dump /Applications/DVIA-v2.app/Frameworks/libswiftos.dylib
libswiftos.dylib.fid: 100%|██████████████████████████████████████████████████████████████████████████████████| 67.1k/67.1k [00:00<00:00, 410kB/s]
start dump /Applications/DVIA-v2.app/Frameworks/libswiftsimd.dylib
libswiftsimd.dylib.fid: 100%|█████████████████████████████████████████████████████████████████████████████████| 417k/417k [00:00<00:00, 1.90MB/s]
start dump /Applications/DVIA-v2.app/libswiftRemoteMirror.dylib
libswiftRemoteMirror.dylib.fid: 100%|█████████████████████████████████████████████████████████████████████████| 383k/383k [00:00<00:00, 2.75MB/s]
slider-bg@2x.png: 63.6MB [00:05, 13.0MB/s]                                                                                                       
0.00B [00:00, ?B/s]
Generating "DVIA-v2.ipa"
```

We now have access to extract and analyze the IPA for DVIA-v2.

*__Static Analysis__*

With a tool like IDA Pro, we can perform static analysis on the Mach-O binary that contains the jailbreak detection code. By having contextual information, such as which function to examine, we can avoid the tedious task of manually searching through the binary for the relevant code.

Assembly for: `_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest1TappedyypF()`

```powershell
SUB SP, SP, #0x60
STP X20, X19, [SP,#0x50+var_10]
STP X29, X30, [SP,#0x50+var_s0]
ADD X29, SP, #0x50
STUR X0, [X29,#var_18]
STUR X20, [X29,#var_20]
STR X20, [SP,#0x50+var_28] 
STR X0, [SP,#0x50+var_30] 
BL __T07DVIA_v213DVIAUtilitiesCMa 
ADRP X20, #_swift_isaMask_ptr@PAGE 
LDR X20, [X20,#_swift_isaMask_ptr@PAGEOFF] 
LDR X30, [X0,#0x58] 
LDR X8, [SP,#0x50+var_28]
LDR X9, [X8] 
LDR X20, [X20] 
AND X9, X9, X20 
LDR X9, [X9,#0x80] 
MOV X20, X8 
STR X0, [SP,#0x50+var_38] 
STR X30, [SP,#0x50+var_40]
BLR X9 
LDR X8, [SP,#0x50+var_28]
STR W0, [SP,#0x50+var_44] 
MOV X0, X8 ; id 
BL _objc_retain 
LDR X9, [SP,#0x50+var_40] 
LDR W10, [SP,#0x50+var_44]
AND W11, W10, #1 
STR X0, [SP,#0x50+var_50] 
MOV X0, X11 
MOV X1, X8 
LDR X20, [SP,#0x50+var_38] 
BLR X9 LDR X0, [SP,#0x50+var_30]
BL ___swift_destroy_boxed_opaque_existential_0 
LDP X29, X30, [SP,#0x50+var_s0] 
LDP X20, X19, [SP,#0x50+var_10] 
ADD SP, SP, #0x60 
RET
```

One important aspect to consider is the invocation of `BL __T07DVIA_v213DVIAUtilitiesCMa`. This call corresponds to the metadata accessor for the `DVIAUtilities` class, which is stored in a lazy cache and holds data about the device, such as whether it is jailbroken or not. 

When calling `__T07DVIA_v213DVIAUtilitiesCMa`, the specific metadata is stored on the stack and later loaded into the x8 register using `LDR X8, [SP,#0x50+var_28]`. Then, the x0 register is written to be cleared, and the contents of x8 are loaded into x0.

```powershell
LDR X8, [SP,#0x50+var_28]
STR W0, [SP,#0x50+var_44] 
MOV X0, X8 ; id 
```

*__Dynamic Analysis__*

To gain more information and context for our static analysis, we can use Frida to hook into the process and inject our own JavaScript code. By doing so, we can read specific register values and extract more information to inform our analysis.

Since I am not totally proficient in JavaScript, I would like to express my gratitude to **Phil Keeble** for sharing his code samples in his blog post on the same topic.

We can use the following JavaScript code to view the data in the x0 register at the time of execution to see what kind of check we are dealing with. Not only will this help us with making further dynamic bypasses, but we can also use this for writing a static bypass.

By utilizing the following JavaScript code, we can view the data in the x0 register during execution to gain insights into the type of jailbreak detection being employed. This information can be useful for both further dynamic bypasses and for crafting static bypass solutions.

```Powershell
var targetModule = 'DVIA-v2';
var addr = ptr(0x192c64);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                    console.log('At the address ' + addr + ' the value is currently ' + this.context.x0);
        },
    });
```

We can inject the following Frida script into the DVIA-v2 app by running the command `frida -U -l x0retval.js DVIA-v2`. Once executed, we can trigger the jailbreak detection test and observe the value in the x0 register, which is revealed to be 0x1. This indicates that a simple binary bit check is being performed, with valid jailbreak detection status represented by 0x1.

```
redacted@redacted:~$ frida -U -l x0retval.js DVIA-v2
     ____
    / _  |   Frida 16.0.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iOS Device 
                                                                                
[iOS Device::DVIA-v2 ]-> At the address 0x192c64 the value is currently 0x1
```

With this additional information, we can now write a simple static patch for the binary to always bypass the jailbreak detection. Here is an example:

```Powershell
0000000100192C64 LDR X8, [SP,#0x50+var_28] 
0000000100192C68 STR W0, [SP,#0x50+var_44] 
0000000100192C6C MOV W0, #0
```
__
However, __Phil Keeble's__ provided code allows us to conduct a dynamic bypass using the following JavaScript code with frida:

```Powershell
var targetModule = 'DVIA-v2';
var addr = ptr(0x192c64);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x0 == 0x01){
                    this.context.x0=0x00
                    console.log("Bypass Test1");
            }
        },
    });
```

*__Jailbreak Detection / Bypass Continued__*

In this section, we will delve into another aspect of the DVIA-v2 jailbreak detection/bypass challenge. We'll kick things off with another frida trace to determine the function that is invoked when we execute the test within the DVIA-v2 app.

```
Instrumenting...                                                        
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest2TappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_6aa20fff.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest4TappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_8217c5bc.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest1TappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_f34069fe.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest3TappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_ab2cd03f.js"
_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest5TappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_43991a7c.js"
_T07DVIA_v240ApplicationPatchingDetailsViewControllerC19jailbreakTestTappedyypF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v240ApplicationPatching_bdca7b85.js"
_T07DVIA_v232JailbreakDetectionViewControllerC14jailbreakTest3yyF: Loaded handler at "/home/redacted/__handlers__/DVIA_v2/_T07DVIA_v232JailbreakDetectionV_f03b6d58.js"
Started tracing 7 functions. Press Ctrl+C to stop.                      
/* TID 0x303 */
6457 ms  _T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest2TappedyypF()

```

We can see in this case, a similar function is called when we start the test.
`_T07DVIA_v232JailbreakDetectionViewControllerC20jailbreakTest2TappedyypF()`

*__Static Analysis__*

The function we are analyzing this time is much more extensive, as it implements multiple checks to detect jailbroken devices. The method used is to search for on-disk artifacts that would exist on a jailbroken device but not on a normal device. 

As an example in the function, we can see mentions of `/Applications/Cydia.app`.
```Powershell
MOV X29, X29 
BL _objc_retainAutoreleasedReturnValue 
ADRL X8, aApplicationsCy ; "/Applications/Cydia.app" 
MOV W9, #0x17 
MOV X1, X9 
MOV W2, #1 
STR X0, [SP,#0x620+var_178] 
MOV X0, X8 BL __T0S2SBp21_builtinStringLiteral_Bw17utf8CodeUnitCountBi1_7isASCIItcfC
```

It will then go on to check whether or not the application present on the device or not by using the Objective-C method `fileExistsAtPath:`.

```Powershell
ADRL X8, selRef_fileExistsAtPath_ 
LDR X1, [X8] ; "fileExistsAtPath:" 
LDR X0, [SP,#0x620+var_188] 
LDR X2, [SP,#0x620+var_178] 
STR X0, [SP,#0x620+var_190] 
MOV X0, X2 ; id 
LDR X2, [SP,#0x620+var_190] 
BL _objc_msgSend 
LDR X1, [SP,#0x620+var_188] 
STR W0, [SP,#0x620+var_194]
```

First, the selector `fileExistsAtPath:` is loaded into register `X1` using the `selRef_fileExistsAtPath_` label. Then, the arguments for the method are loaded into registers `X0` and `X2` from the stack, and the first argument is stored into a temporary stack variable at offset `var_190`.

Next, the `id` object (which represents the receiver of the method, i.e., the object on which the method is called) is moved into register `X0`. The second argument is then loaded into register `X2` from the temporary stack variable at offset `var_190`.

The Objective-C runtime function `_objc_msgSend` is then called with these three registers as arguments, which will invoke the `fileExistsAtPath:` method on the object in `X0`. The return value of the method (which will be a boolean indicating whether the file exists) is stored into a temporary stack variable at offset `CydiaExistCheck`.

The function will also check for `/Library/MobileSubstrate/MobileSubstrate.dylib` alongside multiple other artifacts. Essentially all you need to know if that for each check that occurs in the function, if the artifact if found then it will set a global variable to equal 0x1.

There are two methods to dynamically bypass this jailbreak detection. The first approach involves injecting code into the process and altering a register value that is utilized in the final check.

```Powershell
LDURB W8, [X29,#var_30] 
AND W8, W8, #1 
TBZ W8, #0, loc_100195DA8
```

The above assembly code is part of the final jailbreak detection check. To bypass it dynamically, we can use the same JavaScript snippet as before, but modify the address & register context to change the value of the W8 register to 0x0 during execution.

```Powershell
var targetModule = 'DVIA-v2';
var addr = ptr(0x1959d8);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x8 == 0x01){
                    this.context.x8=0x00
                    console.log("[X] Wrote 0x0 to register x8. Detection Bypassed.");
            }
        },
    });
```

The jailbreak detection was bypassed. 

```
     ____
    / _  |   Frida 16.0.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iOS Device 
                                                                                
[iOS Device::DVIA-v2 ]-> [X] Wrote 0x0 to register x8. Detection Bypassed.

```

The second method involves dynamically changing the register value for each artifact check that occurs. While not needed in this situation, it can be a useful technique to practice Javascript development and demonstrate the effectiveness of the idea.

Here is the address list that we need:
```Powershell
0x195330 
0x1953f8 
0x1954c0 
0x195588 
0x195650 
0x1957bC 
0x1959d0
```

Javascript code:

```Powershell
var targetModule = 'DVIA-v2';
var addresses = [
    0x195330,
    0x1953f8,
    0x1954c0,
    0x195588,
    0x195650,
    0x1957bc,
    0x1959d0
];

addresses.forEach(function(addr) {
    var moduleBase = Module.getBaseAddress(targetModule);
    var targetAddress = moduleBase.add(ptr(addr));

    Interceptor.attach(targetAddress, {
        onEnter: function(args) {
            if (this.context.x8 == 0x01) {
                this.context.x8 = 0x00
                console.log("[X] Wrote 0x0 to register x8. Detection Bypassed.");
            }
        },
    });
});
```
