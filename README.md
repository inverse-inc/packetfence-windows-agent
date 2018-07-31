# PacketFence Windows Agent in Golang

Windows app for the auto-configuration of wired and wireless networks with PacketFence

## Getting Started

Follow the following instructions to get your PacketFence agent running.


### Set up

Compiled with Go Programming Language amd64 version 1.10.1
To set up your Go environment, see [Getting Started](http://golang.org/doc/install.html).

Then set up your environment variables :
 * Search "env" in Windows and click Enter
 * Click on 'Environment Variables'
 * In System Variables, select Path and click 'Edit'
 * Click on 'New', and add `C:\\Go\\src`, `C:\\Go\\bin`, and the directory of the PacketFence Windows agent (usually `C:\Users\[UserName]\Go\bin`)

===========

Files used :
parse.go, rsrc.syso

===========

#### Create the manifest `packetfence-windows-agent.exe.manifest`

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly
	xmlns="urn:schemas-microsoft-com:asm.v1"
	manifestVersion="1.0"
	xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
	<assemblyIdentity
		version="1.0.0.0"
		processorArchitecture="*"
		name="packetfence-windows-agent.exe"
		type="win32"
	/>
	<dependency>
		<dependentAssembly>
			<assemblyIdentity
				type="win32"
				name="Microsoft.Windows.Common-Controls"
				version="6.0.0.0"
				processorArchitecture="*"
				publicKeyToken="6595b64144ccf1df"
				language="*"
			/>
		</dependentAssembly>
	</dependency>
	<asmv3:application>
		<asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
			<dpiAware>true</dpiAware>
		</asmv3:windowsSettings>
	</asmv3:application>
	<description>PacketFence Provisioner</description>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
```

Then compile the manifest using the [rsrc tool] (https://github.com/akavel/rsrc) :

  ```
  go get github.com/akavel/rsrc  
  rsrc -manifest packetfence-windows-agent.exe.manifest -o rsrc.syso
  ```

##### Build app

In the directory containing `parse.go`, run :

	go build

To get rid of the cmd window, run :

	go build -ldflags="-H windowsgui"

##### Run app

To run the application, type :

	pf.exe
