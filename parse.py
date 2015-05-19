#Python program for autoconfig wireless network on windows 7/8
import os
import urllib2 as U2
import xml.etree.ElementTree as ET
import plistlib as PL
import wx
import re
import base64
import sys
import easygui
from imageBG import bgimg

def parsing():
	WINDOWSpeap = """<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
		<name></name>
		<SSIDConfig>
			<SSID>
				<hex></hex>
				<name></name>
			</SSID>
			<nonBroadcast>false</nonBroadcast>
		</SSIDConfig>
		<connectionType>ESS</connectionType>
		<connectionMode>auto</connectionMode>
		<autoSwitch>false</autoSwitch>
		<MSM>
			<security>
				<authEncryption>
					<authentication>WPA2</authentication>
					<encryption>AES</encryption>
					<useOneX>true</useOneX>
				</authEncryption>
				<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
					<cacheUserData>true</cacheUserData>
					<authMode>user</authMode>
					<EAPConfig>
						<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
							<EapMethod>
								<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
								<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
								<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
								<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
							</EapMethod>
							<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
								<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
									<Type>25</Type>
									<EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
										<ServerValidation>
											<DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
											<ServerNames></ServerNames>
											<TrustedRootCA>df 72 a6 7b b9 f5 9a 61 96 68 f5 b8 da ca 36 76 21 84 98 ec </TrustedRootCA>
										</ServerValidation>
										<FastReconnect>true</FastReconnect>
										<InnerEapOptional>false</InnerEapOptional>
										<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
											<Type>26</Type>
											<EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
												<UseWinLogonCredentials>false</UseWinLogonCredentials>
											</EapType>
										</Eap>
										<EnableQuarantineChecks>false</EnableQuarantineChecks>
										<RequireCryptoBinding>false</RequireCryptoBinding>
										<PeapExtensions>
											<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">true</PerformServerValidation>
											<AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName>
											<PeapExtensionsV2 xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">
												<AllowPromptingWhenServerCANotFound xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3">true</AllowPromptingWhenServerCANotFound>
											</PeapExtensionsV2>
										</PeapExtensions>
									</EapType>
								</Eap>
							</Config>
						</EapHostConfig>
					</EAPConfig>
				</OneX>
			</security>
		</MSM>
	</WLANProfile>
	"""
	WINDOWStls = """<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
		<name></name>
		<SSIDConfig>
			<SSID>
				<hex></hex>
				<name></name>
			</SSID>
			<nonBroadcast>false</nonBroadcast>
		</SSIDConfig>
		<connectionType>ESS</connectionType>
		<connectionMode>auto</connectionMode>
		<autoSwitch>false</autoSwitch>
		<MSM>
			<security> 
				<authEncryption>
					<authentication>WPA2</authentication>
					<encryption>AES</encryption>
					<useOneX>true</useOneX>
					<FIPSMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v2">false</FIPSMode>
				</authEncryption>
				<PMKCacheMode>enabled</PMKCacheMode>
				<PMKCacheTTL>720</PMKCacheTTL>
				<PMKCacheSize>128</PMKCacheSize>
				<preAuthMode>disabled</preAuthMode>
				<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
					<cacheUserData>true</cacheUserData>
					<authMode>machineOrUser</authMode> 
					<EAPConfig>
						<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
							<EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
								<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
								<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
								<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
							</EapMethod>
							<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
								<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
									<Type>13</Type>
									<EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
										<CredentialsSource>
											<CertificateStore>
												<SimpleCertSelection>true</SimpleCertSelection>
											</CertificateStore>
										</CredentialsSource>
										<ServerValidation>
											<DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
											<ServerNames/>
											<TrustedRootCA></TrustedRootCA>
										</ServerValidation>
										<DifferentUsername>false</DifferentUsername>
										<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
										<AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">false</AcceptServerName>
										</EapType>
								</Eap>
							</Config>
						</EapHostConfig>
					</EAPConfig> 
				</OneX> 
			</security> 
		</MSM> 
	</WLANProfile>
	"""
	WINDOWSopen = """<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
		<name></name>
		<SSIDConfig>
			<SSID>
				<hex></hex>
				<name></name>
			</SSID>
			<nonBroadcast>true</nonBroadcast>
		</SSIDConfig>
		<connectionType>ESS</connectionType>
		<connectionMode>manual</connectionMode>
		<autoSwitch>false</autoSwitch>
		<MSM>
			<security>
				<authEncryption>
					<authentication>WPA2PSK</authentication>
					<encryption>AES</encryption>
					<useOneX>false</useOneX>
					<FIPSMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v2">false</FIPSMode>
				</authEncryption>
				<sharedKey>
					<keyType>passPhrase</keyType>
					<protected>false</protected>
					<keyMaterial></keyMaterial>
				</sharedKey>
			</security>
		</MSM>
	</WLANProfile>
	"""
	
	#Download mobileconfig file, convert to str
	try:
		origin = U2.urlopen("http://packetfence.org/wireless-profile.mobileconfig") 
		data = origin.read()
	except:
		easygui.msgbox("The program was unable to retrieve your wireless profile, please contact your IT Support", "Error")
		sys.exit(0)
		
		
	
	#Get temp folder path user path
	pa = os.getenv("tmp")
	reun = re.search(r"(.*)\\AppData", pa)
	userlocal = reun.group(1)
	
	#Get data from the mobileconfig file, ssidname, security type, password, profile name, certificate
	try:
		r = PL.readPlistFromString(data)
		ssidn = r["PayloadContent"][0]["SSID_STR"]
		sec = r["PayloadContent"][0]["EncryptionType"]
		profile = r["PayloadDisplayName"]
		passk = ""
	except:
		easygui.msgbox("The program cannot read the profile data, please contact your IT Support", "Error")
		sys.exit(0)
		
	#Security of the SSID
	ddata = ""
	if "EAPClientConfiguration" in data:
		un = r["PayloadContent"][0]["EAPClientConfiguration"]["UserName"]
		eap = r["PayloadContent"][0]["EAPClientConfiguration"]["AcceptEAPTypes"][0]
		if eap == 25:
			root = ET.fromstring(WINDOWSpeap)
		elif eap == 13:
			root = ET.fromstring(WINDOWStls)
			try:
				certp12 = os.path.join(pa, un+".p12")
				cdata = r["PayloadContent"][1]["PayloadContent"] 
				ddata = base64.b64decode(str(cdata))
				tmpcer = open(certp12, 'wb')
				tmpcer.write(ddata)
				tmpcer.close()
			except:
				easygui.msgbox("Your personal certificate file could not be generated, please contact your IT support.","Error")
				sys.exit(0)
			try:
				caname = r["PayloadContent"][2]["PayloadCertificateFileName"]
				reca = re.search(r"(.*)\.", caname)
				myca = reca.group(1)
				cabin = os.path.join(pa, myca+".cer")
				cadata = r["PayloadContent"][2]["PayloadContent"]
				caddata = base64.b64decode(str(cadata))
				tmpca = open(cabin, 'wb')
				tmpca.write(caddata)
				tmpca.close()
			except:
				easygui.msgbox("The certificate of Authority file could not be generated, please contact your IT support.","Error")
				sys.exit(0)
		enc = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
		sec = "WPA2"
		enc.text = "AES"
	else:
		root = ET.fromstring(WINDOWSopen)
		passk = r["PayloadContent"][0]["Password"]
		enc = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
		if sec == "WEP":
			sec = "open"
			enc.text = "WEP"
		elif sec == "WPA":
			sec = "WPA2PSK"
			enc.text = "AES"
		else:
			sec = "open"
			enc.text = "none"

	#Search specific fields in wintemplate and remplace it
	nname = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
	nname.text = profile
	ssid = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}SSID")[0]
	name = ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
	name.text = ssidn
	hexname = ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}hex")[0]
	hexname.text = ssidn.encode("hex")  
	secf = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security")[0]
	sect = secf.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}authentication")[0]
	onex = secf.findall("{http://www.microsoft.com/networking/OneX/v1}OneX")[0]
	eapc = onex.findall("{http://www.microsoft.com/networking/OneX/v1}EAPConfig")[0]
	eaphc = eapc.findall("{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")[0]
	eapt = eaphc.findall("{http://www.microsoft.com/provisioning/EapHostConfig}EapMethod/{http://www.microsoft.com/provisioning/EapCommon}Type")[0]
	if eap == 13:
		eapty = eaphc.findall("{http://www.microsoft.com/provisioning/EapHostConfig}Config/{http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1}Eap/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}EapType")[0]
		trustedca = eapty.findall("{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}ServerValidation/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}TrustedRootCA")[0]
		fingerprint = r["cafingerprint"]
		trustedca.text = fingca
	
	if sec == "open":
		passt = secf.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyType")[0]
		passt.text = "networkKey"
		sect.text = "open"
	else:
		sect.text = sec
	if passk != "":
		passw = secf.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyMaterial")[0]
		passw.text = passk
		
	#Get the file to temp folder(right to write)
	file = os.path.join(pa, "template-out.xml")

	config = ET.tostring(root) 
	
	#Add certificate to windows
	if ddata != "":
		badpw = True
		while badpw:
			badpw = False
			userpw = easygui.passwordbox("Please enter your certificate password", "Certificate Password")
			cmd = " -f -user -p "
			cmd2 = " -importpfx "
			cmdcert = cmd+userpw+cmd2
			certutil = "C:\Windows\System32\certutil.exe"
			addcert = os.system(certutil+cmdcert+certp12)
			if addcert == 0:
				easygui.msgbox("Your certificate was successfully installed, please press OK to continue.", "Success")
			elif addcert == -2147024810:
				easygui.msgbox ("The password you filled in was wrong, please try again", "BadPassword")
				badpw = True
			else:
				easygui.msgbox("Your certificate could not be installed on your machine, please contact your IT support.", "Error")
				sys.exit(0)
	
	#add CA to the machine
	try:
		command = " -addstore -user \"Root\" "
		os.system(certutil+command+cabin)
	except:
		easygui.msgbox("The CA could not be installed on your machine, please contact your IT support.", "Error")
		sys.exit(0)	
	
	#Create new file with data 
	with open(file, "w") as configfile:
		configfile.write(config)

	#Win command to add wifi profile
	try:
		net = "netsh wlan add profile filename="
		os.system(net+file)
		#print ht
		#ans = True
		#while ans:
		#	ans = False
		#	ht = os.system(net+file)
		#	print ht
		#	if ht == 0:	
		successmsg = "The profile was successfully added to the machine, please select your newly added profile "+profile+" in the Wifi networks."
		easygui.msgbox(successmsg, "Information")
	except:
		easygui.msgbox("The profile could not be added to your machine, please contact your IT support.", "Error")
		sys.exit(0)
		
	#Remove files
	df = "del /F "
	os.system(df+file)
	if ddata != "":
		os.system(df+certp12)
		os.system(df+cabin)
	sys.exit(0)
		
class MainPanel(wx.Panel):
 
	def OnClose(self, e):
		parsing()
		
	def __init__(self, parent):
		"""Constructor"""
		wx.Panel.__init__(self, parent=parent)
		self.frame = parent
 
		sizer = wx.BoxSizer(wx.VERTICAL)
		hSizer = wx.BoxSizer(wx.HORIZONTAL)
 
		cbtn = wx.Button(self, label='Configure', pos=(196, 144))
		cbtn.Bind(wx.EVT_BUTTON, self.OnClose)
		
		self.SetSizer(hSizer)
		self.Bind(wx.EVT_ERASE_BACKGROUND, self.OnEraseBackground)		
				
	def OnEraseBackground(self, evt):
		"""
		Background Image
		"""
		dc = evt.GetDC()
 
		if not dc:
			dc = wx.ClientDC(self)
			rect = self.GetUpdateRegion().GetBox()
			dc.SetClippingRect(rect)
		dc.Clear()
		img = bgimg.GetImage()
		bmp = img.ConvertToBitmap()
		dc.DrawBitmap(bmp, 0, 0)
 
 
########################################################################
class MainFrame(wx.Frame):
 
	def __init__(self):
		wx.Frame.__init__(self, None, size=(480,318))
		panel = MainPanel(self)        
		self.Center()


		
########################################################################
class Main(wx.App):
 
	def __init__(self, redirect=False, filename=None):
		wx.App.__init__(self, redirect, filename)
		dlg = MainFrame()
		dlg.Show()
 
if __name__ == "__main__":
	app = Main()
	app.MainLoop()

		
#  Copyright (C) 2005-2015 Inverse inc.
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
#  USA.
