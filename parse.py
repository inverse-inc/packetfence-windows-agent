#Python program for autoconfig wireless network on windows 7/8
from os import path, getenv
from urllib2 import urlopen
from xml.etree.ElementTree import fromstring, tostring
from plistlib import readPlistFromString
from re import search
from base64 import b64decode
from sys import exit
from subprocess import Popen, PIPE, STARTF_USESHOWWINDOW, STARTUPINFO
from easygui import msgbox, passwordbox
from M2Crypto import X509
from imageBG import bgimg
import wx

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
					<authMode>user</authMode> 
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
		origin = urlopen("http://packetfence.org/profile.xml")
		data = origin.read()
	except:
		msgbox("The program was unable to retrieve your wireless profile, please contact your IT Support", "Error")
		exit(0)
		
		
	
	#Get temp folder path user path
	temp_path = getenv("tmp")
	user_logged = search(r"(.*)\\AppData", temp_path)
	userlocal = user_logged.group(1)
	
	#Get data from the mobileconfig file, ssid_nameame, security type, password, profile name, certificate
	try:
		read_profile = readPlistFromString(data)
		ssid_name = read_profile["PayloadContent"][0]["SSID_STR"]
		sec_type = read_profile["PayloadContent"][0]["EncryptionType"]
		wifi_key = ""
	except:
		msgbox("The program cannot read the profile data, please contact your IT Support", "Error")
		exit(0)
		
	#Security of the SSID
	user_cert_decode = ""
	if "EAPClientConfiguration" in data:
		user_auth = read_profile["PayloadContent"][0]["EAPClientConfiguration"]["UserName"]
		eap_type = read_profile["PayloadContent"][0]["EAPClientConfiguration"]["AcceptEAPTypes"][0]
		if eap_type == 25:
			root = fromstring(WINDOWSpeap)
		elif eap_type == 13:
			root = fromstring(WINDOWStls)
			try:
				cert_p12 = path.join(temp_path, user_auth+".p12")
				user_cert = read_profile["PayloadContent"][1]["PayloadContent"] 
				user_cert_decode = b64decode(str(user_cert))
				tmp_cert = open(cert_p12, 'wb')
				tmp_cert.write(user_cert_decode)
				tmp_cert.close()
			except:
				msgbox("Your personal certificate file could not be generated, please contact your IT support.","Error")
				exit(0)
			try:
				ca_name = read_profile["PayloadContent"][2]["PayloadCertificateFileName"]
				ca_file_binary = path.join(temp_path, ca_name+".cer")
				ca_cert = read_profile["PayloadContent"][2]["PayloadContent"]
				ca_cert_decode = b64decode(str(ca_cert))
				b64decode(str(ca_cert))
				tmp_ca = open(ca_file_binary, 'wb')
				tmp_ca.write(ca_cert_decode)
				tmp_ca.close()
			except:
				msgbox("The certificate of Authority file could not be generated, please contact your IT support.","Error")
				exit(0)
		encryption = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
		sec_type = "WPA2"
		encryption.text = "AES"
	else:
		root = fromstring(WINDOWSopen)
		wifi_key = read_profile["PayloadContent"][0]["Password"]
		encryption = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
		if sec_type == "WEP":
			sec_type = "open"
			encryption.text = "WEP"
		elif sec_type == "WPA":
			sec_type = "WPA2PSK"
			encryption.text = "AES"
		else:
			sec_type = "open"
			encryption.text = "none"

	#Search specific fields in wintemplate and remplace it
	profile_name = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
	profile_name.text = ssid_name
	profile_ssid = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}SSID")[0]
	profile_ssid_name = profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
	profile_ssid_name.text = ssid_name
	ssid_hex = profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}hex")[0]
	ssid_hex.text = ssid_name.encode("hex")  
	sec_section = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security")[0]
	sec_auth = sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}authentication")[0]
	onex = sec_section.findall("{http://www.microsoft.com/networking/OneX/v1}OneX")[0]
	eap_config = onex.findall("{http://www.microsoft.com/networking/OneX/v1}EAPConfig")[0]
	eap_host_config = eap_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")[0]
	if eap_type == 13:
		eap_type_key = eap_host_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}Config/{http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1}Eap/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}EapType")[0]
		ca_to_trust = eap_type_key.findall("{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}ServerValidation/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}TrustedRootCA")[0]
		with open(ca_file_binary, 'rb') as read_bin_cert:
			cert_object = read_bin_cert.read()
		read_bin_cert.close()
		my_cert = X509.load_cert_der_string(cert_object)
		ca_fingerprint = my_cert.get_fingerprint('sha1')
		parse_ca_fingerprint = " ".join(ca_fingerprint[i:i+2] for i in range(0, len(ca_fingerprint), 2))
		ca_to_trust.text = parse_ca_fingerprint
	
	if sec_type == "open":
		open_passcode = sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyType")[0]
		open_passcode.text = "networkKey"
		sec_auth.text = "open"
	else:
		sec_auth.text = sec_type
	if wifi_key != "":
		profile_wifi_key = sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyMaterial")[0]
		profile_wifi_key.text = wifi_key
		
	#Get the file to temp folder(right to write)
	profile_file = path.join(temp_path, "template-out.xml")

	profile_value = tostring(root) 
	
	#Add certificate to windows
	if user_cert_decode != "":
		bad_cert_password = True
		while bad_cert_password:
			bad_cert_password = False
			cert_password = passwordbox("Please enter your certificate password", "Certificate Password")
			option_certutil = " -f -user -p "
			format_certutil = " -importpfx "
			certutil_command = option_certutil+cert_password+format_certutil
			certutil = "C:\Windows\System32\certutil.exe"
			si = STARTUPINFO()
			si.dwFlags |= STARTF_USESHOWWINDOW
			add_cert = Popen(certutil+certutil_command+cert_p12, stdout=PIPE, stdin=PIPE, stderr=PIPE, startupinfo=si)
			cert_code = add_cert.communicate()[0]
			return_cert = add_cert.returncode
			if return_cert == 0:
				msgbox("Your certificate was successfully installed, please press OK to continue.", "Success")
			elif return_cert == -2147024810:
				msgbox ("The password you filled in was wrong, please try again", "BadPassword")
				bad_cert_password = True
			else:
				msgbox("Your certificate could not be installed on your machine, please contact your IT support.", "Error")
				exit(0)
	
	#add CA to the machine
	try:
		add_ca = " -addstore -user \"Root\" "
		Popen(certutil+add_ca+ca_file_binary, shell=True)
	except:
		msgbox("The Certificate of Authority could not be installed on your machine, please contact your IT support.", "Error")
		exit(0)	
	
	#Create new file with data 
	with open(profile_file, "w") as configfile:
		configfile.write(profile_value)

	#Win command to add wifi profile
	try:
		netsh_command = "netsh wlan add profile filename="
		Popen(netsh_command+profile_file, shell=True)
		success_msg = "The profile was successfully added to the machine, please select your newly added profile "+ssid_name+" in the Wifi networks."
		msgbox(success_msg, "Information")
	except:
		msgbox("The profile could not be added to your machine, please contact your IT support.", "Error")
		exit(0)
		
	#Remove files
	delete_file = "del /F "
	Popen(delete_file+profile_file, shell=True)
	if user_cert_decode != "":
		Popen(delete_file+cert_p12, shell=True)
		Popen(delete_file+ca_file_binary, shell=True)
	exit(0)
		
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