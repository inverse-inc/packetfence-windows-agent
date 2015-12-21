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

class models:
	WINDOWSpeap = """<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
		<name></name>
		<SSIDConfig>
			<SSID>
				<hex></hex>
				<name></name>
			</SSID>
			<nonBroadcast>true</nonBroadcast>
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
											<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation>
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
			<nonBroadcast>true</nonBroadcast>
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
											<ServerNames></ServerNames>
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

class profile_xml:
    def __init__(self):
    #Download mobileconfig file, convert to str
        try:
            self.origin = urlopen("http://packetfence.org/profile.xml")
            self.data = self.origin.read()
    	except:
            msgbox("The program was unable to retrieve your wireless profile, please contact your local support", "Error")
            exit(0)

    def parse_profile(self):
    #Get data from the mobileconfig file, ssid_name, security type, password, profile name
        try:
            self.read_profile = readPlistFromString(self.data)
            self.ssid_name = self.read_profile["PayloadContent"][0]["SSID_STR"]
            self.sec_type = self.read_profile["PayloadContent"][0]["EncryptionType"]
            self.ssid_broadcast = self.read_profile["PayloadContent"][0]["HIDDEN_NETWORK"]
            self.wifi_key = ""
            return {'read_profile':self.read_profile, 'ssid_name':self.ssid_name, 'sec_type':self.sec_type, 'wifi_key':self.wifi_key, 'ssid_broadcast':self.ssid_broadcast}
        except:
            msgbox("The program cannot read the profile data, please contact your local support", "Error")
            exit(0)

    def create_profile(self):
    	#Search specific fields in wintemplate and remplace it
        self.root = configure_eap()['root']
        self.profile_name = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
        self.profile_name.text = self.parse_profile()['ssid_name']
        self.profile_ssid = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}SSID")[0]
        self.profile_ssid_name = self.profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
        self.profile_ssid_name.text = self.parse_profile()['ssid_name']
        self.ssid_hex = self.profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}hex")[0]
        self.ssid_hex.text = self.parse_profile()['ssid_name'].encode("hex")  
        self.is_ssid_broadcast = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}nonBroadcast")[0]
        if self.parse_profile()['ssid_broadcast'] == True:
            self.ssid_broadcast = 'true'
        elif self.parse_profile()['ssid_broadcast'] == False:
            self.ssid_broadcast = 'false'
        self.is_ssid_broadcast.text = self.ssid_broadcast
        self.sec_section = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security")[0]
        self.sec_auth = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}authentication")[0]
        self.onex = self.sec_section.findall("{http://www.microsoft.com/networking/OneX/v1}OneX")[0]
        self.eap_config = self.onex.findall("{http://www.microsoft.com/networking/OneX/v1}EAPConfig")[0]
        self.eap_host_config = self.eap_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")[0]
        if configure_eap()['eap_type'] == 13:
            self.eap_type_key = self.eap_host_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}Config/{http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1}Eap/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}EapType")[0]
            self.ca_to_trust = self.eap_type_key.findall("{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}ServerValidation/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}TrustedRootCA")[0]
            with open(configure_eap()['ca_file_binary'], 'rb') as self.read_bin_cert:
            	self.cert_object = self.read_bin_cert.read()
            self.read_bin_cert.close()
            self.my_cert = X509.load_cert_der_string(self.cert_object)
            self.ca_fingerprint = self.my_cert.get_fingerprint('sha1')
            if (len(self.ca_fingerprint) % 2 != 0):
            	self.ca_fingerprint = '0' + self.ca_fingerprint
            self.parse_ca_fingerprint = " ".join(self.ca_fingerprint[i:i+2] for i in range(0, len(self.ca_fingerprint), 2))
            self.ca_to_trust.text = self.parse_ca_fingerprint
	
        if self.parse_profile()['sec_type'] == "open":
            self.open_passcode = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyType")[0]
            self.open_passcode.text = "networkKey"
            self.sec_auth.text = "open"
        else:
            self.sec_auth.text = configure_eap()['sec_type']
        if self.parse_profile()['wifi_key'] != "":
            self.profile_wifi_key = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyMaterial")[0]
            self.profile_wifi_key.text = self.parse_profile()['wifi_key']

        #Get the file to temp folder(right to write)
        self.profile_file = path.join(local_computer().temp_path, "template-out.xml")

        self.profile_value = tostring(self.root) 
        return {'profile_value':self.profile_value, 'profile_file':self.profile_file}

class local_computer:
    def __init__(self):
    	#Get temp folder path
        self.temp_path = getenv("tmp")

    def install_profile(self):
        #Create new file with data 
    	with open(profile_xml().create_profile()['profile_file'], "w") as self.configfile:
            self.configfile.write(profile_xml().create_profile()['profile_value'])

        #Win command to add wifi profile
        try:
            self.netsh_command = "netsh wlan add profile filename="
            Popen(self.netsh_command+profile_xml().create_profile()['profile_file'], shell=True)
            self.success_msg = "The profile was successfully added to the machine, please select your newly added profile "+profile_xml().parse_profile()['ssid_name']+" in the Wifi networks."
            msgbox(self.success_msg, "Information")
        except:
            msgbox("The profile could not be added to your machine, please contact your local support.", "Error")
            exit(0)
 
    def cleanup(self):		
        #Remove files
        self.delete_file = "del /F "
        Popen(self.delete_file+profile_xml().create_profile()['profile_file'], shell=True)
        if configure_eap()['eap_type'] == 13:
            Popen(self.delete_file+configure_eap()['cert_p12'], shell=True)
            Popen(self.delete_file+configure_eap()['ca_file_binary'], shell=True)
        exit(0)

def configure_eap():
    #Security of the SSID
    user_cert_decode = ""
    root = ""
    if "EAPClientConfiguration" in profile_xml().data:
        user_auth = profile_xml().parse_profile()['read_profile']["PayloadContent"][0]["EAPClientConfiguration"]["UserName"]
        if user_auth == "":
            user_auth = "certificate"
        eap_type = profile_xml().parse_profile()['read_profile']["PayloadContent"][0]["EAPClientConfiguration"]["AcceptEAPTypes"][0]
        if eap_type == 25:
            root = fromstring(models().WINDOWSpeap)
            encryption = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
            sec_type = "WPA2"
            encryption.text = "AES"
            return {'root':root, 'eap_type':eap_type, 'sec_type':sec_type}
        elif eap_type == 13:
            root = fromstring(models().WINDOWStls)
            payloads = [a for a in profile_xml().parse_profile()['read_profile']["PayloadContent"] if "PayloadType" in a]
            for type in payloads:
                if type["PayloadType"] == "com.apple.security.pkcs12":
                    try:
                        cert_p12 = path.join(local_computer().temp_path, user_auth+".p12")
                        print cert_p12
                        user_cert = type["PayloadContent"]
                        user_cert_decode = b64decode(str(user_cert))
                        print user_cert_decode
                        tmp_cert = open(cert_p12, 'wb')
                        tmp_cert.write(user_cert_decode)
                        tmp_cert.close()
                    except:
                        msgbox("Your personal certificate file could not be generated, please contact your local support.","Error")
                        exit(0)
                elif type["PayloadType"] == "com.apple.security.root":
                    try:
                        ca_name = type["PayloadCertificateFileName"]
                        ca_file_binary = path.join(local_computer().temp_path, ca_name+".cer")
                        ca_cert = type["PayloadContent"]
                        ca_cert_decode = b64decode(str(ca_cert))
                        b64decode(str(ca_cert))
                        tmp_ca = open(ca_file_binary, 'wb')
                        tmp_ca.write(ca_cert_decode)
                        tmp_ca.close()
                    except:
                        msgbox("The certificate of Authority file could not be generated, please contact your local support.","Error")
                        exit(0)
            encryption = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
            sec_type = "WPA2"
            encryption.text = "AES"
            return {'root':root, 'sec_type':sec_type, 'eap_type':eap_type, 'ca_file_binary':ca_file_binary, 'cert_p12':cert_p12, 'user_cert_decode':user_cert_decode}
    else:
        root = fromstring(models().WINDOWSopen)
        wifi_key = profile_xml().parse_profile()['read_profile']["PayloadContent"][0]["Password"]
        encryption = root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
        if profile_xml().parse_profile()['sec_type'] == "WEP":
            sec_type = "open"
            encryption.text = "WEP"
        elif profile_xml().parse_profile()['sec_type'] == "WPA":
            sec_type = "WPA2PSK"
            encryption.text = "AES"
        else:
            sec_type = "open"
            encryption.text = "none"
        return {'sec_type':sec_type, 'root':root}

class certificate:
    def	install_certificate(self):
        #Add certificate to windows
        if configure_eap()['user_cert_decode'] != "":
            self.bad_cert_password = True
            while self.bad_cert_password:
                self.bad_cert_password = False
                self.cert_password = passwordbox("Please enter your certificate password", "Certificate Password")
                self.option_certutil = " -f -user -p "
                self.format_certutil = " -importpfx "
                self.certutil_command = self.option_certutil+self.cert_password+self.format_certutil
                self.certutil = "C:\Windows\System32\certutil.exe"
                self.si = STARTUPINFO()
                self.si.dwFlags |= STARTF_USESHOWWINDOW
                self.add_cert = Popen(self.certutil+self.certutil_command+configure_eap()['cert_p12'], stdout=PIPE, stdin=PIPE, stderr=PIPE, startupinfo=self.si)
                self.cert_code = self.add_cert.communicate()[0]
                self.return_cert = self.add_cert.returncode
                if self.return_cert == 0:
                	msgbox("Your certificate was successfully installed, please press OK to continue.", "Success")
                elif self.return_cert == -2147024810:
                    msgbox ("The password you filled in was wrong, please try again", "BadPassword")
                    self.bad_cert_password = True
                else:
                    msgbox("Your certificate could not be installed on your machine, please contact your local support.", "Error")
                    exit(0)
	
    	#add CA to the machine
        try:
            self.add_ca = " -addstore -user \"Root\" "
            Popen(certutil+self.add_ca+configure_eap()['ca_file_binary'], shell=True)
        except:
            msgbox("The Certificate of Authority could not be installed on your machine, please contact your local support.", "Error")
            exit(0)	
    
class MainPanel(wx.Panel):

	def ExecuteOperations(self, e):
		if configure_eap()['eap_type'] == 13:
			certificate().install_certificate()
		local_computer().install_profile()
		local_computer().cleanup()
		
	def __init__(self, parent):
		"""Constructor"""
		wx.Panel.__init__(self, parent=parent)
		self.frame = parent
 
		sizer = wx.BoxSizer(wx.VERTICAL)
		hSizer = wx.BoxSizer(wx.HORIZONTAL)
 
		cbtn = wx.Button(self, label='Configure', pos=(196, 144))
		cbtn.Bind(wx.EVT_BUTTON, self.ExecuteOperations)
		
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
