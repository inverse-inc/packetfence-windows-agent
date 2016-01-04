#Python program for autoconfig wireless network on windows 7/8
from os import path, getenv
import requests
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

class Models:
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

class Profile(object):
    read_profile = ""
    ssid_name = ""
    sec_type = ""
    ssid_broadcast = ""
    wifi_key = ""
    data = ""
    readp = ""
    user_auth = ""
    eap_type = ""
    def download(self):
    #Download mobileconfig file, convert to str
        try:
            self.origin = requests.get("http://packetfence.org/profile.xml")
            P.data = self.origin.text
    	except:
            msgbox("The program was unable to retrieve your wireless profile, please contact your local support", "Error")
            exit(0)


    def read_profile(self, data):
    #converting the download to object
        try:
            P.readp = readPlistFromString(P.data)
        except:
            msgbox("The program could not parse the profile, please contact your local support", "Error")
            exit(0)

    def parse_profile(self, readp):
    #Get data from the mobileconfig file, ssid_name, security type, password, profile name
        try:
            self.read_profile = P.readp
            self.ssid_name = self.read_profile["PayloadContent"][0]["SSID_STR"]
            self.sec_type = self.read_profile["PayloadContent"][0]["EncryptionType"]
            self.ssid_broadcast = self.read_profile["PayloadContent"][0]["HIDDEN_NETWORK"]
            if "EAPClientConfiguration" in P.readp:
                self.user_auth = self.read_profile["PayloadContent"][0]["EAPClientConfiguration"]["UserName"]
                if self.user_auth == "":
                    self.user_auth = "certificate"
                self.eap_type = self.read_profile["PayloadContent"][0]["EAPClientConfiguration"]["AcceptEAPTypes"][0]

        except:
            msgbox("The program cannot read the profile data, please contact your local support", "Error")
            exit(0)

class Configure(object):
    root = ""
    profile_file = ""
    profile_value = ""
    ca_file_binary = ""
    cert_p12 = ""
    def configure_eap(self, data):
        #Security of the SSID
        self.user_cert_decode = ""
        if P.eap_type == 25:
            C.root = fromstring(M.WINDOWSpeap)
            self.encryption = C.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
            P.sec_type = "WPA2"
            self.encryption.text = "AES"
            #return {'root':root, 'eap_type':eap_type, 'sec_type':sec_type}
        elif P.eap_type == 13:
            C.root = fromstring(M.WINDOWStls)
            self.payloads = [a for a in P.readp["PayloadContent"] if "PayloadType" in a]
            for type in self.payloads:
                if type["PayloadType"] == "com.apple.security.pkcs12":
                    try:
                        self.cert_p12 = path.join(LC.temp_path, P.user_auth+".p12")
                        self.user_cert = type["PayloadContent"]
                        self.user_cert_decode = b64decode(str(self.user_cert))
                        self.tmp_cert = open(self.cert_p12, 'wb')
                        self.tmp_cert.write(self.user_cert_decode)
                        self.tmp_cert.close()
                    except:
                        msgbox("Your personal certificate file could not be generated, please contact your local support.","Error")
                        exit(0)
                elif type["PayloadType"] == "com.apple.security.root":
                    try:
                        self.ca_name = type["PayloadCertificateFileName"]
                        self.ca_file_binary = path.join(LC.temp_path, self.ca_name+".cer")
                        self.ca_cert = type["PayloadContent"]
                        self.ca_cert_decode = b64decode(str(self.ca_cert))
                        self.tmp_ca = open(self.ca_file_binary, 'wb')
                        self.tmp_ca.write(self.ca_cert_decode)
                        self.tmp_ca.close()
                    except:
                        msgbox("The certificate of Authority file could not be generated, please contact your local support.","Error")
                        exit(0)
            self.encryption = C.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
            P.sec_type = "WPA2"
            self.encryption.text = "AES"
            #return {'root':root, 'sec_type':sec_type, 'eap_type':eap_type, 'ca_file_binary':ca_file_binary, 'cert_p12':cert_p12, 'user_cert_decode':user_cert_decode}
        else:
            C.root = fromstring(M.WINDOWSopen)
            P.wifi_key = P.readp["PayloadContent"][0]["Password"]
            self.encryption = C.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security/{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}encryption")[0]
            if P.sec_type == "WEP":
                P.sec_type = "open"
                self.encryption.text = "WEP"
            elif P.sec_type == "WPA":
                P.sec_type = "WPA2PSK"
                self.encryption.text = "AES"
            else:
                P.sec_type = "open"
                self.encryption.text = "none"
            #return {'sec_type':sec_type, 'root':root}


    def create_profile(self):
    	#Search specific fields in wintemplate and remplace it
        self.root = C.root
        self.profile_name = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
        self.profile_name.text = P.ssid_name
        self.profile_ssid = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}SSID")[0]
        self.profile_ssid_name = self.profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}name")[0]
        self.profile_ssid_name.text = P.ssid_name
        self.ssid_hex = self.profile_ssid.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}hex")[0]
        self.ssid_hex.text = P.ssid_name.encode("hex")  
        self.is_ssid_broadcast = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}SSIDConfig/{http://www.microsoft.com/networking/WLAN/profile/v1}nonBroadcast")[0]
        if P.ssid_broadcast == True:
            self.ssid_broadcast = 'true'
        elif P.ssid_broadcast == False:
            self.ssid_broadcast = 'false'
        self.is_ssid_broadcast.text = self.ssid_broadcast
        self.sec_section = self.root.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}MSM/{http://www.microsoft.com/networking/WLAN/profile/v1}security")[0]
        self.sec_auth = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}authEncryption/{http://www.microsoft.com/networking/WLAN/profile/v1}authentication")[0]
        self.onex = self.sec_section.findall("{http://www.microsoft.com/networking/OneX/v1}OneX")[0]
        self.eap_config = self.onex.findall("{http://www.microsoft.com/networking/OneX/v1}EAPConfig")[0]
        self.eap_host_config = self.eap_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")[0]
        if P.eap_type == 13:
            self.eap_type_key = self.eap_host_config.findall("{http://www.microsoft.com/provisioning/EapHostConfig}Config/{http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1}Eap/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}EapType")[0]
            self.ca_to_trust = self.eap_type_key.findall("{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}ServerValidation/{http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1}TrustedRootCA")[0]
            with open(C.ca_file_binary, 'rb') as self.read_bin_cert:
            	self.cert_object = self.read_bin_cert.read()
            self.read_bin_cert.close()
            self.my_cert = X509.load_cert_der_string(self.cert_object)
            self.ca_fingerprint = self.my_cert.get_fingerprint('sha1')
            if (len(self.ca_fingerprint) % 2 != 0):
            	self.ca_fingerprint = '0' + self.ca_fingerprint
            self.parse_ca_fingerprint = " ".join(self.ca_fingerprint[i:i+2] for i in range(0, len(self.ca_fingerprint), 2))
            self.ca_to_trust.text = self.parse_ca_fingerprint
	
        if P.sec_type == "open":
            self.open_passcode = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyType")[0]
            self.open_passcode.text = "networkKey"
            self.sec_auth.text = "open"
        else:
            self.sec_auth.text = P.sec_type
        if P.wifi_key != "":
            self.profile_wifi_key = self.sec_section.findall("{http://www.microsoft.com/networking/WLAN/profile/v1}sharedKey/{http://www.microsoft.com/networking/WLAN/profile/v1}keyMaterial")[0]
            self.profile_wifi_key.text = P.wifi_key

        #Get the file to temp folder(right to write)
        self.profile_file = path.join(LC.temp_path, "template-out.xml")

        self.profile_value = tostring(C.root) 

class LocalComputer(object):
    def __init__(self):
    	#Get temp folder path
        temp_path = getenv("tmp")

    def install_profile(self, profil_value):
        #Create new file with data 
    	with open(C.profile_file, "w") as self.configfile:
            self.configfile.write(C.profile_value)

        #Win command to add wifi profile
        try:
            self.netsh_command = "netsh wlan add profile filename="
            Popen(self.netsh_command+C.profile_file, shell=True)
            self.success_msg = "The profile was successfully added to the machine, please select your newly added profile "+P.ssid_name+" in the Wifi networks."
            msgbox(self.success_msg, "Information")
        except:
            msgbox("The profile could not be added to your machine, please contact your local support.", "Error")
            exit(0)
 
    def cleanup(self):		
        #Remove files
        self.delete_file = "del /F "
        Popen(self.delete_file+P.profile_file, shell=True)
        if P.eap_type == 13:
            Popen(self.delete_file+C.cert_p12, shell=True)
            Popen(self.delete_file+C.ca_file_binary, shell=True)
        exit(0)

class Certificate(object):
    def	install_certificate(self):
        #Add certificate to windows
        if C.user_cert_decode != "":
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
                self.add_cert = Popen(self.certutil+self.certutil_command+C.cert_p12, stdout=PIPE, stdin=PIPE, stderr=PIPE, startupinfo=self.si)
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
            Popen(self.certutil+self.add_ca+C.ca_file_binary, shell=True)
        except:
            msgbox("The Certificate of Authority could not be installed on your machine, please contact your local support.", "Error")
            exit(0)	

P = Profile()
C = Configure()
M = Models()
LC = LocalComputer()
Cer = Certificate()
   
class MainPanel(wx.Panel):

    def ExecuteOperations(self, profile_value):
        if P.eap_type == 13:
            Cer.install_certificate()
        LC.install_profile(C.profile_value)
        LC.cleanup()

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
