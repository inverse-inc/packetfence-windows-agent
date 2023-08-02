package main

// templates
const WIFI_PEAP_TEMPLATE = `<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{{.ProfileName}}</name>
  <SSIDConfig>
    <SSID>
      <hex>{{.SsidStringToHex}}</hex>
      <name>{{.ProfileName}}</name>
    </SSID>
    <nonBroadcast>{{.IsSSIDBroadcast}}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{{.SecAuth}}</authentication>
        <encryption>{{.Encryption}}</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
      <cacheUserData>true</cacheUserData>
        <authMode>machineOrUser</authMode>
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
</WLANProfile>`
const WIFI_TLS_TEMPLATE = `<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{{.ProfileName}}</name>
  <SSIDConfig>
    <SSID>
      <hex>{{.SsidStringToHex}}</hex>
      <name>{{.ProfileName}}</name>
    </SSID>
    <nonBroadcast>{{.IsSSIDBroadcast}}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{{.SecAuth}}</authentication>
        <encryption>{{.Encryption}}</encryption>
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
                    <TrustedRootCA>{{.CaToTrust}}</TrustedRootCA>
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
</WLANProfile>`
const WIFI_OPEN_TEMPLATE = `<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{{.ProfileName}}</name>
  <SSIDConfig>
    <SSID>
      <hex>{{.SsidStringToHex}}</hex>
      <name>{{.ProfileName}}</name>
    </SSID>
    <nonBroadcast>{{.IsSSIDBroadcast}}</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>{{.SecAuth}}</authentication>
        <encryption>{{.Encryption}}</encryption>
        <useOneX>false</useOneX>
        <FIPSMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v2">false</FIPSMode>
      </authEncryption>
      <sharedKey>
        <keyType>{{.OpenPasscode}}</keyType>
        <protected>false</protected>
        <keyMaterial>{{.WifiKey}}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>`
const WIRED_TLS_TEMPLATE = `<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1">
  <MSM>
    <security>
      <OneXEnforced>false</OneXEnforced>
      <OneXEnabled>true</OneXEnabled>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <cacheUserData>true</cacheUserData>
        <authMode>machineOrUser</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
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
                  </ServerValidation>
                  <DifferentUsername>false</DifferentUsername>
                  <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">false</PerformServerValidation>
                  <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">false</AcceptServerName>
                </EapType>
              </Eap>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</LANProfile>`
const WIRED_PEAP_TEMPLATE = `<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1">
  <MSM>
    <security>
      <OneXEnforced>false</OneXEnforced>
      <OneXEnabled>true</OneXEnabled>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"
                         xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon"
                         xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodConfig">
            <EapMethod>
                <eapCommon:Type>25</eapCommon:Type>
                <eapCommon:AuthorId>0</eapCommon:AuthorId>
           </EapMethod>
           <Config xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"
                   xmlns:msPeap="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"
                   xmlns:msChapV2="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
             <baseEap:Eap>
               <baseEap:Type>25</baseEap:Type>
               <msPeap:EapType>
                 <msPeap:ServerValidation>
                   <msPeap:DisableUserPromptForServerValidation>false</msPeap:DisableUserPromptForServerValidation>
                   <msPeap:TrustedRootCA/>
                 </msPeap:ServerValidation>
                 <msPeap:FastReconnect>true</msPeap:FastReconnect>
                 <msPeap:InnerEapOptional>0</msPeap:InnerEapOptional>
                 <baseEap:Eap>
                   <baseEap:Type>26</baseEap:Type>
                   <msChapV2:EapType>
                     <msChapV2:UseWinLogonCredentials>false</msChapV2:UseWinLogonCredentials>
                   </msChapV2:EapType>
                 </baseEap:Eap>
                 <msPeap:EnableQuarantineChecks>false</msPeap:EnableQuarantineChecks>
                 <msPeap:RequireCryptoBinding>false</msPeap:RequireCryptoBinding>
                 <msPeap:PeapExtensions />
               </msPeap:EapType>
             </baseEap:Eap>
           </Config>
         </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</LANProfile>`
