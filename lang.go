package main

const ENGLISH_TRANSLATION = `[
  {
    "id": "errorMainWindow",
    "translation": "An error occured. Please try again."
  },
  {
    "id": "wlanErrorMessage",
    "translation": "The wireless profile could not be added to your machine, please contact your local support."
  },
  {
    "id": "wiredErrorMessage",
    "translation": "The wired profile could not be added to your machine, please contact your local support."
  },
  {
    "id": "wiredSuccessMessage",
    "translation": "The wired profile was succesfully added to the machine."
  },
  {
    "id": "invalidTempPath",
    "translation": "Invalid path to Temp directory."
  },
  {
    "id": "cannotRetrieveProfileFile",
    "translation": "Unable to retrieve your profile file, please contact your local support."
  },
  {
    "id": "cannotReadProfileData",
    "translation": "Cannot read the profile data, please contact your local support."
  },
  {
    "id": "cannotDecodeProfileFile",
    "translation": "Unable to decode the profile file, please contact you local support."
  },
  {
    "id": "cannotGenerateCertificateFile",
    "translation": "Your personal certificate file could not be generated, please contact your local support."
  },
  {
    "id": "cannotGenerateCAFile",
    "translation": "The Certificate of Authority file could not be generated, please contact your local support."
  },
  {
    "id": "Unexpected PayloadType {{.PayloadType}} please contact your local support.",
    "translation": "Unexpected PayloadType {{.PayloadType}} please contact your local support."
  },
  {
    "id": "The wireless profile was successfully added to the machine. \nPlease select your newly added profile {{.SsidString}} in the WiFi networks.",
    "translation": "The wireless profile was successfully added to the machine. \nPlease select your newly added profile {{.SsidString}} in the WiFi networks."
  },
  {
    "id": "unexpectedEAPType",
    "translation": "Extensible Authentication Protocol type not supported by the program."
  },
  {
    "id": "dot3svcFail",
    "translation": "The Wired AutoConfig service could not be started."
  },
  {
    "id": "cannotDecodeCertificateFile",
    "translation": "Unable to decode the certificate file, please contact your local support."
  },
  {
    "id": "cannotCreateTempFile",
    "translation": "Unable to create temporary file, please contact your local support."
  },
  {
    "id": "cannotWriteIntoTempFile",
    "translation": "Unable to write into the temporary file, please contact your local support."
  },
  {
    "id": "enterCertificatePassword",
    "translation": "Enter Your Certificate Password"
  },
  {
    "id": "wrongPassword",
    "translation": "The password you filled in was wrong, please try again."
  },
  {
    "id": "invalidCertificate",
    "translation": "The certificate is invalid, please contact your local support."
  },
  {
    "id": "cannotFindCertificateFile",
    "translation": "Unable to find the certificate file, please contact your local support."
  },
  {
    "id": "cannotInstallCertificate",
    "translation": "The certificate could not be installed on your machine, please contact your local support."
  },
  {
    "id": "certificateInstallationSuccess",
    "translation": "Your certificate was successfully installed, please press OK to continue."
  },
  {
    "id": "caErrorCanceled",
    "translation": "The Certificate of Authority could not be installed on your machine.\nIf you chose not to install the Certificate of Authority, the program will terminate."
  },
  {
    "id": "cannotInstallCA",
    "translation": "The Certificate of Authority could not be installed on your machine, please contact your local support."
  },
  {
    "id": "caInstallationSuccess",
    "translation": "The CA was successfully installed on your machine."
  },
  {
    "id": "cannotOpenCAFile",
    "translation": "Error opening the Certificate of Authority file, please contact your local support."
  },
  {
    "id": "cannotCopyCAFile",
    "translation": "Unable to copy the Certificate of Authority file, please contact your local support."
  },
  {
    "id": "cannotParseTemplate",
    "translation": "Unable to parse template, please contact your local support."
  },
  {
    "id": "cannotExecuteTemplate",
    "translation": "Unable to execute template, please contact your local support."
  },
  {
    "id": "cannotCreateWLANProfile",
    "translation": "Unable to create your WLAN profile, please contact your local support."
  },
  {
    "id": "cannotCreateProfileFile",
    "translation": "Unable to create the profile file, please contact your local support."
  },
  {
    "id": "cannotWriteIntoProfileFile",
    "translation": "Unable to write into the profile file, please contact your local support."
  },
  {
    "id": "profileCreationSuccess",
    "translation": "The profile file was successfully created."
  },
  {
    "id": "errorWindowTitle",
    "translation": "Error"
  },
  {
    "id": "successWindowTitle",
    "translation": "Success"
  }
]
`
const FRENCH_TRANSLATION = `[
  {
    "id": "errorMainWindow",
    "translation": "Une erreur est survenue. Veuillez essayer de nouveau."
  },
  {
    "id": "wlanErrorMessage",
    "translation": "Le profil sans fil n'a pas pu être ajouté à votre appareil, contactez votre support local."
  },
  {
    "id": "wiredErrorMessage",
    "translation": "Le profil filaire n'a pas pu être ajouté à votre machine, contactez votre support local."
  },
  {
    "id": "wiredSuccessMessage",
    "translation": "Le profil filaire a été ajouté avec succès à la machine."
  },
  {
    "id": "invalidTempPath",
    "translation": "Chemin d'accès au répertoire Temp non valide."
  },
  {
    "id": "cannotRetrieveProfileFile",
    "translation": "Impossible de récupérer votre profil, contactez votre support local."
  },
  {
    "id": "cannotReadProfileData",
    "translation": "Impossible de lire les données de votre profil, contactez votre support local."
  },
  {
    "id": "cannotDecodeProfileFile",
    "translation": "Impossible de décoder votre profil, contactez votre support local."
  },
  {
    "id": "cannotGenerateCertificateFile",
    "translation": "Votre fichier de certificat personnel n'a pas pu être généré, contactez votre support local."
  },
  {
    "id": "cannotGenerateCAFile",
    "translation": "Le fichier d'Autorité de Certification n'a pas pu être généré, contactez votre support local."
  },
  {
    "id": "Unexpected PayloadType {{.PayloadType}} please contact your local support.",
    "translation": "PayloadType {{.PayloadType}} inattendu, contactez votre support local."
  },
  {
    "id": "The wireless profile was successfully added to the machine. \nPlease select your newly added profile {{.SsidString}} in the WiFi networks.",
    "translation": "Le profil sans fil a été ajouté avec succès à la machine.\nVeuillez sélectionner votre profil nouvellement ajouté {{.SsidString}} dans les réseaux WiFi."
  },
  {
    "id": "unexpectedEAPType",
    "translation": "EAP Type non pris en charge par le programme."
  },
  {
    "id": "dot3svcFail",
    "translation": "Le service Wired AutoConfig n'a pas pu être démarré."
  },
  {
    "id": "cannotDecodeCertificateFile",
    "translation": "Impossible de décoder le fichier de certificat, contactez votre support local."
  },
  {
    "id": "cannotCreateTempFile",
    "translation": "Impossible de créer un fichier temporaire, contactez votre support local."
  },
  {
    "id": "cannotWriteIntoTempFile",
    "translation": "Impossible d'écrire dans le fichier temporaire, contactez votre support local."
  },
  {
    "id": "enterCertificatePassword",
    "translation": "Entrez le mot de passe de votre certificat"
  },
  {
    "id": "wrongPassword",
    "translation": "Mot de passe erroné, veuillez réessayer."
  },
  {
    "id": "invalidCertificate",
    "translation": "Le certificat est invalide, contactez votre support local."
  },
  {
    "id": "cannotFindCertificateFile",
    "translation": "Impossible de trouver le fichier de certificat, contactez votre support local."
  },
  {
    "id": "cannotInstallCertificate",
    "translation": "Le certificat n'a pas pu être installé sur votre machine, contactez votre support local."
  },
  {
    "id": "certificateInstallationSuccess",
    "translation": "Votre certificat a été installé avec succès, veuillez cliquer sur OK pour continuer."
  },
  {
    "id": "caErrorCanceled",
    "translation": "L'Autorité de Certification n'a pas pu être installée sur votre machine.\nSi vous choisissez de ne pas l'installer, le programme se terminera."
  },
  {
    "id": "cannotInstallCA",
    "translation": "L'Autorité de Certification n'a pas pu être installée sur votre machine, contactez votre support local."
  },
  {
    "id": "caInstallationSuccess",
    "translation": "L'Autorité de Certification a été installée avec succès sur votre machine."
  },
  {
    "id": "cannotOpenCAFile",
    "translation": "Erreur lors de l'ouverture du fichier d'Autorité de Certification, contactez votre support local."
  },
  {
    "id": "cannotCopyCAFile",
    "translation": "Impossible de copier le fichier d'Autorité de Certification, contactez votre support local."
  },
  {
    "id": "cannotParseTemplate",
    "translation": "Impossible de parser le template, contactez votre support local."
  },
  {
    "id": "cannotExecuteTemplate",
    "translation": "Impossible d'exécuter le template, contactez votre support local."
  },
  {
    "id": "cannotCreateWLANProfile",
    "translation": "Impossible de créer votre profil WiFi, contactez votre support local."
  },
  {
    "id": "cannotCreateProfileFile",
    "translation": "Impossible de créer le fichier de profil, contactez votre support local."
  },
  {
    "id": "cannotWriteIntoProfileFile",
    "translation": "Impossible d'écrire dans le fichier de profil, contactez votre support local."
  },
  {
    "id": "profileCreationSuccess",
    "translation": "Le fichier de profil a été créé avec succès."
  },
  {
    "id": "errorWindowTitle",
    "translation": "Erreur"
  },
  {
    "id": "successWindowTitle",
    "translation": "Succès"
  }
]
`
