#!/bin/bash

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Installation de GoaScan...${NC}"

# Vérifier si Node.js est installé
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js n'est pas installé. Veuillez l'installer d'abord:${NC}"
    echo -e "${YELLOW}https://nodejs.org/en/download/${NC}"
    exit 1
fi

# Vérifier si npm est installé
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm n'est pas installé. Veuillez l'installer d'abord.${NC}"
    exit 1
fi

# Vérifier si Trivy est installé
if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}Trivy n'est pas installé. Installation...${NC}"
    
    # Détection du système d'exploitation
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Détection de la distribution Linux
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
                # Installation pour Ubuntu/Debian
                echo -e "${GREEN}Détection de Ubuntu/Debian. Installation via apt...${NC}"
                sudo apt-get install wget apt-transport-https gnupg lsb-release -y
                wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
                sudo apt-get update
                sudo apt-get install trivy -y
            elif [[ "$ID" == "fedora" || "$ID" == "rhel" || "$ID" == "centos" ]]; then
                # Installation pour Fedora/RHEL/CentOS
                echo -e "${GREEN}Détection de Fedora/RHEL/CentOS. Installation via rpm...${NC}"
                sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.38.0/trivy_0.38.0_Linux-64bit.rpm
            elif [[ "$ID" == "alpine" ]]; then
                # Installation pour Alpine
                echo -e "${GREEN}Détection de Alpine. Installation via apk...${NC}"
                sudo apk add --no-cache trivy
            else
                echo -e "${YELLOW}Distribution Linux non reconnue. Tentative d'installation via script...${NC}"
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
            fi
        else
            echo -e "${YELLOW}Impossible de détecter la distribution Linux. Tentative d'installation via script...${NC}"
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # Installation pour macOS
        echo -e "${GREEN}Détection de macOS. Installation via Homebrew...${NC}"
        if ! command -v brew &> /dev/null; then
            echo -e "${YELLOW}Homebrew n'est pas installé. Installation...${NC}"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install trivy
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Installation pour Windows
        echo -e "${YELLOW}Détection de Windows. Veuillez installer Trivy manuellement:${NC}"
        echo -e "${YELLOW}https://aquasecurity.github.io/trivy/latest/getting-started/installation/#windows${NC}"
        echo -e "${YELLOW}Ou exécutez: choco install trivy${NC}"
        exit 1
    else
        echo -e "${RED}Système d'exploitation non supporté pour l'installation automatique de Trivy.${NC}"
        echo -e "${YELLOW}Veuillez installer Trivy manuellement:${NC}"
        echo -e "${YELLOW}https://aquasecurity.github.io/trivy/latest/getting-started/installation/${NC}"
        exit 1
    fi
    
    # Vérifier si l'installation a réussi
    if command -v trivy &> /dev/null; then
        echo -e "${GREEN}Trivy a été installé avec succès!${NC}"
        trivy --version
    else
        echo -e "${RED}L'installation de Trivy a échoué.${NC}"
        echo -e "${YELLOW}Veuillez installer Trivy manuellement:${NC}"
        echo -e "${YELLOW}https://aquasecurity.github.io/trivy/latest/getting-started/installation/${NC}"
        exit 1
    fi
fi

# Créer un dossier temporaire
TMP_DIR=$(mktemp -d)
cd $TMP_DIR

echo -e "${GREEN}Téléchargement de GoaScan...${NC}"

# Télécharger la dernière version
curl -s https://api.github.com/repos/AbrahamOP/GoaScan/releases/latest \
| grep "browser_download_url.*tgz" \
| cut -d : -f 2,3 \
| tr -d \" \
| wget -qi -

# Extraire et installer
echo -e "${GREEN}Installation...${NC}"
tar xzf *.tgz
cd package
npm install -g .

# Nettoyage
cd ..
rm -rf $TMP_DIR

# Vérifier l'installation
if command -v goascan &> /dev/null; then
    echo -e "${GREEN}GoaScan a été installé avec succès!${NC}"
    echo -e "${GREEN}Utilisez 'goascan --help' pour voir les commandes disponibles.${NC}"
else
    echo -e "${RED}Une erreur est survenue lors de l'installation.${NC}"
    exit 1
fi
