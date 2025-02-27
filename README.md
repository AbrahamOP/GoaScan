# GoaScan 🛡️

Un scanner de vulnérabilités moderne et puissant pour images Docker et systèmes de fichiers.

## ✨ Caractéristiques

- 🐳 **Scan d'images Docker**
  - Détection automatique des images locales
  - Pull automatique si l'image n'existe pas
  - Analyse complète des dépendances

- 📁 **Scan de fichiers et répertoires**
  - Analyse des dépendances des projets
  - Support pour plusieurs langages de programmation
  - Détection des vulnérabilités dans le code

- 📊 **Rapport détaillé**
  - Classification par niveau de sévérité (CRITICAL → HIGH → MEDIUM → LOW)
  - Statistiques et pourcentages
  - Présentation claire et colorée des résultats

- 🔧 **Solutions de remédiation**
  - Instructions de mise à jour détaillées
  - Commandes spécifiques par gestionnaire de paquets
  - Mitigations temporaires suggérées
  - Liens vers la documentation et les CVE

## 🚀 Installation

### Prérequis

- **Node.js** (v14 ou supérieur)
- **Docker** (pour scanner des images Docker)
- **Trivy** (installé automatiquement par le script d'installation)

### Méthode recommandée (avec script d'installation)

Le script d'installation `install.sh` automatise l'ensemble du processus, y compris l'installation de Trivy :

```bash
# Cloner le dépôt
git clone https://github.com/AbrahamOP/GoaScan.git

# Accéder au répertoire
cd GoaScan

# Rendre le script d'installation exécutable
chmod +x install.sh

# Exécuter le script d'installation
./install.sh
```

Le script d'installation :
1. Vérifie que Node.js et npm sont installés
2. Installe Trivy automatiquement (selon votre système d'exploitation)
3. Installe GoaScan globalement

### Installation manuelle

Si vous préférez une installation manuelle :

#### 1. Installer Trivy

Trivy est un prérequis essentiel. Choisissez la méthode adaptée à votre système :

**macOS** :
```bash
brew install trivy
```

**Ubuntu/Debian** :
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy -y
```

**Fedora/RHEL/CentOS** :
```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.38.0/trivy_0.38.0_Linux-64bit.rpm
```

**Windows** :
```bash
choco install trivy
```

Pour d'autres systèmes, consultez la [documentation officielle de Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/).

#### 2. Installer GoaScan

Après avoir installé Trivy, installez GoaScan :

```bash
# Cloner le dépôt
git clone https://github.com/AbrahamOP/GoaScan.git

# Accéder au répertoire
cd GoaScan

# Installer globalement
npm install -g .
```

### Vérification de l'installation

Pour vérifier que GoaScan est correctement installé :

```bash
goascan --help
```

Vous devriez voir s'afficher l'aide de l'application avec les commandes disponibles.

## 📖 Utilisation

### Scanner une image Docker

```bash
goascan docker ubuntu:latest
```

Cette commande :
- Vérifie si l'image existe localement
- Télécharge l'image si nécessaire
- Analyse l'image pour détecter les vulnérabilités
- Affiche un rapport détaillé

### Scanner un fichier ou répertoire

```bash
goascan fs /chemin/vers/fichier
```

Cette commande analyse les dépendances et le code source pour détecter les vulnérabilités.

### Mode d'affichage compact

Pour un affichage plus compact des résultats, utilisez l'option `--compact` ou `-c` :

```bash
goascan docker ubuntu:latest --compact
goascan fs /chemin/vers/fichier -c
```

Le mode compact affiche un tableau unique avec toutes les vulnérabilités, sans les détails de remédiation, ce qui facilite la lecture rapide des résultats.

### Voir l'aide

```bash
goascan --help
```

## 📋 Format des résultats

### Résumé global
- Nombre total de vulnérabilités
- Répartition par niveau de sévérité avec pourcentages
- Vue d'ensemble rapide des risques

### Détails par vulnérabilité
- **Package** : Nom du package affecté
- **Version** : Version actuellement installée
- **ID** : Identifiant unique de la vulnérabilité
- **Description** : Description du problème
- **Solution** : Instructions détaillées de remédiation

### Solutions proposées
1. **Instructions de mise à jour**
   - Version cible recommandée
   - Commandes spécifiques selon le gestionnaire de paquets
   ```bash
   # Exemple pour apt
   apt update && apt upgrade package-name
   
   # Exemple pour npm
   npm update package-name
   
   # Exemple pour pip
   pip install --upgrade package-name
   ```

2. **Documentation**
   - Liens vers les CVE
   - Documentation technique
   - Ressources additionnelles

3. **Mitigations temporaires**
   - Solutions alternatives
   - Mesures de sécurité temporaires
   - Bonnes pratiques recommandées

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Ouvrir une issue pour signaler un bug
- Proposer des améliorations
- Soumettre une pull request

## 📝 Licence

ISC

## 🔗 Liens utiles

- [Documentation Trivy](https://aquasecurity.github.io/trivy/latest/)
- [Node.js](https://nodejs.org/)
- [Docker](https://www.docker.com/)
