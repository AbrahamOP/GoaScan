#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const { table } = require('table');
const Docker = require('dockerode');
const { execSync } = require('child_process');

// Vérification de l'installation de Trivy
function checkTrivyInstallation() {
    try {
        execSync('trivy --version', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

// Fonction pour scanner une image Docker
async function scanImage(imageName) {
    try {
        const docker = new Docker();
        
        // Vérifier si l'image existe localement
        try {
            await docker.getImage(imageName).inspect();
        } catch {
            console.log(chalk.yellow(`L'image ${imageName} n'existe pas localement. Tentative de pull...`));
            try {
                // Utiliser une promesse pour attendre la fin du pull
                await new Promise((resolve, reject) => {
                    docker.pull(imageName, (err, stream) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        
                        // Afficher la progression du pull
                        docker.modem.followProgress(stream, (err, output) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            console.log(chalk.green(`Pull de l'image ${imageName} terminé avec succès.`));
                            resolve(output);
                        });
                    });
                });
            } catch (err) {
                console.error(chalk.red(`Erreur lors du pull de l'image ${imageName}: ${err.message}`));
                return null;
            }
        }

        // Scanner l'image avec Trivy
        const result = execSync(`trivy image -f json ${imageName}`, { encoding: 'utf-8' });
        return JSON.parse(result);
    } catch (err) {
        console.error(chalk.red(`Erreur lors du scan: ${err.message}`));
        return null;
    }
}

// Fonction pour scanner un fichier ou répertoire
function scanFilesystem(path) {
    try {
        const result = execSync(`trivy filesystem -f json ${path}`, { encoding: 'utf-8' });
        return JSON.parse(result);
    } catch (err) {
        console.error(chalk.red(`Erreur lors du scan: ${err.message}`));
        return null;
    }
}

// Fonction pour afficher le résumé des vulnérabilités
function displaySummary(vulnCount, target, severityOrder) {
    // Afficher le résumé avec barre de séparation
    console.log(chalk.bold('\n' + '='.repeat(50)));
    console.log(chalk.bold(`Résumé des vulnérabilités pour ${target}`));
    console.log('='.repeat(50));

    const totalVulns = Object.values(vulnCount).reduce((a, b) => a + b, 0);
    console.log(chalk.bold(`\nTotal des vulnérabilités: ${totalVulns}`));

    severityOrder.forEach(severity => {
        if (vulnCount[severity] > 0) {
            const color = {
                CRITICAL: chalk.red,
                HIGH: chalk.red,
                MEDIUM: chalk.yellow,
                LOW: chalk.blue,
                UNKNOWN: chalk.white
            }[severity];
            
            const percentage = ((vulnCount[severity] / totalVulns) * 100).toFixed(1);
            console.log(color(`${severity}: ${vulnCount[severity]} (${percentage}%)`));
        }
    });
    
    return totalVulns;
}

// Affichage des vulnérabilités
function displayVulnerabilities(scanResult, target) {
    if (!scanResult || !scanResult.Results) {
        console.log(chalk.red(`Aucun résultat valide pour ${target}`));
        return;
    }

    // Initialisation des compteurs et tableaux par sévérité
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const vulnCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    const vulnsBySeverity = {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        UNKNOWN: []
    };

    // Collecter et trier les vulnérabilités
    scanResult.Results.forEach(result => {
        if (!result.Vulnerabilities) return;

        result.Vulnerabilities.forEach(vuln => {
            const severity = vuln.Severity || 'UNKNOWN';
            vulnCount[severity]++;
            vulnsBySeverity[severity].push(vuln);
        });
    });

    // Afficher le résumé au début
    const totalVulns = displaySummary(vulnCount, target, severityOrder);

    // Afficher les détails par niveau de sévérité
    if (totalVulns > 0) {
        severityOrder.forEach(severity => {
            const vulns = vulnsBySeverity[severity];
            if (vulns.length > 0) {
                const color = {
                    CRITICAL: chalk.red,
                    HIGH: chalk.red,
                    MEDIUM: chalk.yellow,
                    LOW: chalk.blue,
                    UNKNOWN: chalk.white
                }[severity];

                console.log(chalk.bold('\n' + '='.repeat(50)));
                console.log(color(`Vulnérabilités ${severity} (${vulns.length}):`));
                console.log('='.repeat(50));

                const tableData = [
                    ['Package', 'Version', 'ID', 'Description', 'Solution'].map(h => chalk.bold(h))
                ];

                vulns.forEach(vuln => {
                    // Préparer la solution détaillée
                    let solution = '';
                    
                    // 1. Version fixe si disponible
                    if (vuln.FixedVersion) {
                        solution = `1. Mettre à jour vers la version ${vuln.FixedVersion}\n`;
                        
                        // Commandes spécifiques selon le type de package
                        if (vuln.PkgName) {
                            solution += '   Commande: ';
                            if (vuln.PkgName.includes('apt')) {
                                solution += `\n   → apt update && apt upgrade ${vuln.PkgName}`;
                            } else if (vuln.PkgName.includes('npm')) {
                                solution += `\n   → npm update ${vuln.PkgName}`;
                            } else if (vuln.PkgName.includes('pip')) {
                                solution += `\n   → pip install --upgrade ${vuln.PkgName}`;
                            } else if (vuln.PkgName.includes('gem')) {
                                solution += `\n   → gem update ${vuln.PkgName}`;
                            } else if (vuln.PkgName.includes('composer')) {
                                solution += `\n   → composer update ${vuln.PkgName}`;
                            } else {
                                solution += `\n   → Mettre à jour ${vuln.PkgName} via votre gestionnaire de paquets`;
                            }
                        }
                    }

                    // 2. Ajouter les références CVE et documentation
                    if (vuln.References && vuln.References.length > 0) {
                        solution += '\n2. Documentation:';
                        vuln.References.slice(0, 2).forEach(ref => {
                            solution += `\n   → ${ref}`;
                        });
                    }

                    // 3. Ajouter des mitigations temporaires si disponibles
                    if (vuln.Description) {
                        solution += '\n3. Mitigations possibles:';
                        if (vuln.Description.toLowerCase().includes('injection')) {
                            solution += '\n   → Valider toutes les entrées utilisateur';
                            solution += '\n   → Utiliser des requêtes préparées';
                        } else if (vuln.Description.toLowerCase().includes('overflow')) {
                            solution += '\n   → Activer les protections ASLR/DEP';
                            solution += '\n   → Limiter les tailles des buffers';
                        } else if (vuln.Description.toLowerCase().includes('xss')) {
                            solution += '\n   → Échapper les sorties HTML';
                            solution += '\n   → Utiliser les en-têtes de sécurité CSP';
                        }
                    }

                    // Si aucune solution spécifique n'est trouvée
                    if (!solution) {
                        solution = 'Pas de version fixe disponible.\n';
                        solution += '→ Surveiller les mises à jour du projet\n';
                        solution += '→ Évaluer la possibilité de changer de composant';
                    }

                    tableData.push([
                        chalk.cyan(vuln.PkgName || 'N/A'),
                        chalk.yellow(vuln.InstalledVersion || 'N/A'),
                        chalk.magenta(vuln.VulnerabilityID || 'N/A'),
                        (vuln.Title || 'N/A').substring(0, 100),
                        chalk.green(solution)
                    ]);
                });

                // Afficher des conseils généraux pour ce niveau de sévérité
                const recommendations = {
                    CRITICAL: [
                        "→ Appliquer les mises à jour immédiatement",
                        "→ Isoler les systèmes affectés si possible",
                        "→ Surveiller les logs pour détecter d'éventuelles exploitations"
                    ],
                    HIGH: [
                        "→ Planifier les mises à jour rapidement",
                        "→ Mettre en place des mesures de mitigation temporaires"
                    ],
                    MEDIUM: [
                        "→ Inclure les mises à jour dans le prochain cycle de maintenance",
                        "→ Documenter les vulnérabilités pour le suivi"
                    ],
                    LOW: [
                        "→ Évaluer l'impact sur votre environnement",
                        "→ Planifier les mises à jour lors des maintenances régulières"
                    ]
                };

                if (recommendations[severity]) {
                    console.log(chalk.bold('\nRecommandations générales:'));
                    recommendations[severity].forEach(rec => {
                        console.log(color(rec));
                    });
                }

                console.log(table(tableData, {
                    border: {
                        topBody: '─',
                        topJoin: '┬',
                        topLeft: '┌',
                        topRight: '┐',
                        bottomBody: '─',
                        bottomJoin: '┴',
                        bottomLeft: '└',
                        bottomRight: '┘',
                        bodyLeft: '│',
                        bodyRight: '│',
                        bodyJoin: '│',
                        joinBody: '─',
                        joinLeft: '├',
                        joinRight: '┤',
                        joinJoin: '┼'
                    }
                }));
            }
        });
    } else {
        console.log(chalk.green('\nAucune vulnérabilité trouvée!'));
    }
    
    // Afficher le résumé à la fin pour les résultats avec des vulnérabilités
    if (totalVulns > 0) {
        // Afficher le résumé à nouveau à la fin
        displaySummary(vulnCount, target, severityOrder);
    }
}

// Fonction pour afficher les vulnérabilités en format compact
function displayVulnerabilitiesCompact(scanResult, target) {
    if (!scanResult || !scanResult.Results) {
        console.log(chalk.red(`Aucun résultat valide pour ${target}`));
        return;
    }

    // Initialisation des compteurs et tableaux par sévérité
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const vulnCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    const vulnsBySeverity = {
        CRITICAL: [],
        HIGH: [],
        MEDIUM: [],
        LOW: [],
        UNKNOWN: []
    };

    // Collecter et trier les vulnérabilités
    scanResult.Results.forEach(result => {
        if (!result.Vulnerabilities) return;

        result.Vulnerabilities.forEach(vuln => {
            const severity = vuln.Severity || 'UNKNOWN';
            vulnCount[severity]++;
            vulnsBySeverity[severity].push(vuln);
        });
    });

    // Afficher le résumé
    console.log(chalk.bold('\n' + '='.repeat(50)));
    console.log(chalk.bold(`Résumé des vulnérabilités pour ${target}`));
    console.log('='.repeat(50));

    const totalVulns = Object.values(vulnCount).reduce((a, b) => a + b, 0);
    console.log(chalk.bold(`\nTotal des vulnérabilités: ${totalVulns}`));

    severityOrder.forEach(severity => {
        if (vulnCount[severity] > 0) {
            const color = {
                CRITICAL: chalk.red,
                HIGH: chalk.red,
                MEDIUM: chalk.yellow,
                LOW: chalk.blue,
                UNKNOWN: chalk.white
            }[severity];
            
            const percentage = ((vulnCount[severity] / totalVulns) * 100).toFixed(1);
            console.log(color(`${severity}: ${vulnCount[severity]} (${percentage}%)`));
        }
    });

    // Afficher un tableau compact avec toutes les vulnérabilités
    if (totalVulns > 0) {
        console.log(chalk.bold('\n' + '='.repeat(50)));
        console.log(chalk.bold(`Liste des vulnérabilités (format compact)`));
        console.log('='.repeat(50) + '\n');

        const tableData = [
            ['Sévérité', 'Package', 'Version', 'ID', 'Description'].map(h => chalk.bold(h))
        ];

        severityOrder.forEach(severity => {
            const vulns = vulnsBySeverity[severity];
            if (vulns.length > 0) {
                const color = {
                    CRITICAL: chalk.red,
                    HIGH: chalk.red,
                    MEDIUM: chalk.yellow,
                    LOW: chalk.blue,
                    UNKNOWN: chalk.white
                }[severity];

                vulns.forEach(vuln => {
                    tableData.push([
                        color(severity),
                        chalk.cyan(vuln.PkgName || 'N/A'),
                        chalk.yellow(vuln.InstalledVersion || 'N/A'),
                        chalk.magenta(vuln.VulnerabilityID || 'N/A'),
                        (vuln.Title || 'N/A').substring(0, 60) + (vuln.Title && vuln.Title.length > 60 ? '...' : '')
                    ]);
                });
            }
        });

        console.log(table(tableData, {
            border: {
                topBody: '─',
                topJoin: '┬',
                topLeft: '┌',
                topRight: '┐',
                bottomBody: '─',
                bottomJoin: '┴',
                bottomLeft: '└',
                bottomRight: '┘',
                bodyLeft: '│',
                bodyRight: '│',
                bodyJoin: '│',
                joinBody: '─',
                joinLeft: '├',
                joinRight: '┤',
                joinJoin: '┼'
            }
        }));
    } else {
        console.log(chalk.green('\nAucune vulnérabilité trouvée!'));
    }
}

// Configuration du CLI
program
    .name('goascan')
    .description('Scanner de vulnérabilités pour images Docker et fichiers')
    .version('1.0.0')
    .option('-c, --compact', 'Afficher les résultats en format compact');

program
    .command('docker <image>')
    .description('Scanner une image Docker')
    .action(async (image) => {
        if (!checkTrivyInstallation()) {
            console.error(chalk.red('Erreur: Trivy n\'est pas installé.'));
            console.log('Instructions d\'installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/');
            process.exit(1);
        }

        console.log(chalk.blue(`Scanning de l'image Docker: ${image}`));
        const result = await scanImage(image);
        if (result) {
            if (program.opts().compact) {
                displayVulnerabilitiesCompact(result, image);
            } else {
                displayVulnerabilities(result, image);
            }
        }
    });

program
    .command('fs <path>')
    .description('Scanner un fichier ou répertoire')
    .action((path) => {
        if (!checkTrivyInstallation()) {
            console.error(chalk.red('Erreur: Trivy n\'est pas installé.'));
            console.log('Instructions d\'installation: https://aquasecurity.github.io/trivy/latest/getting-started/installation/');
            process.exit(1);
        }

        console.log(chalk.blue(`Scanning du système de fichiers: ${path}`));
        const result = scanFilesystem(path);
        if (result) {
            if (program.opts().compact) {
                displayVulnerabilitiesCompact(result, path);
            } else {
                displayVulnerabilities(result, path);
            }
        }
    });

program.parse();
