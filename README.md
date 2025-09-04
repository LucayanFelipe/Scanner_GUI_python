Port Scanner (TCP & UDP) com GUI

Um scanner de portas completo com interface gráfica desenvolvido em Python usando PyQt5. Suporta varredura TCP (SYN e Connect) e UDP, com capacidade de escanear múltiplos IPs, ranges e redes CIDR.
📋 Pré-requisitos

    Linux Mint Cinnamon (ou qualquer distribuição Linux baseada em Debian/Ubuntu)

    Python 3.8 ou superior

    Acesso root para varredura SYN (opcional mas recomendado)

🚀 Instalação Passo a Passo
1. Configuração da Máquina Virtual no VirtualBox

    Criar Nova Máquina Virtual:

        Abra o VirtualBox e clique em "Nova"

        Nome: "Linux Scanner"

        Tipo: Linux

        Versão: Other linux (64-bit)

    Configurar Rede em Modo Bridge:

        Selecione sua VM criada e clique em "Configurações"

        Vá em "Rede" → "Adaptador 1"

        Marque "Habilitar Placa de Rede"

        Modo de Acesso: "Bridge"

        Clique em OK

    Instalar Sistema Operacional:

        Inicie a VM

        Selecione a imagem ISO do Linux Mint Cinnamon

        Siga o processo de instalação padrão


2. Instalação das Dependências do Sistema

Abra o terminal (Ctrl+Alt+T) e execute:

# Atualizar lista de pacotes
sudo apt update

# Instalar Python e ferramentas essenciais
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5

# Instalar dependências para o scapy (opcional mas recomendado)
sudo apt install -y tcpdump libpcap-dev

# Instalar scapy (para varreduras avançadas)
pip install scapy
ou
sudo apt install -y python3-scapy

4. Obter o Código do Scanner

# Clone o repositório ou baixe o arquivo
git clone <Scanner_GUI_python>

5. Executar o Scanner

# Execute com sudo
sudo python3 scanner.py

🎯 Como Usar o Scanner

    Targets: Insira IPs (192.168.1.1), ranges (192.168.1.1-192.168.1.10) ou redes CIDR (192.168.1.0/24)

    Portas: Especifique portas individuais (80,443) ou ranges (1-1024)

    Modo: Selecione TCP, UDP ou ambos

    Threads: Ajuste o número de threads paralelas (100 é um bom padrão)

    Clique em "Start Scan" para iniciar a varredura

🔧 Funcionalidades

    Varredura TCP: SYN scan (com scapy/root) ou Connect scan (fallback)

    Varredura UDP: Detecta portas abertas através de respostas ICMP

    Interface gráfica intuitiva com tabela de resultados colorida

    Suporte a múltiplos formatos de entrada (IPs, ranges, CIDR)

    Log de atividades e barra de progresso

    Resultados em tempo real com timestamp

📊 Exemplos de Uso
bash

# Escanear portas comuns em localhost
Targets: 127.0.0.1
Portas: 22,80,443,53,161
Modo: TCP

# Escanear range de IPs na rede local
Targets: 192.168.1.1-192.168.1.50
Portas: 1-1024
Modo: BOTH

# Escanear rede completa
Targets: 192.168.1.0/24
Portas: 80,443
Modo: TCP

📝 Notas Importantes

    A varredura SYN requer privilégios root e scapy instalado

    Resultados UDP podem mostrar "open|filtered" devido à natureza do protocolo
