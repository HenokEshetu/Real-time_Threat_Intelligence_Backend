#!/bin/bash

OS=$(uname -s)

debian_ubuntu_install_vault() {
    wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
    sudo apt update && sudo apt install vault
}

centos_rhel_install_vault() {
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
    sudo yum -y install vault
}

fedora_40_install_vault() {
    sudo dnf install -y dnf-plugins-core
    sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo
    sudo dnf -y install vault
}

fedora_41_and_above_install_vault() {
    sudo dnf install -y dnf-plugins-core
    sudo dnf config-manager addrepo --from-repofile=https://rpm.releases.hashicorp.com/fedora/hashicorp.repo
    sudo dnf -y install vault
}

homebrew_install_vault() {
    brew tap hashicorp/tap
    brew install hashicorp/tap/vault
}

if [ "$OS" = "Linux" ]; then
    if command -v lsb_release >/dev/null 2>&1; then
        DISTRO=$(lsb_release -si)
        VERSION=$(lsb_release -sr)

        case "$DISTRO" in
            Ubuntu|Debian)
                debian_ubuntu_install_vault
                ;;
            CentOS|RHEL)
                centos_rhel_install_vault
                ;;
            Fedora)
                case "$VERSION" in
                    40*)
                        fedora_40_install_vault
                        ;;
                    41*)
                        fedora_41_and_above_install_vault
                        ;;
                    *)
                        fedora_41_and_above_install_vault
                        ;;
                esac
                ;;
            Homebrew)
                homebrew_install_vault
                ;;
            *)
                echo "Linux Distribution: $DISTRO $VERSION"
                ;;
        esac
    else
        if [ -f /etc/debian_version ]; then
            VERSION=$(cat /etc/debian_version)
            debian_ubuntu_install_vault
        elif [ -f /etc/fedora-release ]; then
            VERSION=$(cat /etc/fedora-release | grep -o '[0-9]\+')
            case "$VERSION" in
                40)
                    fedora_40_install_vault
                    ;;
                41)
                    fedora_41_and_above_install_vault
                    ;;
                *)
                    fedora_41_and_above_install_vault
                    ;;
            esac
        elif [ -f /etc/redhat-release ]; then
            centos_rhel_install_vault
        elif [ -f /etc/centos-release ]; then
            centos_rhel_install_vault
        else
            echo "Linux (unknown distribution)"
        fi
    fi
else
    case "$OS" in
        Darwin*)
            brew tap hashicorp/tap
            brew install hashicorp/tap/vault
            ;;
        FreeBSD*)
            echo "https://releases.hashicorp.com/vault/1.19.3/vault_1.19.3_freebsd_amd64.zip"
            echo "Download and Install hashicorp using this link"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            echo "https://releases.hashicorp.com/vault/1.19.3/vault_1.19.3_windows_amd64.zip"
            echo "Download and Install hashicorp using this link"
            ;;
        *)
            echo "Unknown OS: $OS"
            ;;
    esac
fi

vault server -dev -dev-root-token-id=root --dev-listen-address="0.0.0.0:8200";
