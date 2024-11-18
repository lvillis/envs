use clap::Parser;
use envs::{
    get_environment_info, Capability, ContainerEnvironment, OperatingSystem, VirtualizationPlatform,
};

/// Simple CLI to display environment information.
#[derive(Parser)]
#[command(name = "env_cli")]
#[command(about = "Displays the current environment information", long_about = None)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();

    let info = get_environment_info();

    println!("Operating System: {}", format_os(&info.os));
    println!(
        "Container Environment: {}",
        format_container(&info.container)
    );
    println!(
        "Virtualization Platform: {}",
        format_virtualization(&info.virtualization)
    );

    if let Some(caps) = &info.capabilities {
        println!("Capabilities:");
        for cap in &caps.effective {
            println!("  - {}", format_capability(cap));
        }
    } else {
        println!("Capabilities: Not Available or Not Applicable");
    }
}

/// Formats the OperatingSystem enum into a readable string.
fn format_os(os: &OperatingSystem) -> String {
    match os {
        OperatingSystem::Windows => "Windows".to_string(),
        OperatingSystem::Linux => "Linux".to_string(),
        OperatingSystem::MacOS => "macOS".to_string(),
        OperatingSystem::Unknown(name) => format!("Unknown ({})", name),
    }
}

/// Formats the ContainerEnvironment enum into a readable string.
fn format_container(container: &ContainerEnvironment) -> String {
    match container {
        ContainerEnvironment::Docker => "Docker".to_string(),
        ContainerEnvironment::Kubernetes => "Kubernetes".to_string(),
        ContainerEnvironment::Podman => "Podman".to_string(),
        ContainerEnvironment::None => "None".to_string(),
    }
}

/// Formats the VirtualizationPlatform enum into a readable string.
fn format_virtualization(virtualization: &VirtualizationPlatform) -> String {
    match virtualization {
        VirtualizationPlatform::VMware => "VMware".to_string(),
        VirtualizationPlatform::VirtualBox => "VirtualBox".to_string(),
        VirtualizationPlatform::HyperV => "Hyper-V".to_string(),
        VirtualizationPlatform::KVM => "KVM".to_string(),
        VirtualizationPlatform::Other(name) => format!("Other ({})", name),
        VirtualizationPlatform::None => "None".to_string(),
    }
}

/// Formats a single Capability enum into a readable string.
fn format_capability(cap: &Capability) -> String {
    match cap {
        Capability::CAP_CHOWN => "CAP_CHOWN".to_string(),
        Capability::CAP_DAC_OVERRIDE => "CAP_DAC_OVERRIDE".to_string(),
        Capability::CAP_DAC_READ_SEARCH => "CAP_DAC_READ_SEARCH".to_string(),
        Capability::CAP_FOWNER => "CAP_FOWNER".to_string(),
        Capability::CAP_FSETID => "CAP_FSETID".to_string(),
        Capability::CAP_KILL => "CAP_KILL".to_string(),
        Capability::CAP_SETGID => "CAP_SETGID".to_string(),
        Capability::CAP_SETUID => "CAP_SETUID".to_string(),
        Capability::CAP_SETPCAP => "CAP_SETPCAP".to_string(),
        Capability::CAP_LINUX_IMMUTABLE => "CAP_LINUX_IMMUTABLE".to_string(),
        Capability::CAP_NET_BIND_SERVICE => "CAP_NET_BIND_SERVICE".to_string(),
        Capability::CAP_NET_BROADCAST => "CAP_NET_BROADCAST".to_string(),
        Capability::CAP_NET_ADMIN => "CAP_NET_ADMIN".to_string(),
        Capability::CAP_NET_RAW => "CAP_NET_RAW".to_string(),
        Capability::CAP_IPC_LOCK => "CAP_IPC_LOCK".to_string(),
        Capability::CAP_IPC_OWNER => "CAP_IPC_OWNER".to_string(),
        Capability::CAP_SYS_MODULE => "CAP_SYS_MODULE".to_string(),
        Capability::CAP_SYS_RAWIO => "CAP_SYS_RAWIO".to_string(),
        Capability::CAP_SYS_CHROOT => "CAP_SYS_CHROOT".to_string(),
        Capability::CAP_SYS_PTRACE => "CAP_SYS_PTRACE".to_string(),
        Capability::CAP_SYS_PACCT => "CAP_SYS_PACCT".to_string(),
        Capability::CAP_SYS_ADMIN => "CAP_SYS_ADMIN".to_string(),
        Capability::CAP_SYS_BOOT => "CAP_SYS_BOOT".to_string(),
        Capability::CAP_SYS_NICE => "CAP_SYS_NICE".to_string(),
        Capability::CAP_SYS_RESOURCE => "CAP_SYS_RESOURCE".to_string(),
        Capability::CAP_SYS_TIME => "CAP_SYS_TIME".to_string(),
        Capability::CAP_SYS_TTY_CONFIG => "CAP_SYS_TTY_CONFIG".to_string(),
        Capability::CAP_MKNOD => "CAP_MKNOD".to_string(),
        Capability::CAP_LEASE => "CAP_LEASE".to_string(),
        Capability::CAP_AUDIT_WRITE => "CAP_AUDIT_WRITE".to_string(),
        Capability::CAP_AUDIT_CONTROL => "CAP_AUDIT_CONTROL".to_string(),
        Capability::CAP_SETFCAP => "CAP_SETFCAP".to_string(),
        Capability::Unknown(name) => format!("Unknown ({})", name),
    }
}
