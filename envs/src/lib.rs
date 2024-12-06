use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::fmt;

/// Trait to abstract filesystem operations for easier testing.
pub trait FileSystem {
    fn file_exists(&self, path: &Path) -> bool;
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
}

/// Real filesystem implementation of the `FileSystem` trait.
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn file_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }
}

/// Enum representing supported operating systems.
#[derive(Debug, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOS,
    Unknown(String),
}

impl fmt::Display for OperatingSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperatingSystem::Windows => write!(f, "Windows"),
            OperatingSystem::Linux => write!(f, "Linux"),
            OperatingSystem::MacOS => write!(f, "macOS"),
            OperatingSystem::Unknown(name) => write!(f, "Unknown ({})", name),
        }
    }
}

/// Enum representing different container environments.
#[derive(Debug, PartialEq, Eq)]
pub enum ContainerEnvironment {
    Docker,
    Kubernetes,
    Podman,
    None,
}

impl fmt::Display for ContainerEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerEnvironment::Docker => write!(f, "Docker"),
            ContainerEnvironment::Kubernetes => write!(f, "Kubernetes"),
            ContainerEnvironment::Podman => write!(f, "Podman"),
            ContainerEnvironment::None => write!(f, "None"),
        }
    }
}

/// Enum representing virtualization platforms.
#[derive(Debug, PartialEq, Eq)]
pub enum VirtualizationPlatform {
    VMware,
    VirtualBox,
    HyperV,
    KVM,
    Other(String),
    None,
}

impl fmt::Display for VirtualizationPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VirtualizationPlatform::VMware => write!(f, "VMware"),
            VirtualizationPlatform::VirtualBox => write!(f, "VirtualBox"),
            VirtualizationPlatform::HyperV => write!(f, "Hyper-V"),
            VirtualizationPlatform::KVM => write!(f, "KVM"),
            VirtualizationPlatform::Other(name) => write!(f, "Other ({})", name),
            VirtualizationPlatform::None => write!(f, "None"),
        }
    }
}

/// Enum representing specific capabilities.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Capability {
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_DAC_READ_SEARCH,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_LINUX_IMMUTABLE,
    CAP_NET_BIND_SERVICE,
    CAP_NET_BROADCAST,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_IPC_LOCK,
    CAP_IPC_OWNER,
    CAP_SYS_MODULE,
    CAP_SYS_RAWIO,
    CAP_SYS_CHROOT,
    CAP_SYS_PTRACE,
    CAP_SYS_PACCT,
    CAP_SYS_ADMIN,
    CAP_SYS_BOOT,
    CAP_SYS_NICE,
    CAP_SYS_RESOURCE,
    CAP_SYS_TIME,
    CAP_SYS_TTY_CONFIG,
    CAP_MKNOD,
    CAP_LEASE,
    CAP_AUDIT_WRITE,
    CAP_AUDIT_CONTROL,
    CAP_SETFCAP,
    Unknown(String),
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::CAP_CHOWN => write!(f, "CAP_CHOWN"),
            Capability::CAP_DAC_OVERRIDE => write!(f, "CAP_DAC_OVERRIDE"),
            Capability::CAP_DAC_READ_SEARCH => write!(f, "CAP_DAC_READ_SEARCH"),
            Capability::CAP_FOWNER => write!(f, "CAP_FOWNER"),
            Capability::CAP_FSETID => write!(f, "CAP_FSETID"),
            Capability::CAP_KILL => write!(f, "CAP_KILL"),
            Capability::CAP_SETGID => write!(f, "CAP_SETGID"),
            Capability::CAP_SETUID => write!(f, "CAP_SETUID"),
            Capability::CAP_SETPCAP => write!(f, "CAP_SETPCAP"),
            Capability::CAP_LINUX_IMMUTABLE => write!(f, "CAP_LINUX_IMMUTABLE"),
            Capability::CAP_NET_BIND_SERVICE => write!(f, "CAP_NET_BIND_SERVICE"),
            Capability::CAP_NET_BROADCAST => write!(f, "CAP_NET_BROADCAST"),
            Capability::CAP_NET_ADMIN => write!(f, "CAP_NET_ADMIN"),
            Capability::CAP_NET_RAW => write!(f, "CAP_NET_RAW"),
            Capability::CAP_IPC_LOCK => write!(f, "CAP_IPC_LOCK"),
            Capability::CAP_IPC_OWNER => write!(f, "CAP_IPC_OWNER"),
            Capability::CAP_SYS_MODULE => write!(f, "CAP_SYS_MODULE"),
            Capability::CAP_SYS_RAWIO => write!(f, "CAP_SYS_RAWIO"),
            Capability::CAP_SYS_CHROOT => write!(f, "CAP_SYS_CHROOT"),
            Capability::CAP_SYS_PTRACE => write!(f, "CAP_SYS_PTRACE"),
            Capability::CAP_SYS_PACCT => write!(f, "CAP_SYS_PACCT"),
            Capability::CAP_SYS_ADMIN => write!(f, "CAP_SYS_ADMIN"),
            Capability::CAP_SYS_BOOT => write!(f, "CAP_SYS_BOOT"),
            Capability::CAP_SYS_NICE => write!(f, "CAP_SYS_NICE"),
            Capability::CAP_SYS_RESOURCE => write!(f, "CAP_SYS_RESOURCE"),
            Capability::CAP_SYS_TIME => write!(f, "CAP_SYS_TIME"),
            Capability::CAP_SYS_TTY_CONFIG => write!(f, "CAP_SYS_TTY_CONFIG"),
            Capability::CAP_MKNOD => write!(f, "CAP_MKNOD"),
            Capability::CAP_LEASE => write!(f, "CAP_LEASE"),
            Capability::CAP_AUDIT_WRITE => write!(f, "CAP_AUDIT_WRITE"),
            Capability::CAP_AUDIT_CONTROL => write!(f, "CAP_AUDIT_CONTROL"),
            Capability::CAP_SETFCAP => write!(f, "CAP_SETFCAP"),
            Capability::Unknown(name) => write!(f, "Unknown ({})", name),
        }
    }
}

/// Struct holding the detected capabilities.
#[derive(Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub effective: HashSet<Capability>,
}

/// Struct holding the environment information.
#[derive(Debug, PartialEq, Eq)]
pub struct EnvironmentInfo {
    pub os: OperatingSystem,
    pub container: ContainerEnvironment,
    pub virtualization: VirtualizationPlatform,
    pub capabilities: Option<Capabilities>,
}

/// Retrieves the current operating system.
pub fn get_os() -> OperatingSystem {
    match env::consts::OS {
        "windows" => OperatingSystem::Windows,
        "linux" => OperatingSystem::Linux,
        "macos" => OperatingSystem::MacOS,
        other => OperatingSystem::Unknown(other.to_string()),
    }
}

/// Checks if the environment is Kubernetes by verifying specific environment variables.
fn is_kubernetes() -> bool {
    env::var("KUBERNETES_SERVICE_HOST").is_ok()
}

/// Attempts to determine the container runtime by inspecting specific environment variables.
/// This function can be expanded to include more sophisticated detection mechanisms.
fn get_container_runtime() -> Option<String> {
    // Example: Check for container runtime environment variable.
    env::var("CONTAINER_RUNTIME").ok()
}

/// Detects the current container environment using the provided `FileSystem`.
pub fn detect_container(fs: &dyn FileSystem) -> ContainerEnvironment {
    // Check for Kubernetes environment
    if is_kubernetes() {
        return ContainerEnvironment::Kubernetes;
    }

    // Check for /.dockerenv file
    if fs.file_exists(Path::new("/.dockerenv")) {
        // Further distinguish between Docker and Podman if possible.
        if let Some(container_runtime) = get_container_runtime() {
            return match container_runtime.as_str() {
                "docker" => ContainerEnvironment::Docker,
                "podman" => ContainerEnvironment::Podman,
                _ => ContainerEnvironment::None,
            };
        }
        return ContainerEnvironment::Docker;
    }

    // Check /proc/1/cgroup for Docker or Podman identifiers
    if let Ok(cgroup) = fs.read_to_string(Path::new("/proc/1/cgroup")) {
        if cgroup.contains("docker") {
            return ContainerEnvironment::Docker;
        } else if cgroup.contains("podman") {
            return ContainerEnvironment::Podman;
        }
    }

    ContainerEnvironment::None
}

/// Capability bit position mapping
const CAPABILITY_BIT_MAP: [Option<Capability>; 32] = [
    Some(Capability::CAP_CHOWN),             // 0
    Some(Capability::CAP_DAC_OVERRIDE),      // 1
    Some(Capability::CAP_DAC_READ_SEARCH),   // 2
    Some(Capability::CAP_FOWNER),            // 3
    Some(Capability::CAP_FSETID),            // 4
    Some(Capability::CAP_KILL),              // 5
    Some(Capability::CAP_SETGID),            // 6
    Some(Capability::CAP_SETUID),            // 7
    Some(Capability::CAP_SETPCAP),           // 8
    Some(Capability::CAP_LINUX_IMMUTABLE),   // 9
    Some(Capability::CAP_NET_BIND_SERVICE),  // 10
    Some(Capability::CAP_NET_BROADCAST),     // 11
    Some(Capability::CAP_NET_ADMIN),         // 12
    Some(Capability::CAP_NET_RAW),           // 13
    Some(Capability::CAP_IPC_LOCK),          // 14
    Some(Capability::CAP_IPC_OWNER),         // 15
    Some(Capability::CAP_SYS_MODULE),        // 16
    Some(Capability::CAP_SYS_RAWIO),         // 17
    Some(Capability::CAP_SYS_CHROOT),        // 18
    Some(Capability::CAP_SYS_PTRACE),        // 19
    Some(Capability::CAP_SYS_PACCT),         // 20
    Some(Capability::CAP_SYS_ADMIN),         // 21
    Some(Capability::CAP_SYS_BOOT),          // 22
    Some(Capability::CAP_SYS_NICE),          // 23
    Some(Capability::CAP_SYS_RESOURCE),      // 24
    Some(Capability::CAP_SYS_TIME),          // 25
    Some(Capability::CAP_SYS_TTY_CONFIG),    // 26
    Some(Capability::CAP_MKNOD),             // 27
    Some(Capability::CAP_LEASE),             // 28
    Some(Capability::CAP_AUDIT_WRITE),       // 29
    Some(Capability::CAP_AUDIT_CONTROL),     // 30
    Some(Capability::CAP_SETFCAP),           // 31
];

/// Parses the CapEff value and returns a list of enabled capabilities.
fn parse_capabilities(cap_eff: u64) -> Vec<Capability> {
    let mut capabilities = Vec::new();
    for bit in 0..32 {
        if cap_eff & (1 << bit) != 0 {
            if let Some(cap) = CAPABILITY_BIT_MAP[bit as usize].clone() {
                capabilities.push(cap);
            } else {
                capabilities.push(Capability::Unknown(format!("Bit {}", bit)));
            }
        }
    }
    capabilities
}

/// Reads and parses the CapEff field from /proc/self/status to determine effective capabilities.
fn get_capabilities(fs: &dyn FileSystem) -> Option<Capabilities> {
    let status_path = Path::new("/proc/self/status");
    if !fs.file_exists(status_path) {
        return None;
    }

    let status_content = match fs.read_to_string(status_path) {
        Ok(content) => content,
        Err(_) => return None,
    };

    // Find the CapEff line
    let cap_eff_line = status_content
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .map(|line| line.trim_start_matches("CapEff:").trim());

    let cap_eff_str = match cap_eff_line {
        Some(s) => s,
        None => return None,
    };

    // Parse the hexadecimal CapEff value
    let cap_eff = match u64::from_str_radix(cap_eff_str, 16) {
        Ok(val) => val,
        Err(_) => return None,
    };

    // Parse capabilities using the provided parse_capabilities function
    let capabilities = parse_capabilities(cap_eff);

    Some(Capabilities {
        effective: capabilities.into_iter().collect(),
    })
}

/// Detects the current virtualization platform using the provided `FileSystem`.
pub fn detect_virtualization(fs: &dyn FileSystem) -> VirtualizationPlatform {
    // If running inside a container, skip virtualization detection
    if detect_container(fs) != ContainerEnvironment::None {
        return VirtualizationPlatform::None;
    }

    let mut is_hypervisor = false;

    // On Linux, check for hypervisor or kvm flag in /proc/cpuinfo
    if let Ok(cpuinfo) = fs.read_to_string(Path::new("/proc/cpuinfo")) {
        let cpuinfo_lower = cpuinfo.to_lowercase();
        if cpuinfo_lower.contains("hypervisor") || cpuinfo_lower.contains("kvm") {
            is_hypervisor = true;
        }
    }

    // Additionally, check for /dev/kvm
    if fs.file_exists(Path::new("/dev/kvm")) {
        is_hypervisor = true;
    }

    if is_hypervisor {
        // Further distinguish virtualization platforms by checking DMI info
        for path in [
            Path::new("/sys/class/dmi/id/product_name"),
            Path::new("/sys/class/dmi/id/sys_vendor"),
        ]
            .iter()
        {
            if let Ok(content) = fs.read_to_string(path) {
                let content_lower = content.to_lowercase();
                if content_lower.contains("virtualbox") {
                    return VirtualizationPlatform::VirtualBox;
                } else if content_lower.contains("vmware") {
                    return VirtualizationPlatform::VMware;
                } else if content_lower.contains("hyper-v") || content_lower.contains("microsoft corporation") {
                    return VirtualizationPlatform::HyperV;
                } else if content_lower.contains("kvm") || content_lower.contains("q35") || content_lower.contains("standard pc") {
                    return VirtualizationPlatform::KVM;
                } else if !content.trim().is_empty() {
                    return VirtualizationPlatform::Other(content.trim().to_string());
                }
            }
        }

        // If no DMI info matches, but hypervisor flag is set, assume KVM
        return VirtualizationPlatform::KVM;
    }

    VirtualizationPlatform::None
}

/// Retrieves the complete environment information using the real filesystem.
pub fn get_environment_info() -> EnvironmentInfo {
    let fs = RealFileSystem;
    let container = detect_container(&fs);
    let capabilities = if container == ContainerEnvironment::Docker {
        get_capabilities(&fs)
    } else {
        None
    };
    EnvironmentInfo {
        os: get_os(),
        container,
        virtualization: detect_virtualization(&fs),
        capabilities,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::env;
    use std::path::PathBuf;

    /// Mock filesystem for testing purposes.
    struct MockFileSystem {
        existing_files: Vec<PathBuf>,
        file_contents: HashMap<PathBuf, String>,
    }

    impl MockFileSystem {
        fn new() -> Self {
            Self {
                existing_files: Vec::new(),
                file_contents: HashMap::new(),
            }
        }

        /// Adds a file to the mock filesystem with specified contents.
        fn add_file(&mut self, path: PathBuf, contents: String) {
            self.existing_files.push(path.clone());
            self.file_contents.insert(path, contents);
        }
    }

    impl FileSystem for MockFileSystem {
        fn file_exists(&self, path: &Path) -> bool {
            self.existing_files.iter().any(|p| p == path)
        }

        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            if let Some(content) = self.file_contents.get(path) {
                Ok(content.clone())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File not found",
                ))
            }
        }
    }

    #[test]
    fn test_get_os() {
        let os = get_os();
        #[cfg(target_os = "windows")]
        assert_eq!(os, OperatingSystem::Windows);
        #[cfg(target_os = "linux")]
        assert_eq!(os, OperatingSystem::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(os, OperatingSystem::MacOS);
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        match os {
            OperatingSystem::Unknown(ref s) => println!("Unknown OS: {}", s),
            _ => panic!("Expected Unknown OS variant"),
        }
    }

    #[test]
    fn test_is_kubernetes() {
        // Simulate Kubernetes environment variable
        env::set_var("KUBERNETES_SERVICE_HOST", "localhost");
        assert!(is_kubernetes());

        // Remove the environment variable
        env::remove_var("KUBERNETES_SERVICE_HOST");
        assert!(!is_kubernetes());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_docker() {
        let mut mock_fs = MockFileSystem::new();
        mock_fs.add_file(PathBuf::from("/.dockerenv"), "".to_string());
        // Simulate container runtime
        env::set_var("CONTAINER_RUNTIME", "docker");

        let container = detect_container(&mock_fs);
        assert_eq!(container, ContainerEnvironment::Docker);

        env::remove_var("CONTAINER_RUNTIME");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_podman() {
        let mut mock_fs = MockFileSystem::new();
        mock_fs.add_file(PathBuf::from("/.dockerenv"), "".to_string());
        env::set_var("CONTAINER_RUNTIME", "podman");

        let container = detect_container(&mock_fs);
        assert_eq!(container, ContainerEnvironment::Podman);

        env::remove_var("CONTAINER_RUNTIME");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_docker_via_cgroup() {
        let mut mock_fs = MockFileSystem::new();
        // Simulate /proc/1/cgroup containing "docker"
        mock_fs.add_file(PathBuf::from("/proc/1/cgroup"), "docker".to_string());

        let container = detect_container(&mock_fs);
        assert_eq!(container, ContainerEnvironment::Docker);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_podman_via_cgroup() {
        let mut mock_fs = MockFileSystem::new();
        // Simulate /proc/1/cgroup containing "podman"
        mock_fs.add_file(PathBuf::from("/proc/1/cgroup"), "podman".to_string());

        let container = detect_container(&mock_fs);
        assert_eq!(container, ContainerEnvironment::Podman);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_none() {
        let mock_fs = MockFileSystem::new();
        let container = detect_container(&mock_fs);
        assert_eq!(container, ContainerEnvironment::None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_virtualbox() {
        let mut mock_fs = MockFileSystem::new();
        // Ensure not running in container
        // Simulate /proc/cpuinfo containing "hypervisor"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor".to_string(),
        );
        // Simulate /sys/class/dmi/id/product_name containing "VirtualBox"
        mock_fs.add_file(
            PathBuf::from("/sys/class/dmi/id/product_name"),
            "VirtualBox".to_string(),
        );

        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(virtualization, VirtualizationPlatform::VirtualBox);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_vmware() {
        let mut mock_fs = MockFileSystem::new();
        // Ensure not running in container
        // Simulate /proc/cpuinfo containing "hypervisor"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor".to_string(),
        );
        // Simulate /sys/class/dmi/id/sys_vendor containing "VMware"
        mock_fs.add_file(
            PathBuf::from("/sys/class/dmi/id/sys_vendor"),
            "VMware, Inc.".to_string(),
        );

        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(virtualization, VirtualizationPlatform::VMware);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_hyperv() {
        let mut mock_fs = MockFileSystem::new();
        // Ensure not running in container
        // Simulate /proc/cpuinfo containing "hypervisor"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor".to_string(),
        );
        // Simulate /sys/class/dmi/id/sys_vendor containing "Microsoft Corporation" (Hyper-V)
        mock_fs.add_file(
            PathBuf::from("/sys/class/dmi/id/sys_vendor"),
            "Microsoft Corporation".to_string(),
        );

        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(virtualization, VirtualizationPlatform::HyperV);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_kvm() {
        let mut mock_fs = MockFileSystem::new();
        // Ensure not running in container
        // Simulate /proc/cpuinfo containing "hypervisor" and "kvm"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor kvm".to_string(),
        );
        // Simulate /dev/kvm exists
        mock_fs.add_file(PathBuf::from("/dev/kvm"), "".to_string());

        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(virtualization, VirtualizationPlatform::KVM);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_other() {
        let mut mock_fs = MockFileSystem::new();
        // Ensure not running in container
        // Simulate /proc/cpuinfo containing "hypervisor"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor".to_string(),
        );
        // Simulate /sys/class/dmi/id/sys_vendor containing unknown platform
        mock_fs.add_file(
            PathBuf::from("/sys/class/dmi/id/sys_vendor"),
            "Standard PC (Q35 + ICH9, 2009)".to_string(),
        );

        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(
            virtualization,
            VirtualizationPlatform::Other("Standard PC (Q35 + ICH9, 2009)".to_string())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_virtualization_none() {
        let mock_fs = MockFileSystem::new();
        let virtualization = detect_virtualization(&mock_fs);
        assert_eq!(virtualization, VirtualizationPlatform::None);
    }

    #[test]
    fn test_get_environment_info() {
        // Simulate Kubernetes environment
        env::set_var("KUBERNETES_SERVICE_HOST", "localhost");
        let info = get_environment_info_with_fs(&RealFileSystem);
        #[cfg(target_os = "windows")]
        assert_eq!(info.os, OperatingSystem::Windows);
        #[cfg(target_os = "linux")]
        assert_eq!(info.os, OperatingSystem::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(info.os, OperatingSystem::MacOS);
        assert_eq!(info.container, ContainerEnvironment::Kubernetes);
        assert_eq!(info.virtualization, VirtualizationPlatform::None);
        assert_eq!(info.capabilities, None);
        env::remove_var("KUBERNETES_SERVICE_HOST");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_environment_info_virtualization() {
        let mut mock_fs = MockFileSystem::new();
        // Simulate /proc/cpuinfo containing "hypervisor" and "kvm"
        mock_fs.add_file(
            PathBuf::from("/proc/cpuinfo"),
            "flags : hypervisor kvm".to_string(),
        );
        // Simulate /sys/class/dmi/id/product_name containing "Standard PC (Q35 + ICH9, 2009)"
        mock_fs.add_file(
            PathBuf::from("/sys/class/dmi/id/product_name"),
            "Standard PC (Q35 + ICH9, 2009)".to_string(),
        );

        let info = get_environment_info_with_fs(&mock_fs);
        assert_eq!(info.os, OperatingSystem::Linux);
        assert_eq!(info.container, ContainerEnvironment::None);
        assert_eq!(info.virtualization, VirtualizationPlatform::KVM);
        assert_eq!(info.capabilities, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_environment_info_capabilities() {
        let mut mock_fs = MockFileSystem::new();
        // Simulate Docker environment
        mock_fs.add_file(PathBuf::from("/.dockerenv"), "".to_string());
        // Simulate CapEff in /proc/self/status (e.g., CapEff=00000000002c0000)
        mock_fs.add_file(
            PathBuf::from("/proc/self/status"),
            "CapEff: 00000000002c0000\n".to_string(),
        );

        let capabilities = get_capabilities(&mock_fs).unwrap();
        let expected: HashSet<Capability> = vec![
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SYS_CHROOT,
        ]
            .into_iter()
            .collect();
        assert_eq!(capabilities.effective, expected);
    }

    /// Helper function to get environment info using a specific `FileSystem` implementation.
    fn get_environment_info_with_fs(fs: &dyn FileSystem) -> EnvironmentInfo {
        EnvironmentInfo {
            os: get_os(),
            container: detect_container(fs),
            virtualization: detect_virtualization(fs),
            capabilities: if detect_container(fs) == ContainerEnvironment::Docker {
                get_capabilities(fs)
            } else {
                None
            },
        }
    }
}
