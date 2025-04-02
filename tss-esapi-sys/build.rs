// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    if std::env::var("DOCS_RS").is_ok() {
        // Nothing to be done for docs.rs builds.
        return;
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "generate-bindings")] {
            let installation = tpm2_tss::Installation::probe(true);
            let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
            installation.generate_bindings(&out_dir.join("tss_esapi_bindings.rs"));
        } else {
            target::ensure_supported();
            let _ = tpm2_tss::Installation::probe(false);
        }
    }
}

pub mod target {
    use std::str::FromStr;
    use target_lexicon::{Architecture, OperatingSystem, Triple};
    const TARGET_ENV_VAR_NAME: &str = "TARGET";

    /// Ensures that the `TARGET` is valid for cross compilation.
    pub fn ensure_supported() {
        let target = Triple::from_str(&std::env::var(TARGET_ENV_VAR_NAME).unwrap_or_else(|_| {
            panic!("Missing environment variable `{}`.", TARGET_ENV_VAR_NAME);
        }))
        .expect("Failed to parse target triple.");
        match (target.architecture, target.operating_system) {
            (Architecture::Arm(_), OperatingSystem::Linux)
            | (Architecture::Aarch64(_), OperatingSystem::Linux)
            | (Architecture::X86_64, OperatingSystem::Darwin)
            | (Architecture::X86_64, OperatingSystem::Linux) => {}
            (arch, os) => {
                panic!(
                    "Compilation target (architecture, OS) tuple ({}, {}) is not part of the \
                     supported tuples. Please compile with the \"generate-bindings\" feature or \
                     add support for your platform.",
                    arch, os
                );
            }
        }
    }
}

pub mod tpm2_tss {
    use semver::{Version, VersionReq};
    use std::{
        path::PathBuf,
    };
    const MINIMUM_VERSION: &str = "4.0.1";
    const PATH_ENV_VAR_NAME: &str = "TPM2_TSS_PATH";

    /// The installed tpm2-tss libraries that are of
    /// interest.
    pub struct Installation {
        _tss2_sys: Library,
        #[allow(unused)]
        tss2_esys: Library,
        #[allow(unused)]
        tss2_tctildr: Library,
        #[allow(unused)]
        tss2_mu: Library,
        #[allow(unused)]
        tss2_tcti_tbs: Option<Library>,
    }

    impl Installation {
        /// Probes the system for an installation.
        pub fn probe(with_header_files: bool) -> Self {
            let install_path = Installation::installation_path_from_env_var();
            Installation {
                _tss2_sys: Library::probe_required(
                    "tss2-sys",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_esys: Library::probe_required(
                    "tss2-esys",
                    install_path.as_ref(),
                    with_header_files,
                    true,
                ),
                tss2_tctildr: Library::probe_required(
                    "tss2-tctildr",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_mu: Library::probe_required(
                    "tss2-mu",
                    install_path.as_ref(),
                    with_header_files,
                    false,
                ),
                tss2_tcti_tbs: Library::probe_optional(
                    "tss2-tcti-tbs",
                    install_path.as_ref(),
                    with_header_files,
                ),
            }
        }

        cfg_if::cfg_if! {
            if #[cfg(feature = "generate-bindings")] {

                /// Generates bindings for the Installation.
                pub fn generate_bindings(&self, esapi_out: &Path) {
                    self.bindgen_builder()
                        .generate()
                        .expect("Unable to generate bindings to TSS2 ESYS APIs.")
                        .write_to_file(esapi_out)
                        .expect("Couldn't write ESYS bindings!");
                }

                /// The bindgen builder to use.
                fn bindgen_builder(&self) -> bindgen::Builder {
                    let mut builder = bindgen::Builder::default()
                        .size_t_is_usize(false)
                        .rust_target(bindgen::RustTarget::Stable_1_73) // lower or equal to MSRV.
                        .clang_arg(self.tss2_esys.include_dir_arg())
                        .clang_arg(self.tss2_tctildr.include_dir_arg())
                        .clang_arg(self.tss2_mu.include_dir_arg())
                        .formatter(bindgen::Formatter::Rustfmt)
                        .header(self.tss2_esys.header_file_arg())
                        .header(self.tss2_tctildr.header_file_arg())
                        .header(self.tss2_mu.header_file_arg())
                        //See this issue: https://github.com/parallaxsecond/rust-cryptoki/issues/12
                        .generate_comments(false)
                        .blocklist_type("max_align_t")
                        // Needed for windows
                        .blocklist_type("IMAGE_TLS_DIRECTORY")
                        .blocklist_type("PIMAGE_TLS_DIRECTORY")
                        .blocklist_type("IMAGE_TLS_DIRECTORY64")
                        .blocklist_type("PIMAGE_TLS_DIRECTORY64")
                        .blocklist_type("_IMAGE_TLS_DIRECTORY64")
                        .blocklist_type("MONITORINFOEX")
                        .blocklist_type("MONITORINFOEXA")
                        .blocklist_type("MONITORINFOEXW")
                        .blocklist_type("tagMONITORINFOEXA")
                        .blocklist_type("tagMONITORINFOEXW")
                        .blocklist_type("LPMONITORINFOEX")
                        .blocklist_type("LPMONITORINFOEXA")
                        .blocklist_type("LPMONITORINFOEXW")
                        .derive_default(true);
                    if let Some(tss2_tcti_tbs) = &self.tss2_tcti_tbs {
                        builder = builder
                            .clang_arg(tss2_tcti_tbs.include_dir_arg())
                            .header(tss2_tcti_tbs.header_file_arg());
                    }
                    builder
                }
            }
        }
        /// Retrieves the installation path from the environment variable and validates it.
        fn installation_path_from_env_var() -> Option<(PathBuf, String)> {
            std::env::var(PATH_ENV_VAR_NAME).map_or_else(
                |e| match e {
                    std::env::VarError::NotUnicode(invalid_value) => {
                        panic!(
                            "Invalid `{}` env var: `{:?}`.",
                            PATH_ENV_VAR_NAME, invalid_value
                        );
                    }
                    std::env::VarError::NotPresent => None,
                },
                |var| Some(Installation::ensure_valid_installation_path(var)),
            )
        }

        /// Ensures that the installation path is valid.
        ///
        /// # Details
        /// In order to be considered valid the following
        /// requirements needs to be full filled:
        /// 1. The directory must exist.
        /// 2. Sub directories `include` and `lib` must exist.
        /// 3. A `VERSION` file must be present in the directory and it needs to be
        ///    be specifying a version that is greater then the minimum supported version.
        ///
        /// The function is also responsible for reporting the library search path the rust compiler
        /// should use.
        ///
        /// # Arguments
        /// env_var - The value of the environment variable that contains the installation path.
        ///
        /// # Returns
        /// A tuple containing the validated installation path and the version associated with it.
        fn ensure_valid_installation_path(env_var: String) -> (PathBuf, String) {
            let install_path = PathBuf::from(env_var);
            if !install_path.is_dir() {
                panic!(
                    "The tpm2-tss installation path `{}` specifies an existing directory (`{}`).",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            if !install_path.join("include").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                     contain an `include` directory",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            if !install_path.join("lib").is_dir() {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                     contain an `lib` directory",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                );
            }
            let version_str =
                std::fs::read_to_string(install_path.join("VERSION")).unwrap_or_else(|e| {
                    panic!(
                        "The tpm2-tss installation path `{}` specifies a path `{}`, that does not \
                         contain a readable VERSION file: {}.",
                        PATH_ENV_VAR_NAME,
                        install_path.to_string_lossy(),
                        e,
                    );
                });
            let version = Version::parse(version_str.trim()).unwrap_or_else(|e| {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, contains a \
                     VERSION file that cannot be parsed: {}.",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                    e
                );
            });

            let min_version_req_str = format!(">={}", MINIMUM_VERSION);
            let min_version_req = VersionReq::parse(&min_version_req_str).unwrap_or_else(|e| {
                panic!(
                    "[Internal Error]: Failed to parse minimum tpm2-tss library version \
                     requirement. Error: `{}`. Please report this.",
                    e
                );
            });
            if !min_version_req.matches(&version) {
                panic!(
                    "The tpm2-tss installation path `{}` specifies a path `{}`, contains a \
                     VERSION file that specifies a version `{}` that does not meet the minimum \
                     version requirement `{}`.",
                    PATH_ENV_VAR_NAME,
                    install_path.to_string_lossy(),
                    version_str,
                    MINIMUM_VERSION,
                );
            }
            println!(
                "cargo:rustc-link-search=native={}",
                install_path.join("lib").to_string_lossy()
            );
            (install_path, version_str)
        }
    }

    /// Struct holding the information for a library.
    struct Library {
        #[allow(unused)]
        header_file: Option<PathBuf>,
        #[allow(unused)]
        name: String,
    }

    impl Library {
        /// Probes the different options for a required library.
        ///
        /// # Arguments
        ///     `lib_name`          - The name of the library.
        ///     `install_path`      - Optional path and version of installation.
        ///     `with_header_files` - Flag indicating if header files are required.
        ///     `report_version`    - Flag indicating if the version of the library should
        ///                           be reported to Cargo.
        ///
        /// # Returns
        ///     The detected installed library.
        /// # Panics
        ///     - If the library is not found.
        pub fn probe_required(
            _lib_name: &str,
            _install_path: Option<&(PathBuf, String)>,
            _with_header_files: bool,
            _report_version: bool,
        ) -> Self {
            Self {
                header_file: None,
                name: "".to_string(),
            }
        }

        /// Probes the different options for an optional library.
        ///
        /// # Arguments
        ///     `lib_name`          - The name of the library.
        ///     `install_path`      - Optional path and version of installation.
        ///     `with_header_files` - Flag indicating if header files are required.
        ///
        /// # Returns
        ///     The detected installed library or None if no library was found.
        pub fn probe_optional(
            _lib_name: &str,
            _install_path: Option<&(PathBuf, String)>,
            _with_header_files: bool,
        ) -> Option<Self> {
            None
        }

        /// The include dir `clang_arg` bindgen builder argument.
        ///
        /// # Panics
        ///     - If the library was probe without requiring header files.
        ///     - If the library specifies a header file does not have a parent directory.
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
        #[allow(unused)]
        pub fn include_dir_arg(&self) -> String {
            self.header_file
                .as_ref()
                .unwrap_or_else(|| panic!("No header file present for `{}`.", self.name))
                .parent()
                .unwrap_or_else(|| panic!("Inconsistent `{}` header file path.", self.name))
                .as_os_str()
                .to_str()
                .map_or_else(
                    || {
                        panic!(
                            "Error converting OsString to &str when processing `{}` include dir.",
                            self.name
                        );
                    },
                    |v| format!("-I{}", v),
                )
        }

        /// The header file path to a `header` bindgen argument.
        ///
        /// # Panics
        ///     - If the library specifies a header file path that contain invalid utf-8 characters.
        #[allow(unused)]
        pub fn header_file_arg(&self) -> &str {
            self.header_file.as_ref().map_or_else(
                || {
                    panic!("No header file present for `{}`.", self.name);
                },
                |v| {
                    v.as_os_str().to_str().unwrap_or_else(|| {
                        panic!(
                            "Error converting OsString to &str when processing `{}` include dir.",
                            self.name
                        )
                    })
                },
            )
        }
    }
}
