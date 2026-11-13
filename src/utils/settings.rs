use std::{ops::Deref, str::FromStr, sync::LazyLock};

use adw::prelude::*;

use gtk::{SortType, gio, glib};
use log::{debug, warn};
use strum_macros::{Display, EnumString, FromRepr};

use pastey::paste;

use crate::config::APP_ID;

pub static SETTINGS: LazyLock<Settings> = LazyLock::new(Settings::default);

macro_rules! bool_settings {
    ($($setting_name:ident),*) => {
        $(
            pub fn $setting_name(&self) -> bool {
                self.boolean(&stringify!($setting_name).replace("_", "-"))
            }

            paste! {
                pub fn [<set_ $setting_name>](&self, value: bool) -> Result<(), glib::error::BoolError> {
                    debug!("Setting boolean `{}` to {value}", stringify!($setting_name).replace("_", "-"));
                    self.set_boolean(&stringify!($setting_name).replace("_", "-"), value).inspect_err(|e| warn!("error writing setting `{}` to boolean {value}: {e}", stringify!($setting_name)))
                }

                pub fn [<connect_ $setting_name>]<F: Fn(bool) + 'static>(&self, f: F) -> glib::SignalHandlerId {
                    self.connect_changed(
                        Some(&stringify!($setting_name).replace("_", "-")),
                        move |settings, _key| {
                            f(settings.boolean(&stringify!($setting_name).replace("_", "-")))
                        },
                    )
                }
            }
        )*
    };
}

macro_rules! int_settings {
    ($($setting_name:ident),*) => {
        $(
            pub fn $setting_name(&self) -> i32 {
                self.int(&stringify!($setting_name).replace("_", "-"))
            }

            paste! {
                pub fn [<set_ $setting_name>](&self, value: i32) -> Result<(), glib::error::BoolError> {
                    debug!("Setting int `{}` to {value}", stringify!($setting_name).replace("_", "-"));
                    self.set_int(&stringify!($setting_name).replace("_", "-"), value).inspect_err(|e| warn!("error writing setting `{}` to int {value}: {e}", stringify!($setting_name)))
                }

                pub fn [<connect_ $setting_name>]<F: Fn(i32) + 'static>(&self, f: F) -> glib::SignalHandlerId {
                    self.connect_changed(
                        Some(&stringify!($setting_name).replace("_", "-")),
                        move |settings, _key| {
                            f(settings.int(&stringify!($setting_name).replace("_", "-")))
                        },
                    )
                }
            }
        )*
    };
}

macro_rules! uint_settings {
    ($($setting_name:ident),*) => {
        $(
            pub fn $setting_name(&self) -> u32 {
                self.uint(&stringify!($setting_name).replace("_", "-"))
            }

            paste! {
                pub fn [<set_ $setting_name>](&self, value: u32) -> Result<(), glib::error::BoolError> {
                    debug!("Setting uint `{}` to {value}", stringify!($setting_name).replace("_", "-"));
                    self.set_uint(&stringify!($setting_name).replace("_", "-"), value).inspect_err(|e| warn!("error writing setting `{}` to uint {value}: {e}", stringify!($setting_name)))
                }

                pub fn [<connect_ $setting_name>]<F: Fn(u32) + 'static>(&self, f: F) -> glib::SignalHandlerId {
                    self.connect_changed(
                        Some(&stringify!($setting_name).replace("_", "-")),
                        move |settings, _key| {
                            f(settings.uint(&stringify!($setting_name).replace("_", "-")))
                        },
                    )
                }
            }
        )*
    };
}

macro_rules! enum_settings {
    ($($setting_name:ident: $enum_type:ty),* $(,)?) => {
        $(
            pub fn $setting_name(&self) -> $enum_type {
                <$enum_type>::from_str(self.string(&stringify!($setting_name).replace("_", "-")).as_str())
                    .unwrap_or_default()
            }

            paste! {
                pub fn [<set_ $setting_name>](&self, value: $enum_type) -> Result<(), glib::error::BoolError> {
                    debug!("Setting string `{}` to \"{value}\"", stringify!($setting_name).replace("_", "-"));
                    self.set_string(&stringify!($setting_name).replace("_", "-"), &value.to_string())
                        .inspect_err(|e| {
                            warn!(
                                "error writing setting `{}` to string \"{value}\": {e}",
                                stringify!($setting_name).replace("_", "-")
                            );
                        })
                }

                pub fn [<connect_ $setting_name>]<F: Fn($enum_type) + 'static>(&self, f: F) -> glib::SignalHandlerId {
                    self.connect_changed(
                        Some(&stringify!($setting_name).replace("_", "-")),
                        move |settings, _key| {
                            f(<$enum_type>::from_str(
                                settings.string(&stringify!($setting_name).replace("_", "-")).as_str(),
                            ).unwrap_or_default());
                        },
                    )
                }
            }
        )*
    };
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, EnumString, Display, Hash, FromRepr)]
pub enum Base {
    #[default]
    Decimal,
    Binary,
}

impl Base {
    pub const fn base(&self) -> f64 {
        match self {
            Self::Decimal => 1000.0,
            Self::Binary => 1024.0,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, EnumString, Display, Hash, FromRepr)]
pub enum TemperatureUnit {
    #[default]
    Celsius,
    Kelvin,
    Fahrenheit,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, EnumString, Display, Hash, FromRepr)]
pub enum RefreshSpeed {
    VerySlow,
    Slow,
    #[default]
    Normal,
    Fast,
    VeryFast,
}

impl RefreshSpeed {
    pub const fn ui_refresh_interval(&self) -> f32 {
        match self {
            Self::VerySlow => 3.0,
            Self::Slow => 2.0,
            Self::Normal => 1.0,
            Self::Fast => 0.5,
            Self::VeryFast => 0.25,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, EnumString, Display, Hash, FromRepr)]
pub enum SidebarMeterType {
    #[default]
    ProgressBar,
    Graph,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, EnumString, Display, Hash, FromRepr)]
pub enum MemoryMetric {
    /// Virtual memory allocated by the process (but not necessarily actually used)
    VmSize,
    /// Physical memory currently used by this process, including shared libraries
    Rss,
    /// Physical memory used exclusively by this process, excluding shared libraries
    #[default]
    RssNoSharedMemory,
    /// Physical memory used for the process's heap and stack, excluding files and shared libraries
    RssAnon,
    /// Physical memory used by the process with shared libraries accounted for approximately proportionally (if available, otherwise RssNoSharedMemory). Very accurate but also more CPU-intensive
    ApproximatePss,
    /// Physical memory used by the process with shared libraries accounted for proportionally (if available, otherwise RssNoSharedMemory). Most accurate but also most CPU-intensive.
    Pss,
}

#[derive(Clone, Debug, Hash)]
pub struct Settings(gio::Settings);

impl Settings {
    pub fn last_viewed_page(&self) -> String {
        self.string("last-viewed-page").to_string()
    }

    pub fn set_last_viewed_page<S: AsRef<str>>(
        &self,
        value: S,
    ) -> Result<(), glib::error::BoolError> {
        debug!(
            "Setting string `last-viewed-page` to \"{}\"",
            value.as_ref()
        );
        self.set_string("last-viewed-page", value.as_ref())
            .inspect_err(|e| {
                warn!(
                    "error writing setting `last-viewed-page` to string \"{}\": {e}",
                    value.as_ref()
                );
            })
    }

    pub fn connect_last_viewed_page<F: Fn(String) + 'static>(&self, f: F) -> glib::SignalHandlerId {
        self.connect_changed(Some("last-viewed-page"), move |settings, _key| {
            f(settings.string("last-viewed-page").to_string());
        })
    }

    // the following three functions are kept for compatibility reasons and for not having an oddly named function
    // called "set_is_maximized" generated by the macro
    pub fn maximized(&self) -> bool {
        self.boolean("is-maximized")
    }

    pub fn set_maximized(&self, value: bool) -> Result<(), glib::error::BoolError> {
        debug!("Setting boolean `is-maximized` to {value}");
        self.set_boolean("is-maximized", value)
            .inspect_err(|e| warn!("error writing setting `is-maximized` to boolean {value}: {e}"))
    }

    pub fn connect_maximized<F: Fn(bool) + 'static>(&self, f: F) -> glib::SignalHandlerId {
        self.connect_changed(Some("is-maximized"), move |settings, _key| {
            f(settings.boolean("is-maximized"));
        })
    }

    pub fn processes_sort_by_ascending(&self) -> SortType {
        if self.boolean("processes-sort-by-ascending") {
            SortType::Ascending
        } else {
            SortType::Descending
        }
    }

    pub fn set_processes_sort_by_ascending(
        &self,
        value: SortType,
    ) -> Result<(), glib::error::BoolError> {
        let setting = matches!(value, SortType::Ascending);
        debug!("Setting boolean `processes-sort-by-ascending` to {setting}");
        self.set_boolean("processes-sort-by-ascending", setting)
            .inspect_err(|e| {
                warn!(
                    "error writing setting `processes-sort-by-ascending` to boolean {setting}: {e}",
                );
            })
    }

    pub fn connect_processes_sort_by_ascending<F: Fn(SortType) + 'static>(
        &self,
        f: F,
    ) -> glib::SignalHandlerId {
        self.connect_changed(
            Some("processes-sort-by-ascending"),
            move |settings, _key| {
                let sort_type = if settings.boolean("processes-sort-by-ascending") {
                    SortType::Ascending
                } else {
                    SortType::Descending
                };

                f(sort_type);
            },
        )
    }

    pub fn apps_sort_by_ascending(&self) -> SortType {
        if self.boolean("apps-sort-by-ascending") {
            SortType::Ascending
        } else {
            SortType::Descending
        }
    }

    pub fn set_apps_sort_by_ascending(
        &self,
        value: SortType,
    ) -> Result<(), glib::error::BoolError> {
        let setting = matches!(value, SortType::Ascending);
        debug!("Setting boolean `apps-sort-by-ascending` to {setting}");
        self.set_boolean("apps-sort-by-ascending", setting)
            .inspect_err(|e| {
                warn!("error writing setting `apps-sort-by-ascending` to boolean {setting}: {e}");
            })
    }

    pub fn connect_apps_sort_by_ascending<F: Fn(SortType) + 'static>(
        &self,
        f: F,
    ) -> glib::SignalHandlerId {
        self.connect_changed(Some("apps-sort-by-ascending"), move |settings, _key| {
            let sort_type = if settings.boolean("apps-sort-by-ascending") {
                SortType::Ascending
            } else {
                SortType::Descending
            };

            f(sort_type);
        })
    }

    int_settings!(window_width, window_height, processes_highlight_duration);

    uint_settings!(
        graph_data_points,
        apps_sort_by,
        processes_sort_by,
        processes_details_mode
    );

    bool_settings!(
        show_virtual_drives,
        show_virtual_network_interfaces,
        network_bits,
        apps_show_memory,
        apps_show_cpu,
        apps_show_drive_read_speed,
        apps_show_drive_read_total,
        apps_show_drive_write_speed,
        apps_show_drive_write_total,
        apps_show_gpu,
        apps_show_gpu_memory,
        apps_show_encoder,
        apps_show_decoder,
        apps_show_swap,
        apps_show_combined_memory,
        processes_show_id,
        processes_show_user,
        processes_show_memory,
        processes_show_cpu,
        processes_show_drive_read_speed,
        processes_show_drive_read_total,
        processes_show_drive_write_speed,
        processes_show_drive_write_total,
        processes_show_gpu,
        processes_show_gpu_memory,
        processes_show_encoder,
        processes_show_decoder,
        processes_show_total_cpu_time,
        processes_show_user_cpu_time,
        processes_show_system_cpu_time,
        processes_show_priority,
        processes_show_swap,
        processes_show_combined_memory,
        processes_show_commandline,
        processes_show_virustotal,
        processes_tree_view,
        processes_show_details,
        processes_row_colors,
        memory_show_swap_devices,
        show_logical_cpus,
        show_graph_grids,
        normalize_cpu_usage,
        detailed_priority
    );

    enum_settings!(
        temperature_unit: TemperatureUnit,
        memory_metric: MemoryMetric,
        base: Base,
        refresh_speed: RefreshSpeed,
        sidebar_meter_type: SidebarMeterType,
    );
}

impl Deref for Settings {
    type Target = gio::Settings;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self(gio::Settings::new(APP_ID))
    }
}

unsafe impl Send for Settings {}
unsafe impl Sync for Settings {}
