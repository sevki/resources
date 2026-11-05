use adw::{prelude::*, subclass::prelude::*};
use gtk::glib::{self, clone};
use log::trace;
use std::num::NonZeroU64;

use crate::config::DEVLOPMENT_BUILD;
use crate::devices::memory::{MemoryData, MemoryDevice, SwapDevice};
use crate::ui::widgets::graph_box::ResGraphBox;
use crate::ui::widgets::stack_sidebar_item::UsageLabels;
use crate::utils::i18n::{i18n, i18n_f};
use crate::utils::settings::SETTINGS;
use crate::utils::units::{convert_fraction, convert_storage};

pub const TAB_ID: &str = "memory";
const INACTIVE_SWAP_GRAPH_RETENTION_TICKS: u64 = 600;

struct SwapUiMode {
    usage: Option<SwapUsage>,
    show_options: bool,
}

#[derive(Clone, Copy)]
struct SwapUsage {
    used: u64,
    total: NonZeroU64,
}

impl SwapUsage {
    fn from_devices(swap_devices: &[SwapDevice]) -> Option<Self> {
        let used = swap_devices.iter().map(|device| device.used as u64).sum();
        let total = swap_devices
            .iter()
            .map(|device| device.size as u64)
            .sum::<u64>();

        NonZeroU64::new(total).map(|total| Self { used, total })
    }

    fn fraction(self) -> f64 {
        self.used as f64 / self.total.get() as f64
    }
}

pub struct SwapGraphEntry {
    name: String,
    graph_box: ResGraphBox,
    size_bytes: u64,
    last_seen_tick: u64,
    active: bool,
}

enum SwapUiState {
    Hidden,
    Combined(SwapUiMode),
    PerDevice(SwapUiMode),
}

mod imp {
    use std::cell::{Cell, RefCell};

    use crate::ui::{pages::MEMORY_PRIMARY_ORD, widgets::graph_box::ResGraphBox};

    use super::*;

    use gtk::{
        CompositeTemplate,
        gio::{Icon, ThemedIcon},
        glib::{ParamSpec, Properties, Value},
    };

    #[derive(CompositeTemplate, Properties)]
    #[template(resource = "/org/gnome/Resources/ui/pages/memory.ui")]
    #[properties(wrapper_type = super::ResMemory)]
    pub struct ResMemory {
        #[template_child]
        pub memory: TemplateChild<ResGraphBox>,
        #[template_child]
        pub swap: TemplateChild<ResGraphBox>,
        #[template_child]
        pub options: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub separate_swap_graphs: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub swap_devices: TemplateChild<adw::PreferencesGroup>,

        pub swap_graphs: RefCell<Vec<SwapGraphEntry>>,
        pub swap_tick: Cell<u64>,
        #[template_child]
        pub authentication_banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub properties: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub slots_used: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub speed: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub form_factor: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub memory_type: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub type_detail: TemplateChild<adw::ActionRow>,

        pub memory_devices: RefCell<Vec<MemoryDevice>>,

        #[property(get)]
        uses_meter: Cell<bool>,

        #[property(get)]
        main_graph_color: glib::Bytes,

        #[property(get)]
        icon: RefCell<Icon>,

        #[property(get, set)]
        usage: Cell<f64>,

        #[property(get = Self::tab_name, type = glib::GString)]
        tab_name: Cell<glib::GString>,

        #[property(get = Self::tab_detail_string, set = Self::set_tab_detail_string, type = glib::GString
        )]
        tab_detail_string: Cell<glib::GString>,

        #[property(get, set, type = UsageLabels)]
        tab_usage_labels: RefCell<UsageLabels>,

        #[property(get = Self::tab_id, type = glib::GString)]
        tab_id: Cell<glib::GString>,

        #[property(get)]
        graph_locked_max_y: Cell<bool>,

        #[property(get)]
        primary_ord: Cell<u32>,

        #[property(get)]
        secondary_ord: Cell<u32>,
    }

    impl ResMemory {
        gstring_getter_setter!(tab_name, tab_detail_string, tab_id);
    }

    impl Default for ResMemory {
        fn default() -> Self {
            Self {
                memory: Default::default(),
                swap: Default::default(),
                options: Default::default(),
                separate_swap_graphs: Default::default(),
                swap_devices: Default::default(),
                swap_graphs: Default::default(),
                swap_tick: Default::default(),
                authentication_banner: Default::default(),
                properties: Default::default(),
                slots_used: Default::default(),
                speed: Default::default(),
                form_factor: Default::default(),
                memory_type: Default::default(),
                type_detail: Default::default(),
                memory_devices: Default::default(),
                uses_meter: Cell::new(true),
                main_graph_color: glib::Bytes::from_static(&super::ResMemory::MAIN_GRAPH_COLOR),
                icon: RefCell::new(ThemedIcon::new("memory-symbolic").into()),
                usage: Default::default(),
                tab_name: Cell::new(glib::GString::from(i18n("Memory"))),
                tab_detail_string: Cell::new(glib::GString::new()),
                tab_usage_labels: Default::default(),
                tab_id: Cell::new(glib::GString::from(TAB_ID)),
                graph_locked_max_y: Cell::new(true),
                primary_ord: Cell::new(MEMORY_PRIMARY_ORD),
                secondary_ord: Default::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ResMemory {
        const NAME: &'static str = "ResMemory";
        type Type = super::ResMemory;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            Self::bind_template(klass);
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ResMemory {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();

            // Devel Profile
            if DEVLOPMENT_BUILD {
                obj.add_css_class("devel");
            }
        }

        fn properties() -> &'static [ParamSpec] {
            Self::derived_properties()
        }

        fn set_property(&self, id: usize, value: &Value, pspec: &ParamSpec) {
            self.derived_set_property(id, value, pspec);
        }

        fn property(&self, id: usize, pspec: &ParamSpec) -> Value {
            self.derived_property(id, pspec)
        }
    }

    impl WidgetImpl for ResMemory {}
    impl BinImpl for ResMemory {}
}

glib::wrapper! {
    pub struct ResMemory(ObjectSubclass<imp::ResMemory>)
        @extends gtk::Widget, adw::Bin,
        @implements gtk::Buildable, gtk::ConstraintTarget, gtk::Accessible;
}

impl Default for ResMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl ResMemory {
    const MAIN_GRAPH_COLOR: [u8; 3] = [0xc5, 0x2f, 0x90];

    pub fn new() -> Self {
        trace!("Creating ResMemory GObject…");

        glib::Object::new::<Self>()
    }

    pub fn init(&self) {
        self.setup_widgets();
        self.setup_signals();
    }

    pub fn setup_widgets(&self) {
        trace!("Setting up ResMemory widgets…");

        let imp = self.imp();

        imp.memory.set_title_label(&i18n("Memory"));
        imp.memory.graph().set_graph_color(
            Self::MAIN_GRAPH_COLOR[0],
            Self::MAIN_GRAPH_COLOR[1],
            Self::MAIN_GRAPH_COLOR[2],
        );
        imp.swap.set_title_label(&i18n("Swap"));
        imp.swap.graph().set_graph_color(0x94, 0x29, 0x7c);
        imp.separate_swap_graphs
            .set_active(SETTINGS.memory_show_swap_devices());

        if let Ok(memory_devices) = MemoryDevice::get() {
            self.setup_properties(memory_devices);
        } else {
            imp.properties.set_visible(false);
            imp.authentication_banner.set_revealed(true);
        }
    }

    pub fn setup_properties(&self, memory_devices: Vec<MemoryDevice>) {
        let imp = self.imp();

        let slots_used = memory_devices
            .iter()
            .filter(|md| md.installed)
            .count()
            .to_string();

        let slots = memory_devices.len().to_string();

        let speed = memory_devices
            .iter()
            .filter(|md| md.installed)
            .map(|md| md.speed_mts.unwrap_or(0))
            .max();

        let form_factor = memory_devices.iter().find(|md| md.installed).map_or_else(
            || i18n("N/A"),
            |md| md.form_factor.clone().unwrap_or_else(|| i18n("N/A")),
        );

        let r#type = memory_devices.iter().find(|md| md.installed).map_or_else(
            || i18n("N/A"),
            |md| md.r#type.clone().unwrap_or_else(|| i18n("N/A")),
        );

        let type_detail = memory_devices.iter().find(|md| md.installed).map_or_else(
            || i18n("N/A"),
            |md| md.type_detail.clone().unwrap_or_else(|| i18n("N/A")),
        );

        let total_memory = memory_devices
            .iter()
            .map(|md| md.size.unwrap_or(0))
            .sum::<u64>() as f64;

        self.set_property(
            "tab_detail_string",
            format!(
                "{} {}",
                convert_storage(total_memory, false),
                memory_devices
                    .iter()
                    .find(|md| md.installed)
                    .and_then(|md| md.r#type.clone())
                    .unwrap_or_default()
            ),
        );

        imp.memory_devices.replace(memory_devices);

        imp.slots_used
            .set_subtitle(&i18n_f("{} of {}", &[slots_used.as_str(), slots.as_str()]));

        imp.speed.set_subtitle(&i18n_f(
            "{} MT/s",
            &[&speed.map_or_else(|| i18n("N/A"), |i| i.to_string())],
        ));

        imp.form_factor.set_subtitle(&form_factor);

        imp.memory_type.set_subtitle(&r#type);

        imp.type_detail.set_subtitle(&type_detail);
    }

    pub fn setup_signals(&self) {
        trace!("Setting up ResMemory signals…");

        let imp = self.imp();

        imp.authentication_banner.connect_button_clicked(clone!(
            #[weak(rename_to = this)]
            self,
            move |_| {
                let imp = this.imp();
                if let Ok(memory_devices) = MemoryDevice::pkexec_dmidecode() {
                    this.setup_properties(memory_devices);
                    imp.properties.set_visible(true);
                }
                imp.authentication_banner.set_revealed(false);
            }
        ));

        imp.separate_swap_graphs.connect_active_notify(clone!(
            #[weak(rename_to = this)]
            self,
            move |switch_row| {
                let _ = SETTINGS.set_memory_show_swap_devices(switch_row.is_active());
                this.refresh_swap_ui_from_latest_data();
            }
        ));
    }

    fn refresh_swap_ui_from_latest_data(&self) {
        let imp = self.imp();
        let active_swap_devices = imp
            .swap_graphs
            .borrow()
            .iter()
            .filter(|entry| entry.active)
            .count();
        let swap_state = Self::swap_ui_state(
            imp.separate_swap_graphs.is_active(),
            active_swap_devices,
            None,
        );
        self.apply_swap_ui_state(&swap_state, None);
    }

    pub fn refresh_page(&self, memdata: MemoryData) {
        trace!("Refreshing ResMemory…");

        let imp = self.imp();

        let MemoryData {
            total_mem,
            available_mem,
            swap_devices,
        } = memdata;

        let used_mem = total_mem.saturating_sub(available_mem);

        imp.memory
            .add_storage_point(Some(used_mem as u64), Some(total_mem as u64));

        let combined_usage = SwapUsage::from_devices(&swap_devices);
        let swap_state = Self::swap_ui_state(
            imp.separate_swap_graphs.is_active(),
            swap_devices.len(),
            combined_usage,
        );

        // Always advance both data series; visibility is controlled by swap_state below.
        match combined_usage {
            Some(usage) => imp
                .swap
                .add_storage_point(Some(usage.used), Some(usage.total.get())),
            None => imp.swap.add_storage_point(None, None),
        };
        self.update_swap_device_graphs(&swap_devices);

        let mut usage_labels = UsageLabels::default();
        let memory_fraction = Self::fraction_or_zero(used_mem as u64, total_mem as u64);
        usage_labels.add_with_icon(
            "speedometer-symbolic",
            i18n("Memory Usage"),
            convert_fraction(memory_fraction, true),
        );

        self.apply_swap_ui_state(&swap_state, Some(&mut usage_labels));

        let memory_devices = imp.memory_devices.borrow();

        let total_memory = memory_devices
            .iter()
            .map(|md| md.size.unwrap_or(0))
            .sum::<u64>() as f64;

        self.set_tab_usage_labels(usage_labels);

        self.set_property(
            "tab_detail_string",
            format!(
                "{} {}",
                convert_storage(total_memory, false),
                memory_devices
                    .iter()
                    .find(|md| md.installed)
                    .and_then(|md| md.r#type.clone())
                    .unwrap_or_default()
            ),
        );

        self.set_property("usage", memory_fraction);
    }

    fn apply_swap_ui_state(
        &self,
        swap_state: &SwapUiState,
        usage_labels: Option<&mut UsageLabels>,
    ) {
        let imp = self.imp();
        let mut usage_labels = usage_labels;

        match swap_state {
            SwapUiState::Hidden => {
                imp.swap.set_visible(false);
                imp.swap_devices.set_visible(false);
                imp.options.set_visible(false);
            }
            SwapUiState::Combined(combined) => {
                imp.swap.set_visible(true);
                imp.swap_devices.set_visible(false);
                imp.options.set_visible(combined.show_options);
                if let Some(labels) = usage_labels.as_deref_mut() {
                    Self::add_swap_usage_label(labels, combined.usage);
                }
            }
            SwapUiState::PerDevice(per_device) => {
                imp.swap.set_visible(false);
                imp.swap_devices.set_visible(true);
                imp.options.set_visible(per_device.show_options);
                if let Some(labels) = usage_labels.as_deref_mut() {
                    Self::add_swap_usage_label(labels, per_device.usage);
                }
            }
        }
    }

    fn update_swap_graph_labels(graph_box: &ResGraphBox, device: &SwapDevice) {
        graph_box.set_title_label(&i18n_f(
            "{} · {} · Priority: {}",
            &[
                &device.name,
                &device.r#type.to_string(),
                &device.priority.to_string(),
            ],
        ));
        let fraction = Self::fraction_or_zero(device.used as u64, device.size as u64);
        let subtitle = format!(
            "{} / {} · {}",
            convert_storage(device.used as f64, false),
            convert_storage(device.size as f64, false),
            convert_fraction(fraction, true),
        );
        graph_box.set_subtitle(&subtitle);
    }

    fn add_swap_usage_label(usage_labels: &mut UsageLabels, usage: Option<SwapUsage>) {
        if let Some(swap_usage) = usage {
            usage_labels.add_with_icon(
                "swap-symbolic",
                i18n("Swap Usage"),
                convert_fraction(swap_usage.fraction(), true),
            );
        }
    }

    fn fraction_or_zero(used: u64, total: u64) -> f64 {
        NonZeroU64::new(total).map_or(0.0, |total| used as f64 / total.get() as f64)
    }

    fn update_swap_device_graphs(&self, swap_devices: &[SwapDevice]) {
        let imp = self.imp();
        let current_tick = imp.swap_tick.get().saturating_add(1);
        imp.swap_tick.set(current_tick);

        let mut swap_graphs = imp.swap_graphs.borrow_mut();

        for entry in swap_graphs.iter_mut() {
            entry.active = false;
        }

        for device in swap_devices {
            if let Some(entry) = swap_graphs
                .iter_mut()
                .find(|entry| entry.name == device.name)
            {
                entry.active = true;
                entry.last_seen_tick = current_tick;
                entry.size_bytes = device.size as u64;
                entry.graph_box.set_visible(true);
                entry
                    .graph_box
                    .add_storage_point(Some(device.used as u64), Some(device.size as u64));
                Self::update_swap_graph_labels(&entry.graph_box, device);
                continue;
            }

            let graph_box = ResGraphBox::new();
            graph_box.graph().set_graph_color(0x94, 0x29, 0x7c);
            graph_box.add_storage_point(Some(device.used as u64), Some(device.size as u64));
            Self::update_swap_graph_labels(&graph_box, device);

            imp.swap_devices.add(&graph_box);
            swap_graphs.push(SwapGraphEntry {
                name: device.name.clone(),
                graph_box,
                size_bytes: device.size as u64,
                last_seen_tick: current_tick,
                active: true,
            });
        }

        for entry in swap_graphs.iter_mut().filter(|entry| !entry.active) {
            entry.graph_box.set_visible(false);
            entry
                .graph_box
                .add_storage_point(Some(0), Some(entry.size_bytes));
        }

        let mut remove_indices = Vec::new();
        for (index, entry) in swap_graphs.iter().enumerate() {
            if !entry.active
                && current_tick.saturating_sub(entry.last_seen_tick)
                    > INACTIVE_SWAP_GRAPH_RETENTION_TICKS
            {
                remove_indices.push(index);
            }
        }

        for index in remove_indices.into_iter().rev() {
            if let Some(entry) = swap_graphs.get(index) {
                imp.swap_devices.remove(&entry.graph_box);
            }
            swap_graphs.remove(index);
        }
    }

    fn swap_ui_state(
        is_separate: bool,
        swap_device_count: usize,
        usage: Option<SwapUsage>,
    ) -> SwapUiState {
        if swap_device_count == 0 {
            return SwapUiState::Hidden;
        }

        let has_multiple_devices = swap_device_count > 1;

        if !has_multiple_devices {
            return SwapUiState::Combined(SwapUiMode {
                usage,
                show_options: false,
            });
        }

        if is_separate {
            SwapUiState::PerDevice(SwapUiMode {
                usage,
                show_options: has_multiple_devices,
            })
        } else {
            SwapUiState::Combined(SwapUiMode {
                usage,
                show_options: has_multiple_devices,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResMemory, SwapUiState};

    #[test]
    fn swap_ui_state_hides_when_no_devices_are_present() {
        assert!(matches!(
            ResMemory::swap_ui_state(false, 0, None),
            SwapUiState::Hidden
        ));
    }

    #[test]
    fn swap_ui_state_uses_combined_mode_for_a_single_device_even_if_separate_is_enabled() {
        assert!(matches!(
            ResMemory::swap_ui_state(true, 1, None),
            SwapUiState::Combined(_)
        ));
    }

    #[test]
    fn swap_ui_state_keeps_per_device_mode_for_multiple_devices_when_enabled() {
        assert!(matches!(
            ResMemory::swap_ui_state(true, 2, None),
            SwapUiState::PerDevice(_)
        ));
    }
}
