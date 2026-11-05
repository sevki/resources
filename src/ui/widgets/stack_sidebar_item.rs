use adw::{StyleManager, glib::property::PropertySet, prelude::*, subclass::prelude::*};
use gtk::{
    Ordering,
    gio::Icon,
    glib::{self, clone},
};
use log::trace;

use super::graph::ResGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeterType {
    NoMeter,
    Graph,
    ProgressBar,
}

#[derive(Clone, Default, Debug, PartialEq, PartialOrd, glib::Boxed)]
#[boxed_type(name = "ResUsageLabels")]
pub struct UsageLabels(Vec<(Option<(glib::GString, glib::GString)>, glib::GString)>);

impl UsageLabels {
    pub fn single_without_icon<G: Into<glib::GString>>(text: G) -> Self {
        Self(vec![(None, text.into())])
    }

    pub fn add_with_icon<
        G1: Into<glib::GString>,
        G2: Into<glib::GString>,
        G3: Into<glib::GString>,
    >(
        &mut self,
        icon_name: G1,
        tooltip: G2,
        text: G3,
    ) {
        self.0
            .push((Some((icon_name.into(), tooltip.into())), text.into()));
    }
}

mod imp {
    use std::cell::{Cell, RefCell};

    use crate::ui::widgets::graph::ResGraph;

    use super::*;

    use gtk::{
        CompositeTemplate,
        gio::{Icon, ThemedIcon},
        glib::{ParamSpec, Properties, Value},
    };

    #[derive(CompositeTemplate, Properties)]
    #[template(resource = "/org/gnome/Resources/ui/widgets/stack_sidebar_item.ui")]
    #[properties(wrapper_type = super::ResStackSidebarItem)]
    pub struct ResStackSidebarItem {
        #[template_child]
        pub image: TemplateChild<gtk::Image>,
        #[template_child]
        pub label: TemplateChild<gtk::Label>,
        #[template_child]
        pub detail_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub meter_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub no_meter_page: TemplateChild<gtk::Box>,
        #[template_child]
        pub graph_page: TemplateChild<gtk::Overlay>,
        #[template_child]
        pub graph: TemplateChild<ResGraph>,
        #[template_child]
        pub usage_label_graph: TemplateChild<gtk::FlowBox>,
        #[template_child]
        pub progress_page: TemplateChild<gtk::Box>,
        #[template_child]
        pub usage_label_no_meter: TemplateChild<gtk::FlowBox>,
        #[template_child]
        pub usage_label_bar: TemplateChild<gtk::FlowBox>,
        #[template_child]
        pub progress_bar: TemplateChild<gtk::ProgressBar>,

        #[property(get = Self::name, set = Self::set_name, type = glib::GString)]
        name: Cell<glib::GString>,
        #[property(get = Self::detail, set = Self::set_detail, type = glib::GString)]
        detail: Cell<glib::GString>,
        #[property(get = Self::subtitle, set = Self::set_subtitle, type = glib::GString)]
        subtitle: Cell<glib::GString>,
        #[property(get = Self::icon, set = Self::set_icon, type = Icon)]
        icon: RefCell<Icon>,
        #[property(get, set = Self::set_usage)]
        usage: Cell<f64>,
        #[property(get, set = Self::set_usage_string, type = UsageLabels)]
        usage_labels: RefCell<UsageLabels>,
        #[property(get = Self::tab_id, set = Self::set_tab_id, type = glib::GString)]
        tab_id: Cell<glib::GString>,

        pub primary_ord: Cell<u32>,
        pub secondary_ord: Cell<u32>,
    }

    impl ResStackSidebarItem {
        fn visible_usage_box(&self) -> gtk::FlowBox {
            if let Some(visible) = self.meter_stack.visible_child() {
                if visible == self.no_meter_page.get().upcast::<gtk::Widget>() {
                    return self.usage_label_no_meter.get();
                } else if visible == self.progress_page.get().upcast::<gtk::Widget>() {
                    return self.usage_label_bar.get();
                }
            }

            self.usage_label_graph.get()
        }

        pub fn name(&self) -> glib::GString {
            let name = self.name.take();
            self.name.set(name.clone());
            name
        }

        pub fn set_name(&self, name: &str) {
            let current_name = self.name.take();
            if current_name.as_str() == name {
                self.name.set(current_name);
                return;
            }
            self.name.set(glib::GString::from(name));
            self.label.set_label(name);
        }

        pub fn subtitle(&self) -> glib::GString {
            let subtitle = self.subtitle.take();
            self.subtitle.set(subtitle.clone());
            subtitle
        }

        pub fn set_subtitle(&self, usage_string: &str) {
            let current_usage_string = self.subtitle.take();
            if current_usage_string.as_str() == usage_string {
                self.subtitle.set(current_usage_string);
            }
        }

        pub fn detail(&self) -> glib::GString {
            let detail = self.detail.take();
            self.detail.set(detail.clone());
            detail
        }

        pub fn set_detail(&self, detail: &str) {
            let current_detail = self.detail.take();
            if current_detail.as_str() == detail {
                self.detail.set(current_detail);
                return;
            }
            self.detail_label.set_label(detail);
        }

        pub fn icon(&self) -> Icon {
            let icon = self
                .icon
                .replace_with(|_| ThemedIcon::new("generic-process").into());
            self.icon.set(icon.clone());
            icon
        }

        pub fn set_icon(&self, icon: &Icon) {
            self.image.set_from_gicon(icon);
            self.icon.set(icon.clone());
        }

        pub fn set_usage_string(&self, contents: UsageLabels) {
            if *self.usage_labels.borrow() == contents {
                return;
            }

            self.usage_labels.replace(contents);
            let visible_box = self.visible_usage_box();
            Self::fill_usage_box(&visible_box, &self.usage_labels.borrow());
        }

        pub fn refresh_visible_usage_box(&self) {
            let visible_box = self.visible_usage_box();
            Self::fill_usage_box(&visible_box, &self.usage_labels.borrow());
        }

        pub fn set_usage(&self, usage: f64) {
            self.usage.set(usage);

            let mut highest_value = self.graph.get_highest_value();
            if highest_value < 1.0 {
                highest_value = 1.0;
            }

            self.progress_bar.set_fraction(usage / highest_value);

            self.graph.push_data_point(usage);
        }

        pub fn fill_usage_box(usage_box: &gtk::FlowBox, contents: &UsageLabels) {
            let items = &contents.0;
            let mut current = usage_box.first_child();

            for (icon_name, label) in items.iter() {
                if let Some(flow_child_widget) = current {
                    let flow_child = flow_child_widget
                        .downcast::<gtk::FlowBoxChild>()
                        .expect("child of FlowBox should be a FlowBoxChild");
                    let item_box = flow_child
                        .child()
                        .and_then(|w| w.downcast::<gtk::Box>().ok())
                        .expect("FlowBoxChild should contain a Box");

                    Self::update_item_box(&item_box, icon_name, label);

                    current = flow_child.next_sibling();
                } else {
                    let item_box = gtk::Box::new(gtk::Orientation::Horizontal, 4);
                    Self::update_item_box(&item_box, icon_name, label);
                    usage_box.append(&item_box);
                }
            }

            // drop leftover children only if the new list got shorter
            while let Some(leftover) = current {
                let next = leftover.next_sibling();
                usage_box.remove(&leftover);
                current = next;
            }
        }

        fn update_item_box(
            item_box: &gtk::Box,
            icon_name: &Option<(glib::GString, glib::GString)>,
            label_text: &glib::GString,
        ) {
            const ICON_SIZE: i32 = 12;

            let has_icon_child = item_box.first_child().is_some_and(|w| w.is::<gtk::Image>());

            if let Some((name, tooltip)) = icon_name {
                let icon = if has_icon_child {
                    item_box
                        .first_child()
                        .unwrap()
                        .downcast::<gtk::Image>()
                        .unwrap()
                } else {
                    while let Some(child) = item_box.first_child() {
                        item_box.remove(&child);
                    }
                    let icon = gtk::Image::new();
                    icon.set_pixel_size(ICON_SIZE);
                    item_box.append(&icon);
                    item_box.append(&gtk::Label::new(None));
                    icon
                };

                if &icon.icon_name().unwrap_or_default() != name {
                    icon.set_from_gicon(&ThemedIcon::new(name));
                }
                item_box.set_tooltip_text(Some(tooltip));

                let label = icon
                    .next_sibling()
                    .and_then(|w| w.downcast::<gtk::Label>().ok())
                    .expect("icon should be followed by a label");
                label.set_label(label_text);
            } else {
                let label = if has_icon_child {
                    while let Some(child) = item_box.first_child() {
                        item_box.remove(&child);
                    }
                    let label = gtk::Label::new(None);
                    item_box.append(&label);
                    label
                } else if let Some(widget) = item_box.first_child() {
                    widget.downcast::<gtk::Label>().expect("expected a label")
                } else {
                    let lbl = gtk::Label::new(None);
                    item_box.append(&lbl);
                    lbl
                };

                label.set_label(label_text);
            }
        }

        gstring_getter_setter!(tab_id);
    }

    impl Default for ResStackSidebarItem {
        fn default() -> Self {
            Self {
                image: Default::default(),
                label: Default::default(),
                meter_stack: Default::default(),
                no_meter_page: Default::default(),
                graph_page: Default::default(),
                graph: Default::default(),
                usage_label_graph: Default::default(),
                progress_page: Default::default(),
                usage_label_no_meter: Default::default(),
                usage_label_bar: Default::default(),
                progress_bar: Default::default(),
                detail_label: Default::default(),
                name: Default::default(),
                detail: Default::default(),
                subtitle: Default::default(),
                icon: RefCell::new(ThemedIcon::new("generic-process").into()),
                usage: Default::default(),
                usage_labels: Default::default(),
                tab_id: Default::default(),
                primary_ord: Default::default(),
                secondary_ord: Default::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ResStackSidebarItem {
        const NAME: &'static str = "ResStackSidebarItem";
        type Type = super::ResStackSidebarItem;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            Self::bind_template(klass);
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ResStackSidebarItem {
        fn constructed(&self) {
            self.parent_constructed();
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

    impl WidgetImpl for ResStackSidebarItem {
        // this is dodgy but allows the usage_label_bar items to stay untargetable but still make
        // it look like they have tooltips (also circumvents tooltips disappearing after a refresh)
        fn query_tooltip(
            &self,
            x: i32,
            y: i32,
            _keyboard_tooltip: bool,
            tooltip: &gtk::Tooltip,
        ) -> bool {
            let obj = self.obj();
            let widget: &gtk::Widget = obj.upcast_ref();

            if let Some(picked) = widget.pick(x as f64, y as f64, gtk::PickFlags::NON_TARGETABLE) {
                let mut current = Some(picked);
                while let Some(w) = current {
                    if let Some(text) = w.tooltip_text() {
                        tooltip.set_text(Some(&text));
                        return true;
                    }
                    current = w.parent();
                }
            }
            false
        }
    }

    impl BinImpl for ResStackSidebarItem {}
}

glib::wrapper! {
    pub struct ResStackSidebarItem(ObjectSubclass<imp::ResStackSidebarItem>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Buildable, gtk::ConstraintTarget, gtk::Accessible;
}

impl ResStackSidebarItem {
    pub fn new(
        name: String,
        icon: Icon,
        detail: Option<String>,
        locked_max_y: bool,
        tab_id: String,
        primary_ord: u32,
        secondary_ord: u32,
    ) -> Self {
        trace!("Creating ResStackSidebarItem GObject…");

        let detail = detail.unwrap_or_default();
        let this: Self = glib::Object::builder()
            .property("name", name)
            .property("icon", icon)
            .property("detail", &detail)
            .build();

        this.imp()
            .graph
            .set_locked_max_y(locked_max_y.then_some(1.0));
        this.imp().graph.set_height_request(64);

        this.imp().detail_label.set_visible(!detail.is_empty());

        this.imp().set_tab_id(&tab_id);

        this.imp().primary_ord.set(primary_ord);
        this.imp().secondary_ord.set(secondary_ord);

        this.setup_signals();

        this
    }

    pub fn graph(&self) -> ResGraph {
        self.imp().graph.get()
    }

    pub fn setup_signals(&self) {
        let style_manager = StyleManager::default();

        self.update_class(style_manager.is_dark());

        style_manager.connect_dark_notify(clone!(
            #[weak(rename_to = this)]
            self,
            move |manager| {
                this.update_class(manager.is_dark());
            }
        ));
    }

    fn update_class(&self, is_dark: bool) {
        let label = &self.imp().usage_label_graph;

        if is_dark {
            label.add_css_class("dropshadow");
            label.remove_css_class("dropshadow-light");
        } else {
            label.add_css_class("dropshadow-light");
            label.remove_css_class("dropshadow");
        }
    }

    pub fn set_meter_type(&self, meter_type: MeterType) {
        let imp = self.imp();
        let no_meter = imp.no_meter_page.get();
        let graph = imp.graph_page.get();
        let progress = imp.progress_page.get();

        no_meter.set_visible(false);
        graph.set_visible(false);
        progress.set_visible(false);

        match meter_type {
            MeterType::NoMeter => {
                no_meter.set_visible(true);
                self.imp().meter_stack.set_visible_child(&no_meter);
            }
            MeterType::Graph => {
                graph.set_visible(true);
                self.imp().meter_stack.set_visible_child(&graph);
            }
            MeterType::ProgressBar => {
                progress.set_visible(true);
                self.imp().meter_stack.set_visible_child(&progress);
            }
        }

        imp.refresh_visible_usage_box();
    }

    pub fn set_detail_label_visible(&self, visible: bool) {
        self.imp().detail_label.set_visible(visible);
    }

    pub fn primary_ord(&self) -> u32 {
        self.imp().primary_ord.clone().take()
    }

    pub fn secondary_ord(&self) -> u32 {
        self.imp().secondary_ord.clone().take()
    }

    pub fn ord(&self, other: &Self) -> Ordering {
        if self.primary_ord() > other.primary_ord() {
            Ordering::Larger
        } else if self.primary_ord() < other.primary_ord() {
            Ordering::Smaller
        } else if self.secondary_ord() > other.secondary_ord() {
            Ordering::Larger
        } else if self.secondary_ord() < other.secondary_ord() {
            Ordering::Smaller
        } else {
            Ordering::Equal
        }
    }
}
