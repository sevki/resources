use adw::{glib::property::PropertySet, prelude::*, subclass::prelude::*};
use gtk::{gio::Icon, glib};
use log::trace;

use super::row_state::RowState;

mod imp {
    use std::cell::{Cell, RefCell};

    use super::*;

    use gtk::{
        Box, CompositeTemplate,
        gio::ThemedIcon,
        glib::{ParamSpec, Properties, Value},
    };

    #[derive(CompositeTemplate, Properties)]
    #[template(resource = "/org/gnome/Resources/ui/widgets/process_name_cell.ui")]
    #[properties(wrapper_type = super::ResProcessNameCell)]
    pub struct ResProcessNameCell {
        #[template_child]
        pub image: TemplateChild<gtk::Image>,
        #[template_child]
        pub inscription: TemplateChild<gtk::Inscription>,
        #[template_child]
        pub expander: TemplateChild<gtk::Button>,

        #[property(get = Self::name, set = Self::set_name, type = glib::GString)]
        name: Cell<glib::GString>,
        #[property(get = Self::tooltip, set = Self::set_tooltip, type = glib::GString)]
        tooltip: Cell<glib::GString>,
        #[property(get = Self::icon, set = Self::set_icon, type = Icon)]
        icon: RefCell<Icon>,
        #[property(get, set = Self::set_symbolic)]
        symbolic: Cell<bool>,
        /// Indentation level in the process tree
        #[property(get, set = Self::set_depth)]
        depth: Cell<u32>,
        /// Whether the tree view is active (shows the expander column)
        #[property(get, set = Self::set_tree_visible)]
        tree_visible: Cell<bool>,
        #[property(get, set = Self::set_has_children)]
        has_children: Cell<bool>,
        #[property(get, set = Self::set_expanded)]
        expanded: Cell<bool>,
        #[property(get, set = Self::set_row_state)]
        row_state: RefCell<String>,
    }

    impl Default for ResProcessNameCell {
        fn default() -> Self {
            Self {
                image: Default::default(),
                inscription: Default::default(),
                expander: Default::default(),
                name: Default::default(),
                tooltip: Default::default(),
                icon: RefCell::new(ThemedIcon::new("generic-process").into()),
                symbolic: Default::default(),
                depth: Default::default(),
                tree_visible: Default::default(),
                has_children: Default::default(),
                expanded: Cell::new(true),
                row_state: Default::default(),
            }
        }
    }

    impl ResProcessNameCell {
        pub fn name(&self) -> glib::GString {
            let name = self.name.take();
            self.name.set(name.clone());
            name
        }

        pub fn set_name(&self, name: &str) {
            self.name.set(glib::GString::from(name));
            self.inscription.set_text(Some(name));
        }

        pub fn tooltip(&self) -> glib::GString {
            let tooltip = self.tooltip.take();
            self.tooltip.set(tooltip.clone());
            tooltip
        }

        pub fn set_tooltip(&self, tooltip: &str) {
            self.tooltip.set(glib::GString::from(tooltip));
            self.inscription.set_tooltip_text(Some(tooltip));
        }

        pub fn icon(&self) -> Icon {
            let icon = self
                .icon
                .replace_with(|_| ThemedIcon::new("generic-process").into());
            self.icon.set(icon.clone());
            icon
        }

        pub fn set_icon(&self, icon: &Icon) {
            let current_icon = self
                .icon
                .replace_with(|_| ThemedIcon::new("generic-process").into());

            if &current_icon == icon {
                self.icon.set(current_icon);
                return;
            }

            self.image.set_from_gicon(icon);

            self.icon.set(icon.clone());
        }

        /// Pixel width of the indentation added per tree level
        const INDENT: i32 = 18;

        fn update_expander(&self) {
            let tree = self.tree_visible.get();
            let has_children = self.has_children.get();

            self.expander.set_visible(tree);
            self.expander
                .set_margin_start(self.depth.get() as i32 * Self::INDENT);
            // keep the space occupied so that names of siblings line up
            self.expander
                .set_opacity(if has_children { 1.0 } else { 0.0 });
            self.expander.set_sensitive(has_children);
            self.expander.set_icon_name(if self.expanded.get() {
                "pan-down-symbolic"
            } else {
                "pan-end-symbolic"
            });
        }

        pub fn set_depth(&self, depth: u32) {
            self.depth.set(depth);
            self.update_expander();
        }

        pub fn set_tree_visible(&self, visible: bool) {
            self.tree_visible.set(visible);
            self.update_expander();
        }

        pub fn set_has_children(&self, has_children: bool) {
            self.has_children.set(has_children);
            self.update_expander();
        }

        pub fn set_expanded(&self, expanded: bool) {
            self.expanded.set(expanded);
            self.update_expander();
        }

        pub fn set_row_state(&self, row_state: String) {
            *self.row_state.borrow_mut() = row_state;
            self.apply_row_state_later();
        }

        /// Changing CSS classes of the row widget while GTK is in the middle of
        /// updating the row (which is when bindings fire) can free this very
        /// cell, so the class change is deferred to an idle callback.
        pub fn apply_row_state_later(&self) {
            glib::idle_add_local_once(glib::clone!(
                #[weak(rename_to = cell)]
                self.obj(),
                move || cell.imp().apply_row_state()
            ));
        }

        /// The whole row is what should be highlighted, not just this cell, so
        /// the CSS class has to go on the row widget some levels above.
        pub fn apply_row_state(&self) {
            let obj = self.obj();
            let mut ancestor = obj.parent();
            while let Some(widget) = ancestor {
                if widget.type_().name() == "GtkColumnViewRowWidget" {
                    for class in RowState::ALL_CLASSES {
                        widget.remove_css_class(class);
                    }
                    let state = self.row_state.borrow();
                    if let Some(class) = RowState::from_name(&state).and_then(RowState::css_class) {
                        widget.add_css_class(class);
                    }
                    return;
                }
                ancestor = widget.parent();
            }
        }

        pub fn set_symbolic(&self, symbolic: bool) {
            self.symbolic.set(symbolic);

            if symbolic {
                self.image.set_css_classes(&[]);
            } else {
                self.image.set_css_classes(&["lowres-icon"]);
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ResProcessNameCell {
        const NAME: &'static str = "ResProcessNameCell";
        type Type = super::ResProcessNameCell;
        type ParentType = Box;

        fn class_init(klass: &mut Self::Class) {
            Self::bind_template(klass);
        }

        // You must call `Widget`'s `init_template()` within `instance_init()`.
        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ResProcessNameCell {
        fn constructed(&self) {
            self.parent_constructed();
            // the row widget may not exist yet when the state is first set
            self.obj()
                .connect_map(|cell| cell.imp().apply_row_state_later());
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

    impl WidgetImpl for ResProcessNameCell {}

    impl BoxImpl for ResProcessNameCell {}
}

glib::wrapper! {
    pub struct ResProcessNameCell(ObjectSubclass<imp::ResProcessNameCell>)
        @extends gtk::Widget, gtk::Box,
        @implements gtk::Buildable, gtk::ConstraintTarget, gtk::Accessible;
}

impl Default for ResProcessNameCell {
    fn default() -> Self {
        Self::new()
    }
}

impl ResProcessNameCell {
    /// Runs `f` whenever the user clicks the expander button.
    pub fn connect_expander_clicked<F: Fn(&Self) + 'static>(&self, f: F) {
        self.imp().expander.connect_clicked(glib::clone!(
            #[weak(rename_to = this)]
            self,
            move |_| f(&this)
        ));
    }

    pub fn new() -> Self {
        trace!("Creating ResProcessNameCell GObject…");

        glib::Object::new::<Self>()
    }
}
