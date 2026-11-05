use std::{collections::HashMap, sync::LazyLock};

use gtk::{glib, prelude::*};
use process_data::Niceness;

use crate::utils::i18n::pi18n;

pub mod applications;
pub mod battery;
pub mod cpu;
pub mod drive;
pub mod gpu;
pub mod memory;
pub mod network;
pub mod npu;
pub mod processes;

const APPLICATIONS_PRIMARY_ORD: u32 = 0;
const PROCESSES_PRIMARY_ORD: u32 = 1;
const CPU_PRIMARY_ORD: u32 = 2;
const MEMORY_PRIMARY_ORD: u32 = 3;
const GPU_PRIMARY_ORD: u32 = 4;
const NPU_PRIMARY_ORD: u32 = 5;
const DRIVE_PRIMARY_ORD: u32 = 6;
const NETWORK_PRIMARY_ORD: u32 = 7;
const BATTERY_PRIMARY_ORD: u32 = 8;
const MAX_SPEED_LENGTH: u32 = 12; // e.g. "123.45 MiB/s"
const MAX_STORAGE_LENGTH: u32 = 10; // e.g. "123.45 MiB"
const MAX_PERCENTAGE_LENGTH: u32 = 7; // e.g. "100.0 %"
const MAX_PID_LENGTH: u32 = decimal_digits(libc::pid_t::MAX);

const fn decimal_digits(n: i32) -> u32 {
    if n < 10 {
        1
    } else {
        1 + decimal_digits(n / 10)
    }
}

#[macro_export]
macro_rules! add_column {
    (
        this: $this:expr,
        column_view: $column_view:expr,
        entry_type: $entry_type:ty,
        title: $title:expr,
        property: $property:ident,
        value_type: $value_type:ty,
        min_chars: $min_chars:expr,
        $(xalign: $xalign:expr,)?
        sorter: $sorter:ident,
        convert: $convert:expr,
        settings_show: $settings_show:ident,
        settings_connect: $settings_connect:ident $(,)?
    ) => {{
        let factory = gtk::SignalListItemFactory::new();
        let col = gtk::ColumnViewColumn::new(Some(&$title), Some(factory.clone()));
        col.set_resizable(true);

        let title_clone = $title.clone();
        factory.connect_setup(clone!(
            move |_factory, item| {
                let item = item.downcast_ref::<gtk::ListItem>().unwrap();

                let row = gtk::Inscription::new(None);
                row.set_min_chars($min_chars);
                $( row.set_xalign($xalign); )?

                let label = title_clone.clone();
                row.connect_text_notify(move |inscription| {
                    inscription.update_property(&[Property::Label(&format!(
                        "{}: {}",
                        label,
                        inscription.text().unwrap_or_default()
                    ))]);
                });

                item.set_child(Some(&row));

                add_column!(@bind item, $entry_type, $property, $value_type, row, $convert);
            }
        ));

        factory.connect_teardown(move |_factory, item| {
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            item.set_child(None::<&gtk::Inscription>);
        });

        let sorter = add_column!(@sorter $sorter, $entry_type, $property);
        col.set_sorter(Some(&sorter));
        col.set_visible(SETTINGS.$settings_show());
        $column_view.append_column(&col);

        SETTINGS.$settings_connect(clone!(
            #[weak]
            col,
            move |visible| col.set_visible(visible)
        ));

        col
    }};

    // With convert closure
    (@bind $item:expr, $entry_type:ty, $property:ident, $value_type:ty, $row:expr, $convert:expr) => {
        $item
            .property_expression("item")
            .chain_property::<$entry_type>(stringify!($property))
            .chain_closure::<String>(closure!(|_: Option<Object>, val: $value_type| {
                ($convert)(val)
            }))
            .bind(&$row, "text", Widget::NONE);
    };

    (@sorter numeric, $entry_type:ty, $property:ident) => {
        NumericSorter::builder()
            .sort_order(SortType::Ascending)
            .expression(gtk::PropertyExpression::new(
                <$entry_type>::static_type(),
                None::<&gtk::Expression>,
                stringify!($property),
            ))
            .build()
    };

    (@sorter string, $entry_type:ty, $property:ident) => {
        StringSorter::builder()
            .ignore_case(true)
            .expression(gtk::PropertyExpression::new(
                <$entry_type>::static_type(),
                None::<&gtk::Expression>,
                stringify!($property),
            ))
            .build()
    };
}

pub fn add_context_menu_gesture<P: IsA<gtk::Widget>>(
    column_view: &gtk::ColumnView,
    page: &glib::WeakRef<P>,
    list_item_at: impl Fn(&gtk::ColumnView, f64, f64) -> Option<gtk::ListItem> + 'static,
    on_secondary_click: impl Fn(&P, u32, f32, f32) + 'static,
) {
    let column_view = column_view.clone();
    let page = page.clone();

    let gesture = gtk::GestureClick::new();
    gesture.set_button(gtk::gdk::BUTTON_SECONDARY);
    let view = column_view.clone();
    gesture.connect_pressed(move |gesture, _, x, y| {
        let Some(item) = list_item_at(&view, x, y) else {
            return;
        };

        let position = item.position();
        if position == gtk::INVALID_LIST_POSITION {
            return;
        }

        let Some(page) = page.upgrade() else {
            return;
        };

        let Some(point) = view.compute_point(&page, &gtk::graphene::Point::new(x as f32, y as f32))
        else {
            return;
        };

        on_secondary_click(&page, position, point.x(), point.y());
        gesture.set_state(gtk::EventSequenceState::Claimed);
    });

    column_view.add_controller(gesture);
}

pub static NICE_TO_LABEL: LazyLock<HashMap<Niceness, (String, u32)>> = LazyLock::new(|| {
    let mut hash_map = HashMap::new();

    for i in -20..=-8 {
        hash_map.insert(
            Niceness::try_new(i).unwrap(),
            (pi18n("process priority", "Very High"), 0),
        );
    }

    for i in -7..=-3 {
        hash_map.insert(
            Niceness::try_new(i).unwrap(),
            (pi18n("process priority", "High"), 1),
        );
    }

    for i in -2..=2 {
        hash_map.insert(
            Niceness::try_new(i).unwrap(),
            (pi18n("process priority", "Normal"), 2),
        );
    }

    for i in 3..=6 {
        hash_map.insert(
            Niceness::try_new(i).unwrap(),
            (pi18n("process priority", "Low"), 3),
        );
    }

    for i in 7..=19 {
        hash_map.insert(
            Niceness::try_new(i).unwrap(),
            (pi18n("process priority", "Very Low"), 4),
        );
    }

    hash_map
});
