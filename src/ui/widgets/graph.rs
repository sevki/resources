use adw::prelude::WidgetExt;
use gtk::glib::{self};
use gtk::prelude::GtkWindowExt;
use gtk::subclass::prelude::*;
use log::trace;
use plotters::style::RGBColor;

use std::f64;

use crate::application::Application;
use crate::utils::settings::SETTINGS;

const MAX_DATA_POINTS: u32 = 600;

mod imp {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        error::Error,
    };

    use adw::prelude::SnapshotExt;
    use adw::prelude::WidgetExt;
    use gtk::{
        glib,
        subclass::{
            prelude::{
                ObjectImpl, ObjectImplExt, ObjectSubclass, ObjectSubclassExt, ObjectSubclassIsExt,
            },
            widget::WidgetImpl,
        },
    };
    use plotters::{
        prelude::*,
        series::AreaSeries,
        style::{Color, RGBColor},
    };
    use plotters_cairo::CairoBackend;

    use crate::utils::settings::SETTINGS;

    use super::MAX_DATA_POINTS;

    #[derive(Debug)]
    pub struct ResGraph {
        pub data_points: RefCell<VecDeque<f64>>,
        /// Optional description of what caused each data point (e.g. the
        /// process using the most CPU), always the same length as `data_points`
        pub labels: RefCell<VecDeque<Option<String>>>,
        /// Label attached to the next pushed data point
        pub pending_label: RefCell<Option<String>>,
        pub max_y: Cell<Option<f64>>,
        pub graph_color: Cell<RGBColor>,
    }

    impl Default for ResGraph {
        fn default() -> Self {
            let mut empty_deque = VecDeque::with_capacity(MAX_DATA_POINTS as usize);
            for _ in 0..MAX_DATA_POINTS {
                empty_deque.push_back(0.0);
            }

            Self {
                data_points: RefCell::new(empty_deque),
                labels: RefCell::new(VecDeque::from(vec![None; MAX_DATA_POINTS as usize])),
                pending_label: RefCell::new(None),
                max_y: Cell::new(Some(1.0)),
                graph_color: Cell::default(),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ResGraph {
        const NAME: &'static str = "ResGraph";
        type Type = super::ResGraph;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for ResGraph {
        fn constructed(&self) {
            self.parent_constructed();

            let obj = self.obj();
            obj.set_has_tooltip(true);
            obj.connect_query_tooltip(|graph, x, _y, _keyboard, tooltip| {
                let imp = graph.imp();
                let labels = imp.labels.borrow();
                let width = f64::from(graph.width());
                let index = super::label_index(
                    f64::from(x),
                    width,
                    SETTINGS.graph_data_points() as usize,
                    labels.len(),
                );
                match index
                    .and_then(|index| labels.get(index))
                    .and_then(|label| label.as_deref())
                {
                    Some(label) => {
                        tooltip.set_text(Some(label));
                        true
                    }
                    None => false,
                }
            });
        }
    }

    impl WidgetImpl for ResGraph {
        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let width = self.obj().width() as u32;
            let height = self.obj().height() as u32;
            if width == 0 || height == 0 {
                return;
            }

            let bounds = gtk::graphene::Rect::new(0.0, 0.0, width as f32, height as f32);
            let cr: gtk::cairo::Context = snapshot.append_cairo(&bounds);
            let backend = CairoBackend::new(&cr, (width, height)).unwrap();
            self.plot_graph(backend).unwrap();
        }
    }

    impl ResGraph {
        pub fn plot_graph<'a, DB>(&self, backend: DB) -> Result<(), Box<dyn Error + 'a>>
        where
            DB: DrawingBackend + 'a,
        {
            let data_points = self.data_points.borrow();
            let color = self.graph_color.get();

            let start_point =
                (MAX_DATA_POINTS.saturating_sub(SETTINGS.graph_data_points())) as usize;

            let root = backend.into_drawing_area();

            root.fill(&self.graph_color.get().mix(0.1))?;

            let y_max = self.max_y.get().unwrap_or_else(|| {
                let max = *data_points
                    .range(start_point..(MAX_DATA_POINTS as usize))
                    .max_by(|x, y| x.total_cmp(y))
                    .unwrap_or(&0.0);
                if max == 0.0 { f64::EPSILON } else { max }
            });

            let mut chart = ChartBuilder::on(&root).build_cartesian_2d(
                0f64..(f64::from(SETTINGS.graph_data_points()) - 1.0),
                0f64..y_max,
            )?;

            if SETTINGS.show_graph_grids() {
                chart
                    .configure_mesh()
                    .disable_axes()
                    .max_light_lines(0)
                    .bold_line_style(color.mix(0.4))
                    .draw()?;
            }

            chart.draw_series(
                AreaSeries::new(
                    (0..)
                        .zip(data_points.range(start_point..(MAX_DATA_POINTS as usize)))
                        .map(|(x, y)| (f64::from(x), *y)),
                    0.0,
                    color.mix(0.4),
                )
                .border_style(color),
            )?;

            root.present()?;
            Ok(())
        }
    }
}

glib::wrapper! {
    pub struct ResGraph(ObjectSubclass<imp::ResGraph>)
        @extends gtk::Widget,
        @implements gtk::Buildable, gtk::ConstraintTarget, gtk::Accessible;
}

impl Default for ResGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl ResGraph {
    pub fn new() -> Self {
        trace!("Creating ResGraph GObject…");

        glib::Object::new::<Self>()
    }

    pub fn set_graph_color(&self, r: u8, g: u8, b: u8) {
        let imp = self.imp();
        imp.graph_color.set(RGBColor(r, g, b));
        self.queue_draw_if_not_suspended();
    }

    pub fn set_locked_max_y(&self, y_max: Option<f64>) {
        let imp = self.imp();
        imp.max_y.set(y_max);
        self.queue_draw_if_not_suspended();
    }

    pub fn get_highest_value(&self) -> f64 {
        let imp = self.imp();

        let start_point = (MAX_DATA_POINTS.saturating_sub(SETTINGS.graph_data_points())) as usize;

        *imp.data_points
            .borrow()
            .range(start_point..(MAX_DATA_POINTS as usize))
            .max_by(|x, y| x.total_cmp(y))
            .unwrap_or(&0.0)
    }

    pub fn push_data_point(&self, data: f64) {
        let imp = self.imp();
        let mut data_points = imp.data_points.borrow_mut();
        if data_points.len() >= MAX_DATA_POINTS as usize {
            data_points.pop_front();
        }
        data_points.push_back(data);

        let mut labels = imp.labels.borrow_mut();
        if labels.len() >= MAX_DATA_POINTS as usize {
            labels.pop_front();
        }
        labels.push_back(imp.pending_label.take());

        self.queue_draw_if_not_suspended();
    }

    /// Sets a description shown in the tooltip for the next data point pushed
    /// with [`Self::push_data_point`], e.g. the process causing the load.
    pub fn set_pending_label(&self, label: Option<String>) {
        *self.imp().pending_label.borrow_mut() = label;
    }

    pub fn data_points(&self) -> Vec<f64> {
        self.imp().data_points.borrow().iter().copied().collect()
    }

    pub fn push_data_points(&self, data: &[f64]) {
        let imp = self.imp();
        let mut data_points = imp.data_points.borrow_mut();
        for data_point in data {
            if data_points.len() >= MAX_DATA_POINTS as usize {
                data_points.pop_front();
            }
            data_points.push_back(*data_point);

            let mut labels = imp.labels.borrow_mut();
            if labels.len() >= MAX_DATA_POINTS as usize {
                labels.pop_front();
            }
            labels.push_back(None);
        }
        self.queue_draw_if_not_suspended();
    }

    pub fn clear_data_points(&self) {
        self.imp().data_points.borrow_mut().clear();
        self.imp().labels.borrow_mut().clear();
    }

    pub fn queue_draw_if_not_suspended(&self) {
        if crate::gui::ARGS.no_suspend_pause {
            self.imp().obj().queue_draw();
        } else if Application::try_default()
            .and_then(|app| app.try_main_window())
            .is_some_and(|main_window| main_window.is_suspended())
        {
            trace!("Graph refresh skipped due to app being suspended");
        } else {
            self.imp().obj().queue_draw();
        }
    }
}

/// Maps a horizontal position in the graph to the index of the data point
/// drawn there. The graph shows the most recent `shown` of `total` points
/// spread over `width`.
fn label_index(x: f64, width: f64, shown: usize, total: usize) -> Option<usize> {
    if width <= 0.0 || shown == 0 || total == 0 {
        return None;
    }
    let shown = shown.min(total);
    let start = total - shown;
    let position = if shown == 1 {
        0.0
    } else {
        (x / width).clamp(0.0, 1.0) * (shown - 1) as f64
    };
    Some(start + position.round() as usize)
}

#[cfg(test)]
mod tests {
    use super::label_index;

    #[test]
    fn maps_edges_and_middle() {
        // 600 stored points, last 60 shown over 300px
        assert_eq!(label_index(0.0, 300.0, 60, 600), Some(540));
        assert_eq!(label_index(300.0, 300.0, 60, 600), Some(599));
        assert_eq!(label_index(150.0, 300.0, 60, 600), Some(540 + 30));
    }

    #[test]
    fn clamps_and_handles_degenerate_input() {
        assert_eq!(label_index(-50.0, 300.0, 60, 600), Some(540));
        assert_eq!(label_index(900.0, 300.0, 60, 600), Some(599));
        assert_eq!(label_index(10.0, 0.0, 60, 600), None);
        assert_eq!(label_index(10.0, 300.0, 0, 600), None);
        assert_eq!(label_index(10.0, 300.0, 60, 0), None);
        // fewer stored points than shown
        assert_eq!(label_index(300.0, 300.0, 60, 10), Some(9));
        assert_eq!(label_index(0.0, 300.0, 1, 10), Some(9));
    }
}
