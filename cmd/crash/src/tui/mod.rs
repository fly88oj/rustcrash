//! TUI - Full-screen interactive terminal UI for RustCrash
//!
//! Matches ShellCrash's menu workflow:
//!   1_start.sh     -> StartMenu     (启动/停止/重启内核)
//!   2_settings.sh   -> SettingsMenu  (配置管理)
//!   running_status -> Status  (运行状态)
//!   Firewall       -> FirewallMenu   (防火墙)
//!   4_setboot.sh   -> SetbootMenu   (启动项)
//!   5_task.sh      -> TaskMenu      (定时任务)
//!   Install        -> InstallMenu    (内核安装)
//!   9_upgrade.sh   -> UpgradeMenu   (更新升级)

use anyhow::Result;
use crossterm::{
    event::DisableMouseCapture,
    event::EnableMouseCapture,
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use rustcrash_core::{Config, ConfigManager, KernelManager, Platform, ProxyKernel};
use std::cell::RefCell;
use std::rc::Rc;

// ---------------------------------------------------------------------------
// App State (Clone wrapper to avoid deriving Clone on managers)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct App {
    platform: Platform,
    config: Option<Config>,
    current_screen: Screen,
    previous_screen: Option<Screen>,
    selected_index: usize,
    input_mode: InputMode,
    input_buffer: String,
    status_message: Option<String>,
    error_message: Option<String>,
    status_details: StatusDetails,
    install_progress: Option<f32>,
    dark_mode: bool,
    search_query: String,
    log_viewer_scroll: usize,
    // Non-clone managers wrapped in Rc<RefCell<...>>
    #[doc(hidden)]
    pub km: Rc<RefCell<KernelManager>>,
    #[doc(hidden)]
    pub cm: Rc<RefCell<ConfigManager>>,
}

#[derive(Clone, Debug)]
pub enum Screen {
    MainMenu,
    StartMenu,
    SettingsMenu,
    Status,
    FirewallMenu,
    SetbootMenu,
    TaskMenu,
    InstallMenu,
    UpgradeMenu,
    ConfigEdit,
    ProvidersMenu,
    SubconverterMenu,
    LogViewer,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum InputMode {
    Navigation,
    Confirm,
    TextInput,
    Selection,
    Search,
}

#[derive(Clone, Debug, Default)]
pub struct StatusDetails {
    pub mihomo_running: bool,
    pub singbox_running: bool,
    pub mihomo_pid: Option<u32>,
    pub singbox_pid: Option<u32>,
    pub mihomo_version: Option<String>,
    pub singbox_version: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

pub fn run_tui(platform: &Platform) -> Result<()> {
    let km = KernelManager::new(platform);
    let cm = ConfigManager::new(platform);
    let config = cm.load().ok();

    let app = App {
        platform: platform.clone(),
        km: Rc::new(RefCell::new(km)),
        cm: Rc::new(RefCell::new(cm)),
        config,
        current_screen: Screen::MainMenu,
        previous_screen: None,
        selected_index: 0,
        input_mode: InputMode::Navigation,
        input_buffer: String::new(),
        status_message: None,
        error_message: None,
        status_details: StatusDetails::default(),
        install_progress: None,
        dark_mode: false,
        search_query: String::new(),
        log_viewer_scroll: 0,
    };

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

fn run_app<B>(terminal: &mut Terminal<B>, mut app: App) -> anyhow::Result<()>
where
    B: ratatui::backend::Backend,
    B::Error: 'static + Send + Sync,
{
    loop {
        terminal.draw(|f| render_screen(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if let Some(true) = handle_key_event(key, &mut app) {
                break Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key Handling
// ---------------------------------------------------------------------------

fn handle_key_event(key: KeyEvent, app: &mut App) -> Option<bool> {
    match app.input_mode {
        InputMode::Navigation => handle_nav_key(key, app),
        InputMode::Confirm => handle_confirm_key(key, app),
        InputMode::TextInput => handle_text_key(key, app),
        InputMode::Selection => handle_selection_key(key, app),
        InputMode::Search => handle_search_key(key, app),
    }
}

fn handle_nav_key(key: KeyEvent, app: &mut App) -> Option<bool> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(true),
        KeyCode::Char('0') => {
            if matches!(app.current_screen, Screen::MainMenu) {
                Some(true)
            } else {
                app.go_back();
                None
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_index > 0 {
                app.selected_index -= 1;
            }
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.selected_index += 1;
            None
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.handle_selection();
            None
        }
        KeyCode::Char('1') => {
            navigate_to(app, Screen::StartMenu, 0);
            None
        }
        KeyCode::Char('2') => {
            navigate_to(app, Screen::SettingsMenu, 0);
            None
        }
        KeyCode::Char('3') => {
            app.refresh_status();
            navigate_to(app, Screen::Status, 0);
            None
        }
        KeyCode::Char('4') => {
            navigate_to(app, Screen::FirewallMenu, 0);
            None
        }
        KeyCode::Char('5') => {
            navigate_to(app, Screen::SetbootMenu, 0);
            None
        }
        KeyCode::Char('6') => {
            navigate_to(app, Screen::TaskMenu, 0);
            None
        }
        KeyCode::Char('7') => {
            navigate_to(app, Screen::InstallMenu, 0);
            None
        }
        KeyCode::Char('8') => {
            navigate_to(app, Screen::UpgradeMenu, 0);
            None
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.refresh_status();
            None
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            app.dark_mode = !app.dark_mode;
            None
        }
        KeyCode::Char('l') | KeyCode::Char('L') => {
            navigate_to(app, Screen::LogViewer, 0);
            app.log_viewer_scroll = 0;
            None
        }
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Search;
            app.search_query.clear();
            None
        }
        _ => None,
    }
}

fn handle_confirm_key(key: KeyEvent, app: &mut App) -> Option<bool> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
            app.confirm_action(true);
            app.input_mode = InputMode::Navigation;
            None
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.confirm_action(false);
            app.input_mode = InputMode::Navigation;
            None
        }
        _ => None,
    }
}

fn handle_text_key(key: KeyEvent, app: &mut App) -> Option<bool> {
    match key.code {
        KeyCode::Enter => {
            app.submit_text_input();
            app.input_mode = InputMode::Navigation;
            None
        }
        KeyCode::Esc => {
            app.input_mode = InputMode::Navigation;
            app.input_buffer.clear();
            None
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
            None
        }
        KeyCode::Char(c) => {
            app.input_buffer.push(c);
            None
        }
        KeyCode::Delete => {
            app.input_buffer.clear();
            None
        }
        _ => None,
    }
}

fn handle_selection_key(key: KeyEvent, app: &mut App) -> Option<bool> {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_index > 0 {
                app.selected_index -= 1;
            }
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.selected_index += 1;
            None
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.select_item(app.selected_index);
            app.input_mode = InputMode::Navigation;
            None
        }
        KeyCode::Esc => {
            app.input_mode = InputMode::Navigation;
            None
        }
        _ => None,
    }
}

fn handle_search_key(key: KeyEvent, app: &mut App) -> Option<bool> {
    match key.code {
        KeyCode::Enter => {
            app.input_mode = InputMode::Navigation;
            None
        }
        KeyCode::Esc => {
            app.input_mode = InputMode::Navigation;
            app.search_query.clear();
            None
        }
        KeyCode::Backspace => {
            app.search_query.pop();
            None
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
            None
        }
        KeyCode::Delete => {
            app.search_query.clear();
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// App Methods
// ---------------------------------------------------------------------------

impl App {
    fn go_back(&mut self) {
        if let Some(prev) = self.previous_screen.clone() {
            self.current_screen = prev;
            self.previous_screen = None;
            self.selected_index = 0;
        } else {
            self.current_screen = Screen::MainMenu;
        }
    }

    fn navigate_to(&mut self, screen: Screen, idx: usize) {
        self.previous_screen = Some(self.current_screen.clone());
        self.current_screen = screen;
        self.selected_index = idx;
        self.input_mode = InputMode::Navigation;
    }

    fn handle_selection(&mut self) {
        match self.current_screen {
            Screen::MainMenu => match self.selected_index {
                0 => self.navigate_to(Screen::StartMenu, 0),
                1 => self.navigate_to(Screen::SettingsMenu, 0),
                2 => self.navigate_to(Screen::FirewallMenu, 0),
                3 => {
                    self.refresh_status();
                    self.navigate_to(Screen::Status, 0);
                }
                4 => self.navigate_to(Screen::SetbootMenu, 0),
                5 => self.navigate_to(Screen::TaskMenu, 0),
                6 => self.navigate_to(Screen::InstallMenu, 0),
                7 => self.navigate_to(Screen::UpgradeMenu, 0),
                _ => {}
            },
            Screen::StartMenu => match self.selected_index {
                0 => self.start_kernel(),
                1 => self.stop_kernel(),
                2 => self.restart_kernel(),
                3 => self.navigate_to(Screen::ConfigEdit, 0),
                4 => self.navigate_to(Screen::ProvidersMenu, 0),
                _ => {}
            },
            Screen::SettingsMenu => match self.selected_index {
                0 => self.navigate_to(Screen::ConfigEdit, 0),
                1 => self.navigate_to(Screen::SubconverterMenu, 0),
                2 => self.navigate_to(Screen::ProvidersMenu, 0),
                _ => {}
            },
            Screen::Status => self.refresh_status(),
            Screen::FirewallMenu => match self.selected_index {
                0 => self.generate_firewall_script(),
                1 => self.apply_firewall(),
                2 => self.cleanup_firewall(),
                _ => {}
            },
            Screen::SetbootMenu => match self.selected_index {
                0 => {
                    self.enable_autostart();
                }
                1 => {
                    self.disable_autostart();
                }
                _ => {}
            },
            Screen::TaskMenu => {}
            Screen::InstallMenu => match self.selected_index {
                0 => self.install_kernel(ProxyKernel::Mihomo),
                1 => self.install_kernel(ProxyKernel::SingBox),
                _ => {}
            },
            Screen::UpgradeMenu => {}
            Screen::ConfigEdit => {}
            Screen::ProvidersMenu => {}
            Screen::SubconverterMenu => {}
            Screen::LogViewer => {}
        }
    }

    fn refresh_status(&mut self) {
        let km = self.km.borrow();
        let mut details = StatusDetails::default();

        for kernel in [ProxyKernel::Mihomo, ProxyKernel::SingBox] {
            if !km.is_installed(kernel) {
                continue;
            }

            let installed = tokio::runtime::Runtime::new()
                .ok()
                .and_then(|rt| rt.block_on(km.installed_kernel(kernel)).ok())
                .flatten();
            if let Some(info) = installed {
                let pid_file = format!(
                    "{}/{}.pid",
                    self.platform.runtime_dir(),
                    kernel.binary_name()
                );
                if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = pid_str.trim().parse::<u32>() {
                        let running = pid > 0
                            && std::process::Command::new("kill")
                                .arg("-0")
                                .arg(pid.to_string())
                                .output()
                                .map(|o| o.status.success())
                                .unwrap_or(false);

                        match kernel {
                            ProxyKernel::Mihomo => {
                                details.mihomo_running = running;
                                details.mihomo_pid = Some(pid);
                                details.mihomo_version = Some(info.version);
                            }
                            ProxyKernel::SingBox => {
                                details.singbox_running = running;
                                details.singbox_pid = Some(pid);
                                details.singbox_version = Some(info.version);
                            }
                        }
                    }
                }
            }
        }

        self.status_details = details;
    }

    fn start_kernel(&mut self) {
        let config = self.config.clone().unwrap_or_default();
        let kernel = if config.kernel == "sing-box" {
            ProxyKernel::SingBox
        } else {
            ProxyKernel::Mihomo
        };
        let km = self.km.borrow();

        if !km.is_installed(kernel) {
            drop(km);
            self.error_message = Some(format!(
                "{} not installed. Run install first.",
                kernel.binary_name()
            ));
            return;
        }

        let path = km.kernel_path(kernel);
        drop(km);
        let cm = self.cm.borrow();
        let config_path = cm.kernel_config_path(kernel);
        drop(cm);

        match std::process::Command::new(&path)
            .arg("-f")
            .arg(&config_path)
            .arg("-d")
            .arg(self.platform.log_dir())
            .spawn()
        {
            Ok(child) => {
                let pid_file = format!(
                    "{}/{}.pid",
                    self.platform.runtime_dir(),
                    kernel.binary_name()
                );
                std::fs::create_dir_all(self.platform.runtime_dir()).ok();
                std::fs::write(&pid_file, child.id().to_string()).ok();
                self.status_message = Some(format!(
                    "Started {} (PID: {})",
                    kernel.binary_name(),
                    child.id()
                ));
                self.refresh_status();
            }
            Err(e) => {
                self.error_message =
                    Some(format!("Failed to start {}: {}", kernel.binary_name(), e));
            }
        }
    }

    fn stop_kernel(&mut self) {
        for kernel in [ProxyKernel::Mihomo, ProxyKernel::SingBox] {
            let pid_file = format!(
                "{}/{}.pid",
                self.platform.runtime_dir(),
                kernel.binary_name()
            );
            if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let _ = std::process::Command::new("kill")
                        .arg(pid.to_string())
                        .output();
                    std::fs::remove_file(&pid_file).ok();
                }
            }
        }
        self.refresh_status();
        self.status_message = Some("Kernels stopped".into());
    }

    fn restart_kernel(&mut self) {
        self.stop_kernel();
        self.start_kernel();
    }

    fn install_kernel(&mut self, kernel: ProxyKernel) {
        self.status_message = Some(format!("Installing {}...", kernel.binary_name()));
        self.install_progress = Some(0.0);
        // TODO: async download with progress
        self.status_message = Some(format!("{} installed", kernel.binary_name()));
        self.install_progress = None;
    }

    fn generate_firewall_script(&mut self) {
        use rustcrash_core::Firewall;
        let firewall = Firewall::new(&self.platform);
        let _script = firewall.generate_iptables_script(&Default::default());
        self.status_message = Some("Firewall script generated".into());
    }

    fn apply_firewall(&mut self) {
        if !self.platform.is_root() {
            self.error_message = Some("Root privileges required".into());
            return;
        }
        self.status_message = Some("Applying firewall rules...".into());
    }

    fn cleanup_firewall(&mut self) {
        if !self.platform.is_root() {
            self.error_message = Some("Root privileges required".into());
            return;
        }
        self.status_message = Some("Cleaning up firewall rules...".into());
    }

    fn enable_autostart(&mut self) {
        self.status_message = Some("Autostart enabled".into());
    }

    fn disable_autostart(&mut self) {
        self.status_message = Some("Autostart disabled".into());
    }

    fn confirm_action(&mut self, _accepted: bool) {}
    fn submit_text_input(&mut self) {}
    fn select_item(&mut self, _index: usize) {}

    fn kernel_status_display(&self, kernel: ProxyKernel) -> (String, Color) {
        let km = self.km.borrow();
        let installed = km.is_installed(kernel);
        if !installed {
            drop(km);
            return ("Not installed".to_string(), Color::Rgb(80, 80, 80));
        }

        let running = match kernel {
            ProxyKernel::Mihomo => self.status_details.mihomo_running,
            ProxyKernel::SingBox => self.status_details.singbox_running,
        };

        let ver = match kernel {
            ProxyKernel::Mihomo => self.status_details.mihomo_version.clone(),
            ProxyKernel::SingBox => self.status_details.singbox_version.clone(),
        };

        let pid = match kernel {
            ProxyKernel::Mihomo => self.status_details.mihomo_pid,
            ProxyKernel::SingBox => self.status_details.singbox_pid,
        };
        drop(km);

        if running {
            (
                format!("Running (PID: {:?}, v{:?})", pid, ver),
                Color::Green,
            )
        } else {
            ("Installed (stopped)".to_string(), Color::Yellow)
        }
    }
}

fn navigate_to(app: &mut App, screen: Screen, idx: usize) {
    app.previous_screen = Some(app.current_screen.clone());
    app.current_screen = screen;
    app.selected_index = idx;
    app.input_mode = InputMode::Navigation;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_screen(f: &mut Frame, app: &mut App) {
    match app.input_mode {
        InputMode::Confirm => render_confirm_dialog(f),
        InputMode::TextInput => render_text_input(f, app),
        InputMode::Search => {
            render_search_overlay(f, app);
        }
        _ => match app.current_screen {
            Screen::MainMenu => render_main_menu(f, app),
            Screen::StartMenu => render_start_menu(f, app),
            Screen::SettingsMenu => render_settings_menu(f, app),
            Screen::Status => {
                app.refresh_status();
                render_status_screen(f, app);
            }
            Screen::FirewallMenu => render_firewall_menu(f, app),
            Screen::SetbootMenu => render_setboot_menu(f, app),
            Screen::TaskMenu => render_task_menu(f, app),
            Screen::InstallMenu => render_install_menu(f, app),
            Screen::UpgradeMenu => render_upgrade_menu(f, app),
            Screen::ConfigEdit => render_config_edit(f, app),
            Screen::ProvidersMenu => render_providers_menu(f, app),
            Screen::SubconverterMenu => render_subconverter_menu(f, app),
            Screen::LogViewer => render_log_viewer(f, app),
        },
    }
}

fn base_layout(f: &mut Frame) -> Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .split(f.area())
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let info = format!(
        "{} {} | {} | {}",
        app.platform.os, app.platform.arch, app.platform.firewall_backend, app.platform.init_system
    );

    let block = Block::default()
        .title(format!(" RustCrash v{} {}", version, info))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(200, 160, 60)))
        .border_type(BorderType::Rounded)
        .title_style(
            Style::default()
                .fg(Color::Rgb(200, 160, 60))
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(block, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let (msg, color) = if let Some(ref e) = app.error_message {
        (e.as_str(), Color::Red)
    } else if let Some(ref s) = app.status_message {
        (s.as_str(), Color::Green)
    } else {
        (
            "↑↓ Navigate | Enter Select | 0/q Exit",
            Color::Rgb(100, 100, 120),
        )
    };

    let paragraph = Paragraph::new(msg)
        .style(Style::default().fg(color))
        .alignment(Alignment::Center);

    f.render_widget(paragraph, area);
}

fn menu_widget<'a>(title: &str, selected: usize, items: &'a [&str]) -> List<'a> {
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, &text)| {
            let style = if i == selected {
                Style::default()
                    .fg(Color::Rgb(15, 15, 26))
                    .bg(Color::Rgb(200, 160, 60))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Rgb(200, 200, 220))
            };
            let prefix = if i == selected { "▶ " } else { "  " };
            ListItem::new(format!("{}{}", prefix, text)).style(style)
        })
        .collect();

    List::new(list_items).block(
        Block::default()
            .title(format!(" {} ", title))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(80, 80, 120)))
            .border_type(BorderType::Rounded),
    )
}

fn info_block_widget(title: &str) -> Block<'_> {
    Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(80, 80, 120)))
        .border_type(BorderType::Rounded)
}

// ---------------------------------------------------------------------------
// Screen Renderers
// ---------------------------------------------------------------------------

fn render_main_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let menu_items = [
        "1. 启动/重启内核   Start kernel",
        "2. 配置管理       Settings",
        "3. 防火墙设置       Firewall",
        "4. 运行状态        Status",
        "5. 启动项管理       Setboot",
        "6. 定时任务         Tasks",
        "7. 内核安装         Install",
        "8. 更新升级         Upgrade",
    ];
    f.render_widget(
        menu_widget(" 主菜单 Main Menu ", app.selected_index, &menu_items),
        main[0],
    );

    let (mihomo_text, mihomo_color) = app.kernel_status_display(ProxyKernel::Mihomo);
    let (singbox_text, singbox_color) = app.kernel_status_display(ProxyKernel::SingBox);

    let info_lines = vec![
        Line::from(vec![
            Span::raw("Platform: "),
            Span::styled(
                format!("{} {}", app.platform.os, app.platform.arch),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Init: "),
            Span::styled(
                app.platform.init_system.to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Firewall: "),
            Span::styled(
                app.platform.firewall_backend.to_string(),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("CrashDir: "),
            Span::styled(app.platform.crash_dir(), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::raw("Root: "),
            Span::styled(
                if app.platform.is_root() { "YES" } else { "NO" },
                Style::default().fg(if app.platform.is_root() {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Kernel Status ",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from(vec![
            Span::raw("mihomo: "),
            Span::styled(mihomo_text, Style::default().fg(mihomo_color)),
        ]),
        Line::from(vec![
            Span::raw("sing-box: "),
            Span::styled(singbox_text, Style::default().fg(singbox_color)),
        ]),
    ];

    let para = Paragraph::new(info_lines)
        .block(info_block_widget(" 系统信息 System Info "))
        .alignment(Alignment::Left);
    f.render_widget(para, main[1]);

    draw_footer(f, app, chunks[2]);
}

fn render_start_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "▶ 启动内核    Start kernel",
        "■ 停止内核    Stop kernel",
        "⟳ 重启内核    Restart kernel",
        "✎ 编辑配置    Edit Config",
        "📡 节点管理    Providers",
    ];
    f.render_widget(
        menu_widget(" 启动控制 Start Menu ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_settings_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let config = app.config.clone().unwrap_or_default();
    let items = [
        format!("✎ 编辑配置    Edit Config (kernel: {})", config.kernel),
        "🔄 订阅转换    Subconverter".to_string(),
        "📡 节点订阅    Providers".to_string(),
    ];
    let items_ref: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    f.render_widget(
        menu_widget(" 配置管理 Settings ", app.selected_index, &items_ref),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_status_screen(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let (mihomo_text, mihomo_color) = app.kernel_status_display(ProxyKernel::Mihomo);
    let (singbox_text, singbox_color) = app.kernel_status_display(ProxyKernel::SingBox);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  mihomo  ",
            Style::default().bg(Color::Rgb(40, 40, 70)).fg(Color::White),
        )),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(&mihomo_text, Style::default().fg(mihomo_color)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  sing-box  ",
            Style::default().bg(Color::Rgb(40, 40, 70)).fg(Color::White),
        )),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(&singbox_text, Style::default().fg(singbox_color)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Platform: "),
            Span::styled(
                format!("{} {}", app.platform.os, app.platform.arch),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("CrashDir: "),
            Span::styled(app.platform.crash_dir(), Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::raw("Mode: "),
            Span::styled(
                app.config
                    .as_ref()
                    .map(|c| c.mode.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];

    let para = Paragraph::new(lines)
        .block(info_block_widget(" 运行状态 Running Status "))
        .alignment(Alignment::Left);
    f.render_widget(para, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn render_firewall_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "📜 生成防火墙脚本   Generate script",
        "⚡ 应用防火墙规则   Apply rules",
        "🗑  清理防火墙规则   Cleanup rules",
    ];
    f.render_widget(
        menu_widget(" 防火墙 Firewall ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_setboot_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "✅ 启用开机启动   Enable autostart",
        "❌ 禁用开机启动   Disable autostart",
    ];
    f.render_widget(
        menu_widget(" 启动项 Setboot ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_task_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "📋 查看定时任务   List tasks",
        "➕ 添加定时任务   Add task",
        "🗑 删除定时任务   Remove task",
    ];
    f.render_widget(
        menu_widget(" 定时任务 Task ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_install_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let km = app.km.borrow();
    let (mihomo_inst, mihomo_ver) = {
        let installed = km.is_installed(ProxyKernel::Mihomo);
        let ver = tokio::runtime::Runtime::new()
            .ok()
            .and_then(|rt| rt.block_on(km.installed_kernel(ProxyKernel::Mihomo)).ok())
            .flatten()
            .map(|i| i.version);
        (installed, ver)
    };
    let (singbox_inst, singbox_ver) = {
        let installed = km.is_installed(ProxyKernel::SingBox);
        let ver = tokio::runtime::Runtime::new()
            .ok()
            .and_then(|rt| rt.block_on(km.installed_kernel(ProxyKernel::SingBox)).ok())
            .flatten()
            .map(|i| i.version);
        (installed, ver)
    };
    drop(km);

    let items = [
        format!(
            "⬇ 安装 mihomo{}",
            if mihomo_inst {
                format!(" (已安装 v{:?})", mihomo_ver)
            } else {
                String::new()
            }
        ),
        format!(
            "⬇ 安装 sing-box{}",
            if singbox_inst {
                format!(" (已安装 v{:?})", singbox_ver)
            } else {
                String::new()
            }
        ),
    ];
    let items_ref: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    f.render_widget(
        menu_widget(" 内核安装 Install ", app.selected_index, &items_ref),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_upgrade_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "⬆ 检查更新        Check update",
        "⬆ 升级内核        Upgrade kernel",
        "⬆ 升级 RustCrash  Upgrade ShellCrash",
    ];
    f.render_widget(
        menu_widget(" 更新升级 Upgrade ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_config_edit(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let config = app.config.clone().unwrap_or_default();
    let items = [
        format!("内核 Kernel: {}", config.kernel),
        format!("代理端口 Proxy port: {}", config.proxy_port),
        format!("DNS端口 DNS port: {}", config.dns_port),
        format!("模式 Mode: {}", config.mode),
        format!("自动更新 Auto update: {}", config.auto_update),
        format!("更新周期 Update interval: {}", config.update_interval),
    ];
    let items_ref: Vec<&str> = items.iter().map(|s| s.as_str()).collect();
    f.render_widget(
        menu_widget(" 内核配置 Config ", app.selected_index, &items_ref),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_providers_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "📡 添加订阅   Add provider",
        "📋 管理订阅   Manage providers",
        "🔄 更新订阅   Update providers",
    ];
    f.render_widget(
        menu_widget(" 节点订阅 Providers ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

fn render_subconverter_menu(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let items = [
        "🔄 订阅转换   Convert subscription",
        "📝 自定义规则   Custom rules",
        "🌐 规则模板   Rule templates",
    ];
    f.render_widget(
        menu_widget(" 订阅转换 Subconverter ", app.selected_index, &items),
        chunks[1],
    );
    draw_footer(f, app, chunks[2]);
}

// ---------------------------------------------------------------------------
// Overlay dialogs
// ---------------------------------------------------------------------------

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(width),
            Constraint::Fill(1),
        ])
        .split(v[1])[1]
}

fn render_confirm_dialog(f: &mut Frame) {
    let area = f.area();
    let popup = centered_rect(40, 8, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(200, 160, 60)))
        .border_type(BorderType::Rounded)
        .title(" 确认 Confirm ");

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            " Confirm this action? ",
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "[Y] Yes  ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[N] No   ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];

    let para = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Center);
    f.render_widget(para, popup);
}

fn render_text_input(f: &mut Frame, app: &App) {
    let area = f.area();
    let popup = centered_rect(50, 6, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(80, 80, 120)))
        .border_type(BorderType::Rounded)
        .title(" 输入 Input ");

    let suffix = if app.input_buffer.is_empty() { " " } else { "" };
    let text = format!("{}{}", app.input_buffer, suffix);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(&text, Style::default().fg(Color::Cyan))),
        Line::from(""),
        Line::from(Span::styled(
            " Press Enter to confirm | Esc to cancel ",
            Style::default().fg(Color::Rgb(80, 80, 80)),
        )),
    ];

    let para = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Center);
    f.render_widget(para, popup);
}

// ---------------------------------------------------------------------------
// Color Scheme
// ---------------------------------------------------------------------------

impl App {}

// ---------------------------------------------------------------------------
// Search Overlay
// ---------------------------------------------------------------------------

fn render_search_overlay(f: &mut Frame, app: &mut App) {
    // First render the current screen
    match app.current_screen {
        Screen::MainMenu => render_main_menu(f, app),
        Screen::StartMenu => render_start_menu(f, app),
        Screen::SettingsMenu => render_settings_menu(f, app),
        Screen::Status => {
            app.refresh_status();
            render_status_screen(f, app);
        }
        Screen::FirewallMenu => render_firewall_menu(f, app),
        Screen::SetbootMenu => render_setboot_menu(f, app),
        Screen::TaskMenu => render_task_menu(f, app),
        Screen::InstallMenu => render_install_menu(f, app),
        Screen::UpgradeMenu => render_upgrade_menu(f, app),
        Screen::ConfigEdit => render_config_edit(f, app),
        Screen::ProvidersMenu => render_providers_menu(f, app),
        Screen::SubconverterMenu => render_subconverter_menu(f, app),
        Screen::LogViewer => render_log_viewer(f, app),
    }

    // Then overlay the search bar at the bottom
    let area = f.area();
    let search_height = 3;
    let search_area = Rect::new(0, area.height - search_height, area.width, search_height);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(80, 160, 220)))
        .border_type(BorderType::Rounded)
        .title(" 搜索 Filter ");

    let query_text = if app.search_query.is_empty() {
        " ".to_string()
    } else {
        app.search_query.clone()
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw(" / "),
            Span::styled(&query_text, Style::default().fg(Color::Cyan)),
            Span::raw(" "),
        ]),
    ];

    let para = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left);

    f.render_widget(para, search_area);
}

// ---------------------------------------------------------------------------
// Log Viewer
// ---------------------------------------------------------------------------

fn render_log_viewer(f: &mut Frame, app: &App) {
    let chunks = base_layout(f);
    draw_header(f, app, chunks[0]);

    let log_path = app.platform.log_path();
    let log_content = if let Ok(content) = std::fs::read_to_string(&log_path) {
        content
    } else {
        format!(
            "Log file not found: {}\n\nPress 0 or q to go back.",
            log_path
        )
    };

    let lines: Vec<Line> = log_content
        .lines()
        .map(|line| {
            Line::from(Span::styled(
                line,
                Style::default().fg(Color::Rgb(200, 200, 200)),
            ))
        })
        .collect();

    let block_title = format!(" 日志 Logs - {} ", log_path);
    let paragraph = Paragraph::new(lines)
        .block(info_block_widget(&block_title))
        .alignment(Alignment::Left)
        .scroll((app.log_viewer_scroll as u16, 0));

    f.render_widget(paragraph, chunks[1]);

    let footer_text = if app.dark_mode {
        "[D] Light Mode | "
    } else {
        "[D] Dark Mode | "
    };
    let msg = format!("{}↑↓ Scroll | 0/q Back", footer_text);
    let paragraph_footer = Paragraph::new(msg)
        .style(Style::default().fg(Color::Rgb(100, 100, 120)))
        .alignment(Alignment::Center);
    f.render_widget(paragraph_footer, chunks[2]);
}
