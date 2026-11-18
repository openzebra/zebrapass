//! End-to-end UI/UX and cryptographic permission tests for the 4-role
//! shared vault system (`Owner`, `Admin`, `Writer`, `Reader`), the Home
//! shared-vault banner, role-aware toolbar chips, and the `[m]` Members modal.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

mod common;

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use memberlog::Role;
use record::{Document, TAG_TITLE};
use tui::App;
use tui::app::flows::dialog::Dialog;
use tui::app::flows::home::Filter;
use tui::app::flows::members::{MembersButton, MembersFocus};
use tui::app::flows::share::{ShareState, Step};
use tui::app::flows::unlocked::{Unlocked, View};
use tui::app::screen::Screen;

use common::{
    PASSWORD, app, keep_to_this_device, make_vault, press, render, render_all, settle, temp_dir,
    tick, type_text, unlock, wait,
};

fn state(app: &App) -> &Unlocked {
    let Screen::Unlocked(state) = &app.screen else {
        panic!("not unlocked")
    };
    state
}

fn share(app: &App) -> &ShareState {
    let View::Sync(share) = &state(app).view else {
        panic!("not on the share screen")
    };
    share
}

fn signed_in(tag: &str) -> App {
    let base = temp_dir(tag);
    make_vault(&base);
    keep_to_this_device(&base);
    let mut app = app(&base);
    unlock(&mut app, PASSWORD);
    app
}

fn until(app: &mut App, what: &str, mut done: impl FnMut(&App) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done(app) {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tick(app, Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn allow_loopback(app: &App) {
    if let Some(p2p) = state(app).p2p.as_deref() {
        p2p.provider.allow_loopback_peers();
    }
}

fn open_shared_home(app: &mut App) {
    let Screen::Unlocked(unlocked) = &mut app.screen else {
        panic!("not unlocked");
    };
    let item = &unlocked.shared[0];
    let id = item.reference.vault_id;
    let name = item.name().to_owned();
    unlocked.view = View::Home;
    unlocked.dialog = None;
    unlocked.home.searching = false;
    unlocked.home.filter = Filter::Shared(id, name.into());
    unlocked.home.selected = 0;
    unlocked.load_detail();
}

fn create_record_in_active(app: &mut App, title: &str) {
    let mut doc = Document::new();
    doc.set_text(TAG_TITLE, title);
    let Screen::Unlocked(unlocked) = &mut app.screen else {
        panic!("not unlocked");
    };
    unlocked.write_active(None, Box::new(doc), &mut app.ctx);
}

fn bring_in_via_share(owner: &mut App, guest: &mut App) {
    press(guest, KeyCode::Char('S'));
    let key = share(guest).me.as_ref().unwrap().text.to_string();
    press(guest, KeyCode::Esc);

    press(owner, KeyCode::Char('S'));
    press(owner, KeyCode::Char('a'));
    owner.on_paste(&key);
    press(owner, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share(owner).step else {
        panic!("expected AddDone")
    };
    let invitation = invitation.to_string();
    press(owner, KeyCode::Esc);
    press(owner, KeyCode::Esc);

    press(guest, KeyCode::Char('S'));
    press(guest, KeyCode::Char('j'));
    guest.on_paste(&invitation);
    press(guest, KeyCode::Enter);
    wait(guest);
    allow_loopback(owner);
    allow_loopback(guest);
    until(guest, "shared vault sync", |app| {
        state(app).shared[0].ready()
    });
}

#[test]
fn home_banner_and_members_modal_render_for_all_roles_and_sizes() {
    let mut alice = signed_in("ui-alice");
    let mut bob = signed_in("ui-bob");

    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "KEYS");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    press(&mut alice, KeyCode::Esc);

    open_shared_home(&mut alice);
    create_record_in_active(&mut alice, "kimi");

    // Bring Bob in (Writer).
    bring_in_via_share(&mut alice, &mut bob);
    open_shared_home(&mut alice);
    open_shared_home(&mut bob);

    // Owner view at 140x40, 100x30, 60x20.
    let [owner_normal, owner_small, owner_wide] = render_all(&alice);
    for screen in [&owner_normal, &owner_wide] {
        assert!(screen.contains("KEYS"), "{screen}");
        assert!(screen.contains("OWNER"), "{screen}");
        assert!(screen.contains("[m] Members"), "{screen}");
        assert!(screen.contains("[a] + Add"), "{screen}");
        assert!(screen.contains("[d] Del record"), "{screen}");
    }
    assert!(owner_small.contains("OWNER"), "{owner_small}");
    assert!(owner_small.contains("[m] Members"), "{owner_small}");
    assert!(owner_wide.contains("[m] MEMBERS"), "{owner_wide}");

    // Writer view at 100x30.
    let writer_screen = render(&bob, 100, 30);
    assert!(writer_screen.contains("WRITER"), "{writer_screen}");
    assert!(writer_screen.contains("[m] Members"), "{writer_screen}");
    assert!(
        writer_screen.contains("can edit, no delete"),
        "{writer_screen}"
    );

    // Owner opens `[m]` Members modal and renders across all sizes.
    press(&mut alice, KeyCode::Char('m'));
    assert!(matches!(
        state(&alice).dialog.as_deref(),
        Some(Dialog::Members(_))
    ));
    let [modal_normal, modal_small, modal_wide] = render_all(&alice);
    for screen in [&modal_normal, &modal_small, &modal_wide] {
        assert!(screen.contains("PARTICIPANTS"), "{screen}");
        assert!(screen.contains("OWNER"), "{screen}");
        assert!(screen.contains("WRITER"), "{screen}");
        assert!(screen.contains("+ Add"), "{screen}");
    }
    assert!(modal_wide.contains("(you)"), "{modal_wide}");
    press(&mut alice, KeyCode::Esc);
    assert!(state(&alice).dialog.is_none());

    // Promote Bob to Admin, refresh Bob, check Admin banner & modal.
    press(&mut alice, KeyCode::Char('m'));
    press(&mut alice, KeyCode::Char('c'));
    press(&mut alice, KeyCode::Right); // Writer -> Admin
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(
        state(&alice).dialog.as_deref(),
        Some(Dialog::Members(_))
    ));
    assert_eq!(state(&alice).people(0)[0].role, Role::Admin);
    press(&mut alice, KeyCode::Esc);

    press(&mut bob, KeyCode::Char('S'));
    press(&mut bob, KeyCode::Char('r'));
    until(&mut bob, "Bob becomes Admin", |app| {
        state(app).shared[0].my_role == Some(Role::Admin)
    });
    open_shared_home(&mut bob);
    let admin_screen = render(&bob, 100, 30);
    assert!(admin_screen.contains("ADMIN"), "{admin_screen}");
    assert!(admin_screen.contains("[d] Del record"), "{admin_screen}");

    // Admin opens `[m]` Members modal and is blocked from managing members.
    press(&mut bob, KeyCode::Char('m'));
    let admin_modal = render(&bob, 100, 30);
    assert!(admin_modal.contains("ADMIN"), "{admin_modal}");
    assert!(!admin_modal.contains("Remove [x]"), "{admin_modal}");
    press(&mut bob, KeyCode::Char('a'));
    let toast_screen = render(&bob, 100, 30);
    assert!(
        toast_screen.contains("Only owners can add people"),
        "{toast_screen}"
    );
    press(&mut bob, KeyCode::Esc);

    // Demote Bob to Reader, check Reader banner.
    press(&mut alice, KeyCode::Char('m'));
    press(&mut alice, KeyCode::Char('c'));
    press(&mut alice, KeyCode::Right); // Admin -> Owner
    press(&mut alice, KeyCode::Right); // Owner -> Reader
    press(&mut alice, KeyCode::Enter);
    press(&mut alice, KeyCode::Esc);
    press(&mut bob, KeyCode::Char('S'));
    press(&mut bob, KeyCode::Char('r'));
    until(&mut bob, "Bob becomes Reader", |app| {
        state(app).shared[0].my_role == Some(Role::Reader)
    });
    open_shared_home(&mut bob);
    let reader_screen = render(&bob, 100, 30);
    assert!(reader_screen.contains("READER"), "{reader_screen}");
    assert!(reader_screen.contains("view only"), "{reader_screen}");
}

#[test]
fn add_role_change_remove_and_delete_permissions_work_end_to_end() {
    let mut alice = signed_in("e2e-alice");
    let mut bob = signed_in("e2e-bob");
    let mut carol = signed_in("e2e-carol");

    // Alice creates shared vault KEYS with two records.
    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('n'));
    type_text(&mut alice, "KEYS");
    press(&mut alice, KeyCode::Enter);
    wait(&mut alice);
    press(&mut alice, KeyCode::Esc);
    open_shared_home(&mut alice);
    create_record_in_active(&mut alice, "alpha");
    create_record_in_active(&mut alice, "beta");

    // Grab Bob's contact card and Carol's contact card.
    press(&mut bob, KeyCode::Char('S'));
    let bob_key = share(&bob).me.as_ref().unwrap().text.to_string();
    press(&mut bob, KeyCode::Esc);

    press(&mut carol, KeyCode::Char('S'));
    let carol_key = share(&carol).me.as_ref().unwrap().text.to_string();
    press(&mut carol, KeyCode::Esc);

    // Owner opens `[m]` Members modal -> navigates to `+ Add` button -> adds Bob.
    press(&mut alice, KeyCode::Char('m'));
    press(&mut alice, KeyCode::Down); // List -> Button(Add) when 1 member (self)
    let Some(Dialog::Members(modal)) = state(&alice).dialog.as_deref() else {
        panic!("expected Members modal");
    };
    assert_eq!(modal.focus, MembersFocus::Button(MembersButton::Add));
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(share(&alice).step, Step::PasteCard));
    alice.on_paste(&bob_key);
    press(&mut alice, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share(&alice).step else {
        panic!("expected AddDone for Bob");
    };
    let bob_invite = invitation.to_string();
    press(&mut alice, KeyCode::Esc); // Returns cleanly to Home + MembersModal!
    assert!(matches!(state(&alice).view, View::Home));
    assert!(matches!(
        state(&alice).dialog.as_deref(),
        Some(Dialog::Members(_))
    ));
    assert_eq!(
        state(&alice)
            .vault_members(&state(&alice).shared[0].reference.vault_id)
            .len(),
        2
    );

    // Also add Carol via `[a]` hotkey directly from Members modal, defaulting role to Admin.
    press(&mut alice, KeyCode::Char('a'));
    alice.on_paste(&carol_key);
    press(&mut alice, KeyCode::Right); // Writer -> Admin
    press(&mut alice, KeyCode::Enter);
    let Step::AddDone { invitation, .. } = &share(&alice).step else {
        panic!("expected AddDone for Carol");
    };
    let carol_invite = invitation.to_string();
    press(&mut alice, KeyCode::Esc);
    assert_eq!(
        state(&alice)
            .vault_members(&state(&alice).shared[0].reference.vault_id)
            .len(),
        3
    );
    press(&mut alice, KeyCode::Esc);

    // Bob (Writer) and Carol (Admin) join and sync.
    allow_loopback(&alice);
    for (guest, inv) in [(&mut bob, bob_invite), (&mut carol, carol_invite)] {
        press(guest, KeyCode::Char('S'));
        press(guest, KeyCode::Char('j'));
        guest.on_paste(&inv);
        press(guest, KeyCode::Enter);
        wait(guest);
        allow_loopback(guest);
        until(guest, "initial shared sync", |app| {
            state(app).shared[0].ready() && state(app).shared[0].cache.len() == 2
        });
        open_shared_home(guest);
    }

    // 1. Writer (Bob) tries to delete a record (`d`) -> blocked with message; both records remain.
    press(&mut bob, KeyCode::Char('d'));
    assert!(
        state(&bob).dialog.is_none(),
        "writer must not open Delete confirm dialog"
    );
    let blocked_screen = render(&bob, 100, 30);
    assert!(
        blocked_screen.contains("Only owners and admins can delete records"),
        "{blocked_screen}"
    );
    assert_eq!(state(&bob).shared[0].cache.len(), 2);

    // 2. Admin (Carol) deletes the first record (`d` + `Enter`) -> deletes and syncs to Alice!
    let target_title = state(&carol).selected().unwrap().display_title().to_owned();
    press(&mut carol, KeyCode::Char('d'));
    assert!(matches!(
        state(&carol).dialog.as_deref(),
        Some(Dialog::Confirm(_))
    ));
    press(&mut carol, KeyCode::Enter);
    settle(&mut carol);
    assert_eq!(state(&carol).shared[0].cache.len(), 1);

    press(&mut alice, KeyCode::Char('S'));
    press(&mut alice, KeyCode::Char('r'));
    until(&mut alice, "Admin deletion reaches Owner", |app| {
        state(app).shared[0].cache.len() == 1
    });
    assert!(
        state(&alice).shared[0]
            .cache
            .iter()
            .all(|rec| rec.display_title() != target_title)
    );
    press(&mut alice, KeyCode::Esc);

    // 3. Owner deletes the remaining record on Home (`d` + `Enter`) -> 0 records left!
    open_shared_home(&mut alice);
    press(&mut alice, KeyCode::Char('d'));
    press(&mut alice, KeyCode::Enter);
    assert_eq!(state(&alice).shared[0].cache.len(), 0);

    // 4. Owner opens `[m]` Members modal and removes a participant (`x` -> Enter) -> rekeys & returns!
    press(&mut alice, KeyCode::Char('m'));
    press(&mut alice, KeyCode::Char('x'));
    assert!(matches!(share(&alice).step, Step::RemoveConfirm { .. }));
    press(&mut alice, KeyCode::Enter);
    assert!(matches!(state(&alice).view, View::Home));
    assert!(matches!(
        state(&alice).dialog.as_deref(),
        Some(Dialog::Members(_))
    ));
    assert_eq!(state(&alice).shared[0].people, 2);
    assert_eq!(state(&alice).shared[0].reference.epoch, 1);
}
