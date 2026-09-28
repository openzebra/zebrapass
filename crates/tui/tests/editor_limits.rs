//! The editor refuses input past the record limits before any buffer grows:
//! custom names at `MAX_CUSTOM_NAME`, values at the `u16` wire length, the
//! document at `MAX_DOC_LEN`, and the field count at `MAX_FIELDS`.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

use record::{MAX_CUSTOM_NAME, MAX_DOC_LEN};
use tui::app::flows::editor::{EditorState, Part, Value, VALUE_MAX};

fn focus(editor: &mut EditorState, index: usize, part: Part) {
    editor.focus = editor
        .stops()
        .iter()
        .position(|stop| *stop == (index, part))
        .unwrap();
}

#[test]
fn custom_names_stop_at_the_limit() {
    let mut editor = EditorState::new_record();
    assert!(editor.add(0));
    let index = editor
        .fields
        .iter()
        .position(|field| field.name.is_some())
        .unwrap();
    focus(&mut editor, index, Part::Name);
    editor.on_paste(&"n".repeat(MAX_CUSTOM_NAME + 20));
    assert_eq!(
        editor.fields[index].name.as_ref().unwrap().len(),
        MAX_CUSTOM_NAME
    );
}

#[test]
fn secret_values_stop_at_the_wire_length_without_growing_past_it() {
    let mut editor = EditorState::new_record();
    let index = editor
        .fields
        .iter()
        .position(|field| field.tag == record::TAG_PASSWORD)
        .unwrap();
    focus(&mut editor, index, Part::Value);
    editor.on_paste(&"p".repeat(VALUE_MAX + 5_000));
    let Value::Secret(input) = &editor.fields[index].value else {
        panic!("password is secret")
    };
    assert_eq!(input.len(), VALUE_MAX);
    assert!(
        input.capacity() <= VALUE_MAX,
        "capacity {} grew past the limit",
        input.capacity()
    );
}

#[test]
fn the_document_stays_under_one_mebibyte() {
    let mut editor = EditorState::new_record();
    for _ in 0..24 {
        if !editor.add(1) {
            break;
        }
        let index = editor
            .fields
            .iter()
            .rposition(|field| field.name.is_some())
            .unwrap();
        focus(&mut editor, index, Part::Name);
        editor.on_paste("blob");
        focus(&mut editor, index, Part::Value);
        editor.on_paste(&"x".repeat(VALUE_MAX));
        assert!(
            editor.estimated_size() <= MAX_DOC_LEN,
            "size {} passed the limit",
            editor.estimated_size()
        );
    }
    assert!(
        editor.estimated_size() > MAX_DOC_LEN - VALUE_MAX,
        "the test filled the document"
    );
}
