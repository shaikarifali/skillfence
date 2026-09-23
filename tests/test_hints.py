from skillfence.hints import parse_hints


def test_parses_numbered_list_into_ordered_hints():
    text = "1. First hint.\n2. Second hint.\n3. Third hint.\n"
    assert parse_hints(text) == ["First hint.", "Second hint.", "Third hint."]


def test_hint_may_wrap_multiple_lines():
    text = "1. This hint\nkeeps going on the next line.\n2. A short one.\n"
    assert parse_hints(text) == ["This hint keeps going on the next line.", "A short one."]


def test_empty_text_yields_no_hints():
    assert parse_hints("") == []


def test_text_with_no_numbered_markers_yields_no_hints():
    assert parse_hints("Just a paragraph with no list at all.\n") == []


def test_ignores_leading_prose_before_the_first_numbered_item():
    text = "Some preamble.\n\n1. Actual hint one.\n2. Actual hint two.\n"
    assert parse_hints(text) == ["Actual hint one.", "Actual hint two."]
