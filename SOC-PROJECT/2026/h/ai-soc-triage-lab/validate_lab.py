import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def load_json(filename):
    with (BASE_DIR / filename).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def event_matches_rule(event, rule):
    if rule.get("event_type") and event.get("event_type") != rule["event_type"]:
        return False

    fields = [
        event.get("message"),
        event.get("process"),
        event.get("command_line"),
        event.get("username"),
        event.get("src_ip"),
        event.get("dest_ip"),
    ]
    haystack = " ".join(value or "" for value in fields).lower()
    return all(keyword.lower() in haystack for keyword in rule.get("keywords", []))


def main():
    events = load_json("sample_events.json")
    rules = load_json("detection_rules.json")
    alerts = [
        (event["id"], rule["id"], rule["name"])
        for event in events
        for rule in rules
        if event_matches_rule(event, rule)
    ]

    print(f"events={len(events)} rules={len(rules)} alerts={len(alerts)}")
    for event_id, rule_id, rule_name in alerts:
        print(f"{event_id} -> {rule_id}: {rule_name}")


if __name__ == "__main__":
    main()
