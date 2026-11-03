"""Config flow + entity setup for custom_components/argus against a mocked Argus API."""
from homeassistant import config_entries
from homeassistant.const import CONF_TOKEN, CONF_URL, CONF_VERIFY_SSL
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.argus.const import DOMAIN

URL = "http://argus.local:8080"

OVERVIEW = {
    "version": "1.2.0",
    "generated_at": "2026-11-03T10:00:00+00:00",
    "totals": {"systems": 2, "systems_with_updates": 1, "updates": 3, "critical": 1,
               "high": 2, "eol": 1, "scan_errors": 0, "agents": 1, "agents_pending": 0},
    "systems": [
        {"id": 1, "name": "NAS", "kind": "synology", "hostname": "nas", "updates": 3,
         "critical": 1, "high": 2, "packages": 40, "status": "ok",
         "last_scan_at": "2026-11-03T09:00:00+00:00", "os_support": "END-OF-LIFE",
         "eol": True, "group": "Home", "tags": []},
        {"id": 2, "name": "Pi", "kind": "linux", "updates": 0, "critical": 0, "high": 0,
         "packages": 10, "status": "ok", "last_scan_at": None, "eol": False, "tags": []},
    ],
}


async def test_config_flow_success(hass, aioclient_mock):
    aioclient_mock.get(f"{URL}/api/overview", json=OVERVIEW)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_URL: URL + "/", CONF_TOKEN: "t", CONF_VERIFY_SSL: True})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_URL] == URL


async def test_config_flow_invalid_auth(hass, aioclient_mock):
    aioclient_mock.get(f"{URL}/api/overview", status=401)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_URL: URL, CONF_TOKEN: "bad", CONF_VERIFY_SSL: True})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}


async def test_entities(hass, aioclient_mock):
    aioclient_mock.get(f"{URL}/api/overview", json=OVERVIEW)
    aioclient_mock.post(f"{URL}/api/systems/1/scan", json={"ok": True})
    entry = MockConfigEntry(domain=DOMAIN, title="Argus (argus.local)",
                            data={CONF_URL: URL, CONF_TOKEN: "t", CONF_VERIFY_SSL: True},
                            unique_id=URL)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    states = {s.entity_id: s for s in hass.states.async_all()}
    by_name = {s.attributes.get("friendly_name"): s for s in states.values()}

    assert by_name["Argus (argus.local) Critical CVEs"].state == "1"
    assert by_name["Argus (argus.local) Systems"].state == "2"
    assert by_name["NAS Pending updates"].state == "3"
    assert by_name["NAS Update available"].state == "on"
    assert by_name["NAS OS end-of-life"].state == "on"
    assert by_name["Pi Update available"].state == "off"
    assert by_name["Pi Last scan"].state == "unknown"

    rescan = by_name["NAS Rescan"].entity_id
    await hass.services.async_call("button", "press", {"entity_id": rescan}, blocking=True)
    assert any(str(call[1]).endswith("/api/systems/1/scan") for call in aioclient_mock.mock_calls)

    assert await hass.config_entries.async_unload(entry.entry_id)
