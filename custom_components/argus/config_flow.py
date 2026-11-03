"""Config flow: Argus URL + API token (SECSCAN_API_TOKEN)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_TOKEN, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import ArgusAuthError, ArgusClient, ArgusError
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN, MIN_SCAN_INTERVAL


class ArgusConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def _validate(self, url: str, token: str, verify: bool) -> tuple[dict, str | None]:
        client = ArgusClient(async_get_clientsession(self.hass, verify_ssl=verify),
                             url, token, verify)
        try:
            return await client.overview(), None
        except ArgusAuthError:
            return {}, "invalid_auth"
        except ArgusError:
            return {}, "cannot_connect"

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            url = user_input[CONF_URL].strip().rstrip("/")
            if not url.startswith(("http://", "https://")):
                errors[CONF_URL] = "invalid_url"
            else:
                await self.async_set_unique_id(url.lower())
                self._abort_if_unique_id_configured()
                _, error = await self._validate(url, user_input[CONF_TOKEN],
                                                user_input[CONF_VERIFY_SSL])
                if error:
                    errors["base"] = error
                else:
                    title = url.split("://", 1)[1].split("/", 1)[0]
                    return self.async_create_entry(
                        title=f"Argus ({title})",
                        data={CONF_URL: url, CONF_TOKEN: user_input[CONF_TOKEN],
                              CONF_VERIFY_SSL: user_input[CONF_VERIFY_SSL]},
                    )
        schema = vol.Schema({
            vol.Required(CONF_URL, default=(user_input or {}).get(CONF_URL, "")): str,
            vol.Required(CONF_TOKEN): str,
            vol.Required(CONF_VERIFY_SSL, default=True): bool,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            _, error = await self._validate(entry.data[CONF_URL], user_input[CONF_TOKEN],
                                            entry.data.get(CONF_VERIFY_SSL, True))
            if error:
                errors["base"] = error
            else:
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_TOKEN: user_input[CONF_TOKEN]}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_TOKEN): str}),
            errors=errors,
            description_placeholders={"url": entry.data[CONF_URL]},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return ArgusOptionsFlow()


class ArgusOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        current = self.config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        schema = vol.Schema({
            vol.Required(CONF_SCAN_INTERVAL, default=current):
                vol.All(vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=86400)),
        })
        return self.async_show_form(step_id="init", data_schema=schema)
