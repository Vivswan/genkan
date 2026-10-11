// MV3 grants browser.permissions.request only inside a user gesture, which the service worker that persists
// the allowlist never has, so the options page must ask for the host permission inside the Add click and
// persist nothing when the prompt is declined; a site that reaches the list without its permission fails at
// injection with no visible reason.

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

let sent: Array<{ type: string; glob?: string }>;
let request: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  const EN = {
    popup_no_sites: { message: "No sites yet." },
    common_add: { message: "Add" },
    common_remove: { message: "Remove" },
    settings_add_site_placeholder: { message: "https://example.com/*" },
    settings_add_site_format: { message: "Format should be https://host/*" },
    settings_add_site_parse_failed: { message: "Could not parse the URL" },
    settings_add_site_permission_declined: { message: "Permission declined; nothing was added." },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: string; glob?: string };
    sent.push(m);
    return m.type === "get_allowlist" ? { ok: true, list: [] } : { ok: true, list: [m.glob] };
  });
  request = vi.fn();
  (fakeBrowser as unknown as Record<string, unknown>).permissions = { request };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function addSite(url: string) {
  const { SiteList } = await import("@/entrypoints/options/SiteList");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  render(<SiteList />);
  const user = userEvent.setup();
  await user.type(screen.getByPlaceholderText("https://example.com/*"), url);
  await user.click(screen.getByRole("button", { name: "Add" }));
}

describe("SiteList add", () => {
  const cases: [label: string, prompt: () => Promise<boolean>, persisted: boolean][] = [
    ["granted: the glob is persisted", async () => true, true],
    ["declined: nothing is persisted and the note says so", async () => false, false],
    [
      "the prompt throws: treated as declined",
      async () => Promise.reject(new Error("no gesture")),
      false,
    ],
  ];
  test.each(cases)("%s", async (_label, prompt, persisted) => {
    request.mockImplementation(prompt);
    await addSite("https://example.com/path");
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    expect(request).toHaveBeenCalledWith({ origins: ["https://example.com/*"] });
    const adds = () => sent.filter((m) => m.type === "add_allow");
    if (persisted) {
      await waitFor(() =>
        expect(adds()).toEqual([{ type: "add_allow", glob: "https://example.com/*" }]),
      );
      expect(screen.queryByRole("alert")).toBeNull();
    } else {
      await screen.findByText("Permission declined; nothing was added.");
      expect(adds()).toEqual([]);
    }
  });
});
