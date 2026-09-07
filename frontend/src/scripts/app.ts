import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";

type JSONValue =
  null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };
type User = {
  ID: string;
  Username: string;
  Enabled: boolean;
  CreatedAt: string;
  LastLoginAt?: string;
  Roles?: string[];
  Permissions?: string[];
};
type Container = {
  Id?: string;
  ID?: string;
  Names?: string[];
  Image?: string;
  State?: string;
  Status?: string;
  Created?: number;
  Labels?: Record<string, string>;
  Ports?: Array<{
    PrivatePort: number;
    PublicPort?: number;
    Type: string;
    IP?: string;
  }>;
  Health?: { Status?: string };
};
type Role = {
  ID: string;
  Name: string;
  Description: string;
  Builtin: boolean;
  Permissions?: string[];
};
type Permission = {
  Name: string;
  Category: string;
  Description: string;
  Roles?: string[];
};
type Rule = {
  ID?: string;
  Effect: string;
  Action: string;
  SubjectRoleID?: string;
  MatchType: string;
  MatchKey: string;
  MatchValue: string;
  Priority?: number;
};
type Policy = {
  ID: string;
  Name: string;
  Description: string;
  Enabled: boolean;
  Rules?: Rule[];
};
type Audit = {
  ID: string;
  Timestamp: string;
  Username: string;
  Action: string;
  ResourceType: string;
  ResourceID: string;
  Result: string;
  Reason: string;
};

const $ = <T extends Element>(
  selector: string,
  root: ParentNode = document,
): T | null => root.querySelector<T>(selector);
const $$ = <T extends Element>(
  selector: string,
  root: ParentNode = document,
): T[] => Array.from(root.querySelectorAll<T>(selector));
const esc = (value: unknown): string =>
  String(value ?? "").replace(
    /[&<>'"]/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[
        c
      ] ?? c,
  );
const text = (value: unknown): string =>
  typeof value === "string" ? value : value == null ? "—" : String(value);
const csrf = (): string =>
  decodeURIComponent(
    document.cookie
      .split("; ")
      .find((x) => x.startsWith("dv_csrf="))
      ?.split("=")[1] ?? "",
  );
const page = document.body.dataset.page ?? "";
let currentUser: User | null = null;
let containers: Container[] = [];

class APIError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly status: number,
  ) {
    super(message);
  }
}
async function api<T = JSONValue>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set("Content-Type", "application/json");
  if (options.method && options.method !== "GET")
    headers.set("X-CSRF-Token", csrf());
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  if (response.status === 204) return undefined as T;
  const body = (await response.json().catch(() => ({
    error: { message: "Invalid server response", code: "BAD_RESPONSE" },
  }))) as { error?: { message?: string; code?: string } };
  if (!response.ok)
    throw new APIError(
      body.error?.message ?? "Request failed",
      body.error?.code ?? "REQUEST_FAILED",
      response.status,
    );
  return body as T;
}
function toast(message: string) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = message;
  el.classList.add("show");
  window.setTimeout(() => el.classList.remove("show"), 2600);
}
function showError(form: HTMLFormElement, error: unknown) {
  const el = $(".form-error", form);
  if (el)
    el.textContent =
      error instanceof Error ? error.message : "Something went wrong";
}
function nameOf(c: Container): string {
  return (c.Names?.[0] ?? c.ID ?? c.Id ?? "unknown").replace(/^\//, "");
}
function idOf(c: Container): string {
  return c.ID ?? c.Id ?? nameOf(c);
}
function has(permission: string): boolean {
  return currentUser?.Permissions?.includes(permission) ?? false;
}
function fmtDate(v: unknown): string {
  if (!v) return "Never";
  const d = new Date(text(v));
  return Number.isNaN(d.valueOf())
    ? text(v)
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(d);
}
function uptime(c: Container): string {
  if (!c.Created) return "—";
  const seconds = Math.max(0, Date.now() / 1000 - c.Created);
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
function ports(c: Container): string {
  return (
    (c.Ports ?? [])
      .map((p) =>
        p.PublicPort
          ? `${p.PublicPort}:${p.PrivatePort}/${p.Type}`
          : `${p.PrivatePort}/${p.Type}`,
      )
      .join(", ") || "—"
  );
}
function jsonObject(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

async function initAuth() {
  const loading = $("#auth-loading");
  try {
    const status = await api<{ needs_setup: boolean }>("/status");
    loading?.setAttribute("hidden", "");
    const form = $<HTMLFormElement>(
      status.needs_setup ? "#setup-form" : "#login-form",
    );
    form?.removeAttribute("hidden");
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (status.needs_setup) {
        const data = new FormData(form);
        if (data.get("password") !== data.get("confirm")) {
          showError(form, new Error("Passwords do not match"));
          return;
        }
      }
      const data = Object.fromEntries(new FormData(form));
      delete data.confirm;
      try {
        await api(status.needs_setup ? "/bootstrap" : "/auth/login", {
          method: "POST",
          body: JSON.stringify(data),
        });
        location.href = "/app/overview/";
      } catch (err) {
        showError(form, err);
      }
    });
  } catch {
    if (loading)
      loading.textContent = "DockerView is unavailable. Check the server logs.";
  }
}
async function initShell() {
  try {
    const result = await api<{ user: User }>("/auth/me");
    currentUser = result.user;
    const name = $("#account-name"),
      role = $("#account-role"),
      avatar = $("#avatar");
    if (name) name.textContent = currentUser.Username;
    if (role) role.textContent = (currentUser.Roles ?? []).join(" · ");
    if (avatar)
      avatar.textContent = currentUser.Username.slice(0, 2).toUpperCase();
    $$<HTMLElement>("[data-permission]").forEach((el) => {
      if (!has(el.dataset.permission ?? "")) el.hidden = true;
    });
    const admin = $<HTMLElement>("[data-admin]");
    if (admin && !$$<HTMLElement>("[data-admin-link]").some((el) => !el.hidden))
      admin.hidden = true;
    $(`[data-nav="${page}"]`)?.classList.add("active");
    const status = await api<{ instance: string; environment: string }>(
      "/status",
    );
    const i = $("#instance-name"),
      e = $("#environment-name");
    if (i) i.textContent = status.instance;
    if (e) e.textContent = status.environment;
    $("#logout")?.addEventListener("click", async () => {
      await api("/auth/logout", { method: "POST" });
      location.href = "/";
    });
    $("#refresh")?.addEventListener("click", () => location.reload());
    $$<HTMLElement>("[data-action=refresh]").forEach((el) =>
      el.addEventListener("click", () => location.reload()),
    );
    await route();
  } catch (err) {
    if (err instanceof APIError && err.status === 401) location.href = "/";
    else toast(err instanceof Error ? err.message : "Unable to initialize");
  }
}
async function loadContainers(): Promise<Container[]> {
  if (containers.length === 0)
    containers = await api<Container[]>("/containers/");
  return containers;
}
function containerOptions(list: Container[], allowStopped = true): string {
  return list
    .filter((c) => allowStopped || c.State === "running")
    .map(
      (c) =>
        `<option value="${esc(idOf(c))}" data-system="${c.Labels?.["dockerview.system"] ?? "false"}">${esc(nameOf(c))} · ${esc(c.State)}</option>`,
    )
    .join("");
}

async function overview() {
  const data = await api<{
    running: number;
    stopped: number;
    unhealthy: number;
    docker: string;
    containers: Container[];
    host: Record<string, unknown>;
  }>("/overview");
  containers = data.containers;
  const cards = $$("#overview-metrics article strong");
  [
    data.running,
    data.stopped,
    data.unhealthy,
    "Connected",
    data.host.NCPU ?? "—",
    formatBytes(Number(data.host.MemTotal ?? 0)),
  ].forEach((v, i) => {
    if (cards[i]) cards[i].textContent = String(v);
  });
  const body = $("#overview-containers");
  if (body)
    body.innerHTML =
      containers
        .slice(0, 8)
        .map(
          (c) =>
            `<tr><td class="name-cell">${esc(nameOf(c))}<small>${esc(idOf(c).slice(0, 12))}</small></td><td><span class="badge ${c.State === "running" ? "" : "stopped"}">${esc(c.State)}</span></td><td>${esc(c.Image)}</td><td>${esc(ports(c))}</td><td>${c.Labels?.["dockerview.system"] === "true" ? '<span class="badge system">Protected</span>' : "—"}</td></tr>`,
        )
        .join("") ||
      '<tr><td colspan="5" class="empty">No containers found</td></tr>';
}
async function containersPage() {
  await loadContainers();
  const body = $("#containers-table"),
    search = $<HTMLInputElement>("#container-search"),
    filter = $<HTMLSelectElement>("#status-filter"),
    count = $("#container-count");
  const render = () => {
    const q = search?.value.toLowerCase() ?? "",
      state = filter?.value ?? "";
    const list = containers.filter(
      (c) =>
        (!q ||
          nameOf(c).toLowerCase().includes(q) ||
          (c.Image ?? "").toLowerCase().includes(q)) &&
        (!state || c.State === state),
    );
    if (count)
      count.textContent = `${list.length} container${list.length === 1 ? "" : "s"}`;
    if (body)
      body.innerHTML =
        list
          .map((c) => {
            const system = c.Labels?.["dockerview.system"] === "true";
            const id = esc(idOf(c));
            const actions = [
              has("container.inspect")
                ? `<button class="secondary small inspect" data-id="${id}">Inspect</button>`
                : "",
              has("container.logs")
                ? `<a class="secondary small" href="/app/logs/?container=${encodeURIComponent(idOf(c))}">Logs</a>`
                : "",
              has("container.exec") && !system && c.State === "running"
                ? `<a class="secondary small" href="/app/terminal/?container=${encodeURIComponent(idOf(c))}">Terminal</a>`
                : "",
              has("container.restart") && !system
                ? `<button class="danger small restart" data-id="${id}">Restart</button>`
                : "",
            ]
              .filter(Boolean)
              .join(" ");
            return `<tr><td class="name-cell">${esc(nameOf(c))}<small>${esc(idOf(c).slice(0, 12))}</small></td><td><span class="badge ${c.State === "running" ? "" : "stopped"}">${esc(c.State)}</span></td><td>${esc(c.Health?.Status ?? "—")}</td><td>${esc(c.Image)}</td><td data-cpu="${id}">—</td><td data-memory="${id}">—</td><td>${esc(uptime(c))}</td><td>${esc(ports(c))}</td><td data-risk="${id}">${system ? '<span class="badge critical">Critical</span>' : '<span class="badge">Loading…</span>'}</td><td>${actions || "—"}</td></tr>`;
          })
          .join("") ||
        '<tr><td colspan="10" class="empty">No matching containers</td></tr>';
    $$<HTMLButtonElement>(".inspect", body ?? document).forEach((b) =>
      b.addEventListener("click", () => showContainer(b.dataset.id ?? "")),
    );
    $$<HTMLButtonElement>(".restart", body ?? document).forEach((b) =>
      b.addEventListener("click", async () => {
        const id = b.dataset.id ?? "";
        if (
          !window.confirm(
            "Restart this container? Active work may be interrupted.",
          )
        )
          return;
        await api(`/containers/${encodeURIComponent(id)}/restart`, {
          method: "POST",
        });
        toast("Container restart requested");
      }),
    );
    list
      .filter((c) => c.State === "running")
      .slice(0, 25)
      .forEach((c) => loadStatsRow(idOf(c)));
    if (has("container.inspect"))
      list
        .filter((c) => c.Labels?.["dockerview.system"] !== "true")
        .slice(0, 25)
        .forEach((c) => loadRiskRow(idOf(c)));
  };
  search?.addEventListener("input", render);
  filter?.addEventListener("change", render);
  render();
  const dialog = $<HTMLDialogElement>("#container-detail");
  $(".dialog-close", dialog ?? document)?.addEventListener("click", () =>
    dialog?.close(),
  );
}
async function loadRiskRow(id: string) {
  try {
    const result = await api<{ risk: { level: string } }>(
      `/containers/${encodeURIComponent(id)}/`,
    );
    const el = $<HTMLElement>(`[data-risk="${CSS.escape(id)}"]`);
    if (el)
      el.innerHTML = `<span class="badge ${esc(result.risk.level.toLowerCase())}">${esc(result.risk.level)}</span>`;
  } catch {
    /* risk enrichment is best effort */
  }
}
async function loadStatsRow(id: string) {
  try {
    const s = jsonObject(
      await api(`/containers/${encodeURIComponent(id)}/stats`),
    );
    const cpu = jsonObject(s.cpu_stats),
      pre = jsonObject(s.precpu_stats),
      usage = jsonObject(cpu.cpu_usage),
      preUsage = jsonObject(pre.cpu_usage);
    const total =
        Number(usage.total_usage ?? 0) - Number(preUsage.total_usage ?? 0),
      system =
        Number(cpu.system_cpu_usage ?? 0) - Number(pre.system_cpu_usage ?? 0),
      cpus = Number(cpu.online_cpus ?? 1);
    const pct = system > 0 ? (total / system) * cpus * 100 : 0;
    const mem = jsonObject(s.memory_stats),
      used = Math.max(
        0,
        Number(mem.usage ?? 0) - Number(jsonObject(mem.stats).cache ?? 0),
      );
    const cpuEl = $<HTMLElement>(`[data-cpu="${CSS.escape(id)}"]`),
      memEl = $<HTMLElement>(`[data-memory="${CSS.escape(id)}"]`);
    if (cpuEl) cpuEl.textContent = `${pct.toFixed(1)}%`;
    if (memEl) memEl.textContent = formatBytes(used);
  } catch {
    /* individual stats are best effort */
  }
}
function formatBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 3);
  return `${(n / 1024 ** i).toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
}
async function showContainer(id: string) {
  const dialog = $<HTMLDialogElement>("#container-detail"),
    content = $("#container-detail-content");
  if (!dialog || !content) return;
  content.innerHTML = '<p class="empty">Loading inspection…</p>';
  dialog.showModal();
  try {
    const result = await api<{
      inspect: Record<string, unknown>;
      risk: { level: string; findings: string[] };
      system: boolean;
    }>(`/containers/${encodeURIComponent(id)}/`);
    const v = result.inspect,
      cfg = jsonObject(v.Config),
      state = jsonObject(v.State),
      host = jsonObject(v.HostConfig),
      mounts = Array.isArray(v.Mounts) ? v.Mounts : [],
      networks = jsonObject(jsonObject(v.NetworkSettings).Networks),
      env = Array.isArray(cfg.Env) ? cfg.Env : [];
    content.innerHTML = `<div class="detail-head"><div><p class="kicker">Container inspect</p><h2>${esc(text(v.Name).replace(/^\//, ""))}</h2></div><span class="badge ${esc(result.risk.level.toLowerCase())}">${esc(result.risk.level)} risk</span>${result.system ? '<span class="badge system">Protected system container</span>' : ""}</div><div class="detail-tabs"><button class="active" data-tab="overview">Overview</button><button data-tab="environment">Environment</button><button data-tab="networks">Networks</button><button data-tab="mounts">Mounts</button><button data-tab="inspect">Raw inspect</button></div><div data-pane="overview"><dl class="detail-grid">${pairs({ ID: text(v.Id).slice(0, 20), Image: cfg.Image, Status: state.Status, Health: jsonObject(state.Health).Status, Created: v.Created, "Restart policy": jsonObject(host.RestartPolicy).Name, PID: state.Pid, "Network mode": host.NetworkMode })}</dl><div class="callout ${result.risk.level.toLowerCase()}"><b>${esc(result.risk.level)} runtime risk</b><p>${result.risk.findings.map(esc).join(" · ")}</p></div></div><div data-pane="environment" hidden><pre class="json">${esc(env.join("\n") || "No environment variables")}</pre>${has("secret.view") ? `<button class="secondary small" id="reveal-secrets" data-id="${esc(id)}">Reveal audited secrets</button>` : ""}</div><div data-pane="networks" hidden><dl class="detail-grid">${
      Object.entries(networks)
        .map(([name, n]) => {
          const x = jsonObject(n);
          return `<div><dt>${esc(name)}</dt><dd>IP ${esc(x.IPAddress)} · Gateway ${esc(x.Gateway)} · MAC ${esc(x.MacAddress)}</dd></div>`;
        })
        .join("") || "<div>No networks</div>"
    }</dl></div><div data-pane="mounts" hidden><pre class="json">${esc(JSON.stringify(mounts, null, 2))}</pre></div><div data-pane="inspect" hidden><pre class="json">${esc(JSON.stringify(v, null, 2))}</pre></div>`;
    $$<HTMLButtonElement>("[data-tab]", content).forEach((b) =>
      b.addEventListener("click", () => {
        $$("[data-tab]", content).forEach((x) =>
          x.classList.toggle("active", x === b),
        );
        $$<HTMLElement>("[data-pane]", content).forEach(
          (x) => (x.hidden = x.dataset.pane !== b.dataset.tab),
        );
      }),
    );
    $("#reveal-secrets", content)?.addEventListener("click", async () => {
      if (confirm("Reveal container secrets? This action is audited.")) {
        const reveal = await api<{ inspect: Record<string, unknown> }>(
          `/containers/${encodeURIComponent(id)}/?reveal=true`,
        );
        const pane = $<HTMLElement>("[data-pane=environment]", content);
        const values = jsonObject(reveal.inspect.Config).Env;
        if (pane)
          pane.innerHTML = `<pre class="json">${esc(Array.isArray(values) ? values.join("\n") : "No environment")}</pre>`;
      }
    });
  } catch (err) {
    content.innerHTML = `<p class="empty">${esc(err instanceof Error ? err.message : "Unable to inspect")}</p>`;
  }
}
function pairs(input: Record<string, unknown>): string {
  return Object.entries(input)
    .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
    .join("");
}

async function logsPage() {
  const list = await loadContainers(),
    select = $<HTMLSelectElement>("#log-container"),
    output = $("#log-output"),
    live = $<HTMLButtonElement>("#log-live"),
    pause = $<HTMLButtonElement>("#log-pause"),
    tail = $<HTMLSelectElement>("#log-tail");
  if (select)
    select.innerHTML =
      '<option value="">Select a container…</option>' + containerOptions(list);
  const selectedContainer = new URLSearchParams(location.search).get(
    "container",
  );
  if (
    select &&
    selectedContainer &&
    Array.from(select.options).some((o) => o.value === selectedContainer)
  ) {
    select.value = selectedContainer;
  }
  let source: EventSource | null = null,
    paused = false,
    buffer = "";
  const render = () => {
    if (output) {
      const q = $<HTMLInputElement>("#log-search")?.value ?? "";
      output.textContent = q
        ? buffer
            .split("\n")
            .filter((x) => x.toLowerCase().includes(q.toLowerCase()))
            .join("\n")
        : buffer;
      output.scrollTop = output.scrollHeight;
    }
  };
  select?.addEventListener("change", async () => {
    source?.close();
    if (!select.value) return;
    const data = await api<{ logs: string }>(
      `/containers/${encodeURIComponent(select.value)}/logs?tail=${tail?.value ?? 500}`,
    );
    buffer = data.logs;
    render();
    const state = $("#log-state");
    if (state)
      state.textContent = `${select.options[select.selectedIndex]?.text} · snapshot`;
  });
  if (select?.value) select.dispatchEvent(new Event("change"));
  live?.addEventListener("click", () => {
    if (!select?.value) return;
    source?.close();
    source = new EventSource(
      `/api/v1/containers/${encodeURIComponent(select.value)}/logs/stream?tail=${tail?.value ?? 500}`,
    );
    source.onmessage = (e) => {
      if (!paused) {
        buffer += JSON.parse(e.data) as string;
        if (buffer.length > 5_000_000) buffer = buffer.slice(-4_000_000);
        render();
      }
    };
    source.onerror = () => {
      const state = $("#log-state");
      if (state) state.textContent = "Stream disconnected";
    };
    if (pause) pause.disabled = false;
    const state = $("#log-state");
    if (state) state.textContent = "Following live";
  });
  pause?.addEventListener("click", () => {
    paused = !paused;
    pause.textContent = paused ? "Resume" : "Pause";
  });
  $("#log-search")?.addEventListener("input", render);
  $("#copy-logs")?.addEventListener("click", () =>
    navigator.clipboard.writeText(buffer),
  );
  window.addEventListener("beforeunload", () => source?.close());
}
async function terminalPage() {
  const list = await loadContainers(),
    select = $<HTMLSelectElement>("#terminal-container"),
    shell = $<HTMLSelectElement>("#terminal-shell"),
    connect = $<HTMLButtonElement>("#terminal-connect"),
    disconnect = $<HTMLButtonElement>("#terminal-disconnect"),
    state = $("#terminal-state"),
    duration = $("#terminal-duration");
  if (select)
    select.innerHTML =
      '<option value="">Select a running container…</option>' +
      containerOptions(
        list.filter((c) => c.Labels?.["dockerview.system"] !== "true"),
        false,
      );
  const selectedContainer = new URLSearchParams(location.search).get(
    "container",
  );
  if (
    select &&
    selectedContainer &&
    Array.from(select.options).some((o) => o.value === selectedContainer)
  ) {
    select.value = selectedContainer;
  }
  const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: {
        background: "#070a0e",
        foreground: "#b8cac9",
        cursor: "#55e6c1",
        selectionBackground: "#245246",
      },
    }),
    fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open($("#terminal")!);
  fit.fit();
  let ws: WebSocket | null = null,
    timer = 0,
    started = 0;
  const stop = () => {
    ws?.close();
    ws = null;
    window.clearInterval(timer);
    connect!.disabled = false;
    disconnect!.disabled = true;
    if (duration) duration.textContent = "Disconnected";
  };
  connect?.addEventListener("click", async () => {
    if (!select?.value) return;
    try {
      const result = await api<{ session_id: string; shell: string }>(
        `/containers/${encodeURIComponent(select.value)}/terminal`,
        {
          method: "POST",
          body: JSON.stringify({ shell: shell?.value ?? "auto" }),
        },
      );
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(
        `${protocol}://${location.host}/api/v1/terminal/${encodeURIComponent(result.session_id)}/ws?csrf=${encodeURIComponent(csrf())}`,
      );
      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        terminal.clear();
        terminal.focus();
        fit.fit();
        connect.disabled = true;
        if (disconnect) disconnect.disabled = false;
        if (state)
          state.textContent = `${select.options[select.selectedIndex]?.text} · ${result.shell}`;
        started = Date.now();
        timer = window.setInterval(() => {
          if (duration)
            duration.textContent = `Connected ${Math.floor((Date.now() - started) / 1000)}s`;
        }, 1000);
        ws?.send(
          JSON.stringify({
            type: "resize",
            cols: terminal.cols,
            rows: terminal.rows,
          }),
        );
      };
      ws.onmessage = (e) =>
        terminal.write(
          e.data instanceof ArrayBuffer
            ? new Uint8Array(e.data)
            : String(e.data),
        );
      ws.onclose = () => {
        terminal.writeln("\r\n\x1b[33m[DockerView session closed]\x1b[0m");
        stop();
      };
      ws.onerror = () => toast("Terminal connection failed");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Terminal failed");
    }
  });
  terminal.onData((data) => {
    if (ws?.readyState === WebSocket.OPEN)
      ws.send(new TextEncoder().encode(data));
  });
  window.addEventListener("resize", () => {
    fit.fit();
    if (ws?.readyState === WebSocket.OPEN)
      ws.send(
        JSON.stringify({
          type: "resize",
          cols: terminal.cols,
          rows: terminal.rows,
        }),
      );
  });
  disconnect?.addEventListener("click", stop);
  window.addEventListener("beforeunload", stop);
}

async function usersPage() {
  const [users, roles] = await Promise.all([
    api<User[]>("/users"),
    api<Role[]>("/roles"),
  ]);
  const body = $("#users-table"),
    dialog = $<HTMLDialogElement>("#user-dialog"),
    form = $<HTMLFormElement>("#user-form");
  if (body)
    body.innerHTML = users
      .map(
        (u) =>
          `<tr><td class="name-cell">${esc(u.Username)}<small>${esc(u.ID.slice(0, 10))}</small></td><td><span class="badge ${u.Enabled ? "" : "stopped"}">${u.Enabled ? "enabled" : "disabled"}</span></td><td>${esc((u.Roles ?? []).join(", "))}</td><td>${esc(fmtDate(u.CreatedAt))}</td><td>${esc(fmtDate(u.LastLoginAt))}</td><td><button class="secondary small edit-user" data-id="${esc(u.ID)}">Edit</button> <button class="secondary small invalidate" data-id="${esc(u.ID)}">Invalidate sessions</button></td></tr>`,
      )
      .join("");
  const roleOptions = (selected: string[] = []) =>
    roles
      .map(
        (r) =>
          `<label class="check"><input type="checkbox" name="role" value="${esc(r.ID)}" ${selected.includes(r.Name) ? "checked" : ""}/> ${esc(r.Name)}</label>`,
      )
      .join("");
  const open = (u?: User) => {
    if (!form || !dialog) return;
    form.reset();
    const id = $<HTMLInputElement>("[name=id]", form),
      username = $<HTMLInputElement>("[name=username]", form),
      enabled = $<HTMLInputElement>("[name=enabled]", form),
      title = $("#user-form-title");
    if (id) id.value = u?.ID ?? "";
    if (username) {
      username.value = u?.Username ?? "";
      username.disabled = !!u;
    }
    if (enabled) enabled.checked = u?.Enabled ?? true;
    if (title) title.textContent = u ? `Edit ${u.Username}` : "Create user";
    const options = $("#user-role-options");
    if (options) options.innerHTML = roleOptions(u?.Roles);
    dialog.showModal();
  };
  $("#new-user")?.addEventListener("click", () => open());
  $$<HTMLButtonElement>(".edit-user").forEach((b) =>
    b.addEventListener("click", () =>
      open(users.find((u) => u.ID === b.dataset.id)),
    ),
  );
  $$<HTMLButtonElement>(".invalidate").forEach((b) =>
    b.addEventListener("click", async () => {
      await api(
        `/users/${encodeURIComponent(b.dataset.id ?? "")}/invalidate-sessions`,
        { method: "POST" },
      );
      toast("Sessions invalidated");
    }),
  );
  $(".dialog-close", dialog ?? document)?.addEventListener("click", () =>
    dialog?.close(),
  );
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form),
      id = text(data.get("id")),
      payload = {
        username: text(data.get("username")),
        password: text(data.get("password")),
        roles: data.getAll("role").map(text),
        enabled: data.get("enabled") === "on",
      };
    try {
      if (id)
        await api(`/users/${encodeURIComponent(id)}`, {
          method: "PUT",
          body: JSON.stringify({
            password: payload.password,
            roles: payload.roles,
            enabled: payload.enabled,
          }),
        });
      else
        await api("/users", { method: "POST", body: JSON.stringify(payload) });
      location.reload();
    } catch (err) {
      showError(form, err);
    }
  });
}
async function permissionsPage() {
  const list = await api<Permission[]>("/permissions"),
    body = $("#permissions-table");
  if (body)
    body.innerHTML = list
      .map(
        (p) =>
          `<tr><td><span class="chip">${esc(p.Name)}</span></td><td>${esc(p.Category)}</td><td>${esc(p.Description)}</td><td>${esc((p.Roles ?? []).join(", ") || "—")}</td></tr>`,
      )
      .join("");
}
async function rolesPage() {
  const [roles, permissions] = await Promise.all([
      api<Role[]>("/roles"),
      api<Permission[]>("/permissions"),
    ]),
    grid = $("#roles-grid"),
    dialog = $<HTMLDialogElement>("#role-dialog"),
    form = $<HTMLFormElement>("#role-form");
  if (grid)
    grid.innerHTML = roles
      .map(
        (r) =>
          `<article class="panel role-card"><div class="page-actions"><div><h3>${esc(r.Name)}</h3><span class="meta">${r.Builtin ? "Built-in role" : "Custom role"}</span></div><span class="badge">${r.Permissions?.length ?? 0} permissions</span></div><p class="muted">${esc(r.Description)}</p><div class="chips">${(r.Permissions ?? []).map((p) => `<span class="chip">${esc(p)}</span>`).join("")}</div><div class="card-actions"><button class="secondary small edit-role" data-id="${esc(r.ID)}">Edit</button>${r.Builtin ? "" : `<button class="danger small delete-role" data-id="${esc(r.ID)}">Delete</button>`}</div></article>`,
      )
      .join("");
  const open = (r?: Role) => {
    if (!form || !dialog) return;
    form.reset();
    const id = $<HTMLInputElement>("[name=id]", form),
      name = $<HTMLInputElement>("[name=name]", form),
      desc = $<HTMLTextAreaElement>("[name=description]", form);
    if (id) id.value = r?.ID ?? "";
    if (name) {
      name.value = r?.Name ?? "";
      name.readOnly = r?.Builtin ?? false;
    }
    if (desc) desc.value = r?.Description ?? "";
    const grouped = Map.groupBy(permissions, (p) => p.Category),
      target = $("#permission-options");
    if (target)
      target.innerHTML = Array.from(grouped.entries())
        .map(
          ([cat, ps]) =>
            `<fieldset><legend>${esc(cat)}</legend><div class="checks">${ps.map((p) => `<label class="check"><input type="checkbox" name="permission" value="${esc(p.Name)}" ${(r?.Permissions ?? []).includes(p.Name) ? "checked" : ""}/> <span><b>${esc(p.Name)}</b><small>${esc(p.Description)}</small></span></label>`).join("")}</div></fieldset>`,
        )
        .join("");
    dialog.showModal();
  };
  $("#new-role")?.addEventListener("click", () => open());
  $$<HTMLButtonElement>(".edit-role").forEach((b) =>
    b.addEventListener("click", () =>
      open(roles.find((r) => r.ID === b.dataset.id)),
    ),
  );
  $$<HTMLButtonElement>(".delete-role").forEach((b) =>
    b.addEventListener("click", async () => {
      if (confirm("Delete this custom role?")) {
        await api(`/roles/${encodeURIComponent(b.dataset.id ?? "")}`, {
          method: "DELETE",
        });
        location.reload();
      }
    }),
  );
  $(".dialog-close", dialog ?? document)?.addEventListener("click", () =>
    dialog?.close(),
  );
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form),
      id = text(data.get("id")),
      payload = {
        ID: id,
        Name: text(data.get("name")),
        Description: text(data.get("description")),
        Permissions: data.getAll("permission").map(text),
      };
    try {
      await api(id ? `/roles/${encodeURIComponent(id)}` : "/roles", {
        method: id ? "PUT" : "POST",
        body: JSON.stringify(payload),
      });
      location.reload();
    } catch (err) {
      showError(form, err);
    }
  });
}
function ruleMarkup(rule?: Rule): string {
  return `<div class="rule-row"><select name="effect"><option value="allow" ${rule?.Effect === "allow" ? "selected" : ""}>Allow</option><option value="deny" ${rule?.Effect === "deny" ? "selected" : ""}>Deny</option></select><select name="match_type"><option value="name" ${rule?.MatchType !== "label" ? "selected" : ""}>Container name</option><option value="label" ${rule?.MatchType === "label" ? "selected" : ""}>Container label</option></select><input name="match" value="${esc(rule?.MatchType === "label" ? `${rule.MatchKey}=${rule.MatchValue}` : (rule?.MatchValue ?? ""))}" placeholder="api-* or key=value" maxlength="128"/><button type="button" class="remove-rule">×</button></div>`;
}
async function policiesPage() {
  const policies = (await api<Policy[] | null>("/policies")) ?? [],
    grid = $("#policies-grid"),
    dialog = $<HTMLDialogElement>("#policy-dialog"),
    form = $<HTMLFormElement>("#policy-form"),
    rules = $("#policy-rules");
  if (grid)
    grid.innerHTML =
      policies
        .map(
          (p) =>
            `<article class="panel role-card"><div class="page-actions"><div><h3>${esc(p.Name)}</h3><span class="meta">${p.Enabled ? "Enabled" : "Disabled"}</span></div><span class="badge ${p.Enabled ? "" : "stopped"}">${p.Rules?.length ?? 0} rules</span></div><p class="muted">${esc(p.Description)}</p><div class="chips">${(p.Rules ?? []).map((r) => `<span class="chip">${esc(r.Effect)} ${esc(r.Action)} · ${esc(r.MatchType)}:${esc(r.MatchKey ? `${r.MatchKey}=${r.MatchValue}` : r.MatchValue)}</span>`).join("")}</div><div class="card-actions"><button class="secondary small edit-policy" data-id="${esc(p.ID)}">Edit</button><button class="danger small delete-policy" data-id="${esc(p.ID)}">Delete</button></div></article>`,
        )
        .join("") ||
      '<article class="panel empty">No policies. Role permissions apply to all non-system containers.</article>';
  const bindRemove = () =>
    $$<HTMLButtonElement>(".remove-rule", rules ?? document).forEach(
      (b) => (b.onclick = () => b.parentElement?.remove()),
    );
  const open = (p?: Policy) => {
    if (!form || !dialog) return;
    form.reset();
    $<HTMLInputElement>("[name=id]", form)!.value = p?.ID ?? "";
    $<HTMLInputElement>("[name=name]", form)!.value = p?.Name ?? "";
    $<HTMLTextAreaElement>("[name=description]", form)!.value =
      p?.Description ?? "";
    $<HTMLInputElement>("[name=enabled]", form)!.checked = p?.Enabled ?? true;
    if (rules)
      rules.innerHTML = (p?.Rules?.length ? p.Rules : [undefined])
        .map(ruleMarkup)
        .join("");
    bindRemove();
    dialog.showModal();
  };
  $("#new-policy")?.addEventListener("click", () => open());
  $("#add-rule")?.addEventListener("click", () => {
    rules?.insertAdjacentHTML("beforeend", ruleMarkup());
    bindRemove();
  });
  $$<HTMLButtonElement>(".edit-policy").forEach((b) =>
    b.addEventListener("click", () =>
      open(policies.find((p) => p.ID === b.dataset.id)),
    ),
  );
  $$<HTMLButtonElement>(".delete-policy").forEach((b) =>
    b.addEventListener("click", async () => {
      if (confirm("Delete this policy?")) {
        await api(`/policies/${encodeURIComponent(b.dataset.id ?? "")}`, {
          method: "DELETE",
        });
        location.reload();
      }
    }),
  );
  $(".dialog-close", dialog ?? document)?.addEventListener("click", () =>
    dialog?.close(),
  );
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form),
      id = text(data.get("id")),
      rows = $$<HTMLElement>(".rule-row", form),
      built: Rule[] = [];
    for (const row of rows) {
      const effect = $<HTMLSelectElement>("[name=effect]", row)!.value,
        matchType = $<HTMLSelectElement>("[name=match_type]", row)!.value,
        match = $<HTMLInputElement>("[name=match]", row)!.value;
      let key = "",
        value = match;
      if (matchType === "label") {
        [key, value] = match.split("=", 2) as [string, string];
      }
      built.push({
        Effect: effect,
        Action: "container.exec",
        MatchType: matchType,
        MatchKey: key,
        MatchValue: value,
      });
    }
    const payload = {
      ID: id,
      Name: text(data.get("name")),
      Description: text(data.get("description")),
      Enabled: data.get("enabled") === "on",
      Rules: built,
    };
    try {
      await api(id ? `/policies/${encodeURIComponent(id)}` : "/policies", {
        method: id ? "PUT" : "POST",
        body: JSON.stringify(payload),
      });
      location.reload();
    } catch (err) {
      showError(form, err);
    }
  });
}
async function auditPage() {
  const list = (await api<Audit[] | null>("/audit?limit=500")) ?? [],
    body = $("#audit-table"),
    search = $<HTMLInputElement>("#audit-search"),
    result = $<HTMLSelectElement>("#audit-result");
  const render = () => {
    const q = search?.value.toLowerCase() ?? "",
      r = result?.value ?? "";
    const shown = list.filter(
      (x) =>
        (!r || x.Result === r) &&
        (!q ||
          `${x.Username} ${x.Action} ${x.ResourceType} ${x.ResourceID}`
            .toLowerCase()
            .includes(q)),
    );
    if (body)
      body.innerHTML = shown
        .map(
          (x) =>
            `<tr><td>${esc(fmtDate(x.Timestamp))}</td><td>${esc(x.Username || "system")}</td><td><span class="chip">${esc(x.Action)}</span></td><td>${esc(`${x.ResourceType}:${x.ResourceID}`)}</td><td><span class="badge ${esc(x.Result)}">${esc(x.Result)}</span></td><td>${esc(x.Reason || "—")}</td></tr>`,
        )
        .join("");
  };
  search?.addEventListener("input", render);
  result?.addEventListener("change", render);
  render();
}
async function settingsPage() {
  const values = await api<Record<string, string>>("/settings"),
    form = $<HTMLFormElement>("#settings-form");
  if (!form) return;
  for (const [k, v] of Object.entries(values)) {
    const input = $<HTMLInputElement>(`[name="${CSS.escape(k)}"]`, form);
    if (input) {
      if (input.type === "checkbox") input.checked = v === "true";
      else input.value = v;
    }
  }
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form),
      payload: Record<string, string> = {};
    for (const [k, v] of data) payload[k] = text(v);
    payload.secret_masking = data.get("secret_masking") ? "true" : "false";
    try {
      await api("/settings", { method: "PUT", body: JSON.stringify(payload) });
      toast("Settings saved");
    } catch (err) {
      showError(form, err);
    }
  });
}

async function route() {
  switch (page) {
    case "overview":
      await overview();
      break;
    case "containers":
      await containersPage();
      break;
    case "logs":
      await logsPage();
      break;
    case "terminal":
      await terminalPage();
      break;
    case "users":
      await usersPage();
      break;
    case "roles":
      await rolesPage();
      break;
    case "permissions":
      await permissionsPage();
      break;
    case "policies":
      await policiesPage();
      break;
    case "audit":
      await auditPage();
      break;
    case "settings":
      await settingsPage();
      break;
  }
}
if (page === "auth") void initAuth();
else void initShell();
