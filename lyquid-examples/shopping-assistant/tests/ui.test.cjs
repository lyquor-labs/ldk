const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

function application() {
    const nodes = new Map();
    const element = (tagName) => ({
        tagName, children: [], dataset: {}, listeners: new Map(), value: "",
        textContent: "", hidden: false, style: {}, attributes: new Map(),
        classList: { values: new Set(), add(...values) { values.forEach((value) => this.values.add(value)); },
            toggle(value, enabled) { enabled ? this.values.add(value) : this.values.delete(value); },
            contains(value) { return this.values.has(value); } },
        setAttribute(name, value) { this.attributes.set(name, value); },
        getAttribute(name) { return this.attributes.get(name); },
        scrollIntoView() {},
        getBoundingClientRect() { return { top: 40, right: 30, height: 10 }; },
        addEventListener(name, callback) { this.listeners.set(name, callback); },
        querySelectorAll(selector) { return this.children.filter((child) => selector.startsWith(".")
            ? child.className?.split(" ").includes(selector.slice(1)) : child.tagName === selector); },
        replaceChildren() { this.children = []; },
        append(...children) { this.children.push(...children); },
    });
    const timers = new Set();
    const context = vm.createContext({
        document: {
            querySelector(selector) {
                if (!nodes.has(selector)) nodes.set(selector, element());
                return nodes.get(selector);
            },
            createElement: element,
            createElementNS: (_, name) => element(name),
        },
        window: { innerHeight: 800 },
        queueMicrotask(callback) { callback(); },
        setTimeout(callback) { timers.add(callback); return callback; },
        clearTimeout(timer) { timers.delete(timer); },
        requestAnimationFrame() {},
        console,
    });
    vm.runInContext(readFileSync(join(__dirname, "../ui/app.js"), "utf8"), context);
    for (const selector of ["[data-role='revisionBar']", "#revisionStatus", "#statusMessage"]) {
        nodes.get(selector).hidden = true;
    }
    return { context, nodes, timers, run: (script) => vm.runInContext(script, context) };
}

function readyApplication() {
    const app = application();
    app.run(`
        state.scopeId = 'scope-1';
        state.activeRun = Object.fromEntries([
            "scopeStatus", "searchRound", "candidateCount", "nextHint", "hardConstraints",
            "softPreferences", "recommendationList", "searchSummary", "sourceList", "revisionFeed", "steps"
        ].map((field) => [field, document.createElement("div")]));
        globalThis.scope = {
            status: "awaiting_input", input_kind: "choice", candidates: [], aggregation_round: 1,
            hard_constraints: [], soft_preferences: [], hint: "What screen size do you prefer?",
            choices: [{id: "refine", label: "Continue refining"}, {id: "restart", label: "New candidates"}]
        };
        renderScope(scope);
    `);
    return app;
}

function response(value, ok = true) {
    return { ok, json: async () => value };
}

function historyApplication() {
    const app = readyApplication();
    app.run(`
        globalThis.revisions = [
            { id: "root", parent_id: null, kind: "initial", summary: "Find a TV", name: "Original" },
            { id: "light", parent_id: "root", kind: "refinement", summary: "Lightweight", name: "Refine: Lightweight" },
            { id: "cheap", parent_id: "root", kind: "refinement", summary: "Inexpensive", name: "Refine: Inexpensive" },
        ].map((revision) => ({...revision, active: revision.id === "cheap", status: "awaiting_input", search_round: 1,
            candidate_count: 2, hard_constraints: [], soft_preferences: [revision.summary]}));
        scope = {...scope, history: {active_revision_id: "cheap", revisions}};
        renderScope(scope);
    `);
    return app;
}

test("history preserves sibling nodes, highlights the selected lineage, and retains branch tooltips", () => {
    const app = historyApplication();
    const track = app.nodes.get("[data-role='revisionTreeTrack']");
    const nodes = track.querySelectorAll(".revision-node");
    assert.deepEqual(nodes.map((node) => node.dataset.revisionId), ["root", "light", "cheap"]);
    assert.equal(nodes[0].classList.contains("on-path"), true);
    assert.equal(nodes[1].classList.contains("on-path"), false);
    assert.equal(nodes[2].classList.contains("active"), true);
    assert.notEqual(nodes[1].style.left, nodes[2].style.left);
    assert.equal(app.nodes.get("#revisionTree").hidden, false);
    nodes[1].listeners.get("mouseenter")();
    const tooltip = app.nodes.get("[data-role='revisionTooltip']");
    assert.equal(tooltip.hidden, false);
    assert.equal(tooltip.children[1].textContent, "Refine: Lightweight");
    assert.equal(app.run("state.activeRun.revisionFeed.children.length"), 1);
    assert.equal(app.run("state.activeRun.revisionFeed.children[0].children[1].textContent"), "Inexpensive");
});

test("history restore navigates checkpoints without submitting refinement or search", async () => {
    const app = historyApplication();
    const calls = [];
    app.context.fetch = async (url, options = {}) => {
        calls.push([url, options.body && JSON.parse(options.body)]);
        return response(options.method === "POST" ? {restored: true}
            : app.run('({...scope, history: {...scope.history, active_revision_id: "root", revisions: revisions.map(p => ({...p, active: p.id === "root"}))}})'));
    };
    await app.run('switchRevision(revisions[0])');
    assert.deepEqual(calls, [
        ["/api/revisions/switch", {scope_id: "scope-1", revision_id: "root"}],
        ["/api/scope?id=scope-1", undefined],
    ]);
    assert.equal(app.run("state.history.revisions.length"), 3);
    assert.equal(app.run("state.activeRun.revisionFeed.children.length"), 0);
});

test("checkpoint tree replaces the standalone undo control", () => {
    const html = readFileSync(join(__dirname, "../ui/index.html"), "utf8");
    assert.match(html, /id="revisionTree"/);
    assert.doesNotMatch(html, /undoSubmit|Undo last refinement/);
    const app = historyApplication();
    assert.equal(app.nodes.has("[data-role='undoSubmit']"), false);
});

test("history cannot restore while processing or submitting input", async () => {
    const app = historyApplication();
    app.context.fetch = () => { assert.fail("history must not race a running model turn"); };
    app.run('renderScope({...scope, status: "processing"})');
    await app.run('switchRevision(revisions[0])');
    assert.ok(app.nodes.get("[data-role='revisionTreeTrack']").querySelectorAll(".revision-node")
        .every((node) => node.getAttribute("aria-disabled") === "true"));
    app.run('renderScope(scope); setRefinementBusy(true)');
    await app.run('switchRevision(revisions[0])');
});

test("failed turns can restore the active checkpoint to retry", async () => {
    const app = historyApplication();
    app.run('renderScope({...scope, status: "failed", error: "Model failure"})');
    const posts = [];
    app.context.fetch = async (url, options = {}) => {
        if (options.method === "POST") posts.push(JSON.parse(options.body));
        return response(options.method === "POST" ? {restored: true} : app.run("scope"));
    };
    await app.run("switchRevision(revisions[2])");
    assert.deepEqual(posts, [{scope_id: "scope-1", revision_id: "cheap"}]);
    assert.equal(app.run("state.inputKind"), "choice");
});

test("an old poll cannot overwrite a restored checkpoint", async () => {
    const app = historyApplication();
    let respond;
    app.context.fetch = () => new Promise((resolve) => { respond = resolve; });
    const oldPoll = app.run("refreshScope('scope-1', 0)");
    app.context.fetch = async (_, options = {}) => response(options.method === "POST" ? {restored: true}
        : app.run('({...scope, history: {...scope.history, active_revision_id: "root"}})'));
    await app.run("switchRevision(revisions[0])");
    respond(response(app.run("scope")));
    await oldPoll;
    assert.equal(app.run("state.history.active_revision_id"), "root");
    assert.equal(app.timers.size, 1);
});

test("renders exactly the server-configured choices as text, without hidden default exits", () => {
    const app = application();
    app.run('renderChoices([{id: "refine", label: "Continue"}, {id: "restart", label: "<New candidates>"}])');
    const bar = app.nodes.get("[data-role='choiceBar']");
    assert.deepEqual(bar.children.map((button) => button.dataset.choice), ["refine", "restart"]);
    assert.equal(bar.children[1].textContent, "<New candidates>");
    assert.equal(bar.children[1].type, "button");
    app.run("renderChoices([])");
    assert.equal(bar.children.length, 0);
});

test("shows the feedback bar with the hint before choosing, preserving drafts across polls", () => {
    const app = readyApplication();
    const input = app.nodes.get("[data-role='revisionInput']");
    assert.equal(app.nodes.get("[data-role='revisionBar']").hidden, false);
    assert.equal(app.nodes.get("[data-role='choiceBar']").hidden, false);
    assert.equal(app.nodes.get("[data-role='revisionSubmit']").hidden, true);
    assert.equal(input.placeholder, "What screen size do you prefer?");
    assert.equal(input.disabled, false);
    input.value = "I want a 65-inch screen";
    app.run("renderScope(scope)");
    assert.equal(input.value, "I want a 65-inch screen");
    assert.equal(app.nodes.get("#revisionStatus").textContent,
        "Enter feedback, then continue refining or search for new candidates.");
    assert.equal(app.nodes.get("#revisionStatus").hidden, false);
    assert.equal(app.nodes.get("#statusMessage").textContent, "");
    assert.equal(app.nodes.get("#statusMessage").hidden, true);
});

for (const kind of ["refine", "restart"]) {
    test(`${kind} processing keeps its status in the disabled feedback section`, () => {
        const app = readyApplication();
        app.run(`
            state.pendingRevision = appendRevisionStatus("OLED please", "Feedback", ${JSON.stringify(kind)});
            renderScope({...scope, status: "processing", input_kind: null});
        `);
        assert.equal(app.nodes.get("[data-role='revisionBar']").hidden, false);
        assert.equal(app.nodes.get("[data-role='revisionInput']").disabled, true);
        assert.equal(app.nodes.get("[data-role='revisionSubmit']").hidden, true);
        assert.equal(app.nodes.get("#revisionStatus").textContent, kind === "restart"
            ? "Searching for new products using your feedback and current requirements."
            : "The model is updating the ranking.");
        assert.equal(app.nodes.get("#statusMessage").hidden, true);
        assert.equal(app.nodes.get("#submitButton").disabled, false);
    });
}

test("refinement failures and polling errors stay in the feedback section", async () => {
    const app = readyApplication();
    app.context.fetch = async () => { throw new Error("Cannot refresh this refinement"); };
    await app.run("refreshScope('scope-1', 0)");
    assert.equal(app.nodes.get("#revisionStatus").textContent, "Cannot refresh this refinement");
    assert.equal(app.nodes.get("#statusMessage").hidden, true);
    app.run('renderScope({...scope, status: "failed", error: "The model failed"})');
    assert.equal(app.nodes.get("[data-role='revisionBar']").hidden, false);
    assert.equal(app.nodes.get("#revisionStatus").textContent, "The model failed");
    assert.equal(app.nodes.get("#statusMessage").hidden, true);
});

test("new-request validation stays separate from ongoing refinement guidance", async () => {
    const app = readyApplication();
    app.context.fetch = () => { assert.fail("an empty new request must not replace the scope"); };
    await app.run("startScope()");
    assert.equal(app.nodes.get("#statusMessage").textContent, "Describe what you are looking for.");
    app.run("renderScope(scope)");
    assert.equal(app.run("state.scopeId"), "scope-1");
    assert.equal(app.nodes.get("#statusMessage").textContent, "Describe what you are looking for.");
    assert.match(app.nodes.get("#revisionStatus").textContent, /^Enter feedback/);
});

test("a new search clears refinement guidance and creates a scope instead of choosing restart", async () => {
    const app = readyApplication();
    app.run(`
        state.pendingRevision = appendRevisionStatus("OLED please", "Refine", "refine");
        globalThis.previousRun = state.activeRun;
        // Stub card cloning only; retain real new-scope submission and rendering.
        appendRunCard = () => ({...previousRun, aggregationRound: 0,
            scopeId: document.createElement("strong"), searchModel: document.createElement("strong")});
        appendResultCard = () => {};
    `);
    app.nodes.get("#userRequest").value = "Find a travel mug";
    app.nodes.get("[data-role='revisionInput']").value = "A previous draft";
    const calls = [];
    app.context.fetch = async (url, options = {}) => {
        calls.push([url, options.body && JSON.parse(options.body)]);
        return response(options.method === "POST" ? { scope_id: "scope-2", provider: "scripted" }
            : app.run('({...scope, status: "processing", input_kind: null, aggregation_round: 0})'));
    };
    await app.run("startScope()");
    assert.deepEqual(calls, [
        ["/api/scopes", { request: "Find a travel mug" }],
        ["/api/scope?id=scope-2", undefined],
    ]);
    assert.equal(app.run("state.scopeId"), "scope-2");
    assert.equal(app.run("state.pendingRevision"), null);
    assert.equal(app.nodes.get("[data-role='revisionBar']").hidden, true);
    assert.equal(app.nodes.get("[data-role='revisionInput']").value, "");
    assert.equal(app.nodes.get("#revisionStatus").textContent, "");
    assert.equal(app.nodes.get("#revisionStatus").hidden, true);
    assert.equal(app.nodes.get("#statusMessage").textContent, "search related products...");
});

for (const kind of ["refine", "restart"]) {
    test(`${kind} sends the choice and text to their respective steps in one action`, async () => {
        const app = readyApplication();
        const input = app.nodes.get("[data-role='revisionInput']");
        input.value = "  I want a 65-inch screen  ";
        const calls = [];
        const endpoint = kind === "restart" ? "/api/restarts" : "/api/refinements";
        app.context.fetch = async (url, options = {}) => {
            calls.push([url, options.body && JSON.parse(options.body)]);
            if (options.method === "POST") return response({ accepted: true });
            const inputKind = calls.length === 2 ? kind : "choice";
            return response(app.run(`({...scope, input_kind: ${JSON.stringify(inputKind)}})`));
        };
        const pending = app.run(`submitChoice(${JSON.stringify(kind)})`);
        assert.equal(input.disabled, true);
        assert.ok(app.nodes.get("[data-role='choiceBar']").children.every((button) => button.disabled));
        await app.run(`submitChoice(${JSON.stringify(kind)})`);
        await pending;
        assert.deepEqual(calls, [
            ["/api/choices", {scope_id: "scope-1", choice: kind}],
            ["/api/scope?id=scope-1", undefined],
            [endpoint, {scope_id: "scope-1", [kind === "restart" ? "feedback" : "message"]: "I want a 65-inch screen"}],
            ["/api/scope?id=scope-1", undefined],
        ]);
        assert.equal(input.value, "");
        assert.equal(input.disabled, false);
        assert.equal(app.run("state.pendingRevision"), null);
        assert.equal(app.timers.size, 1);
    });

    test(`${kind} requires feedback before advancing the choice step`, async () => {
        const app = readyApplication();
        app.nodes.get("[data-role='revisionInput']").value = "  ";
        app.context.fetch = () => { assert.fail("empty feedback must not send a request"); };
        await app.run(`submitChoice(${JSON.stringify(kind)})`);
        assert.equal(app.run("state.inputKind"), "choice");
        assert.match(app.nodes.get("#revisionStatus").textContent, /Enter a preference|Explain why/);
        assert.equal(app.nodes.get("#statusMessage").hidden, true);
    });
}

test("Enter in the pre-rendered feedback bar chooses refinement", () => {
    const app = readyApplication();
    app.run('globalThis.submittedKind = null; submitFeedback = (kind = "refine") => { submittedKind = kind; }');
    let prevented = false;
    app.nodes.get("[data-role='revisionInput']").listeners.get("keydown")({
        key: "Enter", isComposing: false, preventDefault() { prevented = true; },
    });
    assert.equal(prevented, true);
    assert.equal(app.run("submittedKind"), "refine");
});

test("waits for the selected text step before submitting feedback", async () => {
    const app = readyApplication();
    app.nodes.get("[data-role='revisionInput']").value = "OLED please";
    const posts = [];
    let polls = 0;
    app.context.fetch = async (url, options = {}) => {
        if (options.method === "POST") {
            posts.push(url);
            return response({ accepted: true });
        }
        polls += 1;
        return response(polls === 1 ? { status: "processing" }
            : app.run(`({...scope, input_kind: ${polls === 2 ? '"refine"' : '"choice"'}})`));
    };
    const pending = app.run('submitChoice("refine")');
    await new Promise(setImmediate);
    assert.deepEqual(posts, ["/api/choices"]);
    assert.equal(app.timers.size, 1);
    const timer = app.timers.values().next().value;
    app.timers.delete(timer);
    timer();
    await pending;
    assert.deepEqual(posts, ["/api/choices", "/api/refinements"]);
    assert.equal(app.timers.size, 1);
});

test("retains failed feedback and retries the text step without submitting the choice again", async () => {
    const app = readyApplication();
    const input = app.nodes.get("[data-role='revisionInput']");
    input.value = "Try smaller TVs";
    const posts = [];
    let failed = false;
    app.context.fetch = async (url, options = {}) => {
        if (options.method !== "POST") return response(app.run('({...scope, input_kind: "restart"})'));
        posts.push(url);
        if (url === "/api/restarts" && !failed) {
            failed = true;
            return response({ error: "Could not send feedback" }, false);
        }
        return response({ accepted: true });
    };
    await app.run('submitChoice("restart")');
    assert.equal(input.value, "Try smaller TVs");
    assert.equal(input.disabled, false);
    assert.equal(app.nodes.get("[data-role='revisionSubmit']").hidden, false);
    assert.equal(app.nodes.get("#revisionStatus").textContent, "Could not send feedback");
    assert.equal(app.nodes.get("#statusMessage").hidden, true);
    await app.run("submitFeedback()");
    assert.deepEqual(posts, ["/api/choices", "/api/restarts", "/api/restarts"]);
    assert.equal(input.value, "");
});

test("does not forward captured feedback after the scope is replaced", async () => {
    const app = readyApplication();
    const input = app.nodes.get("[data-role='revisionInput']");
    input.value = "OLED please";
    const posts = [];
    let respond;
    app.context.fetch = (url, options = {}) => {
        if (options.method === "POST") {
            posts.push(url);
            return Promise.resolve(response({ accepted: true }));
        }
        return new Promise((resolve) => { respond = resolve; });
    };
    const pending = app.run('submitChoice("refine")');
    await new Promise(setImmediate);
    app.run("invalidatePolling(); state.scopeId = 'scope-2'");
    input.value = "A new scope's draft";
    respond(response({ status: "awaiting_input", input_kind: "refine" }));
    await pending;
    assert.deepEqual(posts, ["/api/choices"]);
    assert.equal(input.value, "A new scope's draft");
    assert.equal(app.timers.size, 0);
});

test("finish still submits only the choice and requires no feedback", async () => {
    const app = readyApplication();
    const posts = [];
    app.context.fetch = async (url, options = {}) => {
        if (options.method === "POST") {
            posts.push([url, JSON.parse(options.body)]);
            return response({ accepted: true });
        }
        return response(app.run('({...scope, status: "no_match"})'));
    };
    await app.run('submitChoice("finish")');
    assert.deepEqual(posts, [["/api/choices", { scope_id: "scope-1", choice: "finish" }]]);
    assert.equal(app.timers.size, 0);
});

test("renders all twenty search products with source links and unknown prices", () => {
    const app = application();
    app.run(`
        state.activeRun = { recommendationList: document.createElement("div"), sourceList: document.createElement("details") };
        setRecommendations(Array.from({length: 20}, (_, i) => ({
            id: "product-1-" + i, title: "TV " + i, source_url: "https://maker.example/tv/" + i,
            price: null, source: "Maker", summary: "TV for gaming", attributes: ["120 Hz"]
        })));
        renderSources(["https://maker.example/tvs"]);
    `);
    assert.equal(app.run("state.activeRun.recommendationList.children.length"), 20);
    assert.equal(app.run("state.activeRun.recommendationList.children[0].children[0].href"), "https://maker.example/tv/0");
    assert.equal(app.run("state.activeRun.recommendationList.children[0].children[1].children[1].textContent"), "Price not verified");
    assert.equal(app.run("state.activeRun.sourceList.children[1].children[0].href"), "https://maker.example/tvs");
});

test("keeps recommendations blank while searching and shows an empty result only after processing", () => {
    const app = application();
    app.run(`
        state.activeRun = Object.fromEntries([
            "scopeStatus", "searchRound", "candidateCount", "nextHint", "hardConstraints",
            "softPreferences", "recommendationList", "searchSummary", "sourceList"
        ].map((field) => [field, document.createElement("div")]));
        globalThis.scope = {
            status: "processing", candidates: [], hard_constraints: [], soft_preferences: []
        };
        renderScope(scope);
    `);
    assert.equal(app.run("state.activeRun.recommendationList.children.length"), 0);
    assert.equal(app.nodes.get("#statusMessage").textContent, "search related products...");
    assert.equal(app.nodes.get("[data-role='revisionBar']").hidden, true);

    app.run('renderScope({...scope, status: "awaiting_input", input_kind: "choice", choices: []})');
    assert.equal(app.run("state.activeRun.recommendationList.children[0].textContent"), "No recommendations remain.");
    assert.equal(app.nodes.get("#statusMessage").textContent, "");
    assert.equal(app.nodes.get("#statusMessage").hidden, true);
    assert.equal(app.nodes.get("#revisionStatus").hidden, false);
});

test("polls issued before submitted input cannot render stale rankings or schedule another poll", async () => {
    const app = application();
    let respond;
    app.context.fetch = () => new Promise((resolve) => { respond = resolve; });
    app.run("state.scopeId = 'scope-1'; globalThis.rendered = []; renderScope = (scope) => rendered.push(scope)");
    const pending = app.run("refreshScope('scope-1', 0)");
    app.run("invalidatePolling()");
    respond({ ok: true, json: async () => ({ status: "awaiting_input", candidates: ["stale"] }) });
    await pending;
    assert.equal(app.run("rendered.length"), 0);
    assert.equal(app.timers.size, 0);
});

test("a current-generation poll renders the response and schedules only one successor", async () => {
    const app = application();
    app.context.fetch = async () => ({ ok: true, json: async () => ({ status: "awaiting_input" }) });
    app.run("state.scopeId = 'scope-1'; globalThis.rendered = []; renderScope = (scope) => rendered.push(scope)");
    await app.run("refreshScope('scope-1', 0)");
    assert.equal(app.run("rendered.length"), 1);
    assert.equal(app.timers.size, 1);
    await app.run("refreshScope('scope-1', 0)");
    assert.equal(app.timers.size, 1);
});


test("a removed Scope stops polling and disables stale input and history controls", async () => {
    const app = historyApplication();
    app.context.fetch = async () => ({
        ok: false, status: 404, json: async () => ({error: "This search no longer exists."}),
    });
    await app.run("refreshScope('scope-1', 0)");
    assert.equal(app.run("state.scopeId"), null);
    assert.equal(app.run("state.inputKind"), null);
    assert.equal(app.nodes.get("[data-role='revisionInput']").disabled, true);
    assert.equal(app.nodes.get("[data-role='choiceBar']").hidden, true);
    assert.equal(app.timers.size, 0);
    assert.equal(app.nodes.get("#revisionStatus").textContent, "This search no longer exists.");
});
