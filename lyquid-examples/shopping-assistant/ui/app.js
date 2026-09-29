const POLL_INTERVAL_MS = 800;

const dom = {
    form: document.querySelector("#shoppingForm"),
    conversation: document.querySelector("#conversation"),
    runCardTemplate: document.querySelector("#runCardTemplate"),
    resultCardTemplate: document.querySelector("#resultCardTemplate"),
    hostStatus: document.querySelector("#hostStatus"),
    userRequest: document.querySelector("#userRequest"),
    submitButton: document.querySelector("#submitButton"),
    revisionBar: document.querySelector("[data-role='revisionBar']"),
    choiceBar: document.querySelector("[data-role='choiceBar']"),
    revisionInput: document.querySelector("[data-role='revisionInput']"),
    revisionSubmit: document.querySelector("[data-role='revisionSubmit']"),
    revisionStatus: document.querySelector("#revisionStatus"),
    revisionTree: document.querySelector("#revisionTree"),
    revisionTreeTrack: document.querySelector("[data-role='revisionTreeTrack']"),
    revisionTooltip: document.querySelector("[data-role='revisionTooltip']"),
    statusMessage: document.querySelector("#statusMessage"),
};

const state = {
    scopeId: null,
    pollTimer: null,
    pollGeneration: 0,
    activeRun: null,
    pendingRevision: null,
    inputKind: null,
    history: null,
    scopeStatus: null,
    revisionTreeSignature: null,
    feedRevisionId: null,
    activeRevisionId: null,
};

dom.form.addEventListener("submit", (event) => {
    event.preventDefault();
    void startScope();
});
dom.revisionSubmit.addEventListener("click", () => void submitFeedback());
dom.choiceBar.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-choice]");
    if (button && dom.choiceBar.contains(button)) {
        void submitChoice(button.dataset.choice);
    }
});
dom.revisionInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.isComposing) {
        event.preventDefault();
        void submitFeedback();
    }
});

async function submitChoice(choice) {
    if (!state.scopeId || state.inputKind !== "choice") {
        return;
    }
    if (choice === "refine" || choice === "restart") {
        return submitFeedback(choice);
    }
    const scopeId = state.scopeId;
    const pollGeneration = invalidatePolling();
    state.inputKind = null;
    setRefinementBusy(true);
    dom.choiceBar.hidden = true;
    showMessage(dom.revisionStatus, "Submitting your choice.");
    try {
        await api("/api/choices", {
            method: "POST",
            body: JSON.stringify({ scope_id: scopeId, choice }),
        });
    } catch (error) {
        if (isCurrentPoll(scopeId, pollGeneration)) {
            showMessage(dom.revisionStatus, error.message, true);
        }
    }
    if (isCurrentPoll(scopeId, pollGeneration)) {
        await refreshScope(scopeId, pollGeneration);
    }
}

async function startScope() {
    const request = dom.userRequest.value.trim();
    if (!request) {
        showMessage(dom.statusMessage, "Describe what you are looking for.", true);
        return;
    }

    const pollGeneration = invalidatePolling();
    state.scopeId = null;
    state.pendingRevision = null;
    state.inputKind = null;
    dom.choiceBar.hidden = true;
    dom.conversation.replaceChildren();
    resetRevisionControls();
    state.activeRun = appendRunCard(request);
    appendResultCard();
    setSearchBusy(true);
    showMessage(dom.statusMessage, "Starting the shopping Flow.");
    logStep("Submitting the shopping request.");

    try {
        const started = await api("/api/scopes", {
            method: "POST",
            body: JSON.stringify({ request }),
        });
        if (state.pollGeneration !== pollGeneration) {
            return;
        }
        state.scopeId = started.scope_id;
        state.activeRun.scopeId.textContent = state.scopeId.slice(0, 8);
        state.activeRun.scopeId.title = state.scopeId;
        state.activeRun.searchModel.textContent = started.provider;
        logStep("Started the shopping Flow.", "good");
        await refreshScope(state.scopeId, pollGeneration);
    } catch (error) {
        if (state.pollGeneration !== pollGeneration) {
            return;
        }
        showMessage(dom.statusMessage, error.message, true);
        logStep(error.message, "error");
        updateStatus("failed");
        setSearchBusy(false);
    }
}

async function submitFeedback(kind = state.inputKind === "restart" ? "restart" : "refine") {
    const choosing = state.inputKind === "choice";
    if (!state.scopeId || dom.revisionInput.disabled || (!choosing && state.inputKind !== kind)) {
        return;
    }
    const message = dom.revisionInput.value.trim();
    const restarting = kind === "restart";
    if (!message) {
        showMessage(dom.revisionStatus, restarting
            ? "Explain why you want a different candidate set before restarting."
            : "Enter a preference or requirement to refine the candidates.", true);
        return;
    }

    const scopeId = state.scopeId;
    const pollGeneration = invalidatePolling();
    state.inputKind = null;
    setRefinementBusy(true);
    state.pendingRevision = appendRevisionStatus(message, restarting ? "Restart" : "Refine", kind);
    const progressMessage = restarting
        ? "Requesting another candidate round."
        : "Applying refinement.";
    updateRevisionStatus(state.pendingRevision, progressMessage);
    showMessage(dom.revisionStatus, progressMessage);
    try {
        if (choosing) {
            await api("/api/choices", {
                method: "POST",
                body: JSON.stringify({ scope_id: scopeId, choice: kind }),
            });
            if (!await waitForFeedbackInput(scopeId, pollGeneration, kind)) {
                return;
            }
        }
        await api(restarting ? "/api/restarts" : "/api/refinements", {
            method: "POST",
            body: JSON.stringify({ scope_id: scopeId, ...(restarting ? { feedback: message } : { message }) }),
        });
        if (!isCurrentPoll(scopeId, pollGeneration)) {
            return;
        }
        dom.revisionInput.value = "";
        logStep(restarting ? `Restarting candidate aggregation with: ${message}` : `Refining with: ${message}`,
            restarting ? "warn" : "");
        await refreshScope(scopeId, pollGeneration);
    } catch (error) {
        if (!isCurrentPoll(scopeId, pollGeneration)) {
            return;
        }
        updateRevisionStatus(state.pendingRevision, error.message, "error");
        state.pendingRevision = null;
        await refreshScope(scopeId, pollGeneration);
        if (isCurrentPoll(scopeId, pollGeneration)) {
            showMessage(dom.revisionStatus, error.message, true);
        }
    }
}

async function waitForFeedbackInput(scopeId, pollGeneration, kind) {
    // A single UI action still supplies the choice and text to their separate LDK steps.
    while (isCurrentPoll(scopeId, pollGeneration)) {
        const scope = await api(`/api/scope?id=${scopeId}`);
        if (!isCurrentPoll(scopeId, pollGeneration)) return false;
        if (scope.status === "awaiting_input" && scope.input_kind === kind) return true;
        if (scope.status !== "processing") {
            throw new Error(scope.error || "The scope is no longer waiting for this feedback.");
        }
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    return false;
}

function invalidatePolling() {
    clearTimeout(state.pollTimer);
    state.pollTimer = null;
    state.pollGeneration += 1;
    return state.pollGeneration;
}

function isCurrentPoll(expectedScopeId, expectedGeneration) {
    return state.scopeId === expectedScopeId && state.pollGeneration === expectedGeneration;
}

async function refreshScope(expectedScopeId, expectedGeneration) {
    if (!isCurrentPoll(expectedScopeId, expectedGeneration)) {
        return;
    }
    clearTimeout(state.pollTimer);
    state.pollTimer = null;

    try {
        const scope = await api(`/api/scope?id=${expectedScopeId}`);
        if (!isCurrentPoll(expectedScopeId, expectedGeneration)) {
            return;
        }
        renderScope(scope);
        if (scope.status === "failed" || scope.status === "no_match") {
            return;
        }
    } catch (error) {
        if (!isCurrentPoll(expectedScopeId, expectedGeneration)) {
            return;
        }
        showMessage(dom.revisionBar.hidden ? dom.statusMessage : dom.revisionStatus, error.message, true);
        if (error.status === 404) {
            state.scopeId = null;
            state.inputKind = null;
            updateStatus("unavailable");
            setSearchBusy(false);
            setRefinementBusy(true);
            dom.choiceBar.hidden = true;
            renderHistory(state.history, true);
            return;
        }
    }
    if (isCurrentPoll(expectedScopeId, expectedGeneration)) {
        state.pollTimer = setTimeout(
            () => void refreshScope(expectedScopeId, expectedGeneration),
            POLL_INTERVAL_MS,
        );
    }
}

function renderScope(scope) {
    state.scopeStatus = scope.status;
    const waiting = scope.status === "awaiting_input";
    state.inputKind = waiting ? scope.input_kind : null;
    const choosing = waiting && scope.input_kind === "choice";
    const restarting = scope.status === "processing" && state.pendingRevision?.kind === "restart";
    const labels = {
        processing: "thinking",
        awaiting_input: choosing ? "choose next action" : "waiting for feedback",
        no_match: "no matches",
        failed: "failed",
    };
    updateStatus(restarting ? "restarting" : labels[scope.status] || scope.status);
    const aggregationRound = scope.aggregation_round || 1;
    if (state.activeRun.aggregationRound > 0 && aggregationRound > state.activeRun.aggregationRound) {
        logStep(`Product search round ${aggregationRound} ready.`, "good");
    }
    state.activeRun.aggregationRound = aggregationRound;
    state.activeRun.searchRound.textContent = String(aggregationRound);
    state.activeRun.candidateCount.textContent = String(scope.candidates.length);
    state.activeRun.nextHint.textContent = scope.hint || (waiting ? "state any preference" : "preparing");
    state.activeRun.hardConstraints.textContent = listText(scope.hard_constraints);
    state.activeRun.softPreferences.textContent = listText(scope.soft_preferences);
    const emptyMessage = scope.status === "processing"
        ? ""
        : "No recommendations remain.";
    setRecommendations(scope.candidates, emptyMessage);
    state.activeRun.searchSummary.textContent = scope.search_summary || "";
    renderSources(scope.retrieved_sources || []);
    setSearchBusy(false);
    dom.choiceBar.hidden = !choosing;
    renderChoices(choosing ? scope.choices : []);
    const refining = waiting || scope.aggregation_round > 0 || Boolean(state.pendingRevision);
    if (refining && dom.revisionBar.hidden) {
        showMessage(dom.statusMessage, "");
    }
    dom.revisionBar.hidden = !refining;
    dom.revisionSubmit.hidden = choosing || !waiting;
    dom.revisionInput.placeholder = scope.input_kind === "restart"
        ? "Explain why you want different candidates"
        : scope.hint || "State another preference or requirement";
    setRefinementBusy(!waiting);

    if (choosing && state.pendingRevision) {
        const readyMessage = state.pendingRevision.kind === "restart"
            ? "Replacement candidate round ready."
            : "Updated recommendations ready.";
        updateRevisionStatus(state.pendingRevision, readyMessage, "good");
        state.pendingRevision = null;
    }
    const statusMessage = refining ? dom.revisionStatus : dom.statusMessage;
    if (scope.status === "failed") {
        if (state.pendingRevision) {
            updateRevisionStatus(state.pendingRevision, scope.error || "The Flow failed.", "error");
            state.pendingRevision = null;
        }
        showMessage(statusMessage, scope.error || "The refinement Flow failed.", true);
        logStep(scope.error || "The refinement Flow failed.", "error");
    } else if (scope.status === "no_match") {
        showMessage(statusMessage, "No retrieved products match the current requirements.", true);
        logStep("No candidates remain.", "warn");
    } else {
        const message = restarting
            ? "Searching for new products using your feedback and current requirements."
            : waiting
                ? choosing
                    ? "Enter feedback, then continue refining or search for new candidates."
                    : "State a preference or requirement; the question is only a hint."
                : scope.aggregation_round
                    ? "The model is updating the ranking."
                    : "search related products...";
        showMessage(statusMessage, message);
    }
    renderHistory(scope.history, scope.status === "processing");
}

function renderChoices(choices) {
    dom.choiceBar.replaceChildren();
    if (!choices.length) {
        return;
    }
    for (const choice of choices) {
        const button = document.createElement("button");
        button.type = "button";
        button.dataset.choice = choice.id;
        button.textContent = choice.label;
        if (choice.id === "restart") {
            button.className = "restart-action";
        }
        dom.choiceBar.append(button);
    }
}

function appendRunCard(request) {
    const card = dom.runCardTemplate.content.firstElementChild.cloneNode(true);
    const run = {
        card,
        searchModel: requireNode(card, "[data-field='searchModel']"),
        searchRound: requireNode(card, "[data-field='searchRound']"),
        scopeId: requireNode(card, "[data-field='scopeId']"),
        scopeStatus: requireNode(card, "[data-field='scopeStatus']"),
        candidateCount: requireNode(card, "[data-field='candidateCount']"),
        nextHint: requireNode(card, "[data-field='nextHint']"),
        hardConstraints: requireNode(card, "[data-field='hardConstraints']"),
        softPreferences: requireNode(card, "[data-field='softPreferences']"),
        steps: requireNode(card, "[data-role='steps']"),
        recommendationList: null,
        revisionFeed: null,
        aggregationRound: 0,
    };
    requireNode(card, "[data-field='searchRequest']").textContent = request;
    run.searchRound.textContent = "1";
    dom.conversation.append(card);
    return run;
}

function appendResultCard() {
    const card = dom.resultCardTemplate.content.firstElementChild.cloneNode(true);
    state.activeRun.recommendationList = requireNode(card, "[data-role='recommendationList']");
    state.activeRun.searchSummary = requireNode(card, "[data-role='searchSummary']");
    state.activeRun.sourceList = requireNode(card, "[data-role='sourceList']");
    state.activeRun.revisionFeed = requireNode(card, "[data-role='revisionFeed']");
    dom.conversation.append(card);
    scrollConversationToBottom();
}

function setRecommendations(recommendations, emptyMessage = "No recommendations remain.") {
    const list = state.activeRun.recommendationList;
    list.replaceChildren();
    if (!recommendations.length) {
        if (!emptyMessage) return;
        const empty = document.createElement("p");
        empty.className = "empty-result";
        empty.textContent = emptyMessage;
        list.append(empty);
        return;
    }

    recommendations.forEach((recommendation, index) => {
        const card = document.createElement("article");
        card.className = "recommendation-card";

        const title = document.createElement("a");
        title.className = "recommendation-title";
        title.href = recommendation.source_url;
        title.target = "_blank";
        title.rel = "noreferrer";
        title.textContent = recommendation.title || recommendation.id;

        const meta = document.createElement("div");
        meta.className = "recommendation-meta";
        const rank = document.createElement("span");
        rank.className = "recommendation-rank";
        rank.textContent = `#${index + 1}`;
        const price = document.createElement("span");
        price.textContent = recommendation.price || "Price not verified";
        const source = document.createElement("span");
        source.textContent = recommendation.source;
        meta.append(rank, price, source);

        const summary = document.createElement("p");
        summary.className = "recommendation-why";
        summary.textContent = recommendation.summary;

        const facts = document.createElement("p");
        facts.className = "recommendation-why product-tags";
        facts.textContent = recommendation.attributes.join(" · ");
        card.append(title, meta, summary, facts);
        list.append(card);
    });
}

function renderSources(urls) {
    const list = state.activeRun.sourceList;
    list.replaceChildren();
    list.hidden = !urls.length;
    if (!urls.length) return;
    const heading = document.createElement("summary");
    heading.textContent = "Search sources";
    list.append(heading);
    for (const url of urls) {
        const link = document.createElement("a");
        link.href = url;
        link.target = "_blank";
        link.rel = "noreferrer";
        link.textContent = url;
        const item = document.createElement("p");
        item.append(link);
        list.append(item);
    }
}

function appendRevisionStatus(message, labelText, kind) {
    const item = document.createElement("div");
    item.className = "revision-feed-item";
    const label = document.createElement("span");
    label.className = "revision-feed-label";
    label.textContent = labelText;
    const text = document.createElement("strong");
    text.textContent = message;
    const status = document.createElement("span");
    status.className = "revision-feed-status";
    item.append(label, text, status);
    state.activeRun.revisionFeed.append(item);
    return { item, status, kind };
}

function updateRevisionStatus(entry, text, kind = "pending") {
    if (!entry) {
        return;
    }
    entry.item.classList.toggle("good", kind === "good");
    entry.item.classList.toggle("error", kind === "error");
    entry.status.textContent = text;
}

function logStep(message, kind = "") {
    if (!state.activeRun) {
        return;
    }
    const item = document.createElement("li");
    item.className = kind;
    item.textContent = message;
    state.activeRun.steps.append(item);
    scrollConversationToBottom();
}

function updateStatus(status) {
    if (state.activeRun) {
        state.activeRun.scopeStatus.textContent = status;
    }
}

function resetRevisionControls() {
    state.history = null;
    state.scopeStatus = null;
    state.revisionTreeSignature = null;
    state.feedRevisionId = null;
    state.activeRevisionId = null;
    dom.revisionTree.hidden = true;
    dom.revisionTreeTrack.replaceChildren();
    hideRevisionTooltip();
    dom.revisionBar.hidden = true;
    dom.revisionInput.value = "";
    showMessage(dom.revisionStatus, "");
    setRefinementBusy(false);
}

function setSearchBusy(busy) {
    dom.submitButton.disabled = busy;
    dom.submitButton.textContent = busy ? "searching" : "search";
}

function setRefinementBusy(busy) {
    setRevisionTreeBusy(busy);
    dom.revisionInput.disabled = busy;
    dom.revisionSubmit.disabled = busy;
    dom.revisionSubmit.textContent = busy ? "Sending" : "Send";
    for (const button of dom.choiceBar.querySelectorAll("button")) {
        button.disabled = busy;
    }
}

function showMessage(target, message, error = false) {
    target.textContent = message;
    target.classList.toggle("error", error);
    target.hidden = !message;
}

function listText(values) {
    return values.length ? values.map((value) => `· ${value}`).join("\n") : "None yet";
}

function requireNode(root, selector) {
    const node = root.querySelector(selector);
    if (!node) {
        throw new Error(`UI template is missing ${selector}.`);
    }
    return node;
}

function scrollConversationToBottom() {
    requestAnimationFrame(() => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" }));
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        ...options,
        headers: { "content-type": "application/json", ...(options.headers || {}) },
    });
    const value = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(value.error || `Request failed with status ${response.status}`);
        error.status = response.status;
        throw error;
    }
    return value;
}

function renderHistory(history, busy) {
    state.history = history || { active_revision_id: null, revisions: [] };
    if (!state.pendingRevision && state.feedRevisionId !== state.history.active_revision_id) {
        renderRefinementLineage(state.history);
    }
    renderRevisionTree(state.history, busy);
}

async function switchRevision(revision) {
    if (!state.scopeId || !state.history || state.scopeStatus === "processing" ||
        (dom.revisionInput.disabled && state.scopeStatus === "awaiting_input")) return;
    if (revision.id === state.history.active_revision_id && state.inputKind === "choice") return;
    const scopeId = state.scopeId;
    const pollGeneration = invalidatePolling();
    state.inputKind = null;
    setRefinementBusy(true);
    hideRevisionTooltip();
    try {
        await api("/api/revisions/switch", {
            method: "POST",
            body: JSON.stringify({ scope_id: scopeId, revision_id: revision.id }),
        });
        if (!isCurrentPoll(scopeId, pollGeneration)) return;
        dom.revisionInput.value = "";
        state.feedRevisionId = null;
        await refreshScope(scopeId, pollGeneration);
    } catch (error) {
        if (!isCurrentPoll(scopeId, pollGeneration)) return;
        setRefinementBusy(false);
        await refreshScope(scopeId, pollGeneration);
        if (isCurrentPoll(scopeId, pollGeneration)) showMessage(dom.revisionStatus, error.message, true);
    }
}

function renderRefinementLineage(history) {
    const revisionsById = new Map(history.revisions.map((revision) => [revision.id, revision]));
    const lineage = [];
    const visited = new Set();
    let revision = revisionsById.get(history.active_revision_id);
    while (revision && !visited.has(revision.id)) {
        visited.add(revision.id);
        lineage.push(revision);
        revision = revision.parent_id === null ? null : revisionsById.get(revision.parent_id);
    }

    state.activeRun.revisionFeed.replaceChildren();
    lineage.reverse().forEach((revision) => {
        if (revision.kind !== "refinement" && revision.kind !== "search") {
            return;
        }
        const restarting = revision.kind === "search";
        const entry = appendRevisionStatus(revision.summary, restarting ? "Restart" : "Refine", restarting ? "restart" : "refine");
        const failed = revision.status === "failed";
        const status = failed
            ? "Refinement failed."
            : ["thinking", "searching"].includes(revision.status)
                ? "Applying refinement."
                : "Updated recommendations ready.";
        updateRevisionStatus(entry, status, failed ? "error" : "good");
    });
    state.feedRevisionId = history.active_revision_id;
}

function renderRevisionTree(history, busy) {
    const revisions = history.revisions || [];
    dom.revisionTree.hidden = !revisions.length;
    if (!revisions.length) {
        state.revisionTreeSignature = null;
        dom.revisionTreeTrack.replaceChildren();
        hideRevisionTooltip();
        return;
    }

    const signature = JSON.stringify({ activeRevisionId: history.active_revision_id, revisions });
    if (signature === state.revisionTreeSignature) {
        setRevisionTreeBusy(busy);
        return;
    }
    state.revisionTreeSignature = signature;
    dom.revisionTreeTrack.replaceChildren();
    hideRevisionTooltip();

    const revisionsById = new Map(revisions.map((revision) => [revision.id, revision]));
    const activeLineage = new Set();
    let ancestor = revisionsById.get(history.active_revision_id);
    while (ancestor && !activeLineage.has(ancestor.id)) {
        activeLineage.add(ancestor.id);
        ancestor = revisionsById.get(ancestor.parent_id);
    }

    const topPadding = 20;
    const rowGap = 25;
    const lanes = new Map();
    const childCounts = new Map();
    let nextLane = 1;

    revisions.forEach((revision) => {
        const parentLane = revision.parent_id === null ? 0 : lanes.get(revision.parent_id);
        let lane = 0;
        if (parentLane !== undefined) {
            const siblingIndex = childCounts.get(revision.parent_id) || 0;
            lane = siblingIndex === 0 ? parentLane : nextLane++;
            childCounts.set(revision.parent_id, siblingIndex + 1);
        }
        lanes.set(revision.id, lane);
    });

    const maxLane = Math.max(...lanes.values());
    const laneGap = maxLane > 0 ? Math.min(14, 32 / maxLane) : 14;
    const positions = new Map();
    revisions.forEach((revision, index) => {
        const lane = lanes.get(revision.id);
        positions.set(revision.id, {
            x: 14 + lane * laneGap,
            y: topPadding + index * rowGap,
        });
    });

    const width = 60;
    const height = Math.max(48, topPadding * 2 + (revisions.length - 1) * rowGap);
    dom.revisionTreeTrack.style.width = `${width}px`;
    dom.revisionTreeTrack.style.height = `${height}px`;

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("revision-tree-lines");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("aria-hidden", "true");
    const firstChildByParent = new Map();
    revisions.forEach((revision) => {
        if (revision.parent_id !== null && !firstChildByParent.has(revision.parent_id)) {
            firstChildByParent.set(revision.parent_id, revision.id);
        }
    });
    const activeRoutes = [];
    revisions.forEach((revision) => {
        if (revision.parent_id === null) {
            return;
        }
        const parent = positions.get(revision.parent_id);
        const child = positions.get(revision.id);
        if (!parent || !child) {
            return;
        }
        const connector = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const firstChildId = firstChildByParent.get(revision.parent_id);
        let route = `M ${parent.x} ${parent.y} V ${child.y}`;
        let activeRoute = route;
        if (revision.id !== firstChildId) {
            const firstChild = positions.get(firstChildId);
            if (!firstChild) {
                return;
            }
            const branchY = parent.y + (firstChild.y - parent.y) / 2;
            route = `M ${parent.x} ${branchY} H ${child.x} V ${child.y}`;
            activeRoute = `M ${parent.x} ${parent.y} V ${branchY} H ${child.x} V ${child.y}`;
        }
        connector.setAttribute("d", route);
        connector.classList.add("revision-tree-connector");
        if (activeLineage.has(revision.id)) {
            activeRoutes.push(activeRoute);
        }
        svg.append(connector);
    });
    if (activeRoutes.length) {
        // Draw the complete route last, including the shared trunk up to each fork.
        const highlight = document.createElementNS("http://www.w3.org/2000/svg", "path");
        highlight.setAttribute("d", activeRoutes.join(" "));
        highlight.classList.add("revision-tree-connector", "active");
        svg.append(highlight);
    }
    dom.revisionTreeTrack.append(svg);

    revisions.forEach((revision, index) => {
        const position = positions.get(revision.id);
        const button = document.createElement("button");
        button.type = "button";
        button.className = `revision-node revision-node--${revision.kind}`;
        button.style.left = `${position.x}px`;
        button.style.top = `${position.y}px`;
        button.dataset.revisionId = revision.id;
        button.setAttribute("aria-label", `${revision.active ? "Current state" : "Restore state"}: ${revision.summary}`);
        button.setAttribute("aria-describedby", "revisionTooltip");
        button.setAttribute("aria-current", revision.active ? "step" : "false");
        button.setAttribute("aria-disabled", busy ? "true" : "false");
        button.classList.toggle("on-path", activeLineage.has(revision.id));
        button.classList.toggle("active", revision.active);
        button.classList.toggle("busy", busy);
        button.addEventListener("click", () => {
            if (button.getAttribute("aria-disabled") !== "true") {
                void switchRevision(revision);
            }
        });
        button.addEventListener("mouseenter", () => showRevisionTooltip(revision, button));
        button.addEventListener("mouseleave", hideRevisionTooltip);
        button.addEventListener("focus", () => showRevisionTooltip(revision, button));
        button.addEventListener("blur", hideRevisionTooltip);
        dom.revisionTreeTrack.append(button);

        if (revision.active && state.activeRevisionId !== revision.id) {
            queueMicrotask(() => button.scrollIntoView({ block: "nearest" }));
        }
        if (index === revisions.length - 1) {
            state.activeRevisionId = history.active_revision_id;
        }
    });
}

function setRevisionTreeBusy(busy) {
    dom.revisionTreeTrack.querySelectorAll(".revision-node").forEach((button) => {
        button.classList.toggle("busy", busy);
        button.setAttribute("aria-disabled", busy ? "true" : "false");
    });
}

function showRevisionTooltip(revision, button) {
    const tooltip = dom.revisionTooltip;
    tooltip.replaceChildren();

    const type = document.createElement("span");
    type.className = "revision-tooltip-type";
    type.textContent = `${revision.kind} · round ${revision.search_round}`;
    const title = document.createElement("strong");
    title.textContent = revision.name;
    const summary = document.createElement("p");
    summary.textContent = revision.summary;
    tooltip.append(type, title, summary);

    appendRevisionTooltipList(tooltip, "Requirements", revision.hard_constraints);
    appendRevisionTooltipList(tooltip, "Preferences", revision.soft_preferences);

    const status = document.createElement("span");
    status.className = "revision-tooltip-status";
    status.textContent = `${revision.candidate_count} candidate${revision.candidate_count === 1 ? "" : "s"} · ${revision.status}`;
    tooltip.append(status);
    tooltip.hidden = false;

    const buttonRect = button.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const top = Math.min(
        window.innerHeight - tooltipRect.height - 12,
        Math.max(12, buttonRect.top + buttonRect.height / 2 - tooltipRect.height / 2),
    );
    tooltip.style.left = `${buttonRect.right + 16}px`;
    tooltip.style.top = `${top}px`;
}

function appendRevisionTooltipList(tooltip, labelText, values) {
    if (!values.length) {
        return;
    }
    const section = document.createElement("div");
    section.className = "revision-tooltip-detail";
    const label = document.createElement("span");
    label.textContent = labelText;
    const value = document.createElement("p");
    value.textContent = values.slice(0, 2).join(" · ");
    section.append(label, value);
    tooltip.append(section);
}

function hideRevisionTooltip() {
    dom.revisionTooltip.hidden = true;
}
