document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("analyze-form");
    const urlInput = document.getElementById("url-input");
    const analyzeBtn = document.getElementById("analyze-btn");
    const errorBox = document.getElementById("error-box");
    const loadingState = document.getElementById("loading-state");
    const resultSection = document.getElementById("result-section");
    const recentScansList = document.getElementById("recent-scans-list");

    const themeToggle = document.getElementById("theme-toggle");

    // Theme setup
    const savedTheme = localStorage.getItem("theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    themeToggle.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme");
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        document.documentElement.setAttribute("data-theme", newTheme);
        localStorage.setItem("theme", newTheme);
    });

    function escapeHtml(unsafe) {
        if (unsafe == null) return "";
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function renderResult(data) {
        // Hide loading, show result
        loadingState.classList.add("hidden");
        resultSection.classList.remove("hidden");

        // Banner
        const banner = document.getElementById("verdict-banner");
        banner.className = `banner ${data.label}`;
        document.getElementById("risk-score").textContent = data.risk_score;
        document.getElementById("label-badge").textContent = data.label;
        document.getElementById("verdict-text").textContent = escapeHtml(data.verdict_text);

        // Trust Meter
        document.getElementById("trust-score-val").textContent = data.trust_score;
        const width = (data.trust_score / 8) * 100;
        document.getElementById("trust-bar").style.width = `${width}%`;

        const trustList = document.getElementById("trust-signals-list");
        trustList.innerHTML = "";
        (data.trust_signals || []).forEach(sig => {
            const li = document.createElement("li");
            li.className = "trust-signal";
            li.innerHTML = escapeHtml(sig);
            trustList.appendChild(li);
        });

        // Deep Analysis - Offerings
        const deep = data.deep_analysis || {};
        let offeringsHtml = `<p><strong>Page Title:</strong> ${escapeHtml(deep.page_title)}</p>`;
        offeringsHtml += `<p><strong>Meta Description:</strong> ${escapeHtml(deep.meta_description)}</p>`;

        if (deep.headings) {
            if (deep.headings.h1 && deep.headings.h1.length) {
                offeringsHtml += `<p><strong>H1 Headings:</strong> ${escapeHtml(deep.headings.h1.join(" | "))}</p>`;
            }
            if (deep.headings.h2 && deep.headings.h2.length) {
                offeringsHtml += `<p><strong>H2 Headings:</strong> ${escapeHtml(deep.headings.h2.join(" | "))}</p>`;
            }
        }

        if (deep.nav_links && deep.nav_links.length) {
            offeringsHtml += `<p><strong>Navigation:</strong></p><ul>`;
            deep.nav_links.forEach(link => {
                offeringsHtml += `<li>${escapeHtml(link.text)} (${escapeHtml(link.href)})</li>`;
            });
            offeringsHtml += `</ul>`;
        }
        document.getElementById("offerings-content").innerHTML = offeringsHtml;

        // Identity
        let identityHtml = "";
        const contact = deep.contact_info || {};
        identityHtml += `<p><strong>Email:</strong> ${escapeHtml(contact.email) || "Not found"}</p>`;
        identityHtml += `<p><strong>Phone:</strong> ${escapeHtml(contact.phone) || "Not found"}</p>`;
        identityHtml += `<p><strong>Address:</strong> ${escapeHtml(contact.address) || "Not found"}</p>`;

        const social = deep.social_links || {};
        identityHtml += `<p><strong>Social Media:</strong> `;
        const activeSocials = Object.entries(social).filter(([k,v]) => v).map(([k,v]) => `<a href="${escapeHtml(v)}" target="_blank">${escapeHtml(k)}</a>`);
        identityHtml += activeSocials.length ? activeSocials.join(" | ") : "Not present";
        identityHtml += `</p>`;

        identityHtml += `<ul>`;
        identityHtml += `<li>About page: ${deep.has_about_page ? "✓" : "✗"}</li>`;
        identityHtml += `<li>Privacy policy: ${deep.has_privacy_policy ? "✓" : "✗"}</li>`;
        identityHtml += `<li>Terms of service: ${deep.has_terms_page ? "✓" : "✗"}</li>`;
        identityHtml += `</ul>`;
        document.getElementById("identity-content").innerHTML = identityHtml;

        // Risk Signals
        const riskList = document.getElementById("risk-signals-list");
        riskList.innerHTML = "";
        if (data.reasons && data.reasons.length) {
            data.reasons.forEach(r => {
                const li = document.createElement("li");
                li.className = "risk-signal";
                if (r.includes("phishing") || r.includes("Unreachable") || r.includes("IP address") || r.includes("HTTPS")) {
                    li.classList.add("high-risk");
                }
                li.textContent = escapeHtml(r);
                riskList.appendChild(li);
            });
            // Show red if high risk, we could toggle summary color here
        } else {
            riskList.innerHTML = "<li>No specific risk signals detected.</li>";
        }

        // Technical
        const tech = deep.technical || {};
        let techHtml = `<ul>`;
        techHtml += `<li>HTTPS: ${tech.ssl_valid ? "✓" : "✗"}</li>`;
        techHtml += `<li>Status Code: ${escapeHtml(data.status_code)}</li>`;
        techHtml += `<li>Redirects: ${Math.max(0, (data.redirect_chain || []).length - 1)}</li>`;
        techHtml += `<li>Server: ${escapeHtml(tech.server)}</li>`;
        techHtml += `<li>Page Size: ${escapeHtml(tech.page_size_kb)} KB</li>`;
        techHtml += `<li>External Scripts: ${escapeHtml(tech.external_scripts)}</li>`;
        techHtml += `<li>Iframes: ${escapeHtml(tech.iframes)}</li>`;
        techHtml += `<li>Forms / Password Fields: ${escapeHtml(tech.forms)} / ${escapeHtml(tech.password_fields)}</li>`;
        techHtml += `<li>Favicon: ${tech.has_favicon ? "✓" : "✗"}</li>`;
        techHtml += `<li>robots.txt: ${tech.has_robots_txt ? "✓" : "✗"}</li>`;
        techHtml += `<li>sitemap.xml: ${tech.has_sitemap_xml ? "✓" : "✗"}</li>`;
        techHtml += `</ul>`;
        document.getElementById("technical-content").innerHTML = techHtml;

        // Domain
        let domainHtml = `<ul>`;
        let ageStr = deep.domain_age_days;
        if (ageStr > 365) {
            ageStr = `${Math.floor(ageStr/365)} years, ${Math.floor((ageStr%365)/30)} months`;
        } else if (ageStr < 30) {
            ageStr = `${ageStr} days old — VERY NEW`;
        } else {
            ageStr = `${ageStr} days`;
        }
        domainHtml += `<li>Domain Age: ${ageStr}</li>`;
        domainHtml += `<li>Registrar: ${escapeHtml(deep.registrar)}</li>`;
        domainHtml += `</ul>`;
        document.getElementById("domain-content").innerHTML = domainHtml;

        // Feedback
        document.getElementById("feedback-form").classList.add("hidden");
        document.getElementById("feedback-thanks").classList.add("hidden");
        document.querySelector(".feedback-buttons").classList.remove("hidden");
        document.getElementById("feedback-yes").dataset.id = data.analysis_id;
        document.getElementById("feedback-no").dataset.id = data.analysis_id;

        // Scroll to result
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        saveToSessionStorage(data);
        updateRecentScansTable();
    }

    function saveToSessionStorage(data) {
        let results = JSON.parse(sessionStorage.getItem("detector-results") || "[]");
        // Remove existing if same URL
        results = results.filter(r => r.url !== data.url);
        results.unshift(data);
        if (results.length > 20) results.pop();
        sessionStorage.setItem("detector-results", JSON.stringify(results));
    }

    function updateRecentScansTable() {
        // Initial load could use server side rendered, but we update with session storage on new scan
        const results = JSON.parse(sessionStorage.getItem("detector-results") || "[]");
        if (results.length === 0) return;

        recentScansList.innerHTML = "";
        results.forEach(row => {
            const tr = document.createElement("tr");
            tr.dataset.url = row.url;
            tr.innerHTML = `
                <td>${escapeHtml(row.domain)}</td>
                <td><span class="pill pill-${row.label}">${row.label.toUpperCase()}</span></td>
                <td>${row.risk_score}</td>
                <td>Just now</td>
            `;
            tr.addEventListener("click", () => {
                urlInput.value = row.url;
                renderResult(row);
            });
            recentScansList.appendChild(tr);
        });
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        errorBox.classList.add("hidden");
        resultSection.classList.add("hidden");
        loadingState.classList.remove("hidden");
        analyzeBtn.textContent = "Analyzing...";
        analyzeBtn.disabled = true;

        try {
            const res = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-CSRFToken": document.querySelector("input[name=\x27csrf_token\x27]").value },
                headers: { "Content-Type": "application/json", "X-CSRFToken": document.querySelector("input[name=\x27csrf_token\x27]").value }, body: JSON.stringify({ url })
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error((data.error && data.error.message) || "Analysis failed");
            }
            renderResult(data);
        } catch (err) {
            loadingState.classList.add("hidden");
            errorBox.textContent = err.message;
            errorBox.classList.remove("hidden");
        } finally {
            analyzeBtn.textContent = "Analyze";
            analyzeBtn.disabled = false;
        }
    });

    // Handle feedback
    document.getElementById("feedback-yes").addEventListener("click", () => handleFeedback("satisfied"));
    document.getElementById("feedback-no").addEventListener("click", () => {
        document.querySelector(".feedback-buttons").classList.add("hidden");
        document.getElementById("feedback-form").classList.remove("hidden");
    });

    document.getElementById("feedback-submit").addEventListener("click", () => {
        const note = document.getElementById("feedback-note").value;
        handleFeedback("not_satisfied", note);
    });

    async function handleFeedback(verdict, note = "") {
        const analysis_id = document.getElementById("feedback-yes").dataset.id;
        try {
            await fetch("/api/feedback", {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-CSRFToken": document.querySelector("input[name=\x27csrf_token\x27]").value },
                body: JSON.stringify({ analysis_id, verdict, note })
            });
            document.querySelector(".feedback-buttons").classList.add("hidden");
            document.getElementById("feedback-form").classList.add("hidden");
            document.getElementById("feedback-thanks").classList.remove("hidden");
        } catch (err) {
            console.error("Feedback error", err);
        }
    }

    // Attach click to existing server-rendered rows
    document.querySelectorAll("#recent-scans-list tr").forEach(tr => {
        tr.addEventListener("click", () => {
            const url = tr.dataset.url;
            urlInput.value = url;
            // Fetch result from API if not in session storage
            const results = JSON.parse(sessionStorage.getItem("detector-results") || "[]");
            const cached = results.find(r => r.url === url);
            if (cached) {
                renderResult(cached);
            } else {
                form.dispatchEvent(new Event("submit"));
            }
        });
    });

    // PWA Install
    let deferredPrompt;
    const installBtn = document.getElementById("install-pwa");
    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        installBtn.classList.remove("hidden");
    });

    installBtn.addEventListener("click", async () => {
        if (deferredPrompt !== null) {
            deferredPrompt.prompt();
            const { outcome } = await deferredPrompt.userChoice;
            if (outcome === 'accepted') {
                installBtn.classList.add("hidden");
            }
            deferredPrompt = null;
        }
    });

    // Service Worker
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js').catch(err => {
                console.log('SW registration failed: ', err);
            });
        });
    }
});
