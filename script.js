const fileInput =
    document.getElementById("fileInput");

const dropZone =
    document.getElementById("dropZone");

const sampleButton =
    document.getElementById("sampleButton");

const loading =
    document.getElementById("loading");

const errorBox =
    document.getElementById("error");

const dashboard =
    document.getElementById("dashboard");

const fileName =
    document.getElementById("fileName");

const fileMeta =
    document.getElementById("fileMeta");

const totalEvents =
    document.getElementById("totalEvents");

const errorCount =
    document.getElementById("errorCount");

const warningCount =
    document.getElementById("warningCount");

const criticalCount =
    document.getElementById("criticalCount");

const uniqueIPs =
    document.getElementById("uniqueIPs");

const anomalyScore =
    document.getElementById("anomalyScore");

const infoPercent =
    document.getElementById("infoPercent");

const warningPercent =
    document.getElementById("warningPercent");

const errorPercent =
    document.getElementById("errorPercent");

const criticalPercent =
    document.getElementById("criticalPercent");

const infoBar =
    document.getElementById("infoBar");

const warningBar =
    document.getElementById("warningBar");

const errorBar =
    document.getElementById("errorBar");

const criticalBar =
    document.getElementById("criticalBar");

const assessmentScore =
    document.getElementById("assessmentScore");

const assessmentLabel =
    document.getElementById("assessmentLabel");

const assessmentText =
    document.getElementById("assessmentText");

const criticalRatio =
    document.getElementById("criticalRatio");

const errorRatio =
    document.getElementById("errorRatio");

const ipConcentration =
    document.getElementById("ipConcentration");

const ipList =
    document.getElementById("ipList");

const errorList =
    document.getElementById("errorList");

const timeline =
    document.getElementById("timeline");

const searchInput =
    document.getElementById("searchInput");

const severityFilter =
    document.getElementById("severityFilter");

const logTable =
    document.getElementById("logTable");

const eventCount =
    document.getElementById("eventCount");

const exportButton =
    document.getElementById("exportButton");


let parsedEvents = [];
let currentFileName = "sample.log";


fileInput.addEventListener(
    "change",
    function () {

        const file =
            fileInput.files[0];

        if (!file) {
            return;
        }

        processFile(file);

    }
);


dropZone.addEventListener(
    "dragover",
    function (event) {

        event.preventDefault();

        dropZone.classList.add(
            "dragging"
        );

    }
);


dropZone.addEventListener(
    "dragleave",
    function () {

        dropZone.classList.remove(
            "dragging"
        );

    }
);


dropZone.addEventListener(
    "drop",
    function (event) {

        event.preventDefault();

        dropZone.classList.remove(
            "dragging"
        );

        const file =
            event.dataTransfer.files[0];

        if (!file) {
            return;
        }

        processFile(file);

    }
);


sampleButton.addEventListener(
    "click",
    function () {

        currentFileName =
            "sample-production.log";

        analyzeText(
            generateSampleLogs()
        );

    }
);


searchInput.addEventListener(
    "input",
    renderTable
);


severityFilter.addEventListener(
    "change",
    renderTable
);


exportButton.addEventListener(
    "click",
    exportCSV
);


async function processFile(file) {

    const extension =
        file.name
            .split(".")
            .pop()
            .toLowerCase();

    if (
        extension !== "log" &&
        extension !== "txt"
    ) {

        showError(
            "Format file harus .log atau .txt."
        );

        return;
    }

    if (file.size > 10 * 1024 * 1024) {

        showError(
            "Ukuran file maksimal 10 MB."
        );

        return;
    }

    setLoading(true);

    try {

        currentFileName =
            file.name;

        const text =
            await file.text();

        if (!text.trim()) {

            throw new Error(
                "File log kosong."
            );

        }

        analyzeText(text);

    } catch (err) {

        showError(
            err.message
        );

    } finally {

        setLoading(false);

    }

}


function analyzeText(text) {

    setLoading(true);

    setTimeout(
        function () {

            try {

                parsedEvents =
                    parseLogs(text);

                if (!parsedEvents.length) {

                    throw new Error(
                        "Tidak ada event log yang berhasil dibaca."
                    );

                }

                renderDashboard(
                    parsedEvents
                );

                dashboard.classList.remove(
                    "hidden"
                );

                errorBox.classList.add(
                    "hidden"
                );

                dashboard.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });

            } catch (err) {

                showError(
                    err.message
                );

            } finally {

                setLoading(false);

            }

        },
        300
    );

}


function parseLogs(text) {

    const lines =
        text.split(/\r?\n/);

    const events = [];

    lines.forEach(
        function (line, index) {

            const trimmed =
                line.trim();

            if (!trimmed) {
                return;
            }

            const timestamp =
                extractTimestamp(
                    trimmed
                );

            const severity =
                detectSeverity(
                    trimmed
                );

            const ip =
                extractIP(
                    trimmed
                );

            const message =
                cleanMessage(
                    trimmed,
                    severity
                );

            events.push({

                id: index + 1,

                timestamp:
                    timestamp,

                severity:
                    severity,

                ip:
                    ip,

                message:
                    message,

                raw:
                    trimmed

            });

        }
    );

    return events;

}


function extractTimestamp(line) {

    const patterns = [

        /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,

        /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/,

        /\d{2}\/\d{2}\/\d{4}[ T]\d{2}:\d{2}:\d{2}/,

        /\d{2}:\d{2}:\d{2}/

    ];

    for (const pattern of patterns) {

        const match =
            line.match(pattern);

        if (match) {

            return match[0];

        }

    }

    return "--";

}


function detectSeverity(line) {

    const upper =
        line.toUpperCase();

    if (
        /\bCRITICAL\b/.test(upper) ||
        /\bFATAL\b/.test(upper)
    ) {

        return "CRITICAL";

    }

    if (
        /\bERROR\b/.test(upper) ||
        /\bERR\b/.test(upper)
    ) {

        return "ERROR";

    }

    if (
        /\bWARNING\b/.test(upper) ||
        /\bWARN\b/.test(upper)
    ) {

        return "WARNING";

    }

    return "INFO";

}


function extractIP(line) {

    const match =
        line.match(
            /\b(?:\d{1,3}\.){3}\d{1,3}\b/
        );

    if (!match) {
        return "--";
    }

    const parts =
        match[0]
            .split(".")
            .map(Number);

    const valid =
        parts.every(
            number =>
                number >= 0 &&
                number <= 255
        );

    return valid
        ? match[0]
        : "--";

}


function cleanMessage(
    line,
    severity
) {

    let result =
        line;

    result =
        result.replace(
            /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,
            ""
        );

    result =
        result.replace(
            /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/,
            ""
        );

    result =
        result.replace(
            /\d{2}\/\d{2}\/\d{4}[ T]\d{2}:\d{2}:\d{2}/,
            ""
        );

    result =
        result.replace(
            /\b(INFO|WARN|WARNING|ERROR|ERR|CRITICAL|FATAL)\b/i,
            ""
        );

    result =
        result.replace(
            /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
            ""
        );

    return result
        .replace(
            /^\s*[\[\]:\-|]+\s*/,
            ""
        )
        .trim();

}


function renderDashboard(events) {

    const stats =
        calculateStats(events);

    fileName.textContent =
        currentFileName;

    fileMeta.textContent =
        `${formatNumber(events.length)}
        events ·
        ${formatBytes(events.join("").length)}`;

    totalEvents.textContent =
        formatNumber(stats.total);

    errorCount.textContent =
        formatNumber(stats.error);

    warningCount.textContent =
        formatNumber(stats.warning);

    criticalCount.textContent =
        formatNumber(stats.critical);

    uniqueIPs.textContent =
        formatNumber(
            stats.uniqueIPs
        );

    anomalyScore.textContent =
        stats.anomaly;

    renderSeverity(stats);

    renderAssessment(stats);

    renderIPList(events);

    renderErrorList(events);

    renderTimeline(events);

    renderTable();

}


function calculateStats(events) {

    const total =
        events.length;

    const info =
        events.filter(
            event =>
                event.severity === "INFO"
        ).length;

    const warning =
        events.filter(
            event =>
                event.severity === "WARNING"
        ).length;

    const error =
        events.filter(
            event =>
                event.severity === "ERROR"
        ).length;

    const critical =
        events.filter(
            event =>
                event.severity === "CRITICAL"
        ).length;

    const ips =
        events
            .map(
                event =>
                    event.ip
            )
            .filter(
                ip =>
                    ip !== "--"
            );

    const unique =
        new Set(ips);

    const errorRatioValue =
        (
            ((error + critical) /
                total) * 100
        );

    const criticalRatioValue =
        (
            (critical /
                total) * 100
        );

    const ipScore =
        Math.min(
            unique.size * 4,
            25
        );

    const severityScore =
        Math.min(
            errorRatioValue * 0.8 +
            criticalRatioValue * 1.5,
            55
        );

    const volumeScore =
        Math.min(
            total / 20,
            20
        );

    const anomaly =
        Math.round(
            Math.min(
                100,
                severityScore +
                ipScore +
                volumeScore
            )
        );

    return {

        total,

        info,

        warning,

        error,

        critical,

        uniqueIPs:
            unique.size,

        anomaly,

        errorRatio:
            errorRatioValue,

        criticalRatio:
            criticalRatioValue

    };

}


function renderSeverity(stats) {

    const total =
        stats.total || 1;

    const info =
        (stats.info / total) * 100;

    const warning =
        (stats.warning / total) * 100;

    const error =
        (stats.error / total) * 100;

    const critical =
        (stats.critical / total) * 100;

    infoPercent.textContent =
        `${info.toFixed(1)}%`;

    warningPercent.textContent =
        `${warning.toFixed(1)}%`;

    errorPercent.textContent =
        `${error.toFixed(1)}%`;

    criticalPercent.textContent =
        `${critical.toFixed(1)}%`;

    infoBar.style.width =
        `${info}%`;

    warningBar.style.width =
        `${warning}%`;

    errorBar.style.width =
        `${error}%`;

    criticalBar.style.width =
        `${critical}%`;

}


function renderAssessment(stats) {

    assessmentScore.textContent =
        stats.anomaly;

    criticalRatio.textContent =
        `${stats.criticalRatio.toFixed(1)}%`;

    errorRatio.textContent =
        `${stats.errorRatio.toFixed(1)}%`;

    const ipEntries =
        getIPCounts(parsedEvents);

    if (!ipEntries.length) {

        ipConcentration.textContent =
            "NONE";

    } else {

        const top =
            ipEntries[0][1];

        const percentage =
            (top / stats.total) * 100;

        ipConcentration.textContent =
            `${percentage.toFixed(1)}%`;

    }

    if (stats.anomaly >= 75) {

        assessmentLabel.textContent =
            "HIGH RISK";

        assessmentText.textContent =
            "The dataset contains a high concentration of severe events. Investigate critical failures, recurring errors and suspicious IP activity.";

    } else if (stats.anomaly >= 45) {

        assessmentLabel.textContent =
            "MODERATE RISK";

        assessmentText.textContent =
            "The log contains noticeable abnormal activity. Review recurring failures and event concentration.";

    } else if (stats.anomaly >= 20) {

        assessmentLabel.textContent =
            "LOW RISK";

        assessmentText.textContent =
            "Some abnormal events were detected, but the overall signal remains relatively controlled.";

    } else {

        assessmentLabel.textContent =
            "NORMAL";

        assessmentText.textContent =
            "No significant anomaly signal was detected in the analyzed dataset.";

    }

}


function getIPCounts(events) {

    const counts = {};

    events.forEach(
        function (event) {

            if (event.ip === "--") {
                return;
            }

            counts[event.ip] =
                (counts[event.ip] || 0) + 1;

        }
    );

    return Object.entries(counts)
        .sort(
            (a, b) =>
                b[1] - a[1]
        );

}


function renderIPList(events) {

    ipList.innerHTML = "";

    const entries =
        getIPCounts(events)
            .slice(0, 7);

    if (!entries.length) {

        ipList.innerHTML =
            emptyMessage(
                "No IP addresses detected."
            );

        return;

    }

    entries.forEach(
        function ([ip, count], index) {

            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "rank-item";

            item.innerHTML = `

                <span class="rank-number">
                    ${String(index + 1).padStart(2, "0")}
                </span>

                <span class="rank-name">
                    ${escapeHTML(ip)}
                </span>

                <span class="rank-value">
                    ${count} events
                </span>

            `;

            ipList.appendChild(item);

        }
    );

}


function renderErrorList(events) {

    errorList.innerHTML = "";

    const errorEvents =
        events.filter(
            event =>
                event.severity === "ERROR" ||
                event.severity === "CRITICAL"
        );

    const counts = {};

    errorEvents.forEach(
        function (event) {

            const normalized =
                normalizeError(
                    event.message
                );

            counts[normalized] =
                (counts[normalized] || 0) + 1;

        }
    );

    const entries =
        Object.entries(counts)
            .sort(
                (a, b) =>
                    b[1] - a[1]
            )
            .slice(0, 7);

    if (!entries.length) {

        errorList.innerHTML =
            emptyMessage(
                "No errors detected."
            );

        return;

    }

    entries.forEach(
        function ([message, count], index) {

            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "rank-item";

            item.innerHTML = `

                <span class="rank-number">
                    ${String(index + 1).padStart(2, "0")}
                </span>

                <span class="rank-name">
                    ${escapeHTML(message)}
                </span>

                <span class="rank-value">
                    ${count}x
                </span>

            `;

            errorList.appendChild(item);

        }
    );

}


function normalizeError(message) {

    return message
        .replace(
            /\d+/g,
            "#"
        )
        .replace(
            /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
            "IP"
        )
        .slice(0, 100);

}


function renderTimeline(events) {

    timeline.innerHTML = "";

    const recent =
        events.slice(-10).reverse();

    recent.forEach(
        function (event) {

            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "timeline-item";

            item.innerHTML = `

                <div class="timeline-time">
                    ${escapeHTML(event.timestamp)}
                </div>

                <div class="timeline-text">
                    ${escapeHTML(event.message)}
                </div>

                <span class="timeline-severity">
                    ${event.severity}
                </span>

            `;

            timeline.appendChild(item);

        }
    );

}


function renderTable() {

    logTable.innerHTML = "";

    const search =
        searchInput.value
            .trim()
            .toLowerCase();

    const severity =
        severityFilter.value;

    const filtered =
        parsedEvents.filter(
            function (event) {

                const matchesSearch =
                    !search ||
                    event.raw
                        .toLowerCase()
                        .includes(search);

                const matchesSeverity =
                    severity === "ALL" ||
                    event.severity === severity;

                return (
                    matchesSearch &&
                    matchesSeverity
                );

            }
        );

    filtered
        .slice(0, 500)
        .forEach(
            function (event) {

                const row =
                    document.createElement(
                        "tr"
                    );

                const severityClass =
                    event.severity
                        .toLowerCase();

                row.innerHTML = `

                    <td>
                        ${escapeHTML(event.timestamp)}
                    </td>

                    <td>
                        <span
                            class="
                                severity-badge
                                severity-${severityClass}
                            "
                        >
                            ${event.severity}
                        </span>
                    </td>

                    <td>
                        ${escapeHTML(event.ip)}
                    </td>

                    <td>
                        ${escapeHTML(event.message)}
                    </td>

                `;

                logTable.appendChild(row);

            }
        );

    eventCount.textContent =
        `Showing ${Math.min(
            filtered.length,
            500
        )} of ${filtered.length} events`;

}


function exportCSV() {

    if (!parsedEvents.length) {
        return;
    }

    const header =
        [
            "Timestamp",
            "Severity",
            "IP",
            "Message",
            "Raw"
        ];

    const rows =
        parsedEvents.map(
            function (event) {

                return [

                    event.timestamp,

                    event.severity,

                    event.ip,

                    event.message,

                    event.raw

                ];

            }
        );

    const csv =
        [
            header,
            ...rows
        ]
            .map(
                row =>
                    row
                        .map(csvEscape)
                        .join(",")
            )
            .join("\n");

    const blob =
        new Blob(
            [csv],
            {
                type:
                    "text/csv;charset=utf-8;"
            }
        );

    const url =
        URL.createObjectURL(blob);

    const link =
        document.createElement("a");

    link.href = url;

    link.download =
        "log-analysis.csv";

    link.click();

    URL.revokeObjectURL(url);

}


function csvEscape(value) {

    return `"${String(value)
        .replaceAll('"', '""')}"`;

}


function generateSampleLogs() {

    const lines = [

        "2026-08-09 08:00:01 INFO 192.168.1.20 Application started successfully",

        "2026-08-09 08:01:13 INFO 192.168.1.20 User authentication completed",

        "2026-08-09 08:02:41 INFO 192.168.1.15 Database connection established",

        "2026-08-09 08:03:20 WARNING 192.168.1.15 Database response time exceeded 800ms",

        "2026-08-09 08:04:55 INFO 10.0.0.12 GET /api/users 200",

        "2026-08-09 08:05:12 ERROR 10.0.0.12 Database query failed timeout",

        "2026-08-09 08:05:15 ERROR 10.0.0.12 Database query failed timeout",

        "2026-08-09 08:05:18 ERROR 10.0.0.12 Database query failed timeout",

        "2026-08-09 08:06:44 WARNING 172.16.0.4 Failed login attempt",

        "2026-08-09 08:07:01 WARNING 172.16.0.4 Failed login attempt",

        "2026-08-09 08:07:03 WARNING 172.16.0.4 Failed login attempt",

        "2026-08-09 08:07:08 ERROR 172.16.0.4 Authentication service rejected request",

        "2026-08-09 08:08:31 INFO 192.168.1.20 Cache refreshed",

        "2026-08-09 08:09:10 INFO 192.168.1.15 Background worker started",

        "2026-08-09 08:10:22 ERROR 10.0.0.12 Connection refused port 5432",

        "2026-08-09 08:10:24 ERROR 10.0.0.12 Connection refused port 5432",

        "2026-08-09 08:11:02 CRITICAL 10.0.0.12 Database cluster unavailable",

        "2026-08-09 08:11:05 CRITICAL 10.0.0.12 Database cluster unavailable",

        "2026-08-09 08:11:09 CRITICAL 10.0.0.12 Database cluster unavailable",

        "2026-08-09 08:12:40 ERROR 10.0.0.12 API request failed 503",

        "2026-08-09 08:13:10 ERROR 10.0.0.12 API request failed 503",

        "2026-08-09 08:14:20 WARNING 172.16.0.4 Excessive authentication failures",

        "2026-08-09 08:15:44 INFO 192.168.1.20 Service health check passed",

        "2026-08-09 08:16:22 INFO 192.168.1.20 Worker queue processed",

        "2026-08-09 08:17:05 ERROR 192.168.1.15 Redis connection timeout",

        "2026-08-09 08:17:10 ERROR 192.168.1.15 Redis connection timeout",

        "2026-08-09 08:18:30 WARNING 192.168.1.15 High memory utilization 82%",

        "2026-08-09 08:19:12 INFO 192.168.1.20 Memory utilization normalized",

        "2026-08-09 08:20:33 CRITICAL 10.0.0.12 Payment service unavailable",

        "2026-08-09 08:20:40 CRITICAL 10.0.0.12 Payment service unavailable"

    ];

    return lines.join("\n");

}


function setLoading(state) {

    if (state) {

        loading.classList.remove(
            "hidden"
        );

        errorBox.classList.add(
            "hidden"
        );

    } else {

        loading.classList.add(
            "hidden"
        );

    }

}


function showError(message) {

    errorBox.textContent =
        message;

    errorBox.classList.remove(
        "hidden"
    );

    dashboard.classList.add(
        "hidden"
    );

}


function emptyMessage(message) {

    return `
        <div class="rank-item">
            <span class="rank-name">
                ${escapeHTML(message)}
            </span>
        </div>
    `;

}


function formatNumber(number) {

    return new Intl.NumberFormat(
        "en-US"
    ).format(number || 0);

}


function formatBytes(bytes) {

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(
            bytes / 1024
        ).toFixed(1)} KB`;
    }

    return `${(
        bytes /
        (1024 * 1024)
    ).toFixed(1)} MB`;

}


function escapeHTML(value) {

    return String(value)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );

}