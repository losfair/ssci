if (!("require" in globalThis)) {
    const modules = new Map(
        await Promise.all(
            [
                "assert",
                "async_hooks",
                "buffer",
                "console",
                "crypto",
                "diagnostics_channel",
                "events",
                "http",
                "https",
                "net",
                "perf_hooks",
                "process",
                "querystring",
                "stream",
                "string_decoder",
                "tls",
                "tty",
                "url",
                "util",
                "util/types",
                "worker_threads",
                "zlib",
            ].map((name) =>
                import(`node:${name}`).then((x) => [name, x.default ?? x])
            ),
        ),
    );
    for (const [k, v] of [...modules]) {
        modules.set(`node:${k}`, v);
    }
    globalThis.require = (name) => {
        const m = modules.get(name);
        if (m) {
            return m;
        }
        throw new Error(`Module '${name}' not found`);
    };
}

if (!("Buffer" in globalThis)) {
    globalThis.Buffer = require("buffer").Buffer;
}

if (!("process" in globalThis)) {
    globalThis.process = require("process");
}

globalThis.__injectedModuleUrl = import.meta.url;
