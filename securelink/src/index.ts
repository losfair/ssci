import * as wasm from "./wasm.ts";
export * as wasm from "./wasm.ts";

const crypto = await wasm.VwCrypto.load(wasm.defaultVwContextInit());
