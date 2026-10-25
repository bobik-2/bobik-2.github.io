import { NotSupportedError } from "../../../hpke-common-1.10.1/mod.js";
export function emitNotSupported() {
    return new Promise((_resolve, reject) => {
        reject(new NotSupportedError("Not supported"));
    });
}
