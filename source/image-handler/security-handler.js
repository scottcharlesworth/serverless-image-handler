/*********************************************************************************************************************
 *  Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           *
 *                                                                                                                    *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    *
 *  with the License. A copy of the License is located at                                                             *
 *                                                                                                                    *
 *      http://www.apache.org/licenses/LICENSE-2.0                                                                    *
 *                                                                                                                    *
 *  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES *
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    *
 *  and limitations under the License.                                                                                *
 *********************************************************************************************************************/

const crypto = require('crypto');

class SecurityHandler {

    /**
     * The character used to split the HMAC hash from the encoded string.
     * (Remember to also change this in the 'demo-ui')
     * @type {string}
     */
    hmacSplitter = ".";

    /**
     * Main method for processing incoming URL for HMAC presence.
     * @param {Object} event - Lambda request body.
     */
    async process(event) {
        const path = event["path"];
        const pathIncludesHmacSplitter = path.includes(this.hmacSplitter);
        const hmacAlgorithm = process.env.HMAC_ALGORITHM ? process.env.HMAC_ALGORITHM : "sha1";
        const hmacKey = process.env.HMAC_KEY ? process.env.HMAC_KEY : null;
        const hmacCompulsory = (process.env.HMAC_COMPULSORY === "Yes");

        if (hmacCompulsory && !hmacKey) {
            // If HMAC is compulsory, but no key is set
            throw ({
                status: 400,
                code: 'SecurityHandler::HmacCompulsoryNoKey',
                message: 'The image request you provided could not be processed. HMAC is compulsory, but no key is set.'
            });
        } else if (hmacCompulsory && !pathIncludesHmacSplitter) {
            // HMAC is compulsory, but there doesn't appear to be one in the request
            throw ({
                status: 400,
                code: 'SecurityHandler::HmacCompulsoryNoneProvided',
                message: 'The image request you provided could not be processed. HMAC is compulsory, but no hash was provided with the request.'
            });
        } else if (pathIncludesHmacSplitter && !hmacKey) {
            // The path includes the HMAC splitter, but no key is set
            throw ({
                status: 400,
                code: 'SecurityHandler::HmacProvidedKeyMissing',
                message: 'The image request you provided could not be processed. A HMAC appears to be in the path, but no HMAC key has been set.'
            });
        } else if (pathIncludesHmacSplitter && hmacKey) {
            // The path includes the HMAC splitter, and a HMAC key is set
            const splitPath = await this.splitPath(path, this.hmacSplitter);
            // Set up the HMAC
            const hmac = crypto.createHmac(hmacAlgorithm, hmacKey);
            // Update the value
            hmac.update(splitPath["encoded"]);
            // Get the digest
            const hmacDigest = await hmac.digest("hex");
            // Check the provided HMAC against the digest
            const hmacIsValid = splitPath["hmac"].toString() === hmacDigest.toString();

            // If the hmacIsValid
            if (hmacIsValid) {
                // Modify the event path, to be without the HMAC key and return
                let returnEvent = event;

                returnEvent["path"] = "/" + splitPath["encoded"];

                return returnEvent;
            } else {
                // The request appears to have been tampered with
                throw ({
                    status: 400,
                    code: 'SecurityHandler::HmacProvidedMismatch',
                    message: 'The image request you provided could not be processed. The HMAC key is different from the expected value, and the request appears to have been tampered with.'
                });
            }
        } else {
            // Just return the event as it was provided
            return event;
        }
    }

    /**
     * Splits the requested path using the provided character, and returns
     * an object with the HMAC hash and base64 encoded JSON.
     * @param {string} path - The path value from the Lambda request body.
     * @param {string} hmacSplitter - The HMAC splitter string.
     * @returns {{hmac: string, encoded: string}}
     */
    async splitPath(path, hmacSplitter) {
        const splitPath = path.split("/");
        const fullPath = splitPath[splitPath.length - 1];
        const fullPathSplit = fullPath.split(hmacSplitter);
        const providedHmac = fullPathSplit[0];
        const encodedJson = fullPathSplit[1];

        return {
            "hmac": providedHmac,
            "encoded": encodedJson,
        }
    }
}

// Exports
module.exports = SecurityHandler;