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

const SecurityHandler = require('../security-handler');
let assert = require('assert');

// ----------------------------------------------------------------------------
// [async] process()
// ----------------------------------------------------------------------------
describe('process()', function() {
    describe('001/default', async function() {
        it(`Should pass if the original event object is returned when path doesn't include HMAC splitter
            and HMAC isn't compulsory`, async function() {
            // Arrange
            const event = {
                path : '/eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0='
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "secret",
                HMAC_COMPULSORY : "No",
            }
            // Act
            const securityHandler = new SecurityHandler();
            const result = await securityHandler.process(event);
            // Assert
            assert.deepStrictEqual(event, result, true);
        });
    });
    describe('002/hmacCompulsoryNoKeySet', function() {
        it(`Should throw an error if the HMAC is compulsory but no key has been set`, async function() {
            // Arrange
            const hmacSplitter = "_";
            const hmacHash = '17b1131b7d6f08a29065fadb8b54b727ba25188a';
            const enc = 'eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0=';
            const event = {
                path : hmacHash + hmacSplitter + enc
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "",
                HMAC_COMPULSORY : "Yes",
            }
            // Act
            const securityHandler = new SecurityHandler();
            // Assert
            securityHandler.process(event).then((result) => {
                assert.equal(typeof result, Error);
            }).catch((err) => {
                console.log(err)
            })
        });
    });
    describe('003/hmacCompulsoryNoKeyProvided', function() {
        it(`Should throw an error if the HMAC is compulsory but there isn't one in the request`, async function() {
            // Arrange
            const event = {
                path : '/eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0='
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "secret",
                HMAC_COMPULSORY : "Yes",
            }
            // Act
            const securityHandler = new SecurityHandler();
            // Assert
            securityHandler.process(event).then((result) => {
                assert.equal(typeof result, Error);
            }).catch((err) => {
                console.log(err)
            })
        });
    });
    describe('004/hmacSplitterPresentNoKeySet', function() {
        it(`Should throw an error if the HMAC splitter is present but no key has been set`, async function() {
            // Arrange
            const hmacSplitter = "_";
            const enc = 'eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0=';
            const event = {
                path : "/" + hmacSplitter + enc
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "",
                HMAC_COMPULSORY : "No",
            }
            // Act
            const securityHandler = new SecurityHandler();
            // Assert
            securityHandler.process(event).then((result) => {
                assert.equal(typeof result, Error);
            }).catch((err) => {
                console.log(err)
            })
        });
    });
    describe('005/hmacProvidedMismatch', function() {
        it(`Should throw an error if the HMAC provided is incorrect for the encoded string`, async function() {
            // Arrange
            const hmacSplitter = "_";
            const hmacHash = '469a67474a79221397a6c665986fae3682b70510'; // wrong-secret
            const enc = 'eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0=';
            const event = {
                path : "/" + hmacHash + hmacSplitter + enc
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "secret",
                HMAC_COMPULSORY : "Yes",
            }
            // Act
            const securityHandler = new SecurityHandler();
            // Assert
            securityHandler.process(event).then((result) => {
                assert.equal(typeof result, Error);
            }).catch((err) => {
                console.log(err)
            })
        });
    });
    describe('006/hmacValid', function() {
        it(`Should pass if the original event object is returned with HMAc removed from the path 
            when HMAC is valid`, async function() {
            // Arrange
            const hmacSplitter = "_";
            const hmacHash = '17b1131b7d6f08a29065fadb8b54b727ba25188a';
            const enc = 'eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0=';
            const event = {
                path : "/" + hmacHash + hmacSplitter + enc
            }
            process.env = {
                HMAC_ALGORITHM : "sha1",
                HMAC_KEY : "secret",
                HMAC_COMPULSORY : "Yes",
            }
            // Act
            const securityHandler = new SecurityHandler();
            const result = await securityHandler.process(event);
            // Assert
            const expectedResult = {
                path : "/" + enc
            }
            assert.deepStrictEqual(expectedResult, result, true);
        });
    });
});

// ----------------------------------------------------------------------------
// [async] splitPath()
// ----------------------------------------------------------------------------
describe('splitPath()', function() {
    describe('001/default', function() {
        it(`Should pass if an object containing HMAC and encoded string is returned`, async function() {
            // Arrange
            const hmacSplitter = "_";
            const hmacHash = '17b1131b7d6f08a29065fadb8b54b727ba25188a';
            const enc = 'eyJidWNrZXQiOiJ2YWxpZEJ1Y2tldCIsImtleSI6InZhbGlkS2V5IiwiZWRpdHMiOnsiZ3JheXNjYWxlIjp0cnVlfX0=';
            const path = "/" + hmacHash + hmacSplitter + enc;
            // Act
            const securityHandler = new SecurityHandler();
            const result = await securityHandler.splitPath(path, hmacSplitter);
            // Assert
            const expectedResult = {
                "hmac": hmacHash,
                "encoded": enc,
            };
            assert.deepStrictEqual(expectedResult, result, true);
        });
    });
});