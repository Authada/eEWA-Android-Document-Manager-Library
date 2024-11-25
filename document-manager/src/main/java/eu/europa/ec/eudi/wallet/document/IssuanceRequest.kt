/*
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.document

import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Issuance request class. Contains the necessary information to issue a document.
 * Use the [DocumentManager::createIssuanceRequest] method to create an issuance request.
 *
 * @property documentId document's unique identifier
 * @property docType document's docType (example: "eu.europa.ec.eudi.pid.1")
 * @property name document's name
 * @property hardwareBacked whether the document's keys should be stored in hardware backed storage
 * @property requiresUserAuth whether the document requires user authentication to be accessed
 * @property certificatesNeedAuth list of certificates that will be used for issuing the document
 * @property publicKey public key of the first certificate in [certificatesNeedAuth] list to be included in mobile security object that it will be signed from issuer
 *
 */
interface IssuanceRequest {
    val documentId: DocumentId
    val docType: String
    val format: Format
    var name: String
    val hardwareBacked: Boolean
    val requiresUserAuth: Boolean
    val certificatesNeedAuth: List<X509Certificate>

    /**
     * Public key of the first certificate in [certificatesNeedAuth] list
     * to be included in mobile security object that it will be signed from issuer
     */
    val publicKey: PublicKey
        get() = certificatesNeedAuth.first().publicKey

    /**
     * Sign given data with authentication key
     *
     * Available algorithms are:
     * - [Algorithm.SHA256withECDSA]
     *
     * @param data to be signed
     * @param alg algorithm to be used for signing the data (example: "SHA256withECDSA")
     * @return [SignedWithAuthKeyResult.Success] containing the signature if successful,
     * [SignedWithAuthKeyResult.UserAuthRequired] if user authentication is required to sign data,
     * [SignedWithAuthKeyResult.Failure] if an error occurred while signing the data
     */
    fun signWithAuthKey(
        data: ByteArray,
        @Algorithm alg: String = Algorithm.SHA256withECDSA
    ): SignedWithAuthKeyResult

    fun storeCredential(data: ByteArray): AddDocumentResult
}