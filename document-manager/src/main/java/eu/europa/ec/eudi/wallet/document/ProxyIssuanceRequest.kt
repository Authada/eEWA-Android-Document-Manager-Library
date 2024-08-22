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

import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.securearea.SecureArea
import com.android.identity.util.Timestamp
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant

internal class ProxyIssuanceRequest(
    override val docType: String,
    override val format: Format,
    keySettings: SecureArea.CreateKeySettings,
    private val secureArea: SecureArea,
    override val hardwareBacked: Boolean,
    override val requiresUserAuth: Boolean
) : IssuanceRequest {
    override val documentId: String = PROXY_KEY_ALIAS

    override var name = docType
    override val certificatesNeedAuth: MutableList<X509Certificate>

    init {
        secureArea.deleteKey(PROXY_KEY_ALIAS)
        secureArea.createKey(PROXY_KEY_ALIAS, keySettings)
        certificatesNeedAuth = secureArea.getKeyInfo(documentId).attestation
    }

    override fun signWithAuthKey(
        data: ByteArray,
        @Algorithm alg: String
    ): SignedWithAuthKeyResult {
        val keyUnlockData =
            AndroidKeystoreSecureArea.KeyUnlockData(PROXY_KEY_ALIAS)
        return try {
            secureArea.sign(
                PROXY_KEY_ALIAS,
                alg.algorithm,
                data,
                keyUnlockData
            ).let {
                SignedWithAuthKeyResult.Success(it)
            }
        } catch (e: Exception) {
            when (e) {
                is SecureArea.KeyLockedException -> SignedWithAuthKeyResult.UserAuthRequired(
                    keyUnlockData.getCryptoObjectForSigning(alg.algorithm)
                )

                else -> SignedWithAuthKeyResult.Failure(e)
            }
        }

    }

    override fun storeCredential(data: ByteArray): AddDocumentResult = try {
        AddDocumentResult.Success(documentId, byteArrayOf())
    } catch (e: Exception) {
        AddDocumentResult.Failure(e)
    }

    companion object {
        private const val PROXY_KEY_ALIAS = "PROXY_CREDENTIAL_ISSUANCE"
    }
}