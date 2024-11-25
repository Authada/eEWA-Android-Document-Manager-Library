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

import com.android.identity.storage.StorageEngine
import com.nimbusds.jose.util.JSONObjectUtils
import de.authada.eewa.wallet.PidLib
import eu.europa.ec.eudi.wallet.document.Document.Companion.SE_ID_PREFIX
import eu.europa.ec.eudi.wallet.document.SecureElementIssuanceRequest.Companion.SE_STORED_CREDENTIALS_KEY
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64

internal class SecureElementIssuanceRequest(
    override val docType: String,
    documentId: String,
    private val secureElementPidLib: PidLib,
    private val storageEngine: StorageEngine
) : IssuanceRequest {
    private val keyId = secureElementPidLib.createKeyPair()
    override val format: Format = Format.SE_TLV
    override val hardwareBacked = true
    override var name = docType
    override val requiresUserAuth = true
    override val certificatesNeedAuth = emptyList<X509Certificate>()

    override val documentId: String = "$SE_ID_PREFIX$documentId"
    override val publicKey: PublicKey
        get() = secureElementPidLib.getPublicKey(keyId)

    override fun signWithAuthKey(
        data: ByteArray,
        @Algorithm alg: String
    ): SignedWithAuthKeyResult = try {
        SignedWithAuthKeyResult.Success(secureElementPidLib.signWithKey(keyId, data))
    } catch (e: Exception) {
        SignedWithAuthKeyResult.Failure(e)
    }

    override fun storeCredential(data: ByteArray): AddDocumentResult = try {
        val credentialHandle = secureElementPidLib.storePersonalData(keyId, data)

        val credentialMap = storageEngine.getSeStoredCredentialMap().toMutableMap()
        credentialMap.clear()
        credentialMap.put(documentId, credentialHandle)
        storageEngine.storeSeStoredCredentialMap(credentialMap)
        AddDocumentResult.Success(documentId, byteArrayOf())
    } catch (e: Exception) {
        AddDocumentResult.Failure(e)
    }


    companion object {
        const val SE_STORED_CREDENTIALS_KEY = "SE_STORED_CREDENTIALS"
    }
}

@Suppress("UNCHECKED_CAST")
fun StorageEngine.getSeStoredCredentialMap(): Map<String, ByteArray> {
    val decoder = Base64.getDecoder()
    return (JSONObjectUtils.parse(
        this.get(SE_STORED_CREDENTIALS_KEY)?.toString(Charsets.UTF_8) ?: "{}"
    ) as Map<String, String>).mapValues {
        decoder.decode(it.value)
    }
}

fun StorageEngine.storeSeStoredCredentialMap(map: Map<String, ByteArray>) {
    val encoder = Base64.getEncoder()
    val stringMap = map.mapValues {
        encoder.encodeToString(it.value)
    }
    val byteArray = JSONObjectUtils.toJSONString(stringMap).toByteArray(Charsets.UTF_8)
    this.put(SE_STORED_CREDENTIALS_KEY, byteArray)
}