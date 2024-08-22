/*
 * Copyright (c) 2023 European Commission
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
 *
 * Modified by AUTHADA GmbH
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

import android.content.Context
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.securearea.AndroidKeystoreSecureArea.*
import com.android.identity.credential.Credential
import com.android.identity.credential.CredentialStore
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.StorageEngine
import de.authada.eewa.wallet.PidLib
import eu.europa.ec.eudi.wallet.document.Document.Companion.PROXY_ID_PREFIX
import eu.europa.ec.eudi.wallet.document.Document.Companion.SE_ID_PREFIX
import eu.europa.ec.eudi.wallet.document.internal.EU_PID_DOCTYPE
import eu.europa.ec.eudi.wallet.document.internal.isDeviceSecure
import eu.europa.ec.eudi.wallet.document.internal.supportsStrongBox
import org.bouncycastle.util.encoders.Hex
import java.security.SecureRandom
import java.time.Instant
import java.util.*


/**
 * A [DocumentManager] implementation that uses [StorageEngine] to store documents and [AndroidKeystoreSecureArea] for key management.
 *
 * Features:
 * - Enforces user authentication to access documents, if supported by the device
 * - Enforces hardware backed keys, if supported by the device
 * - P256 curve and Sign1 support for document keys
 *
 * To instantiate it, use the [eu.europa.ec.eudi.wallet.document.DocumentManager.Builder] class.
 *
 * @property storageEngine storage engine used to store documents
 * @property secureArea secure area used to store documents' keys
 * @property userAuth flag that indicates if the document requires user authentication to be accessed
 * @property userAuthTimeoutInMillis timeout in milliseconds for user authentication
 * @property checkPublicKeyBeforeAdding flag that indicates if the public key in the [IssuanceRequest] must match the public key in MSO
 *
 * @constructor
 * @param context
 * @param storageEngine storage engine used to store documents
 * @param secureArea secure area used to store documents' keys
 */
class DocumentManagerImpl(
    context: Context,
    private val storageEngine: StorageEngine,
    private val secureArea: AndroidKeystoreSecureArea,
    private val secureElementPidLib: PidLib?
) : DocumentManager {

    private val context = context.applicationContext
    private val isDeviceSecure: Boolean
        get() = context.isDeviceSecure

    private val secureAreaRepository: SecureAreaRepository by lazy {
        SecureAreaRepository().apply {
            addImplementation(secureArea)
        }
    }

    private val credentialStore: CredentialStore by lazy {
        CredentialStore(storageEngine, secureAreaRepository)
    }

    var userAuth: Boolean = isDeviceSecure
        set(value) {
            field = value && isDeviceSecure
        }

    var userAuthTimeoutInMillis: Long = AUTH_TIMEOUT

    var checkPublicKeyBeforeAdding: Boolean = true

    private val proxyDocMdoc = Document(
        id = "${PROXY_ID_PREFIX}MDOC",
        docType = "eu.europa.ec.eudiw.pid.1",
        name = "Proxy",
        hardwareBacked = true,
        createdAt = Instant.now(),
        requiresUserAuth = false,
        nameSpacedData = mapOf(
            "eu.europa.ec.eudiw.pid.1" to mapOf(
                "family_name" to Hex.decode("69446575747363686572"),
                "given_name" to Hex.decode("6f506572736f6e616c61757377656973"),
                "birth_date" to Hex.decode("d903ec6a323230302d30312d3031"),
                "age_in_years" to Hex.decode("1affffff51"),
                "age_over_18" to Hex.decode("f4"),
                "issuance_date" to Hex.decode("d903ec6a323230302d30312d3031"),
                "age_birth_year" to Hex.decode("190898"),
                "nationality" to Hex.decode("6144"),
                "family_name_birth" to Hex.decode("6144"),
                "birth_place" to Hex.decode("6144"),
                "resident_city" to Hex.decode("6144"),
                "resident_state" to Hex.decode("6144"),
                "resident_street" to Hex.decode("6144"),
                "resident_address" to Hex.decode("6144"),
                "resident_postal_code" to Hex.decode("6144"),
                "resident_country" to Hex.decode("6144"),
                "expiry_date" to Hex.decode("d903ec6a323230302d30312d3031"),
                "issuing_country" to Hex.decode("6144"),
                "issuing_authority" to Hex.decode("6144"),
                "source_document_type" to Hex.decode("6144")
            )
        ),
        format = Format.MSO_MDOC,
    )
    private val proxyDocSdJwt = Document(
        id = "${PROXY_ID_PREFIX}SDJWT",
        docType = "eu.europa.ec.eudiw.pid.1",
        name = "Proxy",
        hardwareBacked = true,
        createdAt = Instant.now(),
        requiresUserAuth = false,
        nameSpacedData = mapOf(
            "eu.europa.ec.eudiw.pid.1" to mapOf(
                "family_name" to "TEST".toByteArray(Charsets.UTF_8),
                "given_name" to "TEST".toByteArray(Charsets.UTF_8),
                "birth_date" to "TEST".toByteArray(Charsets.UTF_8),
                "age_in_years" to "18".toByteArray(Charsets.UTF_8),
                "age_over_18" to "true".toByteArray(Charsets.UTF_8),
                "issuance_date" to "1990-01-01".toByteArray(Charsets.UTF_8),
                "age_birth_year" to "1990".toByteArray(Charsets.UTF_8),
                "nationality" to "D".toByteArray(Charsets.UTF_8),
                "family_name_birth" to "TEST".toByteArray(Charsets.UTF_8),
                "birth_place" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_city" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_state" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_street" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_address" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_postal_code" to "TEST".toByteArray(Charsets.UTF_8),
                "resident_country" to "TEST".toByteArray(Charsets.UTF_8),
                "expiry_date" to "2200-01-01".toByteArray(Charsets.UTF_8),
                "issuing_country" to "DE".toByteArray(Charsets.UTF_8),
                "issuing_authority" to "DE".toByteArray(Charsets.UTF_8),
                "source_document_type" to "DE".toByteArray(Charsets.UTF_8)
            )
        ),
        format = Format.SD_JWT_VC,
    )

    /**
     * Sets whether to require user authentication to access the document.
     *
     * @param enable
     * @return [DocumentManagerImpl]
     */
    fun userAuth(enable: Boolean) = apply { this.userAuth = enable }

    /**
     * Sets the timeout in milliseconds for user authentication.
     *
     * @param timeoutInMillis timeout in milliseconds for user authentication
     * @return [DocumentManagerImpl]
     */
    fun userAuthTimeout(timeoutInMillis: Long) =
        apply { this.userAuthTimeoutInMillis = timeoutInMillis }

    /**
     * Sets whether to check public key in MSO before adding document to storage.
     * By default this is set to true.
     * This check is done to prevent adding documents with public key that is not in MSO.
     * The public key from the [IssuanceRequest] must match the public key in MSO.
     *
     * @see [DocumentManager.addDocument]
     *
     * @param check
     */
    fun checkPublicKeyBeforeAdding(check: Boolean) =
        apply { this.checkPublicKeyBeforeAdding = check }

    override fun getDocuments(): List<Document> {
        val proxyDocs = listOf(proxyDocMdoc, proxyDocSdJwt)
        val seDocs = secureElementPidLib?.let { getSeDocument()?.let { listOf(it) } ?: emptyList() }
        val mainDocs = seDocs ?: proxyDocs
        val androidStoreDocs = credentialStore.listCredentials()
            .mapNotNull { credentialName ->
                credentialStore.lookupCredential(credentialName)?.asDocument
            }
        return mainDocs + androidStoreDocs
    }


    override fun getDocumentById(documentId: DocumentId): Document? =
        when (documentId) {
            proxyDocMdoc.id -> proxyDocMdoc
            proxyDocSdJwt.id -> proxyDocSdJwt
            else -> {
                if (documentId.startsWith(SE_ID_PREFIX)) {
                    getSeDocument(documentId)
                } else {
                    credentialStore.lookupCredential(documentId)?.asDocument
                }
            }
        }

    override fun deleteDocumentById(documentId: DocumentId): DeleteDocumentResult {
        return try {
            val proofOfDeletion = byteArrayOf()
            if (documentId.startsWith(SE_ID_PREFIX)) {
                deleteSeDocument(documentId)
            } else {
                credentialStore.deleteCredential(documentId)
            }
            DeleteDocumentResult.Success(proofOfDeletion)
        } catch (e: Exception) {
            DeleteDocumentResult.Failure(e)
        }
    }

    override fun createIssuanceRequest(
        docType: String,
        format: Format,
        hardwareBacked: Boolean,
        attestationChallenge: ByteArray?,
        storeDocument: Boolean
    ): CreateIssuanceRequestResult = try {
        val documentId = "${UUID.randomUUID()}"
        val nonEmptyChallenge = attestationChallenge
            ?.takeUnless { it.isEmpty() }
            ?: generateRandomBytes(10)
        val strongBoxed = hardwareBacked && context.supportsStrongBox
        val request = when (format) {
            Format.SD_JWT_VC, Format.MSO_MDOC -> {
                if (storeDocument) {
                    AndroidCredentialIssuanceRequest(
                        docType = docType,
                        format = format,
                        credentialStore = credentialStore,
                        nonEmptyChallenge = nonEmptyChallenge,
                        strongBoxed = strongBoxed,
                        documentId = documentId,
                        userAuth = userAuth,
                        userAuthTimeoutInMillis = userAuthTimeoutInMillis,
                        checkPublicKeyBeforeAdding = checkPublicKeyBeforeAdding
                    )
                } else {
                    ProxyIssuanceRequest(
                        docType = docType,
                        format = format,
                        nonEmptyChallenge = nonEmptyChallenge,
                        strongBoxed = strongBoxed,
                        userAuth = userAuth,
                        userAuthTimeoutInMillis = userAuthTimeoutInMillis,
                        secureArea = secureArea
                    )
                }
            }

            Format.SE_TLV -> secureElementPidLib?.let {
                SecureElementIssuanceRequest(
                    docType = docType,
                    documentId = documentId,
                    secureElementPidLib = secureElementPidLib,
                    storageEngine = storageEngine
                )
            }
                ?: throw IllegalStateException("se-tlv issuing is not supported, pid lib is not initialized")
        }
        CreateIssuanceRequestResult.Success(request)
    } catch (e: Exception) {
        CreateIssuanceRequestResult.Failure(e)
    }


    private val Credential.asDocument: Document?
        get() {
            if (this.pendingAuthenticationKeys.isNotEmpty()) return null

            return Document(
                id = name,
                docType = applicationData.getString(AndroidCredentialIssuanceRequest.DOCUMENT_DOC_TYPE),
                name = applicationData.getString(AndroidCredentialIssuanceRequest.DOCUMENT_NAME),
                hardwareBacked = authenticationKeys.firstOrNull()?.alias?.let {
                    credentialSecureArea.getKeyInfo(it).isHardwareBacked
                } ?: false,
                createdAt = Instant.ofEpochMilli(
                    applicationData.getNumber(
                        AndroidCredentialIssuanceRequest.DOCUMENT_CREATED_AT
                    )
                ),
                requiresUserAuth = applicationData.getBoolean(AndroidCredentialIssuanceRequest.DOCUMENT_REQUIRES_USER_AUTH),
                format = Format.valueOf(applicationData.getString(AndroidCredentialIssuanceRequest.DOCUMENT_FORMAT)),
                nameSpacedData = nameSpacedData.nameSpaceNames.associateWith { nameSpace ->
                    nameSpacedData.getDataElementNames(nameSpace)
                        .associateWith { elementIdentifier ->
                            nameSpacedData.getDataElement(nameSpace, elementIdentifier)
                        }
                },
            )
        }

    private fun getSeDocument(documentId: String? = null): Document? {
        val seCredentialMap = storageEngine.getSeStoredCredentialMap()
        val selectedDocumentId = documentId ?: seCredentialMap.keys.firstOrNull() ?: return null
        val credentialHandle = seCredentialMap[selectedDocumentId] ?: return null

        val personalDataMap = secureElementPidLib!!.getPersonalData(credentialHandle)

        return if (personalDataMap?.isNotEmpty() == true) {
            val nameSpacedDataMap = mutableMapOf(EU_PID_DOCTYPE to personalDataMap)

            Document(
                id = selectedDocumentId,
                docType = EU_PID_DOCTYPE,
                name = EU_PID_DOCTYPE,
                hardwareBacked = true,
                createdAt = Instant.EPOCH,
                requiresUserAuth = true,
                format = Format.SD_JWT_VC,
                nameSpacedData = nameSpacedDataMap
            )
        } else null
    }

    private fun deleteSeDocument(documentId: String) {
        secureElementPidLib?.let {
            val storedMap = storageEngine.getSeStoredCredentialMap().toMutableMap()
            val existing = storedMap.remove(documentId) != null
            if (existing) {
                it.deletePersonalData()
                storageEngine.storeSeStoredCredentialMap(
                    storedMap
                )
            } else {
                throw IllegalArgumentException("documentId does not exist in secure element")
            }
        }
    }


    companion object {
        private const val TAG = "DocumentManagerImpl"

        @JvmStatic
        val AUTH_TIMEOUT = 30_000L
    }


    private fun generateRandomBytes(size: Int): ByteArray {
        val secureRandom = SecureRandom()
        val randomBytes = ByteArray(size)
        secureRandom.nextBytes(randomBytes)
        return randomBytes
    }
}
