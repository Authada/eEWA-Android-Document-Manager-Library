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
@file:JvmMultifileClass

package eu.europa.ec.eudi.wallet.document

import android.content.Context
import androidx.biometric.BiometricPrompt.CryptoObject
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.securearea.SecureArea
import com.android.identity.storage.StorageEngine
import de.authada.eewa.wallet.PidLib
import eu.europa.ec.eudi.wallet.document.internal.isDeviceSecure
import eu.europa.ec.eudi.wallet.document.room.DocumentMetaData
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File

/**
 * Document manager object is the entry point to access documents.
 *
 * It is used to add, retrieve and delete documents.
 *
 * A default implementation of this interface is implemented by [DocumentManagerImpl].
 * To instantiate it, use the [eu.europa.ec.eudi.wallet.document.DocumentManager.Builder] class.
 */
interface DocumentManager {
    /**
     * Retrieve all documents
     *
     * @return list of documents
     */
    fun getDocumentsSynchronous(): List<Document>


    /**
     * MetaData retrieval happens asynchronously, therefore the function is suspended
     */
    suspend fun getDocumentsWithMetaData(): List<Document>

    /**
     * Get document by id
     *
     * @param documentId document's unique identifier
     * @return [Document] if exists, null otherwise
     */
    fun getDocumentById(documentId: DocumentId): Document?

    /**
     * Delete document by id
     *
     * @param documentId document's unique identifier
     * @return [DeleteDocumentResult.Success] containing the proof of deletion if successful, [DeleteDocumentResult.Failure] otherwise
     */
    suspend fun deleteDocumentById(documentId: DocumentId): DeleteDocumentResult

    /**
     * Create an issuance request for a given docType. The issuance request can be then used to issue the document
     * from the issuer. The issuance request contains the certificate that must be sent to the issuer.
     *
     * @param docType document's docType (example: "eu.europa.ec.eudi.pid.1")
     * @param hardwareBacked whether the document should be stored in hardware backed storage
     * @param attestationChallenge optional attestationChallenge to check provided by the issuer
     * @return [CreateIssuanceRequestResult.Success] containing the issuance request if successful, [CreateIssuanceRequestResult.Failure] otherwise
     */
    fun createIssuanceRequest(
        docType: String,
        format: Format,
        hardwareBacked: Boolean,
        attestationChallenge: ByteArray? = null,
        storeDocument: Boolean = true
    ): CreateIssuanceRequestResult


    suspend fun storeMetaDataForCredential(documentMetaData: DocumentMetaData)

    /**
     * Builder class to instantiate the default DocumentManager implementation.
     *
     * example:
     * ```
     * val documentManager = DocumentManager.Builder(context)
     *    .useEncryption(true)
     *    .storageDir(context.noBackupFilesDir)
     *    .enableUserAuth(true)
     *    .userAuthTimeout(30000)
     *    .build()
     * ```
     *
     * @property useEncryption whether to encrypt the values stored on disk. Note that keys are not encrypted, only values. By default this is set to true.
     * @property storageDir the directory to store data files in. By default the [Context.getNoBackupFilesDir] is used.
     * @property userAuth flag that indicates if the document requires user authentication to be accessed. By default this is set to true if the device is secured with a PIN, password or pattern.
     * @property userAuthTimeoutInMillis timeout in milliseconds for user authentication. By default this is set to 30 seconds.
     * @property checkPublicKeyBeforeAdding flag that indicates if the public key from the [IssuanceRequest] must match the public key in MSO. By default this is set to true.
     * @constructor
     *
     * @param context [Context] used to instantiate the DocumentManager
     */
    class Builder(context: Context) {
        private val _context = context.applicationContext
        var useEncryption: Boolean = true
        var storageDir: File = _context.noBackupFilesDir
        var userAuth: Boolean = context.isDeviceSecure
        var coroutineScope: CoroutineScope = CoroutineScope(Dispatchers.IO)
        var userAuthTimeoutInMillis: Long = DocumentManagerImpl.AUTH_TIMEOUT
        var checkPublicKeyBeforeAdding: Boolean = true
        var secureElementPidLib: PidLib? = null
        var secureArea: ((StorageEngine) -> SecureArea)? = null

        /**
         * Sets whether to encrypt the values stored on disk.
         * Note that keys are not encrypted, only values.
         * By default this is set to true.
         *
         * @param useEncryption
         * @return [DocumentManager.Builder]
         */
        fun useEncryption(useEncryption: Boolean) = apply { this.useEncryption = useEncryption }

        /**
         * The directory to store data files in.
         * By default the [Context.getNoBackupFilesDir] is used.
         *
         * @param storageDir
         * @return [DocumentManager.Builder]
         */
        fun storageDir(storageDir: File) = apply { this.storageDir = storageDir }

        /**
         * Sets whether to require user authentication to access the document.
         *
         * @param enable
         * @return [DocumentManager.Builder]
         */
        fun enableUserAuth(enable: Boolean) = apply { this.userAuth = enable }

        /**
         * Sets the timeout in milliseconds for user authentication.
         *
         * @param timeoutInMillis timeout in milliseconds for user authentication
         * @return [DocumentManager.Builder]
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
         * @param checkPublicKeyBeforeAdding
         */
        fun checkPublicKeyBeforeAdding(checkPublicKeyBeforeAdding: Boolean) =
            apply { this.checkPublicKeyBeforeAdding = checkPublicKeyBeforeAdding }

        /**
         * Build the DocumentManager
         *
         * @return [DocumentManager]
         */
        fun build(): DocumentManager =
            DocumentManagerImpl(
                context = _context,
                storageEngine = storageEngine,
                secureArea = secureArea?.invoke(storageEngine) ?: androidSecureArea,
                secureElementPidLib = secureElementPidLib,
                coroutineScope = coroutineScope
            ).apply {
                userAuth(this@Builder.userAuth)
                userAuthTimeout(this@Builder.userAuthTimeoutInMillis)
            }

        private val storageEngine: StorageEngine
            get() = AndroidStorageEngine.Builder(_context, storageDir)
                .setUseEncryption(useEncryption)
                .build()

        private val androidSecureArea: AndroidKeystoreSecureArea
            get() = AndroidKeystoreSecureArea(_context, storageEngine)
    }
}


/**
 * Add document result sealed interface
 */
sealed interface AddDocumentResult {

    /**
     * Success result containing the documentId.
     * DocumentId can be then used to retrieve the document from the [DocumentManager::getDocumentById] method
     *
     * @property documentId document's unique identifier
     * @property proofOfProvisioning proof of provisioning
     * @constructor
     *
     * @param documentId document's unique identifier
     * @param proofOfProvisioning proof of provisioning
     */
    class Success(val documentId: DocumentId, val proofOfProvisioning: ByteArray) :
        AddDocumentResult

    /**
     * Failure while adding the document. Contains the throwable that caused the failure
     *
     * @property throwable throwable that caused the failure
     * @constructor
     * @param throwable throwable that caused the failure
     */
    data class Failure(val throwable: Throwable) : AddDocumentResult

    /**
     * Success result containing the documentId and the proof of provisioning if successful
     *
     * @param block block to be executed if the result is successful
     * @return [AddDocumentResult]
     */
    fun onSuccess(block: (DocumentId, ByteArray) -> Unit): AddDocumentResult = apply {
        if (this is Success) block(documentId, proofOfProvisioning)
    }

    /**
     * Failure while adding the document. Contains the throwable that caused the failure
     *
     * @param block block to be executed if the result is a failure
     * @return [AddDocumentResult]
     */
    fun onFailure(block: (Throwable) -> Unit): AddDocumentResult = apply {
        if (this is Failure) block(throwable)
    }
}

sealed interface SignedWithAuthKeyResult {
    /**
     * Success result containing the signature of data
     *
     * @property signature
     */
    data class Success(val signature: ByteArray) : SignedWithAuthKeyResult {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Success

            return signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int {
            return signature.contentHashCode()
        }
    }

    /**
     * User authentication is required to sign data
     *
     * @property cryptoObject
     */
    data class UserAuthRequired(val cryptoObject: CryptoObject?) : SignedWithAuthKeyResult

    /**
     * Failure while signing the data. Contains the throwable that caused the failure
     *
     * @property throwable
     */
    data class Failure(val throwable: Throwable) : SignedWithAuthKeyResult

    /**
     * Execute block if the result is successful
     *
     * @param block
     * @return [SignedWithAuthKeyResult]
     */
    fun onSuccess(block: (ByteArray) -> Unit): SignedWithAuthKeyResult = apply {
        if (this is Success) block(signature)
    }

    /**
     * Execute block if the result is a failure
     *
     * @param block
     * @return [SignedWithAuthKeyResult]
     */
    fun onFailure(block: (Throwable) -> Unit): SignedWithAuthKeyResult = apply {
        if (this is Failure) block(throwable)
    }

    /**
     * Execute block if the result requires user authentication
     *
     * @param block
     * @return [SignedWithAuthKeyResult]
     */
    fun onUserAuthRequired(block: (CryptoObject?) -> Unit): SignedWithAuthKeyResult = apply {
        if (this is UserAuthRequired) block(cryptoObject)
    }
}

/**
 * Create issuance request result sealed interface
 */
sealed interface CreateIssuanceRequestResult {

    /**
     * Success result containing the issuance request. The issuance request can be then used to issue the document
     * from the issuer. The issuance request contains the certificate chain that must be sent to the issuer.
     *
     * @property issuanceRequest
     *
     * @constructor
     * @param issuanceRequest
     */
    data class Success(val issuanceRequest: IssuanceRequest) : CreateIssuanceRequestResult

    /**
     * Failure while creating the issuance request. Contains the throwable that caused the failure
     *
     * @property throwable
     * @constructor Create empty Failure
     */
    data class Failure(val throwable: Throwable) : CreateIssuanceRequestResult

    /**
     * Execute block if the result is successful
     *
     * @param block block to be executed if the result is successful
     * @return [CreateIssuanceRequestResult]
     */
    fun onSuccess(block: (IssuanceRequest) -> Unit): CreateIssuanceRequestResult = apply {
        if (this is Success) block(issuanceRequest)
    }

    /**
     * Execute block if the result is a failure
     *
     * @param block block to be executed if the result is a failure
     * @return [CreateIssuanceRequestResult]
     */
    fun onFailure(block: (Throwable) -> Unit): CreateIssuanceRequestResult = apply {
        if (this is Failure) block(throwable)
    }

    /**
     * Get issuance request or throw the throwable that caused the failure
     *
     * @return [IssuanceRequest]
     */
    fun getOrThrow(): IssuanceRequest = when (this) {
        is Success -> issuanceRequest
        is Failure -> throw throwable
    }
}

/**
 * Delete document result sealed interface
 */
sealed interface DeleteDocumentResult {
    /**
     * Success result containing the proof of deletion
     *
     * @property proofOfDeletion
     * @constructor
     * @param proofOfDeletion
     */
    data class Success(val proofOfDeletion: ByteArray?) : DeleteDocumentResult {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Success

            if (proofOfDeletion != null) {
                if (other.proofOfDeletion == null) return false
                if (!proofOfDeletion.contentEquals(other.proofOfDeletion)) return false
            } else if (other.proofOfDeletion != null) return false

            return true
        }

        override fun hashCode(): Int {
            return proofOfDeletion?.contentHashCode() ?: 0
        }
    }

    /**
     * Failure while deleting the document. Contains the throwable that caused the failure
     *
     * @property throwable throwable that caused the failure
     * @constructor
     * @param throwable throwable that caused the failure
     */
    data class Failure(val throwable: Throwable) : DeleteDocumentResult

    /**
     * Execute block if the result is successful
     *
     * @param block
     * @return [DeleteDocumentResult]
     */
    fun onSuccess(block: (ByteArray?) -> Unit): DeleteDocumentResult = apply {
        if (this is Success) block(proofOfDeletion)
    }

    /**
     * Execute block if the result is a failure
     *
     * @param block
     * @return [DeleteDocumentResult]
     */
    fun onFailure(block: (Throwable) -> Unit): DeleteDocumentResult = apply {
        if (this is Failure) block(throwable)
    }
}
