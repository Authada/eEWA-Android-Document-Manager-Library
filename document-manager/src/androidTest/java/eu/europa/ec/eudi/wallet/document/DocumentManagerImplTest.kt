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
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.storage.EphemeralStorageEngine
import com.android.identity.storage.StorageEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import org.bouncycastle.util.encoders.Hex
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.IOException
import java.security.Signature
import java.util.*
import kotlin.random.Random
import eu.europa.ec.eudi.wallet.document.test.R

@RunWith(AndroidJUnit4::class)
class DocumentManagerImplTest {

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var secureArea: AndroidKeystoreSecureArea
    private lateinit var storageEngine: StorageEngine
    private lateinit var documentManager: DocumentManagerImpl

    @OptIn(ExperimentalCoroutinesApi::class)
    @Before
    @Throws(IOException::class)
    fun setUp() {

        storageEngine = EphemeralStorageEngine()
            .apply {
                deleteAll()
            }
        secureArea = AndroidKeystoreSecureArea(context, storageEngine)
        documentManager = DocumentManagerImpl(
            context = context,
            storageEngine = storageEngine,
            secureArea = secureArea,
            secureElementPidLib = null,
            coroutineScope = CoroutineScope(UnconfinedTestDispatcher())
        )
            .userAuth(false)
    }

    @After
    fun tearDown() {
        storageEngine.deleteAll()
    }

    @Test
    fun test_getDocuments_returns_empty_list() {
        val documents = documentManager.getDocumentsSynchronous()
        assertTrue(documents.isEmpty())
    }

    @Test
    fun test_getDocumentById_returns_null() {
        val documentId = "${UUID.randomUUID()}"
        val document = documentManager.getDocumentById(documentId)
        assertNull(document)
    }

    @Test
    fun test_createIssuanceRequest() {
        val docType = "eu.europa.ec.eudi.pid.1"
        val requestResult = documentManager.createIssuanceRequest(docType, format = Format.MSO_MDOC, false)
        assertTrue(requestResult is CreateIssuanceRequestResult.Success)

        val request = (requestResult as CreateIssuanceRequestResult.Success).issuanceRequest
        val documentId = request.documentId
        assertEquals(docType, request.docType)
        assertFalse(request.hardwareBacked)
        assertTrue(documentId.isNotBlank())
        assertEquals(docType, request.name)
        val stored = storageEngine.enumerate().toSet().filter { it.contains(request.documentId) }
        assertEquals(3, stored.size)
        assertNotNull(stored.firstOrNull { it.contains("AuthenticationKey_$documentId") })
        assertNotNull(stored.firstOrNull { it.contains("Credential_$documentId") })
        assertNotNull(stored.firstOrNull { it.contains("CredentialKey_$documentId") })

        // assert that document manager never returns an incomplete document
        val document = documentManager.getDocumentById(documentId)
        assertNull(document)

        val documents = documentManager.getDocumentsSynchronous()
        assertTrue(documents.isEmpty())

        val data = Random.nextBytes(32)
        val proofResult = request.signWithAuthKey(data)
        assertTrue(proofResult is SignedWithAuthKeyResult.Success)

        proofResult as SignedWithAuthKeyResult.Success

        val proof = proofResult.signature
        val publicKey = request.publicKey

        val sig = Signature.getInstance(Algorithm.SHA256withECDSA).apply {
            initVerify(publicKey)
            update(data)
        }
        assertTrue(sig.verify(proof))
    }

    @Test
    fun test_addDocument() {
        val docType = "eu.europa.ec.eudi.pid.1"
        val data = context.resources.openRawResource(R.raw.eu_pid).use { raw ->
            Hex.decode(raw.readBytes())
        }

        documentManager.checkPublicKeyBeforeAdding(false)
        val issuanceRequest = documentManager.createIssuanceRequest(docType, format = Format.MSO_MDOC, false).getOrThrow()
        val result = issuanceRequest.storeCredential(data)
        assertTrue(result is AddDocumentResult.Success)
        assertEquals(issuanceRequest.documentId, (result as AddDocumentResult.Success).documentId)
    }

    @Test
    fun test_checkPublicKeyInMso() {
        val docType = "eu.europa.ec.eudi.pid.1"
        // some random data with mismatching public key
        val data = context.resources.openRawResource(R.raw.eu_pid).use { raw ->
            Hex.decode(raw.readBytes())
        }
        documentManager.checkPublicKeyBeforeAdding(true)
        val issuanceRequest = documentManager.createIssuanceRequest(docType, format = Format.MSO_MDOC, false)
            .getOrThrow()
        val result = issuanceRequest.storeCredential(data)
        assertTrue(result is AddDocumentResult.Failure)
        result as AddDocumentResult.Failure
        assertTrue(result.throwable is IllegalArgumentException)
        assertEquals(
            "Public key in MSO does not match the one in the request",
            result.throwable.message
        )
    }
}