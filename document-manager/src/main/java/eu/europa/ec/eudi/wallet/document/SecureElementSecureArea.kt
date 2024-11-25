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

import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureArea.EC_CURVE_P256
import com.android.identity.securearea.SecureArea.KEY_PURPOSE_SIGN
import com.android.identity.storage.StorageEngine
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import de.authada.eewa.wallet.PidLib
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date

class SecureElementSecureArea(private val pidLib: PidLib, private val storageEngine: StorageEngine) : SecureArea {

    override fun createKey(p0: String, p1: SecureArea.CreateKeySettings) {
        val seKeyMap = storageEngine.getSeKeyMap().toMutableMap()

        seKeyMap[p0] = pidLib.createKeyPair()
        storageEngine.storeSeKeyMap(seKeyMap)
    }

    override fun deleteKey(p0: String) {
        val seKeyMap = storageEngine.getSeKeyMap().toMutableMap()
        seKeyMap.remove(p0)?.let {
            pidLib.deleteKeyId(it)
            storageEngine.storeSeKeyMap(seKeyMap)
        }
    }

    private fun getKeyIdFromKeyMap(p0: String): ByteArray =
        storageEngine.getSeKeyMap()[p0] ?: throw IllegalArgumentException("Unknown Key")

    override fun sign(
        p0: String,
        p1: Int,
        p2: ByteArray,
        p3: SecureArea.KeyUnlockData?
    ): ByteArray = pidLib.signWithKey(getKeyIdFromKeyMap(p0), p2)

    override fun keyAgreement(p0: String, p1: PublicKey, p2: SecureArea.KeyUnlockData?): ByteArray {
        throw UnsupportedOperationException()
    }

    override fun getKeyInfo(p0: String): SecureArea.KeyInfo {
        val cert = newCert(getKeyIdFromKeyMap(p0))
        val javaCert = X509CertUtils.parse(cert.encoded)
        return SecureElementKeyInfo(
            mutableListOf(javaCert),
            KEY_PURPOSE_SIGN,
            EC_CURVE_P256,
            true
        )
    }

    private fun newCert(keyId: ByteArray): X509CertificateHolder {
        val publicKey = kotlin.runCatching { pidLib.getPublicKey(keyId) }.getOrElse {
            throw SecureArea.KeyLockedException()
        }
        return X509v3CertificateBuilder(
            X500Name(commonName),
            BigInteger(1, publicKey.encoded),
            Date(),
            Date.from(Instant.now() + Duration.ofDays(365 * 10)),
            X500Name(commonName),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded)
        ).build(SecureElementContentSigner(keyId))
    }

    private inner class SecureElementContentSigner(private val keyId: ByteArray) : ContentSigner {
        private val byteArrayOutputStream = ByteArrayOutputStream()
        override fun getAlgorithmIdentifier(): AlgorithmIdentifier =
            AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

        override fun getOutputStream(): OutputStream = byteArrayOutputStream

        override fun getSignature(): ByteArray {
            return pidLib.signWithKey(keyId, byteArrayOutputStream.toByteArray())
        }
    }

    private class SecureElementKeyInfo(
        attestation: MutableList<X509Certificate>,
        keyPurposes: Int,
        ecCurve: Int,
        isHardwareBacked: Boolean
    ) : SecureArea.KeyInfo(attestation, keyPurposes, ecCurve, isHardwareBacked)

    class CreateKeySettings() : SecureArea.CreateKeySettings(SecureElementSecureArea::class.java)

    companion object {
        private const val commonName = "CN=SecureElement"
        private const val SE_KEY_MAP = "SE_KEY_MAP"
    }

    @Suppress("UNCHECKED_CAST")
    private fun StorageEngine.getSeKeyMap(): Map<String, ByteArray> {
        val decoder = Base64.getDecoder()
        return (JSONObjectUtils.parse(
            this.get(SE_KEY_MAP)?.toString(Charsets.UTF_8) ?: "{}"
        ) as Map<String, String>).mapValues {
            decoder.decode(it.value)
        }
    }

    private fun StorageEngine.storeSeKeyMap(map: Map<String, ByteArray>) {
        val encoder = Base64.getEncoder()
        val stringMap = map.mapValues {
            encoder.encodeToString(it.value)
        }
        val byteArray = JSONObjectUtils.toJSONString(stringMap).toByteArray(Charsets.UTF_8)
        this.put(SE_KEY_MAP, byteArray)
    }
}