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
import com.nimbusds.jose.util.X509CertUtils
import de.authada.eewa.wallet.PidLib
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

class SecureElementSecureArea(private val pidLib: PidLib) : SecureArea {

    private val lazyAttestation by lazy {
        pidLib.walletAttestation(byteArrayOf(0))
    }

    override fun createKey(p0: String, p1: SecureArea.CreateKeySettings) {
        lazyAttestation
    }

    override fun deleteKey(p0: String) {
        //TODO Currently does not work as same key is used by multiple credentials and generates errors if the key is deleted by deleting one of these many credentials
//        pidLib.deletePersonalData()
    }

    override fun sign(
        p0: String,
        p1: Int,
        p2: ByteArray,
        p3: SecureArea.KeyUnlockData?
    ): ByteArray = pidLib.signWithDevKey(p2)

    override fun keyAgreement(p0: String, p1: PublicKey, p2: SecureArea.KeyUnlockData?): ByteArray {
        throw UnsupportedOperationException()
    }

    override fun getKeyInfo(p0: String): SecureArea.KeyInfo {
        val publicKey = kotlin.runCatching { pidLib.getDevicePublicKey() }.getOrElse {
            throw SecureArea.KeyLockedException()
        }

        val cert = newCert(publicKey)
        val javaCert = X509CertUtils.parse(cert.encoded)
        return SecureElementKeyInfo(
            mutableListOf(javaCert),
            KEY_PURPOSE_SIGN,
            EC_CURVE_P256,
            true
        )
    }

    private fun newCert(publicKey: ECPublicKey): X509CertificateHolder =
        X509v3CertificateBuilder(
            X500Name(commonName),
            BigInteger(1, publicKey.encoded),
            Date(),
            Date.from(Instant.now() + Duration.ofDays(365 * 10)),
            X500Name(commonName),
            SubjectPublicKeyInfo.getInstance(publicKey.encoded)
        ).build(SecureElementContentSigner())

    private inner class SecureElementContentSigner : ContentSigner {
        private val byteArrayOutputStream = ByteArrayOutputStream()
        override fun getAlgorithmIdentifier(): AlgorithmIdentifier =
            AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

        override fun getOutputStream(): OutputStream = byteArrayOutputStream

        override fun getSignature(): ByteArray =
            pidLib.signWithDevKey(byteArrayOutputStream.toByteArray())
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
    }
}