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

import COSE.Message
import COSE.MessageTag
import COSE.Sign1Message
import android.util.Log
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.credential.CredentialStore
import com.android.identity.credential.NameSpacedData
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.securearea.SecureArea
import com.android.identity.util.Timestamp
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.SignedJWT
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.sdjwt.Claim
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVerifier
import eu.europa.ec.eudi.sdjwt.asClaims
import eu.europa.ec.eudi.wallet.document.internal.getEmbeddedCBORObject
import eu.europa.ec.eudi.wallet.document.internal.withTag24
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import java.time.Instant
import java.util.concurrent.TimeUnit

internal class AndroidCredentialIssuanceRequest(
    override val docType: String,
    override val format: Format,
    credentialStore: CredentialStore,
    nonEmptyChallenge: ByteArray,
    strongBoxed: Boolean,
    documentId: String,
    private val userAuth: Boolean,
    private val userAuthTimeoutInMillis: Long,
    private val checkPublicKeyBeforeAdding: Boolean
) : IssuanceRequest {
    private val keySettings = createKeySettings(nonEmptyChallenge, strongBoxed)
    private val credential = credentialStore.createCredential(documentId, keySettings)

    private val pendingAuthKey = credential.createPendingAuthenticationKey(keySettings, null)
    override val documentId = credential.name
    override val hardwareBacked = keySettings.useStrongBox
    override var name = docType
    override val requiresUserAuth = keySettings.userAuthenticationRequired
    override val certificatesNeedAuth = pendingAuthKey.attestation

    override fun signWithAuthKey(
        data: ByteArray,
        @Algorithm alg: String
    ): SignedWithAuthKeyResult {
        val keyUnlockData =
            AndroidKeystoreSecureArea.KeyUnlockData(pendingAuthKey.alias)
        return try {
            credential.credentialSecureArea.sign(
                pendingAuthKey.alias,
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

    override fun storeCredential(data: ByteArray): AddDocumentResult = when (format) {
        Format.SD_JWT_VC -> addSdJwtDocument(data)
        Format.MSO_MDOC -> addMsoMdocDocument(data)
        Format.SE_TLV -> throw UnsupportedOperationException("se-tlv not supported in android credential storage")
    }

    private fun addMsoMdocDocument(
        data: ByteArray,
    ): AddDocumentResult {
        try {
            val issuerSigned = CBORObject.DecodeFromBytes(data)

            credential.apply {
                val issuerAuthBytes = issuerSigned["issuerAuth"].EncodeToBytes()
                val issuerAuth = Message
                    .DecodeFromBytes(issuerAuthBytes, MessageTag.Sign1) as Sign1Message

                val msoBytes = issuerAuth.GetContent().getEmbeddedCBORObject().EncodeToBytes()

                val mso = MobileSecurityObjectParser()
                    .setMobileSecurityObject(msoBytes)
                    .parse()

                if (mso.deviceKey != publicKey) {
                    val msg = "Public key in MSO does not match the one in the request"
                    Log.d(TAG, msg)
                    if (checkPublicKeyBeforeAdding) {
                        return AddDocumentResult.Failure(IllegalArgumentException(msg))
                    }
                }

                applicationData.apply {
                    setString(DOCUMENT_NAME, name)
                    setNumber(
                        DOCUMENT_CREATED_AT,
                        Instant.now().toEpochMilli()
                    )
                    setString(DOCUMENT_DOC_TYPE, mso.docType)
                    setString(DOCUMENT_FORMAT, Format.MSO_MDOC.name)
                    setBoolean(
                        DOCUMENT_REQUIRES_USER_AUTH,
                        userAuth
                    )
                }

                val nameSpaces = issuerSigned["nameSpaces"]
                val digestIdMapping = nameSpaces.toDigestIdMapping()
                val staticAuthData = StaticAuthDataGenerator(digestIdMapping, issuerAuthBytes)
                    .generate()
                credential.pendingAuthenticationKeys.forEach { key ->
                    key.certify(staticAuthData, mso.validFrom, mso.validUntil)
                }

                nameSpacedData = nameSpaces.asNameSpacedData()
            }
            return AddDocumentResult.Success(credential.name, byteArrayOf())
        } catch (e: Exception) {
            return AddDocumentResult.Failure(e)
        }
    }


    private fun addSdJwtDocument(
        data: ByteArray,
    ): AddDocumentResult {
        try {
            credential.apply {
                val sdJwtIssuance = SdJwtVerifier.verifyIssuance({ unverifiedJwt ->
                    requireNotNull(SignedJWT.parse(unverifiedJwt)) {
                        "Failed to parse SD-JWT"
                    }.jwtClaimsSet.asClaims()
                }, String(data, Charsets.UTF_8)).getOrThrow()

                val claims = claimPairs(sdJwtIssuance).toMap()
                val type = claims["vct"]?.jsonPrimitive?.content
                    ?: throw IllegalStateException("Missing mandatory vct attribute in sd-jwt credential")
                applicationData.apply {
                    setString(DOCUMENT_NAME, name)
                    setNumber(
                        DOCUMENT_CREATED_AT,
                        Instant.now().toEpochMilli()
                    )
                    setString(
                        DOCUMENT_FORMAT,
                        Format.SD_JWT_VC.name
                    )
                    setString(DOCUMENT_DOC_TYPE, type)
                    setBoolean(
                        DOCUMENT_REQUIRES_USER_AUTH,
                        userAuth
                    )
                }
                credential.pendingAuthenticationKeys.forEach { key ->
                    key.certify(
                        data,
                        sdJwtValidFrom(claims),
                        sdJwtValidUntil(claims)
                    )
                }

                val claimPairs = claimPairs(sdJwtIssuance)
                this.nameSpacedData = NameSpacedData.Builder()
                    .apply {
                        claimPairs.forEach { (key, value) ->
                            putEntry(
                                type,
                                key,
                                Json.encodeToString<JsonElement>(value).toByteArray(Charsets.UTF_8)
                            )
                        }

                    }
                    .build()
            }
            return AddDocumentResult.Success(credential.name, byteArrayOf())
        } catch (e: Exception) {
            return AddDocumentResult.Failure(e)
        }
    }

    private fun sdJwtValidUntil(claims: Map<String, JsonElement>) =
        Timestamp.ofEpochMilli(
            TimeUnit.SECONDS.toMillis(claims[JWTClaimNames.EXPIRATION_TIME]!!.jsonPrimitive.long)
        )

    private fun sdJwtValidFrom(claims: Map<String, JsonElement>): Timestamp {
        val notBeforeSeconds = claims[JWTClaimNames.NOT_BEFORE]?.jsonPrimitive?.longOrNull
        val issuedAtSeconds = claims[JWTClaimNames.ISSUED_AT]?.jsonPrimitive?.longOrNull
        return ((notBeforeSeconds ?: issuedAtSeconds)?.let {
            Timestamp.ofEpochMilli(TimeUnit.SECONDS.toMillis(it))
        }
            ?: Timestamp.now())
    }

    private fun claimPairs(claims: SdJwt.Issuance<JwtAndClaims>): List<Claim> {
        val claimPairs = claims.disclosures.map { it.claim() }
            .plus(claims.jwt.second.map { it.key to it.value })
        return claimPairs
    }

    private fun createKeySettings(
        challenge: ByteArray,
        hardwareBacked: Boolean,
    ) = AndroidKeystoreSecureArea.CreateKeySettings.Builder(challenge)
        .setEcCurve(SecureArea.EC_CURVE_P256)
        .setUseStrongBox(hardwareBacked)
        .setUserAuthenticationRequired(
            userAuth, userAuthTimeoutInMillis,
            AUTH_TYPE
        )
        .setKeyPurposes(AndroidKeystoreSecureArea.KEY_PURPOSE_SIGN)
        .build()


    companion object {
        private const val TAG = "AndroidCredentialIssuanceRequest"
        private const val AUTH_TYPE =
            AndroidKeystoreSecureArea.USER_AUTHENTICATION_TYPE_BIOMETRIC or AndroidKeystoreSecureArea.USER_AUTHENTICATION_TYPE_LSKF

        const val DOCUMENT_DOC_TYPE = "docType"
        const val DOCUMENT_NAME = "name"
        const val DOCUMENT_CREATED_AT = "createdAt"
        const val DOCUMENT_REQUIRES_USER_AUTH = "requiresUserAuth"
        const val DOCUMENT_FORMAT = "format"

    }
}


fun CBORObject.asNameSpacedData(): NameSpacedData {
    val builder = NameSpacedData.Builder()
    keys.forEach { nameSpace ->
        this[nameSpace].values.forEach { v ->
            val el = v.getEmbeddedCBORObject()
            builder.putEntry(
                nameSpace.AsString(),
                el["elementIdentifier"].AsString(),
                el["elementValue"].EncodeToBytes(),
            )
        }
    }
    return builder.build()
}

fun CBORObject.toDigestIdMapping(): Map<String, List<ByteArray>> = keys.associate {
    it.AsString() to this[it].values.map { v ->
        val el = v.getEmbeddedCBORObject()
        CBORObject.NewMap()
            .Add("digestID", el["digestID"])
            .Add("random", el["random"])
            .Add("elementIdentifier", el["elementIdentifier"])
            .Add("elementValue", CBORObject.Null)
            .EncodeToBytes()
            .withTag24()
    }
}