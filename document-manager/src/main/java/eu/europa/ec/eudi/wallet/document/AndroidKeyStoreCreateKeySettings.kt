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
import java.time.Duration
import java.time.Instant

class AndroidKeyStoreCreateKeySettings(
    private val userAuth: Boolean,
    private val userAuthTimeoutInMillis: Long,
) : DocumentManagerImpl.CreateKeySettings {
    override fun invoke(challenge: ByteArray, strongBoxed: Boolean, storeDocument: Boolean): SecureArea.CreateKeySettings =
        if(storeDocument) {
            AndroidKeystoreSecureArea.CreateKeySettings.Builder(challenge)
                .setEcCurve(SecureArea.EC_CURVE_P256)
                .setUseStrongBox(strongBoxed)
                .setUserAuthenticationRequired(
                    userAuth,
                    userAuthTimeoutInMillis,
                    AUTH_TYPE
                )
                .setKeyPurposes(AndroidKeystoreSecureArea.KEY_PURPOSE_SIGN)
                .build()
        } else {
            AndroidKeystoreSecureArea.CreateKeySettings.Builder(challenge)
                .setEcCurve(SecureArea.EC_CURVE_P256)
                .setUseStrongBox(strongBoxed)
                .setKeyPurposes(AndroidKeystoreSecureArea.KEY_PURPOSE_SIGN)
                .setValidityPeriod(
                    Timestamp.now(),
                    //1 Hour validity for adhoc issuing
                    Timestamp.ofEpochMilli((Instant.now() + Duration.ofHours(1)).toEpochMilli())
                )
                .build()
        }

    companion object {
        private const val AUTH_TYPE =
            AndroidKeystoreSecureArea.USER_AUTHENTICATION_TYPE_BIOMETRIC or AndroidKeystoreSecureArea.USER_AUTHENTICATION_TYPE_LSKF
    }
}
