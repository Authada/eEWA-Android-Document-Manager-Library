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
package eu.europa.ec.eudi.wallet.document.internal

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.nimbusds.jose.util.JSONArrayUtils
import com.nimbusds.jose.util.JSONObjectUtils
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORType
import eu.europa.ec.eudi.wallet.document.Format
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.json.JSONObject
import java.util.Base64
import kotlin.text.HexFormat

@get:JvmSynthetic
internal val Context.isDeviceSecure: Boolean
    get() = getSystemService(KeyguardManager::class.java).isDeviceSecure

@get:JvmSynthetic
val Context.supportsStrongBox: Boolean
    get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

@JvmSynthetic
fun ByteArray.getEmbeddedCBORObject(): CBORObject {
    return CBORObject.DecodeFromBytes(this).getEmbeddedCBORObject()
}

@JvmSynthetic
internal fun CBORObject.getEmbeddedCBORObject(): CBORObject {
    return if (HasTag(24)) {
        CBORObject.DecodeFromBytes(GetByteString())
    } else {
        this
    }
}

@JvmSynthetic
internal fun ByteArray.withTag24(): ByteArray {
    return CBORObject.FromObjectAndTag(this, 24).EncodeToBytes()
}

@JvmSynthetic
internal fun ByteArray.toObject(format: Format): Any? = when (format) {
    Format.SD_JWT_VC -> decodeJsonObject(this)
    Format.MSO_MDOC -> CBORObject.DecodeFromBytes(this).parse()
    Format.SE_TLV -> throw IllegalStateException("Unsupported format se-tlv for presentation")
}


private fun decodeJsonObject(byteArray: ByteArray): Any {
    val stringData = byteArray.toString(Charsets.UTF_8)
    val objectType = Json.decodeFromString<JsonElement>(stringData)
    return mapObject(objectType, stringData)
}

private fun mapObject(
    objectType: JsonElement,
    stringData: String
): Any {
    return when (objectType) {
        is JsonPrimitive -> {
            objectType.content
        }

        is JsonObject -> {
            JSONObjectUtils.parse(stringData)
        }

        is JsonArray -> {
            objectType.map {
                mapObject(it, Json.encodeToString(it))
            }
        }
    }
}

private fun CBORObject.parse(): Any? {
    if (isNull) return null
    if (isTrue) return true
    if (isFalse) return false

    return when (this.type) {
        CBORType.Boolean, CBORType.SimpleValue -> isTrue
        CBORType.ByteString -> Base64.getEncoder().encodeToString(GetByteString())
        CBORType.TextString -> AsString()
        CBORType.Array -> values.map { it.parse() }.toList()
        CBORType.Map -> keys.associate { it.parse() to this[it].parse() }
        CBORType.Number, CBORType.Integer -> when {
            CanValueFitInInt32() -> ToObject(Int::class.java)
            CanValueFitInInt64() -> ToObject(Long::class.java)
            else -> ToObject(Double::class.java)
        }

        CBORType.FloatingPoint -> ToObject(Float::class.java)
        else -> null
    }
}
