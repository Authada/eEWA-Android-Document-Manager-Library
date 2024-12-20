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
@file:JvmName("Constants")

package eu.europa.ec.eudi.wallet.document.internal

import android.content.Context
import eu.europa.ec.eudi.wallet.document.R

// EU PID
@get:JvmSynthetic
internal const val EU_PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"

// German SD-JWT PID
@get:JvmSynthetic
internal const val GERMAN_SDJWT_PID_DOCTYPE = "https://metadata-8c062a.usercontent.opencode.de/pid.json"

@get:JvmSynthetic
internal const val EU_PID_NAMESPACE = "eu.europa.ec.eudi.pid.1"


// mDL
@get:JvmSynthetic
internal const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"

@get:JvmSynthetic
internal const val MDL_NAMESPACE = "org.iso.18013.5.1"

@JvmSynthetic
internal fun Context.docTypeName(docType: String): String? =
    when (docType) {
        EU_PID_DOCTYPE -> resources.getString(R.string.eu_pid_doctype_name)
        MDL_DOCTYPE -> resources.getString(R.string.mdl_doctype_name)
        else -> null
    }
