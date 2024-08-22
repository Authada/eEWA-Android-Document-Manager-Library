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

import java.time.Instant

/**
 * Data class that represents a document.
 *
 * @property id document's unique identifier
 * @property docType document's docType (example: "eu.europa.ec.eudiw.pid.1")
 * @property name document's name. This is a human readable name.
 * @property hardwareBacked document's storage is hardware backed
 * @property createdAt document's creation date
 * @property requiresUserAuth flag that indicates if the document requires user authentication to be accessed
 * @property nameSpacedData retrieves the document's data, grouped by nameSpace. Values are in CBOR bytes
 * @property nameSpaces retrieves the document's nameSpaces and elementIdentifiers
 *
 * @constructor Creates a document
 * @param id document's unique identifier
 * @param docType document's docType (example: "eu.europa.ec.eudiw.pid.1")
 * @param name document's name. This is a human readable name.
 * @param hardwareBacked document's storage is hardware backed
 * @param createdAt document's creation date
 * @param requiresUserAuth flag that indicates if the document requires user authentication to be accessed
 * @param nameSpacedData retrieves the document's data, grouped by nameSpace. Values are in CBOR bytes
 */
data class Document(
    val id: DocumentId,
    val docType: String,
    val format: Format,
    val name: String,
    val hardwareBacked: Boolean,
    val createdAt: Instant,
    val requiresUserAuth: Boolean,
    val nameSpacedData: Map<NameSpace, Map<ElementIdentifier, ByteArray>>,
) {
    val nameSpaces: Map<NameSpace, List<ElementIdentifier>>
        get() = nameSpacedData.mapValues { it.value.keys.toList() }


    val isProxy: Boolean
        get() = id.startsWith(PROXY_ID_PREFIX)

    companion object {
        const val PROXY_ID_PREFIX = "PROXY_"
        const val SE_ID_PREFIX = "SECURE_ELEMENT_"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Document

        if (id != other.id) return false
        if (docType != other.docType) return false
        if (format != other.format) return false
        if (name != other.name) return false
        if (hardwareBacked != other.hardwareBacked) return false
        if (createdAt != other.createdAt) return false
        if (requiresUserAuth != other.requiresUserAuth) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + docType.hashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + hardwareBacked.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + requiresUserAuth.hashCode()
        return result
    }

}

typealias DocumentId = String
typealias NameSpace = String
typealias ElementIdentifier = String
