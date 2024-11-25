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

package eu.europa.ec.eudi.wallet.document.room

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import eu.europa.ec.eudi.wallet.document.DocumentId

@Dao
internal interface MetaDataDataAccess {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun addNewMetaData(newMetaData: DocumentMetaData)

    @Query("SELECT * FROM $TABLE_NAME_DOCUMENT_METADATA")
    suspend fun getAllDocumentMetaData(): List<DocumentMetaData>

    @Query("SELECT * FROM $TABLE_NAME_DOCUMENT_METADATA WHERE uniqueDocumentId = :documentId")
    suspend fun getDocumentMetaData(documentId: DocumentId): DocumentMetaData?

    @Query("DELETE FROM $TABLE_NAME_DOCUMENT_METADATA WHERE uniqueDocumentId = :documentId")
    suspend fun removeDocumentMetaData(documentId: DocumentId): Int

    companion object {
        const val TABLE_NAME_DOCUMENT_METADATA = "documment_metadata"
    }
}