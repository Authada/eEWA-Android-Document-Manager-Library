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

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters

@Database(entities = [DocumentMetaData::class], version = 1, exportSchema = false)
@TypeConverters(ImageTypeConverter::class)
internal abstract class WalletDatabase : RoomDatabase() {

    abstract fun getDatabase(): MetaDataDataAccess

    companion object {
        private const val DATABASE_NAME = "wallet-database"


        fun getDefault(context: Context): MetaDataDataAccess {
            return Room.databaseBuilder(
                context.applicationContext,
                WalletDatabase::class.java,
                DATABASE_NAME
            ).build().getDatabase()
        }
    }
}