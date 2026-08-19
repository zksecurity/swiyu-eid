package ch.admin.foitt.wallet.platform.database.data.migrations

import androidx.core.database.getStringOrNull
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType

// DB schema v3.7 to v3.8
internal val Migration6to7 = object : Migration(6, 7) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // Add new CredentialKeyBindingTable
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `CredentialKeyBindingEntity` (" +
                "`id` TEXT NOT NULL, " +
                "`credentialId` INTEGER NOT NULL, " +
                "`algorithm` TEXT NOT NULL, " +
                "`bindingType` TEXT NOT NULL, " +
                "`publicKey` BLOB, " +
                "`privateKey` BLOB, " +
                "PRIMARY KEY(`id`), " +
                "FOREIGN KEY(`credentialId`) REFERENCES `Credential`(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialKeyBindingEntity_credentialId` ON `CredentialKeyBindingEntity` (`credentialId`)"
        )

        // Get credentials and for each (where bindingIdentifier and bindingAlgo are not null) insert a key binding
        val cursor = db.query("SELECT * FROM Credential")
        while (cursor.moveToNext()) {
            val credentialId = cursor.getLong(cursor.getColumnIndexOrThrow("id"))
            val bindingIdentifier = cursor.getStringOrNull(cursor.getColumnIndexOrThrow("keyBindingIdentifier"))
            val bindingAlgo = cursor.getStringOrNull(cursor.getColumnIndexOrThrow("keyBindingAlgorithm"))

            if (bindingIdentifier != null && bindingAlgo != null) {
                db.execSQL(
                    "INSERT INTO `CredentialKeyBindingEntity` (" +
                        "`id`, `credentialId`, `algorithm`, `bindingType`, `publicKey`, `privateKey`" +
                        ") " +
                        "VALUES ('$bindingIdentifier', $credentialId, '$bindingAlgo', '${KeyBindingType.HARDWARE.name}', NULL, NULL)"
                )
            }
        }

        /*
        Dropping a column in SQLite is only supported from version 3.35 onwards. Android versions 11 and below are shipped with a maximum of
        SQLite 3.34. It is possible that there are devices that have our app installed, but not 3.35+, meaning we can not rely on the
        "DROP COLUMN" command and need to do the special migration of re-creating the table without the columns...
        https://www.sqlite.org/lang_altertable.html#otheralter
         */
        db.execSQL("PRAGMA foreign_keys = OFF")
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `new_Credential` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`status` TEXT NOT NULL, " +
                "`payload` TEXT NOT NULL, " +
                "`issuer` TEXT, " +
                "`format` TEXT NOT NULL, " +
                "`validFrom` INTEGER, " +
                "`validUntil` INTEGER, " +
                "`createdAt` INTEGER NOT NULL, " +
                "`updatedAt` INTEGER" +
                ")"
        )
        db.execSQL(
            "INSERT INTO `new_Credential` " +
                "SELECT `id`, `status`, `payload`, `issuer`, `format`, `validFrom`, `validUntil`, `createdAt`, `updatedAt` " +
                "FROM `Credential`"
        )
        db.execSQL("DROP TABLE `Credential`")
        db.execSQL("ALTER TABLE `new_Credential` RENAME TO `Credential`")
        db.execSQL("PRAGMA foreign_key_check")
        db.execSQL("PRAGMA foreign_keys = ON")
    }
}
