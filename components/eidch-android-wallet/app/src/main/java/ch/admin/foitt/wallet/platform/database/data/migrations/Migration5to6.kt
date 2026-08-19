package ch.admin.foitt.wallet.platform.database.data.migrations

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

// DB schema v3.6 to v3.7
internal val Migration5to6 = object : Migration(5, 6) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // 1. add cluster table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `CredentialClaimClusterEntity` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`credentialId` INTEGER NOT NULL, " +
                "`parentClusterId` INTEGER, " +
                "`order` INTEGER NOT NULL, " +
                "FOREIGN KEY(`credentialId`) REFERENCES `Credential`(`id`) ON UPDATE CASCADE ON DELETE CASCADE , " +
                "FOREIGN KEY(`parentClusterId`) REFERENCES `CredentialClaimClusterEntity`(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialClaimClusterEntity_credentialId` " +
                "ON `CredentialClaimClusterEntity` (`credentialId`)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialClaimClusterEntity_parentClusterId` " +
                "ON `CredentialClaimClusterEntity` (`parentClusterId`)"
        )
        // 2. add cluster display table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `CredentialClaimClusterDisplayEntity` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`clusterId` INTEGER NOT NULL, " +
                "`name` TEXT NOT NULL, " +
                "`locale` TEXT NOT NULL, " +
                "FOREIGN KEY(`clusterId`) REFERENCES `CredentialClaimClusterEntity`(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialClaimClusterDisplayEntity_clusterId` " +
                "ON `CredentialClaimClusterDisplayEntity` (`clusterId`)"
        )

        // 3. get credentials and for each insert a cluster
        val cursor = db.query("SELECT * FROM `Credential`")
        while (cursor.moveToNext()) {
            val credentialId = cursor.getLong(cursor.getColumnIndexOrThrow("id"))
            // set id of cluster to same id as credential had, to not mess up the claim foreign key ids
            db.execSQL("INSERT INTO `CredentialClaimClusterEntity` VALUES ($credentialId, $credentialId, NULL, -1)")
        }

        // 4. update claims table (add clusterId column with foreign key constraint to cluster table, remove credentialId column)
        // you can not just add a new column with a foreign key constraint -> recreate the table acc.
        // https://www.sqlite.org/lang_altertable.html#otheralter
        db.execSQL("PRAGMA foreign_keys = OFF")
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `new_CredentialClaim` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`clusterId` INTEGER NOT NULL, " +
                "`key` TEXT NOT NULL, " +
                "`value` TEXT NOT NULL, " +
                "`valueType` TEXT, " +
                "`valueDisplayInfo` TEXT, " +
                "`order` INTEGER NOT NULL, " +
                "FOREIGN KEY(`clusterId`) REFERENCES `CredentialClaimClusterEntity`(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )

        db.execSQL(
            "INSERT INTO `new_CredentialClaim` (`id`, `clusterId`, `key`, `value`, `valueType`, `valueDisplayInfo`, `order`) " +
                "SELECT `id`, `credentialId`, `key`, `value`, `valueType`, `valueDisplayInfo`, `order` FROM `CredentialClaim`"
        )
        db.execSQL("DROP TABLE `CredentialClaim`")
        db.execSQL("ALTER TABLE `new_CredentialClaim` RENAME TO `CredentialClaim`")
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_CredentialClaim_clusterId` ON `CredentialClaim` (`clusterId`)")
        db.execSQL("PRAGMA foreign_key_check")
        db.execSQL("PRAGMA foreign_keys = ON")
    }
}
