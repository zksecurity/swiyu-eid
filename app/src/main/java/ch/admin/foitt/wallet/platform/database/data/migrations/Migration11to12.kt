package ch.admin.foitt.wallet.platform.database.data.migrations

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

// DB schema v4.1 to v5.0
internal val Migration11to12 = object : Migration(11, 12) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("PRAGMA foreign_keys = OFF")
        // Add a new EIdRequestCase table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `EIdRequestCase_new` (" +
                "`id` TEXT NOT NULL PRIMARY KEY, " +
                "`credentialId` INTEGER DEFAULT NULL, " +
                "`rawMrz` TEXT NOT NULL, " +
                "`documentNumber` TEXT NOT NULL, " +
                "`selectedDocumentType` TEXT NOT NULL DEFAULT 'SWISS_IDK', " +
                "`firstName` TEXT NOT NULL, " +
                "`lastName` TEXT NOT NULL, " +
                "`createdAt` INTEGER NOT NULL, " +
                "FOREIGN KEY(`credentialId`) REFERENCES Credential(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )

        db.execSQL(
            "INSERT INTO EIdRequestCase_new (" +
                "`id`, `rawMrz`, `documentNumber`, `selectedDocumentType`, " +
                "`firstName`, `lastName`, `createdAt`)" +
                "SELECT id, rawMrz, documentNumber, selectedDocumentType, " +
                "firstName, lastName, createdAt " +
                "FROM EIdRequestCase "
        )

        db.execSQL("DROP TABLE `EIdRequestCase`")
        db.execSQL("ALTER TABLE `EIdRequestCase_new` RENAME TO `EIdRequestCase`")

        // Recreate indexes
        db.execSQL("CREATE INDEX `index_EIdRequestCase_credentialId` ON `EIdRequestCase` (`credentialId`)")

        // Add a new DeferredCredentialEntity table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `DeferredCredentialEntity` (" +
                "`credentialId` INTEGER PRIMARY KEY NOT NULL, " +
                "`progressionState` TEXT NOT NULL DEFAULT 'IN_PROGRESS', " +
                "`transactionId` TEXT NOT NULL, " +
                "`accessToken` TEXT NOT NULL, " +
                "`endpoint` TEXT NOT NULL, " +
                "`pollInterval` INTEGER NOT NULL DEFAULT 5, " +
                "`createdAt` INTEGER NOT NULL, " +
                "`polledAt` INTEGER, " +
                "FOREIGN KEY(`credentialId`) REFERENCES Credential(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )

        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_DeferredCredentialEntity_credentialId` ON `DeferredCredentialEntity` (`credentialId`)"
        )

        // Add a new VerifiableCredentialEntity table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `VerifiableCredentialEntity` (" +
                "`credentialId` INTEGER PRIMARY KEY NOT NULL, " +
                "`status` TEXT NOT NULL, " +
                "`payload` TEXT NOT NULL, " +
                "`issuer` TEXT, " +
                "`progressionState` TEXT NOT NULL DEFAULT 'UNACCEPTED', " +
                "`validFrom` INTEGER, " +
                "`validUntil` INTEGER, " +
                "`createdAt` INTEGER NOT NULL, " +
                "`updatedAt` INTEGER, " +
                "FOREIGN KEY(`credentialId`) REFERENCES Credential(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )

        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_VerifiableCredentialEntity_credentialId` ON `VerifiableCredentialEntity` (`credentialId`)"
        )

        // Migrate current Credential table to verifiableCredentialEntity table
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `new_Credential` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`format` TEXT NOT NULL, " +
                "`createdAt` INTEGER NOT NULL " +
                ")"
        )
        db.execSQL(
            "INSERT INTO `new_Credential` " +
                "SELECT `id`, `format`, `createdAt` " +
                "FROM `Credential`"
        )
        db.execSQL(
            "INSERT INTO `VerifiableCredentialEntity` (" +
                "`status`, `payload`, `issuer`, `validFrom`, `validUntil`, `createdAt`, `updatedAt`, `credentialId`, `progressionState` " +
                ")" +
                "SELECT `status`, `payload`, `issuer`, `validFrom`, `validUntil`, `createdAt`, `updatedAt`, `id`," +
                " 'ACCEPTED' AS progressionState " +
                "FROM `Credential`"
        )

        db.execSQL("DROP TABLE `Credential`")
        db.execSQL("ALTER TABLE `new_Credential` RENAME TO `Credential`")

        db.execSQL(
            "CREATE TABLE IF NOT EXISTS `new_CredentialClaimClusterEntity` (" +
                "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                "`verifiableCredentialId` INTEGER NOT NULL, " +
                "`parentClusterId` INTEGER, " +
                "`order` INTEGER NOT NULL, " +
                "FOREIGN KEY(`verifiableCredentialId`) REFERENCES `VerifiableCredentialEntity`(`credentialId`)" +
                "ON UPDATE CASCADE ON DELETE CASCADE , " +
                "FOREIGN KEY(`parentClusterId`) REFERENCES `CredentialClaimClusterEntity`(`id`) ON UPDATE CASCADE ON DELETE CASCADE " +
                ")"
        )

        db.execSQL(
            "INSERT INTO `new_CredentialClaimClusterEntity` (" +
                "`id`, `verifiableCredentialId`, `parentClusterId`, `order` " +
                ")" +
                "SELECT `id`, `credentialId` AS `verifiableCredentialId`, `parentClusterId`, `order` " +
                "FROM `CredentialClaimClusterEntity`"
        )

        db.execSQL("DROP TABLE `CredentialClaimClusterEntity`")
        db.execSQL("ALTER TABLE `new_CredentialClaimClusterEntity` RENAME TO `CredentialClaimClusterEntity`")

        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialClaimClusterEntity_verifiableCredentialId` " +
                "ON `CredentialClaimClusterEntity` (`verifiableCredentialId`)"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS `index_CredentialClaimClusterEntity_parentClusterId` " +
                "ON `CredentialClaimClusterEntity` (`parentClusterId`)"
        )

        db.execSQL("PRAGMA foreign_key_check")
        db.execSQL("PRAGMA foreign_keys = ON")
    }
}
