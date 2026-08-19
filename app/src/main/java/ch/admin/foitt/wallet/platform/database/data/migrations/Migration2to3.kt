package ch.admin.foitt.wallet.platform.database.data.migrations

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import ch.admin.foitt.wallet.platform.eIdApplicationProcess.domain.model.LegalRepresentativeConsent

// DB schema v3.3 to v3.4
internal val Migration2to3 = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL(
            "ALTER TABLE EIdRequestState " +
                "ADD COLUMN legalRepresentativeConsent TEXT NOT NULL " +
                "DEFAULT '${LegalRepresentativeConsent.NOT_REQUIRED.name}'"
        )
    }
}
