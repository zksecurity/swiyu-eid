package ch.admin.foitt.wallet.platform.ssi.data.source.local

import android.database.sqlite.SQLiteConstraintException
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import ch.admin.foitt.wallet.platform.database.data.AppDatabase
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialDao
import ch.admin.foitt.wallet.platform.database.data.dao.RawCredentialDataDao
import ch.admin.foitt.wallet.platform.database.domain.model.RawCredentialData
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.credential1
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class RawCredentialDataDaoTest {

    private lateinit var database: AppDatabase
    private lateinit var credentialDao: CredentialDao
    private lateinit var rawCredentialDataDao: RawCredentialDataDao

    @Before
    fun setupDatabase() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(), AppDatabase::class.java
        ).allowMainThreadQueries().build()

        credentialDao = database.credentialDao()
        credentialDao.insert(credential1)
        rawCredentialDataDao = database.rawCredentialDataDao()
    }

    @After
    fun closeDatabase() {
        database.close()
    }

    @Test
    fun insertRawCredentialDataTest() = runTest {
        assertEquals(
            emptyList<RawCredentialData>(),
            rawCredentialDataDao.getRawCredentialDataByCredentialId(credentialId = credential1.id)
        )

        val rawCredentialData = RawCredentialData(
            credentialId = credential1.id,
            rawOcaBundle = "rawOcaBundle".toByteArray(),
            rawOIDMetadata = "rawOIDMetadata".toByteArray()
        )

        val id = rawCredentialDataDao.insert(rawCredentialData)
        assertEquals(
            listOf(rawCredentialData.copy(id = id)),
            rawCredentialDataDao.getRawCredentialDataByCredentialId(credentialId = credential1.id)
        )

        val updatedId = rawCredentialDataDao.insert(rawCredentialData)
        assertEquals(
            listOf(rawCredentialData.copy(id = updatedId)),
            rawCredentialDataDao.getRawCredentialDataByCredentialId(credentialId = credential1.id)
        )
    }

    @Test(expected = SQLiteConstraintException::class)
    fun insertWithoutMatchingForeignKeyShouldThrow() {
        val rawCredentialData = RawCredentialData(
            credentialId = -1,
            rawOcaBundle = "rawOcaBundle".toByteArray(),
            rawOIDMetadata = "rawOIDMetadata".toByteArray()
        )
        rawCredentialDataDao.insert(rawCredentialData)
    }
}
