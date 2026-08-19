package ch.admin.foitt.wallet.platform.ssi.data.source.local

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import ch.admin.foitt.wallet.platform.database.data.AppDatabase
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialClaimClusterDisplayEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialClaimClusterEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialDao
import ch.admin.foitt.wallet.platform.database.data.dao.VerifiableCredentialDao
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.cluster1
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.clusterDisplay1
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.credential1
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.verifiableCredential1
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class CredentialClaimClusterDisplayEntityDaoTest {

    private lateinit var database: AppDatabase
    private lateinit var credentialDao: CredentialDao
    private lateinit var verifiableCredentialDao: VerifiableCredentialDao
    private lateinit var credentialClaimClusterEntityDao: CredentialClaimClusterEntityDao
    private lateinit var credentialClaimClusterDisplayEntityDao: CredentialClaimClusterDisplayEntityDao

    @Before
    fun setupDatabase() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(), AppDatabase::class.java
        ).allowMainThreadQueries().build()

        credentialDao = database.credentialDao()
        verifiableCredentialDao = database.verifiableCredentialDao()
        credentialClaimClusterEntityDao = database.credentialClaimClusterEntityDao()
        credentialClaimClusterDisplayEntityDao = database.credentialClaimClusterDisplayEntityDao()

        credentialDao.insert(credential1)
        verifiableCredentialDao.insert(verifiableCredential1)
        credentialClaimClusterEntityDao.insert(cluster1)
    }

    @After
    fun closeDatabase() {
        database.close()
    }

    @Test
    fun insertClusterDisplayTest() = runTest {
        val clusterDisplayId = credentialClaimClusterDisplayEntityDao.insert(clusterDisplay1)

        val clusterDisplay = credentialClaimClusterDisplayEntityDao.getById(clusterDisplayId)
        assertEquals(clusterDisplay1.copy(id = clusterDisplayId), clusterDisplay)
    }

    @Test
    fun deleteCredentialTest() = runTest {
        credentialDao.insert(credential1)
        verifiableCredentialDao.insert(verifiableCredential1)
        credentialClaimClusterEntityDao.insert(cluster1)
        val clusterDisplayId = credentialClaimClusterDisplayEntityDao.insert(clusterDisplay1)

        credentialDao.deleteById(credential1.id)

        assertNull(credentialClaimClusterDisplayEntityDao.getById(clusterDisplayId))
    }
}
