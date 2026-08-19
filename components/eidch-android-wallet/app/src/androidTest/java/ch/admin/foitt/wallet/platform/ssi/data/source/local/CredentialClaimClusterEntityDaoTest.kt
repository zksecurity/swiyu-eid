package ch.admin.foitt.wallet.platform.ssi.data.source.local

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import ch.admin.foitt.wallet.platform.database.data.AppDatabase
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialClaimClusterEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialDao
import ch.admin.foitt.wallet.platform.database.data.dao.VerifiableCredentialDao
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.cluster1
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.clusterWithParent
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.credential1
import ch.admin.foitt.wallet.platform.ssi.data.source.local.mock.CredentialTestData.verifiableCredential1
import junit.framework.TestCase.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

class CredentialClaimClusterEntityDaoTest {

    private lateinit var database: AppDatabase
    private lateinit var credentialDao: CredentialDao
    private lateinit var verifiableCredentialDao: VerifiableCredentialDao
    private lateinit var credentialClaimClusterEntityDao: CredentialClaimClusterEntityDao

    @Before
    fun setupDatabase() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(), AppDatabase::class.java
        ).allowMainThreadQueries().build()

        credentialDao = database.credentialDao()
        verifiableCredentialDao = database.verifiableCredentialDao()
        credentialClaimClusterEntityDao = database.credentialClaimClusterEntityDao()

        credentialDao.insert(credential1)
        verifiableCredentialDao.insert(verifiableCredential1)
    }

    @After
    fun closeDatabase() {
        database.close()
    }

    @Test
    fun insertClusterTest() = runTest {
        val clusterId = credentialClaimClusterEntityDao.insert(cluster1)

        val cluster = credentialClaimClusterEntityDao.getById(clusterId)
        assertEquals(cluster1.copy(id = clusterId), cluster)

        val clusterWithParentId = credentialClaimClusterEntityDao.insert(clusterWithParent)

        val clusterWithParent = credentialClaimClusterEntityDao.getById(clusterWithParentId)
        assertEquals(CredentialTestData.clusterWithParent.copy(id = clusterWithParentId), clusterWithParent)
    }

    @Test
    fun deleteCredentialTest() = runTest {
        credentialDao.insert(credential1)
        verifiableCredentialDao.insert(verifiableCredential1)

        val clusterId = credentialClaimClusterEntityDao.insert(cluster1)

        credentialDao.deleteById(credential1.id)

        assertNull(credentialClaimClusterEntityDao.getById(clusterId))
    }
}
