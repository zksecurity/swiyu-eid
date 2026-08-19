package ch.admin.foitt.wallet.platform.activityList

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import ch.admin.foitt.wallet.platform.activityList.mock.ActivityListMocks.activityActorDisplay1
import ch.admin.foitt.wallet.platform.activityList.mock.ActivityListMocks.credential1
import ch.admin.foitt.wallet.platform.activityList.mock.ActivityListMocks.credentialActivity1
import ch.admin.foitt.wallet.platform.activityList.mock.ActivityListMocks.image1
import ch.admin.foitt.wallet.platform.database.data.AppDatabase
import ch.admin.foitt.wallet.platform.database.data.dao.ActivityActorDisplayEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialActivityEntityDao
import ch.admin.foitt.wallet.platform.database.data.dao.CredentialDao
import ch.admin.foitt.wallet.platform.database.data.dao.ImageEntityDao
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.jupiter.api.Assertions.assertEquals

class ActivityActorDisplayEntityDaoTest {

    private lateinit var database: AppDatabase
    private lateinit var credentialDao: CredentialDao
    private lateinit var credentialActivityEntityDao: CredentialActivityEntityDao
    private lateinit var activityActorDisplayEntityDao: ActivityActorDisplayEntityDao
    private lateinit var imageEntityDao: ImageEntityDao

    @Before
    fun setupDatabase() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(), AppDatabase::class.java
        ).allowMainThreadQueries().build()

        credentialDao = database.credentialDao()
        credentialActivityEntityDao = database.credentialActivityEntityDao()
        activityActorDisplayEntityDao = database.activityActorDisplayEntityDao()
        imageEntityDao = database.imageEntityDao()

        credentialDao.insert(credential1)
        credentialActivityEntityDao.insert(credentialActivity1)
        imageEntityDao.insert(image1)
    }

    @After
    fun closeDatabase() {
        database.close()
    }

    @Test
    fun insertCredentialActivityTest() = runTest {
        val id = activityActorDisplayEntityDao.insert(activityActorDisplay1)

        val actorDisplay = activityActorDisplayEntityDao.getById(id)
        assertEquals(activityActorDisplay1, actorDisplay)
    }
}
