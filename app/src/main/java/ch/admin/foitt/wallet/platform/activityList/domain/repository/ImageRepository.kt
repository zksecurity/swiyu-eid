package ch.admin.foitt.wallet.platform.activityList.domain.repository

import ch.admin.foitt.wallet.platform.activityList.domain.model.ImageRepositoryError
import ch.admin.foitt.wallet.platform.database.domain.model.ImageEntity
import com.github.michaelbull.result.Result

interface ImageRepository {
    suspend fun insert(imageEntity: ImageEntity): Result<Long, ImageRepositoryError>
    suspend fun getByHash(hash: String): Result<ImageEntity, ImageRepositoryError>
}
