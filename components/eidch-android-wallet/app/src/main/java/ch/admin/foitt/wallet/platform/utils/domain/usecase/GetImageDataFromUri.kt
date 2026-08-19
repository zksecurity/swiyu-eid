package ch.admin.foitt.wallet.platform.utils.domain.usecase

fun interface GetImageDataFromUri {
    suspend operator fun invoke(uriString: String?): ByteArray?
}
