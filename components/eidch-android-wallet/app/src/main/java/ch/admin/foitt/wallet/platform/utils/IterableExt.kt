package ch.admin.foitt.wallet.platform.utils

fun <K, V> Iterable<K>.associateWithNotNull(valueSelector: (K) -> V?): Map<K, V> {
    return this.mapNotNull { element ->
        valueSelector(element)?.let { value ->
            element to value
        }
    }.toMap()
}

fun <K, V, W> Iterable<K>.associateNotNull(
    transform: (K) -> Pair<V, W?>,
): Map<V, W> {
    return this.mapNotNull { element ->
        val (key, value) = transform(element)
        value?.let { key to it }
    }.toMap()
}
