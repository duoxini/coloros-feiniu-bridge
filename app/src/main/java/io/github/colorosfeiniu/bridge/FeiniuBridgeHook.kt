package io.github.colorosfeiniu.bridge

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.util.zip.ZipFile

class FeiniuBridgeHook : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PACKAGE) return

        runCatching {
            val tokenDecryptor = XposedHelpers.findClass(TOKEN_DECRYPTOR_CLASS, lpparam.classLoader)
            XposedBridge.hookAllMethods(tokenDecryptor, PREFIX_METHOD, PrefixFallbackHook(lpparam))
            log("installed for ${lpparam.packageName}")
        }.onFailure { error ->
            log("install failed: ${error.javaClass.simpleName}: ${error.message}")
        }
    }

    private class PrefixFallbackHook(
        private val lpparam: XC_LoadPackage.LoadPackageParam,
    ) : XC_MethodHook() {
        override fun afterHookedMethod(param: MethodHookParam) {
            if (param.hasThrowable()) return
            if (!param.result.isNullOrBlankString()) return

            val prefix = PrefixResolver.resolve(lpparam)
            if (prefix.isNullOrBlank()) {
                log("prefix fallback unavailable")
                return
            }

            param.result = prefix
            log("prefix fallback supplied len=${prefix.length}")
        }
    }

    private object PrefixResolver {
        @Volatile
        private var cachedPrefix: String? = null

        fun resolve(lpparam: XC_LoadPackage.LoadPackageParam): String? {
            cachedPrefix?.let { return it }

            val resolved = findFromApkStrings(lpparam)
                ?: KNOWN_PREFIX

            cachedPrefix = resolved
            return resolved
        }

        private fun findFromApkStrings(lpparam: XC_LoadPackage.LoadPackageParam): String? {
            val sourcePaths = buildList {
                add(lpparam.appInfo?.sourceDir)
                lpparam.appInfo?.splitSourceDirs?.let(::addAll)
            }.filterNotNull()

            for (sourcePath in sourcePaths) {
                val prefix = findFromZip(File(sourcePath))
                if (!prefix.isNullOrBlank()) return prefix
            }
            return null
        }

        private fun findFromZip(apk: File): String? {
            if (!apk.isFile) return null
            return runCatching {
                ZipFile(apk).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements()) {
                        val entry = entries.nextElement()
                        if (!entry.name.endsWith(".dex")) continue
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        findFromDexStrings(bytes)?.let { return@use it }
                    }
                    null
                }
            }.getOrNull()
        }

        private fun findFromDexStrings(dex: ByteArray): String? {
            if (dex.size < DEX_HEADER_SIZE || !dex.startsWithDexMagic()) return null

            val stringIdsSize = dex.readUIntLe(DEX_STRING_IDS_SIZE_OFFSET)
            val stringIdsOffset = dex.readUIntLe(DEX_STRING_IDS_OFFSET_OFFSET)
            if (stringIdsSize <= 0 || stringIdsOffset <= 0) return null

            for (index in 0 until stringIdsSize) {
                val stringIdOffset = stringIdsOffset + index * DEX_STRING_ID_SIZE
                if (stringIdOffset + DEX_STRING_ID_SIZE > dex.size) return null

                val stringDataOffset = dex.readUIntLe(stringIdOffset)
                val stringValue = dex.readDexString(stringDataOffset) ?: continue
                if (stringValue.isFeiniuPrefix()) return stringValue
            }

            return null
        }

        private fun ByteArray.startsWithDexMagic(): Boolean {
            return size >= 4 && this[0] == 'd'.code.toByte() && this[1] == 'e'.code.toByte() &&
                this[2] == 'x'.code.toByte() && this[3] == '\n'.code.toByte()
        }

        private fun ByteArray.readUIntLe(offset: Int): Int {
            if (offset < 0 || offset + 4 > size) return -1
            return (this[offset].toInt() and 0xff) or
                ((this[offset + 1].toInt() and 0xff) shl 8) or
                ((this[offset + 2].toInt() and 0xff) shl 16) or
                ((this[offset + 3].toInt() and 0xff) shl 24)
        }

        private fun ByteArray.readDexString(offset: Int): String? {
            if (offset < 0 || offset >= size) return null

            var cursor = offset
            while (cursor < size) {
                val value = this[cursor].toInt() and 0xff
                cursor++
                if ((value and 0x80) == 0) break
            }
            if (cursor >= size) return null

            val start = cursor
            while (cursor < size && this[cursor].toInt() != 0) cursor++
            if (cursor >= size || cursor == start) return null

            return runCatching { String(this, start, cursor - start, Charsets.UTF_8) }.getOrNull()
        }

        private fun String.isFeiniuPrefix(): Boolean {
            return length in 16..80 && PREFIX_REGEX.matches(this)
        }
    }

    companion object {
        private const val TARGET_PACKAGE = "com.coloros.gallery3d"
        private const val TOKEN_DECRYPTOR_CLASS = "com.oplus.aiunit.vision.erq"
        private const val PREFIX_METHOD = "e"
        private const val KNOWN_PREFIX = "tRiM@2025#GwToken!sEcReT*kEy&vALu"
        private const val DEX_HEADER_SIZE = 0x70
        private const val DEX_STRING_IDS_SIZE_OFFSET = 0x38
        private const val DEX_STRING_IDS_OFFSET_OFFSET = 0x3c
        private const val DEX_STRING_ID_SIZE = 4
        private val PREFIX_REGEX = Regex("""[A-Za-z][A-Za-z0-9@#_!*&$%+?.-]{7,79}GwToken[A-Za-z0-9@#_!*&$%+?.-]{4,80}""")

        private fun Any?.isNullOrBlankString(): Boolean {
            return (this as? String).isNullOrBlank()
        }

        private fun log(message: String) {
            XposedBridge.log("ColorOSFeiniuBridge: $message")
        }
    }
}
