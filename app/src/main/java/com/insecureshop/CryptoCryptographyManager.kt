package com.insecureshop

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CryptoCryptographyManager(private val context: Context) {

    private val TAG = "CryptoCryptographyManager"
    
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val KEY_SIZE = 256
        private const val TRANSFORMATION = "$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
        
        private const val HARDCODED_KEY = "InsecureShopSecretKey123!"
        private const val WEAK_KEY = "weak123"
    }

    fun getOrCreateSecretKey(keyName: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        val purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT

        val paramsBuilder = KeyGenParameterSpec.Builder(
            keyName,
            purposes
        ).apply {
            setBlockModes(ENCRYPTION_BLOCK_MODE)
            setEncryptionPaddings(ENCRYPTION_PADDING)
            setKeySize(KEY_SIZE)
            setUserAuthenticationRequired(true)            
        
            // Vulnerabilidade: Não invalidar a chave após mudanças na biometria
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(false)
            }
        }

        val keyGenParams = paramsBuilder.build()
        val keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, ANDROID_KEYSTORE)
        keyGenerator.init(keyGenParams)
        
        Log.d(TAG, "Chave segura gerada: $keyName")
        return keyGenerator.generateKey()
    }

    fun getInsecureSecretKey(): SecretKey {
        Log.w(TAG, "VULNERABILIDADE: Usando chave hardcoded!")
        
        val insecureKey = HARDCODED_KEY.toByteArray()
        
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(128)
        
        Log.e(TAG, "Chave insegura gerada com algoritmo fraco")
        return keyGenerator.generateKey()
    }

    fun encryptWithWeakAlgorithm(data: String): ByteArray {
        Log.w(TAG, "VULNERABILIDADE: Usando algoritmo de criptografia fraco!")
        
        val cipher = Cipher.getInstance("DES")
        val keyGenerator = KeyGenerator.getInstance("DES")
        keyGenerator.init(56)
        
        val weakKey = keyGenerator.generateKey()
        cipher.init(Cipher.ENCRYPT_MODE, weakKey)
        
        return cipher.doFinal(data.toByteArray())
    }

    fun encryptData(data: String, keyName: String): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = getOrCreateSecretKey(keyName)
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        
        val encryptedData = cipher.doFinal(data.toByteArray())
        val iv = cipher.iv
        
        return iv + encryptedData
    }

    fun decryptData(encryptedData: ByteArray, keyName: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = getOrCreateSecretKey(keyName)
        
        val iv = encryptedData.copyOfRange(0, 12)
        val data = encryptedData.copyOfRange(12, encryptedData.size)
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        
        val decryptedData = cipher.doFinal(data)
        return String(decryptedData)
    }

    fun storeSensitiveDataInsecurely(data: String) {
        Log.w(TAG, "VULNERABILIDADE: Armazenando dados sensíveis sem criptografia!")
        
        val sharedPrefs = context.getSharedPreferences("insecure_data", Context.MODE_PRIVATE)
        sharedPrefs.edit().putString("sensitive_data", data).apply()
        
        Log.d(TAG, "Dados sensíveis armazenados: $data")
    }

    fun storeSensitiveDataSecurely(data: String, keyName: String) {
        val encryptedData = encryptData(data, keyName)
        
        val sharedPrefs = context.getSharedPreferences("secure_data", Context.MODE_PRIVATE)
        sharedPrefs.edit().putString("encrypted_data", android.util.Base64.encodeToString(encryptedData, android.util.Base64.DEFAULT)).apply()
        
        Log.d(TAG, "Dados sensíveis armazenados com criptografia")
    }


    fun processDataWithoutIntegrityCheck(data: ByteArray): String {
        Log.w(TAG, "VULNERABILIDADE: Processando dados sem verificação de integridade!")
        
        return String(data)
    }

    fun processDataWithIntegrityCheck(data: ByteArray, expectedHash: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val actualHash = digest.digest(data).joinToString("") { "%02x".format(it) }
        
        if (actualHash == expectedHash) {
            Log.d(TAG, "Integridade dos dados verificada")
            return String(data)
        } else {
            Log.e(TAG, "VULNERABILIDADE: Dados corrompidos detectados!")
            throw SecurityException("Data integrity check failed")
        }
    }

    fun generateWeakKey(): SecretKey {
        Log.w(TAG, "VULNERABILIDADE: Gerando chave com seed previsível!")
        
        val random = java.util.Random(12345)
        val keyBytes = ByteArray(16)
        random.nextBytes(keyBytes)
        
        val keySpec = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
        return keySpec
    }

    fun generateSecureKey(): SecretKey {
        val secureRandom = java.security.SecureRandom()
        val keyBytes = ByteArray(32)
        secureRandom.nextBytes(keyBytes)
        
        val keySpec = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
        Log.d(TAG, "Chave segura gerada com entropia adequada")
        return keySpec
    }

    fun demonstrateCryptoVulnerabilities() {
        Log.d(TAG, "=== DEMONSTRAÇÃO: Vulnerabilidades de Criptografia ===")
        
        getInsecureSecretKey()
        
        encryptWithWeakAlgorithm("dados sensíveis")
        
        storeSensitiveDataInsecurely("senha123")
        
        processDataWithoutIntegrityCheck("dados".toByteArray())
        
        generateWeakKey()
        
        Log.d(TAG, "Demonstração de vulnerabilidades concluída")
    }

  
    fun demonstrateSecureCrypto() {
        Log.d(TAG, "=== DEMONSTRAÇÃO: Criptografia Segura ===")
        
        val keyName = "secure_key"
        val sensitiveData = "dados sensíveis"
        
        try {
            val encryptedData = encryptData(sensitiveData, keyName)
            
            storeSensitiveDataSecurely(sensitiveData, keyName)
            
            val decryptedData = decryptData(encryptedData, keyName)
            
            generateSecureKey()
            
            Log.d(TAG, "Implementação segura concluída com sucesso")
            
        } catch (e: Exception) {
            Log.e(TAG, "Erro na implementação segura: ${e.message}")
        }
    }
}