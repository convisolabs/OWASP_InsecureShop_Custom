# Cryptography Vulnerabilities - CryptoCryptographyManager

## Visão Geral

A `CryptoCryptographyManager` foi criada para fins didáticos, demonstrando vulnerabilidades relacionadas à criptografia e gerenciamento de chaves em aplicações Android. Esta classe é baseada na implementação do Android Keystore e serve como uma ferramenta educacional para entender os riscos de segurança em criptografia.

## Vulnerabilidades Demonstradas

### 1. Chaves Hardcoded (`HARDCODED_KEY`)

**Descrição:** Chaves criptográficas embutidas no código-fonte.

**Código Vulnerável:**
```kotlin
// VULNERABILIDADE: Chave hardcoded
private const val HARDCODED_KEY = "InsecureShopSecretKey123!"

fun getInsecureSecretKey(): SecretKey {
    Log.w(TAG, "VULNERABILIDADE: Usando chave hardcoded!")
    
    // VULNERABILIDADE: Chave hardcoded no código
    val insecureKey = HARDCODED_KEY.toByteArray()
    
    // VULNERABILIDADE: Algoritmo fraco
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(128) // Tamanho pequeno
    
    return keyGenerator.generateKey()
}
```

**Impacto:**
- Chaves expostas no código-fonte
- Facilita ataques de engenharia reversa
- Comprometimento de dados criptografados

### 2. Algoritmos de Criptografia Fracos (`WEAK_ALGORITHM`)

**Descrição:** Uso de algoritmos obsoletos e inseguros.

**Código Vulnerável:**
```kotlin
fun encryptWithWeakAlgorithm(data: String): ByteArray {
    Log.w(TAG, "VULNERABILIDADE: Usando algoritmo de criptografia fraco!")
    
    // VULNERABILIDADE: Algoritmo DES (obsoleto e inseguro)
    val cipher = Cipher.getInstance("DES")
    val keyGenerator = KeyGenerator.getInstance("DES")
    keyGenerator.init(56) // Tamanho muito pequeno
    
    val weakKey = keyGenerator.generateKey()
    cipher.init(Cipher.ENCRYPT_MODE, weakKey)
    
    return cipher.doFinal(data.toByteArray())
}
```

**Impacto:**
- Criptografia facilmente quebrável
- Vulnerável a ataques de força bruta
- Não oferece proteção adequada

### 3. Armazenamento Inseguro de Dados Sensíveis (`INSECURE_STORAGE`)

**Descrição:** Armazenamento de dados sensíveis sem criptografia.

**Código Vulnerável:**
```kotlin
fun storeSensitiveDataInsecurely(data: String) {
    Log.w(TAG, "VULNERABILIDADE: Armazenando dados sensíveis sem criptografia!")
    
    // VULNERABILIDADE: Armazenamento em texto plano
    val sharedPrefs = context.getSharedPreferences("insecure_data", Context.MODE_PRIVATE)
    sharedPrefs.edit().putString("sensitive_data", data).apply()
    
    // VULNERABILIDADE: Log de dados sensíveis
    Log.d(TAG, "Dados sensíveis armazenados: $data")
}
```

**Impacto:**
- Dados sensíveis expostos em armazenamento
- Vazamento por backup/ADB/root
- Logs expõem informações sensíveis

### 4. Falta de Validação de Integridade (`NO_INTEGRITY_CHECK`)

**Descrição:** Processamento de dados sem verificação de integridade.

**Código Vulnerável:**
```kotlin
fun processDataWithoutIntegrityCheck(data: ByteArray): String {
    Log.w(TAG, "VULNERABILIDADE: Processando dados sem verificação de integridade!")
    
    // VULNERABILIDADE: Não verifica integridade dos dados
    return String(data)
}
```

**Impacto:**
- Vulnerável a ataques de manipulação de dados
- Não detecta corrupção de dados
- Possível execução de código malicioso

### 5. Seed Previsível (`PREDICTABLE_SEED`)

**Descrição:** Geração de chaves com seed previsível.

**Código Vulnerável:**
```kotlin
fun generateWeakKey(): SecretKey {
    Log.w(TAG, "VULNERABILIDADE: Gerando chave com seed previsível!")
    
    // VULNERABILIDADE: Seed previsível
    val random = java.util.Random(12345) // Seed fixo
    val keyBytes = ByteArray(16)
    random.nextBytes(keyBytes)
    
    val keySpec = javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
    return keySpec
}
```

**Impacto:**
- Chaves previsíveis e repetíveis
- Vulnerável a ataques de predição
- Falta de entropia adequada

## Implementação Segura Demonstrada

### Android Keystore Seguro

**Código Seguro:**
```kotlin
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
        
        // Configuração segura para Android N+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            setInvalidatedByBiometricEnrollment(false)
        }
    }

    val keyGenParams = paramsBuilder.build()
    val keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, ANDROID_KEYSTORE)
    keyGenerator.init(keyGenParams)
    
    return keyGenerator.generateKey()
}
```

**Características Seguras:**
- Usa Android Keystore para armazenamento seguro
- Requer autenticação do usuário
- Configuração adequada de parâmetros
- Tamanho de chave adequado (256 bits)

### Criptografia AES-GCM Segura

**Código Seguro:**
```kotlin
fun encryptData(data: String, keyName: String): ByteArray {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    val secretKey = getOrCreateSecretKey(keyName)
    
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val encryptedData = cipher.doFinal(data.toByteArray())
    val iv = cipher.iv
    
    // Combina IV + dados criptografados
    return iv + encryptedData
}
```

**Características Seguras:**
- Usa AES-GCM (algoritmo forte)
- IV único para cada operação
- Autenticação de dados integrada

### Validação de Integridade

**Código Seguro:**
```kotlin
fun processDataWithIntegrityCheck(data: ByteArray, expectedHash: String): String {
    // Calcula hash dos dados
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    val actualHash = digest.digest(data).joinToString("") { "%02x".format(it) }
    
    // VALIDAÇÃO SEGURA: Verifica integridade
    if (actualHash == expectedHash) {
        Log.d(TAG, "Integridade dos dados verificada")
        return String(data)
    } else {
        Log.e(TAG, "VULNERABILIDADE: Dados corrompidos detectados!")
        throw SecurityException("Data integrity check failed")
    }
}
```

**Características Seguras:**
- Verificação de hash SHA-256
- Detecção de manipulação de dados
- Falha segura em caso de corrupção

## Como Usar a Demonstração

1. **Compile e instale o app**
2. **Crie uma instância da classe:**
   ```kotlin
   val cryptoManager = CryptoCryptographyManager(context)
   ```
3. **Teste as vulnerabilidades:**
   ```kotlin
   cryptoManager.demonstrateCryptoVulnerabilities()
   ```
4. **Teste a implementação segura:**
   ```kotlin
   cryptoManager.demonstrateSecureCrypto()
   ```
5. **Monitore os logs:**
   ```bash
   adb logcat -s CryptoCryptographyManager
   ```

## Cenários de Teste

### 1. Vulnerabilidades de Criptografia
- Demonstra chaves hardcoded
- Mostra algoritmos fracos (DES)
- Simula armazenamento inseguro
- Demonstra falta de validação de integridade

### 2. Implementação Segura
- Usa Android Keystore
- Implementa AES-GCM
- Valida integridade de dados
- Gera chaves com entropia adequada

## Recomendações de Segurança

### 1. Usar Android Keystore
```kotlin
// Sempre use Android Keystore para armazenamento seguro
val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)
```

### 2. Algoritmos Fortes
```kotlin
// Use algoritmos fortes como AES-GCM
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
```

### 3. Validação de Integridade
```kotlin
// Sempre valide integridade de dados
val digest = MessageDigest.getInstance("SHA-256")
val hash = digest.digest(data)
```

### 4. Entropia Adequada
```kotlin
// Use SecureRandom para geração de chaves
val secureRandom = SecureRandom()
val keyBytes = ByteArray(32)
secureRandom.nextBytes(keyBytes)
```

### 5. Armazenamento Criptografado
```kotlin
// Criptografe dados sensíveis antes do armazenamento
val encryptedData = encryptData(sensitiveData, keyName)
sharedPrefs.edit().putString("encrypted_data", Base64.encodeToString(encryptedData, Base64.DEFAULT)).apply()
```

## Ferramentas de Análise

### 1. APKTool
- Decompila APK para análise de código
- Identifica chaves hardcoded

### 2. JADX
- Decompilador Java/DEX
- Análise estática de código

### 3. MobSF
- Análise estática de aplicações móveis
- Identifica vulnerabilidades de criptografia

### 4. Frida
- Hooking dinâmico
- Intercepta operações criptográficas

## Referências

- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [Cryptography Best Practices](https://developer.android.com/guide/topics/security/cryptography)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)

## Conclusão

A `CryptoCryptographyManager` serve como uma ferramenta educacional valiosa para entender os riscos associados à criptografia inadequada em aplicações Android. Através das demonstrações práticas, desenvolvedores e testadores podem aprender a identificar e corrigir vulnerabilidades relacionadas ao gerenciamento de chaves e criptografia.

**Lembre-se:** Esta classe é intencionalmente vulnerável para fins educacionais. Nunca implemente estas vulnerabilidades em aplicações de produção.

## Vulnerabilidades Identificadas

1. **Chaves Hardcoded** - Chaves criptográficas embutidas no código
2. **Algoritmos Fracos** - Uso de DES e outros algoritmos obsoletos
3. **Armazenamento Inseguro** - Dados sensíveis sem criptografia
4. **Falta de Validação** - Ausência de verificação de integridade
5. **Seed Previsível** - Geração de chaves com entropia inadequada

## Implementações Seguras Demonstradas

1. **Android Keystore** - Armazenamento seguro de chaves
2. **AES-GCM** - Algoritmo de criptografia forte
3. **Validação de Integridade** - Verificação de hash SHA-256
4. **SecureRandom** - Geração de chaves com entropia adequada
5. **Armazenamento Criptografado** - Dados sensíveis protegidos


