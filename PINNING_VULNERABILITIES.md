# SSL Pinning Vulnerabilities - PinningActivity

## Visão Geral

A `PinningActivity` foi criada para fins didáticos, demonstrando vulnerabilidades relacionadas à ausência de SSL pinning e implementações inseguras. Esta Activity é baseada no repositório [AndroidAppVul](https://github.com/zani0x03/AndroidAppVul) e serve como uma ferramenta educacional para entender os riscos de segurança em aplicações Android.

## Vulnerabilidades Demonstradas

### 1. Ausência de SSL Pinning (`NO_SSL_PINNING`)

**Descrição:** A aplicação não implementa SSL pinning, aceitando qualquer certificado válido.

**Código Vulnerável:**
```kotlin
private fun demonstrateNoPinning() {
    val url = URL(SECURE_URL)
    val connection = url.openConnection() as HttpsURLConnection
    
    // VULNERABILIDADE: Não há validação de certificado
    connection.connect()
    
    val certificate = connection.serverCertificates[0] as X509Certificate
    Log.d(TAG, "Certificado aceito sem validação: ${certificate.subjectDN}")
}
```

**Impacto:**
- Vulnerável a ataques MITM com certificados válidos de CAs comprometidas
- Não verifica se o certificado é o esperado
- Aceita certificados de qualquer CA confiável

### 2. Implementação Insegura de SSL Pinning (`INSECURE_SSL_PINNING`)

**Descrição:** Implementação de pinning que ignora erros de SSL e aceita certificados auto-assinados.

**Código Vulnerável:**
```kotlin
private fun demonstrateInsecurePinning() {
    // VULNERABILIDADE: TrustManager que aceita tudo
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })
    
    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    
    // VULNERABILIDADE: Ignora erros de hostname
    connection.hostnameVerifier = { _, _ -> true }
}
```

**Impacto:**
- Ignora erros de SSL
- Aceita certificados auto-assinados
- Não valida o fingerprint do certificado

### 3. Ignorar Erros de SSL (`SSL_ERROR_IGNORE`)

**Descrição:** WebView que sempre aceita conexões SSL, mesmo com erros.

**Código Vulnerável:**
```kotlin
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        // VULNERABILIDADE: Sempre aceita, mesmo com erros de SSL
        Log.w(TAG, "Ignorando erro SSL: ${error?.toString()}")
        handler?.proceed() // PERIGOSO!
    }
}
```

**Impacto:**
- MITM transparente
- Tráfego sensível exposto
- Aceita certificados inválidos

### 4. Cleartext Traffic (`CLEARTEXT_TRAFFIC`)

**Descrição:** Uso de HTTP sem criptografia.

**Evidência no AndroidManifest.xml:**
```xml
android:usesCleartextTraffic="true"
```

**Impacto:**
- Tráfego HTTP sem criptografia sujeito a MITM
- Dados sensíveis transmitidos em texto plano

## Implementação Segura Demonstrada

### SSL Pinning Correto

**Código Seguro:**
```kotlin
private fun demonstrateSecurePinning() {
    val url = URL(SECURE_URL)
    val connection = url.openConnection() as HttpsURLConnection
    connection.connect()
    
    val certificate = connection.serverCertificates[0] as X509Certificate
    val actualFingerprint = getCertificateFingerprint(certificate)
    
    // VALIDAÇÃO SEGURA: Verifica se o fingerprint é o esperado
    if (isValidCertificate(actualFingerprint)) {
        Log.d(TAG, "Certificado válido - Pinning bem-sucedido")
        processSecureResponse(connection)
    } else {
        Log.e(TAG, "Certificado inválido - Possível ataque MITM!")
        throw SecurityException("Certificate pinning failed")
    }
}
```

**Características Seguras:**
- Valida fingerprint do certificado
- Rejeita certificados não esperados
- Implementa fallback para múltiplos certificados
- Usa SHA-256 para fingerprints

### WebView Seguro

**Código Seguro:**
```kotlin
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        Log.e(TAG, "Erro SSL detectado: ${error?.toString()}")
        handler?.cancel() // Rejeita conexões inseguras
    }
}
```

## Como Usar a Demonstração

1. **Compile e instale o app**
2. **Acesse a PinningActivity** via intent ou menu
3. **Teste os diferentes cenários** usando os botões
4. **Monitore os logs** usando:
   ```bash
   adb logcat -s PinningActivity
   ```

## Cenários de Teste

### 1. Sem SSL Pinning
- Demonstra como a aplicação aceita qualquer certificado válido
- Mostra a vulnerabilidade a ataques MITM

### 2. SSL Pinning Inseguro
- Mostra implementação que ignora erros de SSL
- Demonstra aceitação de certificados auto-assinados

### 3. SSL Pinning Seguro
- Implementação correta com validação de fingerprint
- Demonstra como rejeitar certificados inválidos

### 4. Simulação Ataque MITM
- Simula como um atacante poderia interceptar a comunicação
- Mostra o impacto da falta de pinning

### 5. WebView Inseguro
- WebView que ignora erros de SSL
- Demonstra vulnerabilidades em WebViews

### 6. WebView Seguro
- WebView que rejeita conexões inseguras
- Implementação segura de validação SSL

## Recomendações de Segurança

### 1. Implementar SSL Pinning
```kotlin
// Exemplo de implementação segura
private fun isValidCertificate(actualFingerprint: String): Boolean {
    val validFingerprints = listOf(
        "A1:B2:C3:D4:E5:F6:...", // Certificado principal
        "B2:C3:D4:E5:F6:G7:..."  // Certificado de backup
    )
    return actualFingerprint in validFingerprints
}
```

### 2. Usar Network Security Config
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">insecureshopapp.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">A1:B2:C3:D4:E5:F6:...</pin>
            <pin digest="SHA-256">B2:C3:D4:E5:F6:G7:...</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### 3. Desabilitar Cleartext Traffic
```xml
<!-- AndroidManifest.xml -->
android:usesCleartextTraffic="false"
```

### 4. Validar Certificados em WebViews
```kotlin
webView.webViewClient = object : WebViewClient() {
    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        handler?.cancel() // Rejeita conexões inseguras
    }
}
```

## Ferramentas de Análise

### 1. SSL Labs SSL Test
- Testa configurações SSL/TLS
- Identifica vulnerabilidades de certificados

### 2. Burp Suite
- Proxy para interceptar tráfego HTTPS
- Testa bypass de SSL pinning

### 3. Frida
- Framework para hooking dinâmico
- Pode ser usado para bypass de pinning

### 4. Objection
- Framework de pentest mobile
- Testa vulnerabilidades de SSL

## Referências

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Network Security Config](https://developer.android.com/training/articles/security-config)
- [SSL Pinning Best Practices](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [AndroidAppVul Repository](https://github.com/zani0x03/AndroidAppVul)

## Conclusão

A `PinningActivity` serve como uma ferramenta educacional valiosa para entender os riscos associados à ausência de SSL pinning em aplicações Android. Através das demonstrações práticas, desenvolvedores e testadores podem aprender a identificar e corrigir vulnerabilidades relacionadas à validação de certificados SSL/TLS.

**Lembre-se:** Esta Activity é intencionalmente vulnerável para fins educacionais. Nunca implemente estas vulnerabilidades em aplicações de produção.



