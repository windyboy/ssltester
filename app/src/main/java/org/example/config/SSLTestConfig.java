package org.example.config;

import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;

public class SSLTestConfig {
    @Parameters(index = "0", description = "要测试的HTTPS URL")
    private String url;

    @Option(names = {"-t", "--timeout"}, description = "连接超时时间(毫秒)")
    private int connectionTimeout = 5000;

    @Option(names = {"-r", "--read-timeout"}, description = "读取超时时间(毫秒)")
    private int readTimeout = 5000;

    @Option(names = {"-f", "--follow-redirects"}, description = "是否跟随重定向")
    private boolean followRedirects = false;

    @Option(names = {"-k", "--keystore"}, description = "信任库文件路径")
    private File keystoreFile;

    @Option(names = {"-p", "--keystore-password"}, description = "信任库密码", interactive = true)
    private String keystorePassword;

    @Option(names = {"--client-cert"}, description = "客户端证书文件路径")
    private File clientCertFile;

    @Option(names = {"--client-key"}, description = "客户端私钥文件路径")
    private File clientKeyFile;

    @Option(names = {"--client-key-password"}, description = "客户端私钥密码", interactive = true)
    private String clientKeyPassword;

    @Option(names = {"--client-cert-format"}, description = "客户端证书格式: PEM, DER", defaultValue = "PEM")
    private CertificateFormat clientCertFormat = CertificateFormat.PEM;

    @Option(names = {"--client-cert"}, description = "客户端证书文件路径")
    private File clientCertFile;

    @Option(names = {"--client-key"}, description = "客户端私钥文件路径")
    private File clientKeyFile;

    @Option(names = {"--client-key-password"}, description = "客户端私钥密码", interactive = true)
    private String clientKeyPassword;

    @Option(names = {"--client-cert-format"}, description = "客户端证书格式: PEM, DER", defaultValue = "PEM")
    private CertificateFormat clientCertFormat = CertificateFormat.PEM;

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private File outputFile;

    @Option(names = {"--format"}, description = "输出格式: TEXT, JSON, YAML", defaultValue = "TEXT")
    private OutputFormat format = OutputFormat.TEXT;

    @Option(names = {"-v", "--verbose"}, description = "显示详细输出")
    private boolean verbose = false;

    @Option(names = {"-c", "--config"}, description = "配置文件路径 (YAML/JSON)")
    private File configFile;

    @Option(names = {"--check-ocsp"}, description = "是否检查OCSP", defaultValue = "true")
    private boolean checkOCSP = true;

    @Option(names = {"--check-crl"}, description = "是否检查CRL", defaultValue = "true")
    private boolean checkCRL = true;

    // Getters
    public String getUrl() { return url; }
    public int getConnectionTimeout() { return connectionTimeout; }
    public int getReadTimeout() { return readTimeout; }
    public boolean isFollowRedirects() { return followRedirects; }
    public File getKeystoreFile() { return keystoreFile; }
    public String getKeystorePassword() { return keystorePassword; }
    public File getClientCertFile() { return clientCertFile; }
    public File getClientKeyFile() { return clientKeyFile; }
    public String getClientKeyPassword() { return clientKeyPassword; }
    public CertificateFormat getClientCertFormat() { return clientCertFormat; }
    public File getClientCertFile() { return clientCertFile; }
    public File getClientKeyFile() { return clientKeyFile; }
    public String getClientKeyPassword() { return clientKeyPassword; }
    public CertificateFormat getClientCertFormat() { return clientCertFormat; }
    public File getOutputFile() { return outputFile; }
    public OutputFormat getFormat() { return format; }
    public boolean isVerbose() { return verbose; }
    public File getConfigFile() { return configFile; }
    public boolean isCheckOCSP() { return checkOCSP; }
    public boolean isCheckCRL() { return checkCRL; }

    // Setters
    public void setUrl(String url) { this.url = url; }
    public void setConnectionTimeout(int connectionTimeout) { this.connectionTimeout = connectionTimeout; }
    public void setReadTimeout(int readTimeout) { this.readTimeout = readTimeout; }
    public void setFollowRedirects(boolean followRedirects) { this.followRedirects = followRedirects; }
    public void setKeystoreFile(File keystoreFile) { this.keystoreFile = keystoreFile; }
    public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
    public void setClientCertFile(File clientCertFile) { this.clientCertFile = clientCertFile; }
    public void setClientKeyFile(File clientKeyFile) { this.clientKeyFile = clientKeyFile; }
    public void setClientKeyPassword(String clientKeyPassword) { this.clientKeyPassword = clientKeyPassword; }
    public void setClientCertFormat(CertificateFormat clientCertFormat) { this.clientCertFormat = clientCertFormat; }
    public void setClientCertFile(File clientCertFile) { this.clientCertFile = clientCertFile; }
    public void setClientKeyFile(File clientKeyFile) { this.clientKeyFile = clientKeyFile; }
    public void setClientKeyPassword(String clientKeyPassword) { this.clientKeyPassword = clientKeyPassword; }
    public void setClientCertFormat(CertificateFormat clientCertFormat) { this.clientCertFormat = clientCertFormat; }
    public void setOutputFile(File outputFile) { this.outputFile = outputFile; }
    public void setFormat(OutputFormat format) { this.format = format; }
    public void setVerbose(boolean verbose) { this.verbose = verbose; }
    public void setConfigFile(File configFile) { this.configFile = configFile; }
    public void setCheckOCSP(boolean checkOCSP) { this.checkOCSP = checkOCSP; }
    public void setCheckCRL(boolean checkCRL) { this.checkCRL = checkCRL; }

    public enum OutputFormat {
        TEXT, JSON, YAML
    }

    public enum CertificateFormat {
        PEM, DER
    }
} 