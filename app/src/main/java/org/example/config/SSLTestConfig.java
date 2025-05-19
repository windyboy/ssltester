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

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private File outputFile;

    @Option(names = {"--format"}, description = "输出格式: TEXT, JSON, YAML", defaultValue = "TEXT")
    private OutputFormat format = OutputFormat.TEXT;

    @Option(names = {"-v", "--verbose"}, description = "显示详细输出")
    private boolean verbose = false;

    // Getters
    public String getUrl() { return url; }
    public int getConnectionTimeout() { return connectionTimeout; }
    public int getReadTimeout() { return readTimeout; }
    public boolean isFollowRedirects() { return followRedirects; }
    public File getKeystoreFile() { return keystoreFile; }
    public String getKeystorePassword() { return keystorePassword; }
    public File getOutputFile() { return outputFile; }
    public OutputFormat getFormat() { return format; }
    public boolean isVerbose() { return verbose; }

    public enum OutputFormat {
        TEXT, JSON, YAML
    }
} 