import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;

/**
 * Drives the real Java Jasypt library for tests/LiveInteropTest.php.
 *
 * Run with the Jasypt jar on the class path (single-file source launch, JDK 11+):
 *
 *   java -cp jasypt-1.9.3.jar tests/interop/JasyptTool.java
 *
 * It reads four UTF-8 lines from stdin: operation (encrypt or decrypt),
 * algorithm, password, value. It prints the result as UTF-8 with no trailing
 * newline. Input arrives on stdin, not as arguments, because the Windows java
 * launcher converts arguments through the ANSI code page and would damage
 * non-ASCII passwords and values before Jasypt sees them.
 */
public class JasyptTool {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String operation = in.readLine();
        String algorithm = in.readLine();
        String password = in.readLine();
        String value = in.readLine();

        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm(algorithm);
        encryptor.setPassword(password);
        if (algorithm.toUpperCase().contains("AES")) {
            // Jasypt's AES algorithms need a random IV, stored in the payload.
            encryptor.setIvGenerator(new RandomIvGenerator());
        }

        String result = "encrypt".equals(operation) ? encryptor.encrypt(value) : encryptor.decrypt(value);

        PrintStream stdout = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        stdout.print(result);
    }
}
