import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;

class GenerateLocalKey {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Expected private and public paths");
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        var pair = generator.generateKeyPair();
        Files.writeString(Path.of(args[0]), pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        Files.writeString(Path.of(args[1]), pem("PUBLIC KEY", pair.getPublic().getEncoded()));
    }

    private static String pem(String label, byte[] value) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(value)
                + "\n-----END " + label + "-----\n";
    }
}
