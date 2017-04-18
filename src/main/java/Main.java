import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {

    public static void main(String[] args) {

        // AES String aus shared preferences auslesen
        // Kec1leNIw8qTjrvaCgyhgnoho6YtxVc0/hVrHme0CeFQD+WqvG8HvnXHUYoTEgdQlXSG+c4KA9Zi3B3r/bl7eg==
        Object localObject = "Kec1leNIw8qTjrvaCgyhgnoho6YtxVc0/hVrHme0CeFQD+WqvG8HvnXHUYoTEgdQlXSG+c4KA9Zi3B3r/bl7eg==";


        // Parameter preperation
        String code = "1234";
        byte[] paramString = ByteVector.init(code);


        try {
            byte[] newLocalObject = ByteVector.get((String) localObject, paramString);
            String finalString = ByteVector.read(newLocalObject, paramString);
            boolean bool = ByteVector.write(newLocalObject);
            System.out.println(finalString);
        } catch (Exception e) {
            e.printStackTrace();
        }

//        System.out.print(decrypt("Kec1leNIw8qTjrvaCgyhgnoho6YtxVc0/hVrHme0CeFQD+WqvG8HvnXHUYoTEgdQlXSG+c4KA9Zi3B3r/bl7eg=="));


    }

    private static void encrypt() {

    }

    private static String decrypt(String paramString) {
        byte[] arrayOfByte = ByteVector.read();
        byte[] bytes = ByteVector.init(paramString);
        try {
            return ByteVector.read(arrayOfByte, bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}


class ByteVector {

    ByteVector() {
    }

    static String a(String paramString, byte[] paramArrayOfByte) throws Exception {
        return read(paramString.getBytes(), paramArrayOfByte);
    }

    static byte[] get(String paramString, byte[] paramArrayOfByte) throws Exception {
        byte[] decode = HexBin.decode(paramString);
        byte[] arrayOfByte1 = new byte[16];
        byte[] arrayOfByte2 = new byte[decode.length - 16];
        System.arraycopy(decode, 0, arrayOfByte2, 0, arrayOfByte2.length);
        System.arraycopy(decode, arrayOfByte2.length, arrayOfByte1, 0, arrayOfByte1.length);
        return init(arrayOfByte2, paramArrayOfByte, arrayOfByte1);
    }

    private static byte[] get(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3) throws Exception {

        GCMBlockCipher localGCMBlockCipher = new GCMBlockCipher(new OpenPGPCFBBlockCipher(new AESEngine()));
        localGCMBlockCipher.init(true, new ClassWriter(new KeyParameter(paramArrayOfByte2), paramArrayOfByte3));
        return read(localGCMBlockCipher, paramArrayOfByte1);
    }

    private static byte[] init(Integer paramInteger) {

        try {
            SecureRandom localSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            int i = paramInteger;
            byte[] bytes = new byte[i];
            localSecureRandom.nextBytes(bytes);
            return bytes;
        } catch (Exception ignored) {
        }
        return new byte[0];
    }

    static byte[] init(String paramString) {

        byte[] arrayOfByte = "7s1SZS*fX)7J6_5,3ksf|cdTC8W~{r~T<NME[Q2:|q`X*%|L(pid0v:':*O7y=ve".getBytes();
        char[] chars = paramString.toCharArray();
        PKCS5S2ParametersGenerator localPKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator(new SHA256Digest());
        localPKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(chars), arrayOfByte, 4096);
        return ((KeyParameter) localPKCS5S2ParametersGenerator.generateDerivedMacParameters(256)).getKey();
    }

    private static byte[] init(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3) throws Exception {

        GCMBlockCipher localGCMBlockCipher = new GCMBlockCipher(new OpenPGPCFBBlockCipher(new AESEngine()));
        localGCMBlockCipher.init(false, new ClassWriter(new KeyParameter(paramArrayOfByte2), paramArrayOfByte3));
        return read(localGCMBlockCipher, paramArrayOfByte1);
    }

    static String read(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) throws Exception {

        byte[] arrayOfByte = init(16);
        paramArrayOfByte1 = get(paramArrayOfByte1, paramArrayOfByte2, arrayOfByte);
        paramArrayOfByte2 = new byte[arrayOfByte.length + paramArrayOfByte1.length];
        System.arraycopy(paramArrayOfByte1, 0, paramArrayOfByte2, 0, paramArrayOfByte1.length);
        System.arraycopy(arrayOfByte, 0, paramArrayOfByte2, paramArrayOfByte1.length, arrayOfByte.length);
        return new String(HexBin.decode(new String(paramArrayOfByte2)));
    }

    static byte[] read() {

        byte[] arrayOfByte1 = init(32);
        byte[] arrayOfByte2 = new byte[34];
        System.arraycopy(arrayOfByte1, 0, arrayOfByte2, 0, arrayOfByte1.length);
        arrayOfByte2[32] = 97;
        arrayOfByte2[33] = -109;
        return arrayOfByte2;
    }

    private static byte[] read(GCMBlockCipher gcmBlockCipher, byte[] bytes) throws Exception {

        byte[] bytes1 = new byte[bytes.length];
        gcmBlockCipher.doFinal(bytes1, bytes.length);
        int i = gcmBlockCipher.processBytes(bytes, 0, bytes.length, bytes1, 0);
        i += gcmBlockCipher.doFinal(bytes1, i);
        byte[] output = new byte[i];
        System.arraycopy(bytes1, 0, output, 0, i);
        return output;
    }

    static boolean write(byte[] paramArrayOfByte) {
        return (paramArrayOfByte[32] == 97) && (paramArrayOfByte[33] == -109);
    }

}

// HELPER CLASSES
class ClassWriter implements CipherParameters {
    private byte[] a;
    private CipherParameters publicParam;

    ClassWriter(CipherParameters paramCipherParameters, byte[] paramArrayOfByte) {
        this(paramCipherParameters, paramArrayOfByte, 0, paramArrayOfByte.length);
    }

    ClassWriter(CipherParameters paramCipherParameters, byte[] paramArrayOfByte, int paramInt1, int paramInt2) {
        a = new byte[paramInt2];
        publicParam = paramCipherParameters;
        System.arraycopy(paramArrayOfByte, paramInt1, a, 0, paramInt2);
    }

    public CipherParameters getPublic() {
        return publicParam;
    }

    public byte[] toByteArray() {
        return a;
    }
}