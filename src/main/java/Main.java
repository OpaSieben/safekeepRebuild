import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;


public class Main {

    public static void main(String[] args) {


        String aes = "Kec1leNIw8qTjrvaCgyhgnoho6YtxVc0/hVrHme0CeFQD+WqvG8HvnXHUYoTEgdQlXSG+c4KA9Zi3B3r/bl7eg==";
        String pin = "5818";

        try {
            byte[] code = ByteVector.generateKeyFromPin(pin);
            byte[] key = ByteVector.decrypt(aes, code);


            if (ByteVector.pinIsValid(key)) {
                // check if needed
            }

            byte[] decodeKey = new byte[32];

            System.arraycopy(key, 0, decodeKey, 0, 32);

            System.out.println(new String(ByteVector.decrypt("InUBCT0t5V3u/s5j7ihjHD7/Hy7pYV4sn3QV3yQdqdU=", decodeKey)) + "\n");
            System.out.println(new String(ByteVector.decrypt("7Mag57i4xNJfkiLSpd+i47tFlmfYQAbutUTC3kzIwHw=", decodeKey)) + "\n");
            System.out.println(new String(ByteVector.decrypt("trdIdIb4MSYNH6sYfyr1EkhjCvTLeRHeb8yKPlcXkGTcPY5Is2jIRrjTO8RST06h", decodeKey)) + "\n");

        } catch (Exception ignored) {

        }

    }
}


class ByteVector {

    static byte[] decrypt(String paramString, byte[] key) throws Exception {
        byte[] decode = Base64.decode(paramString);
        byte[] iv = new byte[16];
        byte[] enc = new byte[decode.length - 16];
        System.arraycopy(decode, 0, enc, 0, enc.length);
        System.arraycopy(decode, enc.length, iv, 0, iv.length);
        return init(enc, key, iv);
    }

    private static byte[] init(byte[] bytes, byte[] bytes1, byte[] bytes2) throws Exception {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        cipher.init(false, new ParametersWithIV(new KeyParameter(bytes1), bytes2));
        return read(cipher, bytes);
    }

    static byte[] read(PaddedBufferedBlockCipher cipher, byte[] bArr) throws Exception {
        byte[] bytes1 = new byte[cipher.getOutputSize(bArr.length)];
        int i = cipher.processBytes(bArr, 0, bArr.length, bytes1, 0);
        i += cipher.doFinal(bytes1, i);
        byte[] output = new byte[i];
        System.arraycopy(bytes1, 0, output, 0, i);
        return output;
    }

    static byte[] generateKeyFromPin(String paramString) {
        byte[] iv = "7s1SZS*fX)7J6_5,3ksf|cdTC8W~{r~T<NME[Q2:|q`X*%|L(pid0v:':*O7y=ve".getBytes();
        char[] key = paramString.toCharArray();
        PKCS5S2ParametersGenerator pcks5s2 = new PKCS5S2ParametersGenerator(new SHA256Digest());
        pcks5s2.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(key), iv, 4096);
        return ((KeyParameter) pcks5s2.generateDerivedMacParameters(256)).getKey();
    }

    static boolean pinIsValid(byte[] paramArrayOfByte) {
        return (paramArrayOfByte[32] == 97) && (paramArrayOfByte[33] == -109);
    }

}