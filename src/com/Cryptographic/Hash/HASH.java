
package com.Cryptographic.Hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author Randyms
 */
public class HASH {
    
    public static String getHashSha256(String password)throws NoSuchAlgorithmException{
        return getHash(password,"SHA-256");
    }
    public static String getHashMD5(String password)throws NoSuchAlgorithmException{
        return getHash(password,"MD5");
    }
    private static String getHash(String password, String algoritm) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance(algoritm);
        digest.update(password.getBytes());
        byte [] hash_byte = digest.digest();
        return DatatypeConverter.printHexBinary(hash_byte).toUpperCase();
    }
    
}
