/*
 *Esta clase es desarrollada por Randy Montoya como ejemplo
 *de clase de cifrado Aes para un trabajo experiemental 
 *Su uso es libre mientras se reconozcan los creditos
 */
package com.Cryptographic.Aes;

import com.Cryptographic.Hash.HASH;
import com.Management_files.File_Manager;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Randyms
 */
public class Aes extends HASH {

    //Tamano del Iv Buffer por defecto
    private static int iv_size = 16;

    //Metodo de acceso para cifrar y descifrar mensajes con Aes
    public static byte[] cifrarMensaje(String message, String password_user) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String pass = getHashSha256(password_user);
        SecretKey key = getKey(pass);
        IvParameterSpec iv = getIvParameter();
        return encryptAesMessage(message, key, iv);
    }

    public static String descifrarMensaje(byte[] aes_byte, String password_user) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        String pass = getHashSha256(password_user);
        SecretKey key = getKey(pass);
        return decryptAesMessage(aes_byte, key);
    }

    //Metodo de invocacion para el cifrado de archivos
    public static void cifrarFile(String password_user, File source_file) throws IOException {
        try {
            SecretKey key = getKey(HASH.getHashSha256(password_user));
            IvParameterSpec iv = getIvParameter();
            encryptAesFile(source_file,key, iv);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Aes.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void descifrarFile(String password_user, File target_file) {
        try {
            SecretKey key = getKey(HASH.getHashSha256(password_user));
            decryptAesFile(target_file,key);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Aes.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void encryptAesFile(File source_file, SecretKey key, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getEncoded(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            FileInputStream in = new FileInputStream(source_file);
            byte[] entrada = new byte[(int) source_file.length()];
            in.read(entrada);

            byte[] file_encrypt = cipher.doFinal(entrada);
            byte[] tipe_file = File_Manager.getTypeFile(source_file.getName()).getBytes();
            String path = File_Manager.getFileNameWithCryptExtension(source_file.getAbsolutePath(), File_Manager.getTypeFile(source_file.getAbsolutePath()));

            File file_target = File_Manager.createFile(path);

            byte[] file_send = new byte[file_encrypt.length + iv_size + tipe_file.length];
            //Aqui asigansamos el valor para agregar el tipo al final del archivo
            int val_tipo = file_encrypt.length + iv_size;

            //Copiamos todos el texto encriptado asi como el IVParameter y el tipo de 
            //Archivo dentro del byte[] y creamos el archivo
            System.arraycopy(file_encrypt, 0, file_send, 0,file_encrypt.length);
            System.arraycopy(iv.getIV(), 0, file_send, file_encrypt.length,iv_size);
            System.arraycopy(tipe_file, 0, file_send, val_tipo, tipe_file.length);

            FileOutputStream salida = new FileOutputStream(file_target);
            salida.write(file_send);

            in.close();
            salida.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | FileNotFoundException ex) {
            Logger.getLogger(Aes.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Aes.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void decryptAesFile(File target_file, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key.getEncoded(), "AES");

            byte[] input_data = new byte[(int) target_file.length()];
            FileOutputStream file_exit;
            try (FileInputStream in = new FileInputStream(target_file)) {
                in.read(input_data);
                byte[] ivp = new byte[iv_size];
                byte [] tipo = new byte[4];
                int val_text = input_data.length - (ivp.length+tipo.length);
                byte[] text_cipher = new byte[val_text];
                System.arraycopy(input_data, 0, text_cipher, 0, text_cipher.length);
                System.arraycopy(input_data,0,text_cipher,0, val_text);
                System.arraycopy(input_data,val_text,ivp,0, ivp.length);
                System.arraycopy(input_data, 0, text_cipher, 0, val_text);
                //Esta variable coloca en la posicion donde se inicia la extencion del
                //Archivo
                int valor_tipo = text_cipher.length+ivp.length;
                System.arraycopy(input_data,valor_tipo, tipo,0, tipo.length);
                //Creamos el IVParam embedido en el archivo cuando lo ciframos previamente
                IvParameterSpec ivParam = new IvParameterSpec(ivp);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParam);
                String ruta_archivo = File_Manager.getFileNameWithFileExtension(target_file.getAbsolutePath(), tipo);
                File file_source = File_Manager.createFile(ruta_archivo);
                byte[] salida = cipher.doFinal(text_cipher);
                file_exit = new FileOutputStream(file_source);
                file_exit.write(salida);
            }
            file_exit.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Aes.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

        //Metdodos privados que se encargaran del cifrado de mensajes
    private static String decryptAesMessage(byte[] message_aes, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        SecretKeySpec secretKey = new SecretKeySpec(key.getEncoded(), "AES");

        int valor_ivp = message_aes.length - iv_size;
        byte[] iv = new byte[iv_size];
        byte[] text_encrypt = new byte[valor_ivp];

        System.arraycopy(message_aes, valor_ivp, iv, 0, iv_size);
        IvParameterSpec ivparam = new IvParameterSpec(iv);

        System.arraycopy(message_aes, 0, text_encrypt, 0, text_encrypt.length);
        ByteArrayInputStream in = new ByteArrayInputStream(text_encrypt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparam);
        CipherInputStream input = new CipherInputStream(in, cipher);
        InputStreamReader input_reader = new InputStreamReader(input);
        try (BufferedReader reader = new BufferedReader(input_reader)) {
            return reader.readLine();
        }
    }

    private static byte[] encryptAesMessage(String message, SecretKey key, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        SecretKeySpec secretKey = new SecretKeySpec(key.getEncoded(), "AES");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        CipherOutputStream cipherOut = new CipherOutputStream(out, cipher);
        try (OutputStreamWriter salida = new OutputStreamWriter(cipherOut)) {
            salida.write(message);
        }
        byte[] out_data = new byte[out.size() + iv.getIV().length];
        System.arraycopy(out.toByteArray(), 0, out_data, 0, out.size());
        System.arraycopy(iv.getIV(), 0, out_data, out.toByteArray().length, iv.getIV().length);

        return out_data;
    }

    
    //Este metodo privado devuelve la clave ingresada por el usuario
    private static SecretKey getKey(String password) throws NoSuchAlgorithmException {
        KeyGenerator key = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        random.setSeed(password.getBytes());
        key.init(128, random);
        SecretKey secret = key.generateKey();
        return secret;
    }

    //Este metodo devuelve el IVparam para e padding de cifrado
    private static IvParameterSpec getIvParameter() {
        byte[] ivParameter = new byte[iv_size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivParameter);
        IvParameterSpec iv = new IvParameterSpec(ivParameter);
        return iv;
    }
}
